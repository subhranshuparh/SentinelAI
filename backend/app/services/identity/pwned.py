"""Pwned Passwords range client — the k-anonymity half of Module 4.

The security property this file exists to preserve, stated once so the rest of
the code can be read against it:

    **The password never reaches this process.** Not in plaintext, not hashed,
    not encrypted. The extension computes ``SHA-1(password)`` in the popup and
    sends the first **five hex characters** of the digest. Roughly a thousand of the
    corpus's ~900 million passwords share any given five-character prefix, so
    what arrives here is a set membership question about a crowd, not about a
    person.

Why the backend proxies this at all, rather than the popup calling
``api.pwnedpasswords.com`` directly (which would work — it sends
``Access-Control-Allow-Origin: *``):

* The user's IP address never reaches a third party. Prefix + IP over time is a
  meaningfully worse leak than prefix alone.
* One TTL cache serves every rehearsal of the demo. The corpus changes a few
  times a year; re-fetching the same range twenty times in an afternoon is pure
  waste and, on a bad network, twenty chances to fail on stage.
* It matches the rule the rest of the codebase already follows: outbound calls
  originate server-side, where there are no keys in inspectable client code and
  one place to add a timeout.

No API key. This endpoint is free and unauthenticated — it is HIBP's
breach-*by-email* API that has required a paid key since 2019, and that half
stays cut (see ROADMAP §1.4).
"""

from __future__ import annotations

import logging
import re
import threading

import httpx

from app.core.cache import TTLCache

logger = logging.getLogger(__name__)

_ENDPOINT = "https://api.pwnedpasswords.com/range/{prefix}"

#: Exactly five uppercase hex characters. Anything else is rejected before a
#: request is built — a longer prefix would narrow the anonymity set, which is
#: the one thing this module must never allow, even by accident.
PREFIX_PATTERN = re.compile(r"^[0-9A-F]{5}$")

#: Not on the typing path — a user pressed a button and is watching a spinner —
#: so a slower budget than Tier 2 is affordable. Still bounded: a hung request
#: here would leave the popup spinning with no verdict.
TIMEOUT_SECONDS = 6.0

#: The corpus is refreshed a handful of times a year. Twelve hours is
#: indistinguishable from live for correctness and removes every repeat call
#: during a rehearsal.
CACHE_TTL_SECONDS = 12 * 60 * 60

#: HIBP caps a range response at a few hundred lines; this is a sanity ceiling
#: on a body we did not generate, not a functional limit.
MAX_SUFFIXES = 2_000

_cache = TTLCache(max_entries=512)
_client: httpx.Client | None = None
_client_lock = threading.Lock()


def _get_client() -> httpx.Client:
    """One pooled client, same reasoning as the Gemini tier: TLS handshakes are
    a large fraction of a six-second budget and there is no reason to pay one
    per check."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = httpx.Client(
                    timeout=httpx.Timeout(TIMEOUT_SECONDS),
                    headers={
                        # Documented HIBP feature: pads the response with fake
                        # zero-count entries so every range answer is a similar
                        # size. Without it, an observer sitting on the wire could
                        # infer something from the *length* of the reply even
                        # though they cannot read the body over TLS.
                        "Add-Padding": "true",
                        "User-Agent": "SentinelAI-hackathon-build",
                    },
                )
    return _client


def normalise_prefix(prefix: str) -> str | None:
    """Uppercase and validate. ``None`` means "do not send this anywhere"."""
    candidate = prefix.strip().upper()
    return candidate if PREFIX_PATTERN.match(candidate) else None


def _parse_range(body: str) -> dict[str, int]:
    """Parse ``SUFFIX:COUNT`` lines into a mapping.

    Padding entries carry ``count == 0`` and are dropped here: they exist to
    normalise the response size and are not real passwords, so letting one
    through would be a false "your password was found" at count zero.
    """
    suffixes: dict[str, int] = {}
    for line in body.splitlines():
        if len(suffixes) >= MAX_SUFFIXES:
            break
        suffix, _, raw_count = line.partition(":")
        suffix = suffix.strip().upper()
        if len(suffix) != 35:
            continue
        try:
            count = int(raw_count.strip())
        except ValueError:
            continue
        if count <= 0:
            continue  # Padding.
        suffixes[suffix] = count
    return suffixes


def fetch_range(prefix: str) -> dict[str, int] | None:
    """Return ``{suffix: breach_count}`` for a five-char prefix.

    ``None`` means the lookup did not run — bad prefix, timeout, HTTP error.
    An empty dict means it ran and the range genuinely held nothing (possible
    only with padding disabled, but represented distinctly regardless).

    The ``None``/``{}`` distinction is the same invariant the site engine and
    the semantic tier enforce: **a check that did not answer is never a check
    that said "fine"**. A caller that conflated them would show a user a green
    tick because the network was down.
    """
    normalised = normalise_prefix(prefix)
    if normalised is None:
        return None

    cached = _cache.get(normalised)
    if cached is not None:
        return cached

    try:
        response = _get_client().get(_ENDPOINT.format(prefix=normalised))
        response.raise_for_status()
        suffixes = _parse_range(response.text)
    except httpx.TimeoutException:
        logger.info("Pwned Passwords range timed out after %.1fs", TIMEOUT_SECONDS)
        return None
    except httpx.HTTPStatusError as exc:
        # Status only. Never the prefix — a log line pairing prefix with a
        # timestamp is the closest thing to a password this system could leak.
        logger.warning("Pwned Passwords HTTP %d", exc.response.status_code)
        return None
    except Exception:  # noqa: BLE001 - a popup button must not 500.
        logger.warning("Pwned Passwords lookup failed", exc_info=False)
        return None

    _cache.set(normalised, suffixes, CACHE_TTL_SECONDS)
    return suffixes


def count_is_plausible(prefix: str, breach_count: int) -> bool | None:
    """Check that *some* suffix in this range carries ``breach_count``.

    The client matches its own hash locally and reports the resulting count, so
    the number arriving at ``/password-check`` is client-supplied. This verifies
    it against the real range **without learning which suffix it belongs to** —
    any of the ~1,000 entries could be the user's, so a positive answer narrows
    nothing.

    Returns ``True`` / ``False``, or ``None`` when the range could not be
    fetched. ``None`` is treated as "accept but say confidence is lower", never
    as a rejection: a network failure must not stop a user recording a result
    they can see with their own eyes.

    Worth being clear about the threat model. The only party who can lie here is
    the user, about their own password, on their own device — there is no
    adversary to defeat, and the check is a data-quality guard against a broken
    client, not a security control. It is cheap, it is honest about what it
    proves, and it costs one cached lookup.
    """
    if breach_count <= 0:
        # "Not found" is unverifiable by construction: absence from the range is
        # exactly what it claims, and there is no suffix to look for.
        return None
    suffixes = fetch_range(prefix)
    if suffixes is None:
        return None
    return breach_count in set(suffixes.values())


def clear_cache() -> None:
    """Test hook."""
    _cache.clear()
