"""Domain age via RDAP.

RDAP is the IETF replacement for WHOIS: JSON instead of scraped text, served
free and unauthenticated by the registries themselves. No key, no signup, no
vendor. ``rdap.org`` is a bootstrap redirector that follows the IANA registry
map to the correct server per TLD, so ``.com``, ``.xyz`` and ``.top`` all work
through one URL — which is why redirects must be followed.

**Why domain age is worth a network call:** phishing infrastructure is
disposable. A domain registered four days ago that is asking for your banking
password is not a startup, and the registration date is a fact from the registry
rather than an opinion from a model.

**The rule that matters more than the lookup:** a missing answer is *unknown*,
never *safe*. Many ccTLD registries return 404, rate-limit, or omit the
registration event entirely. Defaulting those to "old and trustworthy" would
mean every domain in an unsupported TLD silently scores clean — the exact
failure that makes security tools dangerous instead of merely useless.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.db.models import utcnow

logger = logging.getLogger(__name__)
settings = get_settings()

_BOOTSTRAP = "https://rdap.org/domain/{domain}"

#: rdap.org emits exactly one redirect, to the registry holding the record. The
#: allowance of three is slack for a registry that redirects again internally;
#: it is a loop guard, not an expectation.
_MAX_REDIRECTS = 3

#: Below this, a request is not worth issuing — it would spend the remaining
#: budget on a TCP handshake and time out anyway.
_MIN_USEFUL_SECONDS = 0.4

_client: httpx.Client | None = None
_lock = threading.Lock()


def _get_client() -> httpx.Client:
    """Pooled client with redirects handled **manually**.

    ``follow_redirects=True`` looks like the obvious choice here and is a trap.
    ``httpx.Timeout`` is per *operation* — connect, read, write, pool — not per
    call, so a two-hop chain can legitimately spend twice the configured budget
    and still fail. Measured against real registries, that is exactly what
    happened: ``uidai.gov.in`` returns a perfectly good 200 in 3.5s, but the
    4s setting killed it at 5.03s, because hop 2's read clock started only after
    hop 1 had already finished.

    Following redirects by hand is what makes ``RDAP_TIMEOUT_SECONDS`` mean what
    its name says: a ceiling on the whole lookup, wall-clock, hops included.
    """
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = httpx.Client(
                    follow_redirects=False,
                    headers={"Accept": "application/rdap+json"},
                )
    return _client


def _fetch_within_deadline(url: str) -> httpx.Response | None:
    """GET ``url``, following redirects until the shared deadline expires."""
    deadline = time.monotonic() + settings.RDAP_TIMEOUT_SECONDS
    client = _get_client()

    for _ in range(_MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining < _MIN_USEFUL_SECONDS:
            logger.info("RDAP budget exhausted before %s", url)
            return None

        response = client.get(url, timeout=httpx.Timeout(remaining))
        if not response.is_redirect:
            return response

        location = response.headers.get("location")
        if not location:
            return None
        url = str(response.url.join(location))

    logger.info("RDAP redirect limit reached for %s", url)
    return None


def _parse_registration(body: dict) -> datetime | None:
    """Pull the registration date out of an RDAP response.

    The ``events`` array is the standard location, but registries differ on
    casing and some emit ``registered`` instead of the RFC's ``registration``.
    Both are accepted; anything else is treated as absent rather than guessed at.
    """
    events = body.get("events")
    if not isinstance(events, list):
        return None

    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        if action not in {"registration", "registered"}:
            continue
        raw = event.get("eventDate")
        if not isinstance(raw, str):
            continue
        try:
            # RDAP dates are RFC 3339. Python <3.11 rejects a literal "Z", and
            # normalising it is cheaper than a dateutil dependency.
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        # A naive datetime here would compare wrong against utcnow() and could
        # produce a negative age, which the scorer would read as "the future".
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def domain_age_days(domain: str) -> int | None:
    """Age of ``domain`` in days, or ``None`` when the registry did not say.

    Never raises. The caller treats ``None`` as an absent signal and
    redistributes its weight — see ``site/engine.py``.
    """
    try:
        response = _fetch_within_deadline(_BOOTSTRAP.format(domain=domain))
    except httpx.HTTPError:
        logger.info("RDAP lookup failed for %s", domain)
        return None

    if response is None:
        return None

    if response.status_code != 200:
        # 404 is the common, boring case: plenty of registries simply do not
        # publish RDAP. Logged at info because it is not an error condition.
        logger.info("RDAP returned %d for %s", response.status_code, domain)
        return None

    try:
        registered = _parse_registration(response.json())
    except ValueError:
        return None

    if registered is None:
        return None

    age = (utcnow() - registered).days
    # Clock skew or a registry publishing a future date. Clamp rather than
    # return a negative, which downstream would score as "impossibly new".
    return max(0, age)
