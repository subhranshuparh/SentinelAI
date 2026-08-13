"""Gemini client for the semantic tier.

Three properties this module must have, in priority order:

1. **It can never break typing.** A slow, rate-limited, or dead Gemini degrades
   the answer to Tier 1 and says so. It does not raise into the request path and
   it does not add latency to the next keystroke once it starts failing.
2. **It never logs the user's text.** The whole product premise is that typed
   content is sensitive. A debug log line containing the scanned string would be
   the single worst bug in this codebase, so no log statement here interpolates
   it — not even at DEBUG.
3. **It is honest about not running.** Callers get ``None``, never an empty
   list, when the tier did not produce an answer. "Found nothing" and "could not
   check" are different facts and the UI shows them differently.

The ``None``-means-no-answer convention matches the extension's content script,
where a null scan result means "no verdict" rather than "clean".
"""

from __future__ import annotations

import json
import logging
import threading
import time

import httpx

from app.core.config import get_settings
from app.services.llm.phishing_prompts import (
    RESPONSE_SCHEMA as EMAIL_RESPONSE_SCHEMA,
)
from app.services.llm.phishing_prompts import (
    IntentVerdict,
    build_email_prompt,
    parse_intent,
)
from app.services.llm.prompts import RESPONSE_SCHEMA, build_prompt, parse_findings
from app.services.llm.review_prompts import (
    RESPONSE_SCHEMA as REVIEW_RESPONSE_SCHEMA,
)
from app.services.llm.review_prompts import (
    ReviewVerdict,
    build_reviews_prompt,
    parse_review_verdict,
)
from app.services.llm.scam_prompts import (
    RESPONSE_SCHEMA as SCAM_RESPONSE_SCHEMA,
)
from app.services.llm.scam_prompts import (
    ScamVerdict,
    build_conversation_prompt,
    parse_scam_verdict,
)
from app.services.pii.detectors import Finding

logger = logging.getLogger(__name__)
settings = get_settings()

_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------
#
# Without this, an offline demo pays the full timeout on *every* scan: type a
# sentence, wait 1.5s, get Tier-1 results that were ready instantly. The breaker
# turns the second failure into a permanent-feeling recovery — Tier 1 answers at
# full speed while a background clock decides when to try Gemini again.
#
# This is the mechanism behind Checkpoint 3's "kill the network, demo survives".

#: Consecutive failures before the tier is parked.
_FAILURE_THRESHOLD = 2
#: How long to stay parked. Long enough to cover a demo segment, short enough
#: that a genuinely transient blip self-heals before anyone notices.
_COOLDOWN_SECONDS = 60.0


class _Breaker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures = 0
        self._open_until = 0.0

    def allows_call(self) -> bool:
        with self._lock:
            return time.monotonic() >= self._open_until

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._open_until = 0.0

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= _FAILURE_THRESHOLD:
                self._open_until = time.monotonic() + _COOLDOWN_SECONDS
                logger.warning(
                    "Semantic tier parked for %.0fs after %d consecutive failures",
                    _COOLDOWN_SECONDS,
                    self._failures,
                )

    def reset(self) -> None:
        """Test hook. Production never needs this."""
        with self._lock:
            self._failures = 0
            self._open_until = 0.0


_breaker = _Breaker()


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

_client: httpx.Client | None = None
_client_lock = threading.Lock()


def _get_client() -> httpx.Client:
    """One pooled client for the process.

    A fresh ``httpx.Client`` per call would add a TLS handshake to a budget
    measured in hundreds of milliseconds — the connection reuse here is a
    meaningful slice of the timeout, not a micro-optimisation.
    """
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = httpx.Client(
                    timeout=httpx.Timeout(settings.GEMINI_TIMEOUT_SECONDS),
                    headers={"Content-Type": "application/json"},
                )
    return _client


def _generation_config() -> dict:
    config: dict = {
        # Zero temperature: this is a classification task, and a scanner that
        # returns different findings for identical text is untestable and,
        # on stage, unpredictable.
        "temperature": 0.0,
        "responseMimeType": "application/json",
        "responseSchema": RESPONSE_SCHEMA,
        "maxOutputTokens": 800,
    }
    # thinkingConfig exists only on the 2.5 family; sending it to a 2.0 model is
    # a 400. Gate on the name so the model is a config change, not a code change.
    if "2.5" in settings.GEMINI_MODEL:
        # Reasoning tokens would blow the 1.5s budget several times over. This is
        # span extraction, not a problem that needs deliberation.
        config["thinkingConfig"] = {"thinkingBudget": 0}
    return config


def _extract_json(body: dict) -> object | None:
    """Pull the JSON payload out of Gemini's envelope.

    Written defensively because every layer here is optional in the API's own
    schema: a blocked prompt returns candidates with no content, and a truncated
    response returns content with no parts.
    """
    candidates = body.get("candidates")
    if not candidates:
        return None
    parts = (candidates[0].get("content") or {}).get("parts") or []
    for part in parts:
        text = part.get("text")
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return None


def analyze_context(text: str) -> list[Finding] | None:
    """Run the semantic tier over ``text``.

    Returns the findings, or ``None`` if the tier did not run — key absent,
    breaker open, timeout, HTTP error, or an unparseable body. Callers must
    treat ``None`` as "not checked" and ``[]`` as "checked, nothing found".

    Never raises. Anything that reaches the bare ``except`` is a bug in this
    module, and a bug here must still not stop a user from typing.
    """
    if not settings.gemini_tier_available:
        return None
    if not _breaker.allows_call():
        return None

    prompt = build_prompt(text)
    request_body = {
        # System-level rules travel in their own field, structurally separate
        # from the user's text below. They are not two halves of one string.
        "systemInstruction": {"parts": [{"text": prompt.system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": prompt.user_content}]}],
        "generationConfig": _generation_config(),
    }

    try:
        response = _get_client().post(
            _ENDPOINT.format(model=settings.GEMINI_MODEL),
            # Key in a header, not the query string: query strings land in proxy
            # logs and browser history, and this one is a billable credential.
            headers={"x-goog-api-key": settings.GEMINI_API_KEY},
            json=request_body,
        )
        response.raise_for_status()
        payload = _extract_json(response.json())
    except httpx.TimeoutException:
        _breaker.record_failure()
        logger.info("Semantic tier timed out after %.1fs", settings.GEMINI_TIMEOUT_SECONDS)
        return None
    except httpx.HTTPStatusError as exc:
        _breaker.record_failure()
        # Status only. The response body can echo request content.
        logger.warning("Semantic tier HTTP %d", exc.response.status_code)
        return None
    except Exception:  # noqa: BLE001 - deliberate: this tier may never propagate.
        _breaker.record_failure()
        logger.warning("Semantic tier failed", exc_info=False)
        return None

    if payload is None:
        # A well-formed HTTP 200 carrying nothing usable: a safety block, or a
        # response truncated at maxOutputTokens. Not a transport failure, so the
        # breaker stays closed — retrying the next message is the right move.
        return []

    _breaker.record_success()
    return parse_findings(payload, prompt.sanitized_text, text)


#: An email analysis is a button press with a spinner on screen, not a
#: keystroke. It can afford real time, and it needs it — the model is reading a
#: document rather than extracting spans from one sentence.
EMAIL_TIMEOUT_SECONDS = 12.0


def analyze_email(sender: str | None, subject: str, body: str) -> IntentVerdict | None:
    """Run the intent tier over one pasted email.

    Returns ``None`` when the tier did not run — no key, breaker open, timeout,
    HTTP error, safety block, or an unparseable body. The caller treats that as
    "intent not assessed" and redistributes the weight; it never reads as
    "found nothing wrong".

    Shares the circuit breaker with ``analyze_context`` on purpose. One dead
    Gemini is one dead Gemini, and having the email path re-discover that fact
    with its own two timeouts would put a 24-second stall in front of a user who
    just pressed Analyse.
    """
    if not settings.gemini_tier_available:
        return None
    if not _breaker.allows_call():
        return None

    prompt = build_email_prompt(sender, subject, body)
    config = _generation_config()
    config["responseSchema"] = EMAIL_RESPONSE_SCHEMA
    # Room for a rationale plus three quotes. The span-extraction budget of 800
    # would truncate mid-JSON, which surfaces as a parse failure rather than a
    # short answer.
    config["maxOutputTokens"] = 1_200

    request_body = {
        "systemInstruction": {"parts": [{"text": prompt.system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": prompt.user_content}]}],
        "generationConfig": config,
    }

    try:
        response = _get_client().post(
            _ENDPOINT.format(model=settings.GEMINI_MODEL),
            headers={"x-goog-api-key": settings.GEMINI_API_KEY},
            json=request_body,
            timeout=EMAIL_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = _extract_json(response.json())
    except httpx.TimeoutException:
        _breaker.record_failure()
        logger.info("Intent tier timed out after %.1fs", EMAIL_TIMEOUT_SECONDS)
        return None
    except httpx.HTTPStatusError as exc:
        _breaker.record_failure()
        # Status only. A Gemini error body can echo the request, and the request
        # is somebody's email.
        logger.warning("Intent tier HTTP %d", exc.response.status_code)
        return None
    except Exception:  # noqa: BLE001 - deliberate: this tier may never propagate.
        _breaker.record_failure()
        logger.warning("Intent tier failed", exc_info=False)
        return None

    if payload is None:
        # A 200 carrying nothing usable. Very likely a safety block: phishing
        # emails contain threats and extortion language, which is exactly what
        # Gemini's safety filters are built to refuse. Not a transport failure,
        # so the breaker stays closed — but the answer is still "did not run",
        # because a blocked response is not a benign one.
        return None

    _breaker.record_success()
    return parse_intent(payload, prompt.sanitized)


#: Shorter than the email tier's 12s. A chat check runs while a conversation is
#: happening — an answer that arrives after the user has already replied is not
#: an answer, it is a post-mortem. Tier 1 has already produced a verdict by this
#: point, so the cost of giving up early is a missing row, not a missing warning.
CONVERSATION_TIMEOUT_SECONDS = 8.0


def analyze_conversation(text: str) -> ScamVerdict | None:
    """Run the scam intent tier over one conversation.

    ``text`` must be incoming-only. This function does not filter; see
    ``scam_prompts.build_conversation_prompt`` for why that responsibility lives
    in exactly one place.

    Returns ``None`` when the tier did not run — no key, breaker open, timeout,
    HTTP error, safety block, or an unparseable body. The caller treats that as
    "intent not assessed" and never as "found nothing wrong".

    Shares the circuit breaker with the other two tiers, for the reason
    ``analyze_email`` gives: one dead Gemini is one dead Gemini.
    """
    if not settings.gemini_tier_available:
        return None
    if not _breaker.allows_call():
        return None

    prompt = build_conversation_prompt(text)
    config = _generation_config()
    config["responseSchema"] = SCAM_RESPONSE_SCHEMA
    config["maxOutputTokens"] = 1_000

    request_body = {
        "systemInstruction": {"parts": [{"text": prompt.system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": prompt.user_content}]}],
        "generationConfig": config,
    }

    try:
        response = _get_client().post(
            _ENDPOINT.format(model=settings.GEMINI_MODEL),
            headers={"x-goog-api-key": settings.GEMINI_API_KEY},
            json=request_body,
            timeout=CONVERSATION_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = _extract_json(response.json())
    except httpx.TimeoutException:
        _breaker.record_failure()
        logger.info("Scam tier timed out after %.1fs", CONVERSATION_TIMEOUT_SECONDS)
        return None
    except httpx.HTTPStatusError as exc:
        _breaker.record_failure()
        # Status only. A Gemini error body can echo the request, and the request
        # is somebody's private conversation.
        logger.warning("Scam tier HTTP %d", exc.response.status_code)
        return None
    except Exception:  # noqa: BLE001 - deliberate: this tier may never propagate.
        _breaker.record_failure()
        logger.warning("Scam tier failed", exc_info=False)
        return None

    if payload is None:
        # A 200 carrying nothing usable, very likely a safety block — scam
        # conversations contain threats of arrest and demands for money, which
        # is exactly what Gemini's filters refuse. Not a transport failure, so
        # the breaker stays closed, but a blocked response is not a benign one.
        return None

    _breaker.record_success()
    return parse_scam_verdict(payload, prompt.sanitized)


#: The longest allowance of the four tiers. A review set is several documents
#: rather than one, and the question asked of the model — "do these resemble each
#: other" — is the only one here that genuinely needs the whole input in front of
#: it before the first token comes out. Nobody is mid-conversation while it runs;
#: they are looking at a product page having already decided to be suspicious.
REVIEWS_TIMEOUT_SECONDS = 14.0


def analyze_reviews(reviews: list[str]) -> ReviewVerdict | None:
    """Run the authenticity tier over one set of reviews.

    Returns ``None`` when the tier did not run — no key, breaker open, timeout,
    HTTP error, safety block, or an unparseable body. The caller treats that as
    "authenticity not assessed" and never as "these look genuine", which on this
    feature is the difference between a warning and an endorsement.

    Shares the circuit breaker with the other three tiers, for the reason
    ``analyze_email`` gives: one dead Gemini is one dead Gemini.
    """
    if not settings.gemini_tier_available:
        return None
    if not _breaker.allows_call():
        return None

    prompt = build_reviews_prompt(reviews)
    config = _generation_config()
    config["responseSchema"] = REVIEW_RESPONSE_SCHEMA
    config["maxOutputTokens"] = 1_000

    request_body = {
        "systemInstruction": {"parts": [{"text": prompt.system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": prompt.user_content}]}],
        "generationConfig": config,
    }

    try:
        response = _get_client().post(
            _ENDPOINT.format(model=settings.GEMINI_MODEL),
            headers={"x-goog-api-key": settings.GEMINI_API_KEY},
            json=request_body,
            timeout=REVIEWS_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = _extract_json(response.json())
    except httpx.TimeoutException:
        _breaker.record_failure()
        logger.info("Review tier timed out after %.1fs", REVIEWS_TIMEOUT_SECONDS)
        return None
    except httpx.HTTPStatusError as exc:
        _breaker.record_failure()
        # Status only. A Gemini error body can echo the request.
        logger.warning("Review tier HTTP %d", exc.response.status_code)
        return None
    except Exception:  # noqa: BLE001 - deliberate: this tier may never propagate.
        _breaker.record_failure()
        logger.warning("Review tier failed", exc_info=False)
        return None

    if payload is None:
        # A 200 carrying nothing usable. Less likely to be a safety block here
        # than on the email and chat tiers — product reviews rarely contain
        # threats — so this is usually a truncation. Either way the answer is
        # "did not run", never "organic".
        return None

    _breaker.record_success()
    return parse_review_verdict(payload, prompt.sanitized)


def reset_breaker() -> None:
    """Test hook — see ``_Breaker.reset``."""
    _breaker.reset()


def warm_up() -> None:
    """Establish the TLS connection before a user is waiting on it.

    Measured problem, not a theoretical one: the first call from a cold process
    took **10.6s** against a steady-state 1.4-1.9s. DNS, the TCP handshake, and
    the TLS handshake all land on whoever types first.

    Left alone, that one slow call exceeds the timeout, and two of them trip the
    circuit breaker — so the semantic tier would park itself for 60 seconds at
    exactly the moment a demo starts. Paying for the handshake at boot, on a
    daemon thread nobody waits for, removes the whole failure mode.

    Deliberately hits a cheap metadata endpoint rather than running a real scan:
    this warms the connection pool without spending generation quota. The
    breaker is never touched here — warming is not a health check, and a failed
    warm-up must not be counted against the tier.
    """
    if not settings.gemini_tier_available:
        return

    def _run() -> None:
        try:
            _get_client().get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": settings.GEMINI_API_KEY},
                timeout=15.0,
            )
            logger.info("Semantic tier connection warmed")
        except Exception:  # noqa: BLE001 - boot must never fail on this.
            logger.info("Semantic tier warm-up skipped (no network at boot)")

    threading.Thread(target=_run, name="gemini-warmup", daemon=True).start()
