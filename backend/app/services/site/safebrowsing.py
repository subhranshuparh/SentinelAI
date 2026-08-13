"""Google Safe Browsing v4 lookup.

The one signal here backed by an industry-scale crawl: Google sees phishing and
malware campaigns across the whole web, which no amount of local analysis can
replicate. It is also the *slowest to react* — a domain registered an hour ago
is not on any list yet — which is precisely why it is one of three signals and
not the whole module.

**The privacy trade-off, stated rather than buried.** This endpoint works by
sending the user's URL to Google. Inside a tool whose premise is "your typing is
private", that deserves an explicit decision, so:

  * the query string and fragment are **removed before the request leaves this
    process**. That is where session tokens, password-reset links, email
    addresses in `?email=`, and search terms live. Sending them to a third party
    to ask whether a site is safe would leak more than the check protects.
  * the path is **kept**, because phishing routinely lives on a path of an
    otherwise legitimate host (`sites.google.com/view/…`), and dropping it would
    blind the check to a real and common attack.

The Update API would avoid sending URLs at all by downloading hash prefixes
locally. It is the correct production answer and it is roughly a day of work to
implement and keep in sync — out of scope here, and named as roadmap rather than
quietly skipped.
"""

from __future__ import annotations

import logging
import threading
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

#: The four threat types Safe Browsing publishes. All four are requested:
#: SOCIAL_ENGINEERING is the phishing case this product cares most about, but a
#: user typing their card number into a malware-hosting page is no better off.
_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

#: Plain-language names. The API's own vocabulary ("SOCIAL_ENGINEERING") is
#: meaningless to the people this module is built for.
_THREAT_LABELS = {
    "MALWARE": "software that damages your device",
    "SOCIAL_ENGINEERING": "phishing — a fake page built to steal your details",
    "UNWANTED_SOFTWARE": "software that changes your browser without asking",
    "POTENTIALLY_HARMFUL_APPLICATION": "a harmful app download",
}

_client: httpx.Client | None = None
_lock = threading.Lock()


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = httpx.Client(
                    timeout=httpx.Timeout(settings.SAFE_BROWSING_TIMEOUT_SECONDS),
                    headers={"Content-Type": "application/json"},
                )
    return _client


def strip_sensitive_parts(url: str) -> str:
    """Remove the query string and fragment before the URL leaves this process.

    Public and separately tested, because it is the privacy promise above and a
    promise that is not tested is a hope.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def lookup(url: str) -> tuple[bool, list[str]] | None:
    """Ask Safe Browsing about ``url``.

    Returns ``(is_listed, plain_language_threats)``, or ``None`` when the check
    could not be performed — no key, timeout, HTTP error, or an unparseable
    body. ``None`` is not ``(False, [])``: "Google says it is clean" and "we
    could not ask Google" are different facts, and the scorer weights them
    differently.
    """
    if not settings.SAFE_BROWSING_API_KEY:
        return None

    safe_url = strip_sensitive_parts(url)
    body = {
        "client": {"clientId": "sentinelai", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": safe_url}],
        },
    }

    try:
        response = _get_client().post(
            _ENDPOINT,
            params={"key": settings.SAFE_BROWSING_API_KEY},
            json=body,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPStatusError as exc:
        # Status only. Never the body — it echoes the submitted URL.
        logger.warning("Safe Browsing HTTP %d", exc.response.status_code)
        return None
    except (httpx.HTTPError, ValueError):
        logger.info("Safe Browsing lookup failed")
        return None

    matches = payload.get("matches")
    if not matches:
        # An empty body is Safe Browsing's way of saying "not on any list".
        # A real, informative answer — not a failure.
        return False, []

    threats = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        threat_type = match.get("threatType", "")
        label = _THREAT_LABELS.get(threat_type)
        if label and label not in threats:
            threats.append(label)

    return True, threats or ["a known threat"]
