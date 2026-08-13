"""Phase 0 gate — prove every external dependency works before writing features.

Run this FIRST, and run it again any time the demo behaves strangely.

    python scripts/smoke_test_keys.py

Why this exists as its own script: a Safe Browsing key that needs the API enabled
in the Cloud console, or a Gemini key that is region-blocked, is a 30-minute fix
at hour 0 and a project-killer at hour 14. Each check prints the *specific* fix
for its own failure mode rather than a generic traceback.

Exit code 0 = every required dependency is live.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

# Allow running as `python scripts/smoke_test_keys.py` from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import get_settings  # noqa: E402

settings = get_settings()

OK = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"


async def check_gemini() -> bool:
    """Send the cheapest possible real generation request."""
    if not settings.GEMINI_API_KEY:
        print(f"  {SKIP}  Gemini - no GEMINI_API_KEY in .env")
        print("         Get one free: https://aistudio.google.com/apikey")
        return False

    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.GEMINI_MODEL}:generateContent"
    )
    payload = {
        "contents": [{"parts": [{"text": "Reply with exactly: ready"}]}],
        "generationConfig": {
            # Cap output: this runs often and there is no reason to pay for prose.
            # 64 rather than 10 because 2.5-series models spend output tokens on
            # internal reasoning first — a tight cap returns finishReason
            # MAX_TOKENS with an *empty* parts list, which reads as a broken key.
            "maxOutputTokens": 64,
            "temperature": 0,
            # SentinelAI needs classification, not deliberation, and thinking
            # tokens are pure added latency on a call that sits in the typing path.
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                url, json=payload, headers={"x-goog-api-key": settings.GEMINI_API_KEY}
            )
    except httpx.RequestError as exc:
        print(f"  {FAIL}  Gemini - network error: {exc!r}")
        return False

    if response.status_code == 200:
        candidate = response.json()["candidates"][0]
        # Defensive join: a truncated response has content={} with no "parts",
        # so indexing [0] directly would raise KeyError and mask the real cause.
        text = "".join(
            part.get("text", "") for part in candidate.get("content", {}).get("parts", [])
        ).strip()
        if not text:
            print(f"  {FAIL}  Gemini - 200 OK but empty text "
                  f"(finishReason={candidate.get('finishReason')})")
            print("         -> Raise maxOutputTokens or set thinkingConfig.thinkingBudget=0.")
            return False
        print(f"  {OK}  Gemini ({settings.GEMINI_MODEL}) responded: {text!r}")
        return True

    print(f"  {FAIL}  Gemini - HTTP {response.status_code}: {response.text[:200]}")
    if response.status_code in (400, 403):
        print("         -> Key invalid, or the Generative Language API is not enabled.")
    elif response.status_code == 404:
        print(f"         -> Model {settings.GEMINI_MODEL!r} not available to this key.")
        print("           Try GEMINI_MODEL=gemini-2.5-flash in .env.")
    elif response.status_code == 429:
        # Verified on this project: 429 here is a *per-model* quota of zero, not
        # a burst limit. gemini-2.0-flash 429s immediately on AI Studio express
        # keys while gemini-2.5-flash serves fine, so waiting will not help.
        print("         -> Quota exhausted FOR THIS MODEL. This is usually not a burst")
        print("            limit: set GEMINI_MODEL=gemini-2.5-flash in .env and retry now.")
    return False


async def check_safe_browsing() -> bool:
    """Look up a URL Google publishes specifically for testing detection."""
    if not settings.SAFE_BROWSING_API_KEY:
        print(f"  {SKIP}  Safe Browsing - no SAFE_BROWSING_API_KEY in .env")
        return False

    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "sentinelai", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            # Google's own always-flagged test URL. A live key must match this.
            "threatEntries": [{"url": "http://testsafebrowsing.appspot.com/s/phishing.html"}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                url, params={"key": settings.SAFE_BROWSING_API_KEY}, json=payload
            )
    except httpx.RequestError as exc:
        print(f"  {FAIL}  Safe Browsing - network error: {exc!r}")
        return False

    if response.status_code == 200:
        matches = response.json().get("matches", [])
        if matches:
            print(f"  {OK}  Safe Browsing flagged the test URL: {matches[0]['threatType']}")
            return True
        # 200 with no matches means the key works but detection didn't fire —
        # worth surfacing loudly, because it looks identical to "site is clean".
        print(f"  {FAIL}  Safe Browsing - key works but test URL was NOT flagged.")
        print("         -> Unexpected. Verify the test URL is still live before relying on this.")
        return False

    print(f"  {FAIL}  Safe Browsing - HTTP {response.status_code}: {response.text[:200]}")
    if response.status_code == 403:
        print("         -> Enable 'Safe Browsing API' in the Google Cloud console for this project.")
    return False


async def check_rdap() -> bool:
    """Domain age via RDAP — free, no key, no signup. Must follow redirects."""
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            response = await client.get("https://rdap.org/domain/google.com")
    except httpx.RequestError as exc:
        print(f"  {FAIL}  RDAP - network error: {exc!r}")
        return False

    if response.status_code != 200:
        print(f"  {FAIL}  RDAP - HTTP {response.status_code}")
        return False

    events = response.json().get("events", [])
    registration = next(
        (e["eventDate"] for e in events if e.get("eventAction") == "registration"), None
    )
    if registration:
        print(f"  {OK}  RDAP - google.com registered {registration}")
        return True

    print(f"  {FAIL}  RDAP - 200 OK but no registration event in payload")
    return False


async def main() -> int:
    print("\nSentinelAI - Phase 0 dependency check\n" + "=" * 44)

    gemini, safe_browsing, rdap = await asyncio.gather(
        check_gemini(), check_safe_browsing(), check_rdap()
    )

    print("=" * 44)

    # RDAP is the only hard requirement with no fallback. Gemini absent means
    # Tier-1-only (degraded but demoable); Safe Browsing absent means Module 2
    # loses its strongest signal but still has domain age + brand mismatch.
    if not rdap:
        print("\n\033[91mBLOCKED\033[0m - RDAP unreachable. Check your network.\n")
        return 1

    if gemini and safe_browsing:
        print("\n\033[92mCheckpoint 0 complete.\033[0m All tiers armed. Start Phase 1.\n")
        return 0

    degraded = [
        name
        for name, ok in (("Gemini Tier-2", gemini), ("Safe Browsing", safe_browsing))
        if not ok
    ]
    print(f"\n\033[93mDEGRADED\033[0m - unavailable: {', '.join(degraded)}")
    print("Phase 1 (regex tier) needs neither and can start now. Fix these before Phase 3/4.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
