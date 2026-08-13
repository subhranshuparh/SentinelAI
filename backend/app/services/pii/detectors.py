"""Tier 1 — deterministic PII detection. 14 detectors, zero network, zero cost.

Every detector is a pattern plus, where one exists, a validator. The validator is
what makes this tier trustworthy: a regex proposes, a checksum disposes.

Three precision techniques are used, in increasing order of desperation:

1. **Checksum** (Aadhaar, cards) — near-zero false positives. Preferred always.
2. **Distinctive fixed structure** (IFSC's reserved '0', PAN's 5-4-1 shape,
   ``AKIA`` prefixes) — no checksum exists, but the shape is rare in ordinary text.
3. **Required nearby context** (bank account, DOB) — the pattern alone is far too
   common, so a keyword must appear within a small window. Without this, "my
   order 4567891234" and "born in 1998" would fire constantly.

Detectors that need *semantic* judgement — a postal address, an internal project
name, a revenue figure — are deliberately absent. Structure cannot separate
"meet me at 42 Oak Street" from an address quoted in a news article. That is the
Tier-2 (Gemini) job, and mixing the two here is how a regex layer becomes noisy.

All functions are pure. ``tests/test_detectors.py`` exercises them with no server.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from app.services.pii.checksums import (
    card_brand,
    digits_only,
    ifsc_structurally_valid,
    luhn_valid,
    verhoeff_valid,
)
from app.services.pii.masking import mask_for


@dataclass(frozen=True)
class Finding:
    """One piece of sensitive data located in a span of text.

    ``reason`` and ``confidence`` are non-optional by construction — the
    explainability rule enforced at the type level, matching the DB column and
    the API schema. All three layers agree, so a bare verdict is unrepresentable.
    """

    pii_type: str
    label: str
    risk_level: str
    confidence: float
    reason: str
    explanation: str
    recommendation: str
    start: int
    end: int
    masked_preview: str
    suggested_replacement: str
    detection_tier: str = "regex"

    # --- Module 10: where this was about to go ------------------------------
    #
    # Both stay ``None`` on a typed scan, and that is the whole point. A typed
    # finding was not assessed against a destination, and rendering "not
    # assessed" as anything other than absent would turn silence into a claim.
    # ``never | rarely | expected | unknown`` once assessed.
    destination_fit: str | None = None
    #: One sentence naming the site, e.g. "Discord is not a place an API Key
    #: belongs." Authored in Python from an enum pair — never model output.
    destination_note: str | None = None

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class Detector:
    """A single PII pattern and everything needed to explain a match."""

    name: str
    label: str
    pattern: re.Pattern[str]
    risk_level: str
    base_confidence: float
    explanation: str
    recommendation: str
    #: Returns (is_valid, reason). Rejecting a match is how precision is bought.
    validator: Callable[[str], tuple[bool, str]] | None = None
    #: Keywords that must appear within CONTEXT_WINDOW chars for the match to count.
    context_keywords: tuple[str, ...] = field(default_factory=tuple)
    #: Which regex group holds the value (1 when the pattern has a wrapper).
    value_group: int = 0


#: How far either side of a match to search for a required context keyword.
#: 40 chars ≈ one clause — wide enough for "my account number is X", narrow
#: enough that an unrelated mention two sentences away does not trigger it.
CONTEXT_WINDOW = 40


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _validate_aadhaar(value: str) -> tuple[bool, str]:
    if verhoeff_valid(value):
        return True, "Matches the 12-digit Aadhaar format and the Verhoeff checksum validated"
    return False, ""


def _validate_card(value: str) -> tuple[bool, str]:
    if not luhn_valid(value):
        return False, ""
    brand = card_brand(value)
    length = len(digits_only(value))
    if brand:
        return True, f"{brand} card number: {length} digits and the Luhn checksum validated"
    return True, f"{length}-digit number passing the Luhn card checksum"


def _validate_ifsc(value: str) -> tuple[bool, str]:
    if ifsc_structurally_valid(value):
        return True, "Matches the RBI IFSC format (4 letters, reserved '0', 6 alphanumerics)"
    return False, ""


def _validate_indian_phone(value: str) -> tuple[bool, str]:
    digits = digits_only(value)
    national = digits[-10:]
    # Indian mobile numbers start 6-9. Landlines and short codes do not, and
    # excluding them removes a large slice of false positives on numeric text.
    if len(national) == 10 and national[0] in "6789":
        return True, "10-digit Indian mobile number beginning with 6-9"
    return False, ""


def _always_valid(reason: str) -> Callable[[str], tuple[bool, str]]:
    """For detectors whose pattern is itself the evidence."""

    def _validator(_value: str) -> tuple[bool, str]:
        return True, reason

    return _validator


#: Credential prefixes this tier can name, longest-first so ``sk-proj-`` is
#: reported as an OpenAI *project* key rather than falling to the generic
#: ``sk-`` branch. Insertion order is load-bearing; do not sort it.
#:
#: Module-level rather than a local inside the validator because
#: ``extension/content/clipboard.js`` blocks a paste synchronously on this same
#: set of prefixes, and ``tests/test_destinations.py`` reads both and asserts
#: they agree. A local dict would make that seam untestable, and the two lists
#: would drift the first time someone added a provider to one of them.
API_KEY_PREFIXES: dict[str, str] = {
    "AKIA": "AWS access key ID",
    "ASIA": "AWS temporary access key",
    "AIza": "Google API key",
    "ghp_": "GitHub personal access token",
    "gho_": "GitHub OAuth token",
    "ghu_": "GitHub user-to-server token",
    "ghs_": "GitHub server-to-server token",
    "sk_l": "Stripe live secret key",
    "sk_t": "Stripe test secret key",
    "sk-p": "OpenAI project API key",
    "sk-": "OpenAI API key",
    "xoxb": "Slack bot token",
    "xoxp": "Slack user token",
    "xoxa": "Slack app token",
    "xoxs": "Slack session token",
    "xoxo": "Slack legacy token",
}

#: The JWT detector below has no prefix table because it has exactly one prefix.
#: Named here so the extension-parity test can treat it the same way.
JWT_PREFIX = "eyJ"


def _validate_api_key(value: str) -> tuple[bool, str]:
    for prefix, description in API_KEY_PREFIXES.items():
        if value.startswith(prefix):
            return True, f"Matches the {description} format"
    return True, "Matches a known credential format"


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
#
# Ordering is by specificity, highest first. Overlap resolution (below) keeps the
# stronger finding, so a JWT is never also reported as a generic token.

DETECTORS: tuple[Detector, ...] = (
    # --- Credentials: highest risk, most distinctive shapes -----------------
    Detector(
        name="jwt",
        label="JWT / Session Token",
        # Three base64url segments; both header and payload start with '{"' when
        # decoded, which is what makes eyJ... a reliable marker.
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        risk_level="critical",
        base_confidence=0.97,
        explanation="A session token lets anyone holding it act as you, without a password.",
        recommendation="Never paste tokens into chat. Revoke this session if it has been shared.",
        validator=_always_valid("Three base64url segments in JWT structure, header begins '{\"'"),
    ),
    Detector(
        name="api_key",
        label="API Key / Secret",
        pattern=re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}"
            r"|ASIA[0-9A-Z]{16}"
            r"|AIza[0-9A-Za-z_\-]{35}"
            r"|gh[pous]_[A-Za-z0-9]{36,}"
            r"|sk_(?:live|test)_[0-9a-zA-Z]{16,}"
            # OpenAI: legacy "sk-<48>" and current "sk-proj-<long>". Hyphenated,
            # unlike Stripe's underscored sk_live_, so it needs its own branch.
            r"|sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"
            r"|xox[bpoas]-[0-9A-Za-z-]{10,})\b"
        ),
        risk_level="critical",
        base_confidence=0.96,
        explanation="A leaked key can be used to run up charges or read data on your account.",
        recommendation="Rotate this key immediately. Do not send it in a message.",
        validator=_validate_api_key,
    ),
    Detector(
        name="password",
        label="Password",
        # Only fires on an explicit label. A bare string is not identifiable as a
        # password, and guessing would make this the noisiest detector by far.
        pattern=re.compile(
            r"(?:password|passwd|pwd|passcode)\s*(?:is|:|=)\s*(?P<value>\S{4,})",
            re.IGNORECASE,
        ),
        risk_level="critical",
        base_confidence=0.90,
        explanation="Anyone who reads this message can sign in as you.",
        recommendation="Remove it and change the password if it has already been sent.",
        validator=_always_valid("Password stated explicitly next to a 'password:' label"),
        value_group=1,
    ),
    # --- Government identifiers: checksum-backed ---------------------------
    Detector(
        name="aadhaar",
        label="Aadhaar Number",
        pattern=re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
        risk_level="high",
        base_confidence=0.96,
        explanation="Aadhaar numbers can be used to open accounts or claim benefits in your name.",
        recommendation="Mask before sending. Share Aadhaar only through official UIDAI channels.",
        validator=_validate_aadhaar,
    ),
    Detector(
        name="credit_card",
        label="Payment Card Number",
        pattern=re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        risk_level="critical",
        base_confidence=0.97,
        explanation="A card number plus expiry and CVV is enough for someone to make purchases.",
        recommendation="Never send card details over chat or email. Use the merchant's checkout page.",
        validator=_validate_card,
    ),
    Detector(
        name="pan",
        label="PAN (Permanent Account Number)",
        # 5 letters, 4 digits, 1 letter. The 4th letter encodes holder type.
        pattern=re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        risk_level="high",
        base_confidence=0.92,
        explanation="PAN is used for tax and financial identity, and enables impersonation.",
        recommendation="Mask before sending. Share only with verified financial institutions.",
        validator=_always_valid("Matches the 5-letter / 4-digit / 1-letter PAN structure"),
    ),
    Detector(
        name="passport",
        label="Passport Number",
        # Indian format: one letter (excluding I, O, Q, X, Z) followed by 7 digits.
        pattern=re.compile(r"\b[A-PR-WY][0-9]{7}\b"),
        risk_level="high",
        base_confidence=0.78,  # No checksum exists; the shape is not rare enough for more.
        explanation="Passport numbers are used for identity verification and travel fraud.",
        recommendation="Share only with airlines, visa services, or official travel agents.",
        validator=_always_valid("Matches the Indian passport format (letter followed by 7 digits)"),
    ),
    # --- Financial ---------------------------------------------------------
    Detector(
        name="ifsc",
        label="IFSC Code",
        pattern=re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        risk_level="medium",
        base_confidence=0.94,
        explanation="An IFSC with an account number is enough to attempt fraudulent transfers.",
        recommendation="Send bank details only to people you have verified independently.",
        validator=_validate_ifsc,
    ),
    Detector(
        name="upi_id",
        label="UPI ID",
        # Restricted to real PSP handles — an open @word pattern would match
        # every email address in the text.
        pattern=re.compile(
            r"\b[\w.\-]{2,60}@(?:ybl|okhdfcbank|oksbi|okaxis|okicici|paytm|upi|apl|ibl|axl|"
            r"barodampay|jio|fbl|kotak|indus|hsbc|yesbank|idfcbank)\b",
            re.IGNORECASE,
        ),
        risk_level="medium",
        base_confidence=0.90,
        explanation="A UPI ID lets others send collect requests that look legitimate.",
        recommendation="Share your UPI ID only with people you know. Never approve unexpected requests.",
        validator=_always_valid("Matches a UPI handle from a recognised payment provider"),
    ),
    Detector(
        name="bank_account",
        label="Bank Account Number",
        # 9-18 digits matches far too much on its own, so a nearby keyword is
        # mandatory. This is technique 3 — the least precise, used only where
        # neither a checksum nor a distinctive structure exists.
        pattern=re.compile(r"\b\d{9,18}\b"),
        risk_level="high",
        base_confidence=0.72,
        explanation="Account numbers enable fraudulent transfers and targeted scam calls.",
        recommendation="Send account details through your bank's app, not over chat.",
        validator=_always_valid("Long numeric sequence appearing next to account-related wording"),
        context_keywords=("account", "a/c", "acct", "bank", "ifsc", "transfer", "deposit"),
    ),
    # --- Contact and personal ---------------------------------------------
    Detector(
        name="email",
        label="Email Address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        risk_level="low",
        base_confidence=0.95,
        explanation="Email addresses are the main input for phishing and credential-stuffing.",
        recommendation="Fine to share with people you trust. Avoid posting publicly.",
        validator=_always_valid("Matches standard email address structure"),
    ),
    Detector(
        name="phone",
        label="Phone Number",
        # The internal separator is not optional decoration: Indians write mobile
        # numbers as "98765 43210" far more often than as ten unbroken digits, and
        # requiring an unbroken run missed the most common real-world form.
        # 5+5 grouping only — an unanchored [\s-]? anywhere would start matching
        # digit pairs out of card and Aadhaar groupings.
        pattern=re.compile(r"(?:\+?91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b"),
        risk_level="medium",
        base_confidence=0.85,
        explanation="Phone numbers enable SIM-swap attacks and scam calls.",
        recommendation="Avoid posting publicly. Consider a secondary number for online forms.",
        validator=_validate_indian_phone,
    ),
    Detector(
        name="dob",
        label="Date of Birth",
        pattern=re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b"),
        risk_level="medium",
        base_confidence=0.70,
        explanation="Date of birth is a common identity-verification question for banks.",
        recommendation="Share only where legally required.",
        validator=_always_valid("Date in DD/MM/YYYY form appearing next to birth-related wording"),
        context_keywords=("dob", "birth", "born", "birthday", "b'day"),
    ),
    Detector(
        name="coordinates",
        label="Precise Location",
        # 4+ decimal places is roughly building-level precision. Fewer decimals
        # is city-level and not worth warning about.
        pattern=re.compile(r"\b-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,}\b"),
        risk_level="high",
        base_confidence=0.88,
        explanation="These coordinates pinpoint a location to within a few metres.",
        recommendation="Share a general area instead of exact coordinates.",
        validator=_always_valid("Latitude/longitude pair with metre-level precision"),
    ),
)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _has_context(text: str, start: int, end: int, keywords: tuple[str, ...]) -> bool:
    """True when any keyword appears within CONTEXT_WINDOW chars of the match."""
    window = text[max(0, start - CONTEXT_WINDOW) : end + CONTEXT_WINDOW].lower()
    return any(keyword in window for keyword in keywords)


def _build_finding(detector: Detector, match: re.Match[str], text: str) -> Finding | None:
    """Validate a raw regex match and turn it into an explained Finding.

    Returns None when the validator rejects it or required context is missing —
    the two mechanisms that keep this tier precise.
    """
    group = detector.value_group
    value = match.group(group)
    start, end = match.span(group)

    if detector.context_keywords and not _has_context(text, start, end, detector.context_keywords):
        return None

    reason = ""
    if detector.validator is not None:
        is_valid, reason = detector.validator(value)
        if not is_valid:
            return None

    confidence = detector.base_confidence
    # A context keyword next to an already-valid match is corroborating evidence.
    # Capped at 0.99: this tier is strong but never certain, and a displayed
    # "100% confident" is a promise the system cannot keep.
    if detector.context_keywords:
        confidence = min(0.99, confidence + 0.10)

    masked = mask_for(detector.name, value)
    return Finding(
        pii_type=detector.name,
        label=detector.label,
        risk_level=detector.risk_level,
        confidence=round(confidence, 2),
        reason=reason or f"Matches the {detector.label} format",
        explanation=detector.explanation,
        recommendation=detector.recommendation,
        start=start,
        end=end,
        masked_preview=masked,
        suggested_replacement=masked,
    )


#: Overlap priority by tier. A deterministic finding always beats a semantic one
#: for the same span: a checksum is arithmetic, a model's opinion is not, and a
#: user shown two warnings for one value assumes the tool is broken.
_TIER_RANK = {"regex": 0, "llm": 1}


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep the strongest finding when two detectors claim overlapping spans.

    Necessary because the registry is intentionally redundant: a Google API key
    also matches nothing else, but a 16-digit card also matches ``bank_account``,
    and a UPI ID also matches ``email``. Without this, one value would produce
    two warnings and the toast would look buggy.

    Ranking: tier first, then confidence, then longer span. Longer wins ties
    because the more specific pattern is almost always the one that consumed
    more characters. Shared with the Tier-2 merge in ``engine.py``, which is why
    it is public.
    """
    ordered = sorted(
        findings,
        key=lambda f: (_TIER_RANK.get(f.detection_tier, 9), -f.confidence, -f.length, f.start),
    )
    kept: list[Finding] = []
    for candidate in ordered:
        overlaps = any(candidate.start < k.end and k.start < candidate.end for k in kept)
        if not overlaps:
            kept.append(candidate)
    return sorted(kept, key=lambda f: f.start)


def scan_text(text: str, suppressed_types: frozenset[str] | None = None) -> list[Finding]:
    """Run every detector over ``text`` and return de-overlapped findings.

    ``suppressed_types`` carries the user's per-site "always allow" choices. They
    are filtered here, before any work — a suppressed type is never matched,
    never scored, and never persisted, so the override is a genuine opt-out
    rather than a UI-level hide.
    """
    if not text or not text.strip():
        return []

    suppressed = suppressed_types or frozenset()
    findings: list[Finding] = []

    for detector in DETECTORS:
        if detector.name in suppressed:
            continue
        for match in detector.pattern.finditer(text):
            finding = _build_finding(detector, match, text)
            if finding is not None:
                findings.append(finding)

    return resolve_overlaps(findings)
