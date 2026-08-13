"""Phishing verdict — three deterministic groups, one optional intent tier.

The scoring rule is the same one the site engine uses, for the same reason: the
denominator is the weight that **actually answered**. A sender line that was
never pasted does not vote "fine"; its weight is redistributed across the groups
that did run, so the remaining evidence counts for more rather than being
diluted by a check that never happened.

One rule is specific to this module, and it is the reason Tier 2 is safe to add:

    **The intent tier can raise the score. It can never lower it.**

Concretely, the final penalty is ``max(tier1, blend(tier1, intent))``. If the
heuristics found a link pointing at a lookalike domain and the model says
"benign", the answer stays dangerous. Model judgement earns the right to add a
finding the patterns missed; it does not earn the right to talk the patterns
out of something they proved. This is the asymmetry used throughout the
project — thin evidence blocks a clean bill of health, but never suppresses a
warning.

Nothing here touches the database. See ``phishing_prompts`` for why.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.llm.gemini import analyze_email
from app.services.llm.phishing_prompts import IntentVerdict
from app.services.phishing.heuristics import (
    MIN_BODY_CHARS,
    GroupResult,
    Hit,
    analyse_content,
    analyse_links,
    analyse_sender,
    strip_markup,
)

# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------
#
# Stated as constants so the number on screen can be defended out loud rather
# than reverse-engineered from behaviour.

#: Where the email actually sends you. Highest weight: it is a fact about the
#: message, not a reading of it, and it is what the user is about to act on.
WEIGHT_LINKS = 0.35
#: The ask, the deadline, the threat. Always available, so it is the floor the
#: module stands on when someone pastes a body with no headers.
WEIGHT_CONTENT = 0.30
#: Who it claims to be versus where it came from. Lowest of the three only
#: because it is the one that is routinely missing.
WEIGHT_SENDER = 0.15
#: The share the intent tier may contribute *upward*. See module docstring.
WEIGHT_INTENT = 0.20

#: Score at or above which the email is called dangerous.
THRESHOLD_DANGEROUS = 65
#: Score at or above which it is called suspicious.
THRESHOLD_SUSPICIOUS = 30

#: A clean verdict never claims near-certainty. "We found nothing" and "this is
#: definitely safe" are different statements, and only one of them is true.
MAX_CONFIDENCE_WHEN_CLEAN = 0.80


@dataclass(frozen=True)
class SignalOut:
    """One row in the user-facing explanation.

    ``weight`` uses the same three-value vocabulary as the site module — ``bad``
    for a finding, ``good`` for a check that ran and passed, ``unknown`` for one
    that could not run — so the dashboard renders both with one component and a
    check that did not run is visibly distinct from a check that passed.
    """

    signal: str
    detail: str
    weight: str
    evidence: str | None = None


@dataclass(frozen=True)
class PhishingResult:
    """Everything the API returns, decided here rather than in the router."""

    verdict: str
    #: 0-100, and note the direction: **higher means more dangerous**. This is
    #: the one score in the product that runs that way, because "risk 90" is how
    #: a person reads an email warning. The dashboard label says so explicitly.
    risk_score: int
    confidence: float
    summary: str
    recommendation: str
    signals: tuple[SignalOut, ...]
    #: Null when the intent tier did not run.
    intent: str | None
    intent_label: str | None
    #: True when the deterministic tier alone decided this.
    heuristics_only: bool


def _round_half_up(value: float) -> int:
    """Python's ``round`` is banker's rounding; 0.5 must go up here.

    A displayed score that disagrees with the arithmetic a judge does on paper
    is a credibility problem, not a rounding preference.
    """
    return int(value + 0.5)


# ---------------------------------------------------------------------------
# Copy, authored in Python
# ---------------------------------------------------------------------------
#
# None of these sentences is ever written by a model, and none of them is ever
# assembled from email content. The email chooses which key is looked up; it
# cannot choose what the key says.

_RECOMMENDATIONS: dict[str, str] = {
    "dangerous": (
        "Do not click any link in this email, do not open its attachments, and do not reply. "
        "If it claims to be from your bank or a government office, open their app yourself or "
        "call the number printed on your card or on their official website. Then delete it."
    ),
    "suspicious": (
        "Treat this as unverified. Do not use the links in it. If you think it might be real, "
        "reach the company the way you normally do — their app, or a number you already have — "
        "and ask them whether they sent it."
    ),
    "safe": (
        "Nothing suspicious was found, but that is not a guarantee. Whatever an email says, "
        "never type a password or an OTP into a page you reached by clicking a link in it."
    ),
    "unknown": (
        "There was not enough here to judge. Paste the whole email — the From line, the subject, "
        "and the full message including any links — and check it again."
    ),
}

#: Prepended when a specific finding deserves its own instruction. Ordered by
#: severity: the first match wins, so a user gets one clear action, not a list.
_SPECIFIC_ACTIONS: tuple[tuple[str, str], ...] = (
    (
        "credential_request",
        "If you have already entered a password or OTP because of this email, change that "
        "password now from the company's own app or website, not from this email.",
    ),
    (
        "unusual_payment",
        "If you have already sent a gift card code, crypto, or a transfer, contact your bank "
        "immediately — some transfers can still be stopped in the first few hours.",
    ),
    (
        "attachment_lure",
        "If you have already opened the attachment, disconnect from the internet and run a "
        "full antivirus scan before logging into anything.",
    ),
    (
        "link_display_mismatch",
        "If you have already clicked the link and entered anything, change that password now.",
    ),
    (
        "link_brand_mismatch",
        "If you have already clicked the link and entered anything, change that password now.",
    ),
)

_SUMMARIES: dict[str, str] = {
    "dangerous": "This looks like a phishing email.",
    "suspicious": "Parts of this email do not add up.",
    "safe": "No phishing signs found in this email.",
    "unknown": "Not enough of the email was provided to judge it.",
}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _tier1_penalty(links: GroupResult, content: GroupResult, sender: GroupResult) -> float:
    """Weighted average over the groups that actually ran.

    Links and content are always available, so the denominator can never be
    zero — but it is written as a general redistribution anyway, because the
    day a fourth group is added with its own availability rule is the day a
    hardcoded assumption here becomes a silent bug.
    """
    parts = (
        (WEIGHT_LINKS, links),
        (WEIGHT_CONTENT, content),
        (WEIGHT_SENDER, sender),
    )
    available = sum(weight for weight, group in parts if group.available)
    if available <= 0:
        return 0.0
    return sum(weight * group.penalty for weight, group in parts if group.available) / available


def _apply_intent(tier1: float, intent: IntentVerdict | None) -> float:
    """Fold the intent tier in, upward only. See the module docstring."""
    if intent is None:
        return tier1
    blended = tier1 * (1 - WEIGHT_INTENT) + intent.spec.penalty * WEIGHT_INTENT
    return max(tier1, blended)


def _verdict_for(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:
        return "dangerous"
    if score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _confidence(
    verdict: str,
    sender_available: bool,
    intent: IntentVerdict | None,
    hit_count: int,
) -> float:
    """How much to trust this verdict, stated rather than implied.

    Built from what was actually available: more of the email pasted, more
    tiers that answered, and more independent signals agreeing all raise it.
    """
    confidence = 0.55
    if sender_available:
        confidence += 0.15
    if intent is not None:
        confidence += 0.10
    if hit_count >= 3:
        confidence += 0.10
    elif hit_count == 2:
        confidence += 0.05
    confidence = min(0.95, confidence)
    if verdict == "safe":
        confidence = min(MAX_CONFIDENCE_WHEN_CLEAN, confidence)
    return round(confidence, 2)


def _signals_for(group: GroupResult, passed_name: str, missing_name: str) -> list[SignalOut]:
    """Turn a group into user-facing rows, including the ones with no finding.

    A group that ran and found nothing still emits a row. The list is the
    evidence for the verdict, and evidence includes what was checked and came
    back clean — a user who sees only red rows has no way to know how much of
    the email was examined.
    """
    if not group.available:
        return [SignalOut(signal=missing_name, detail=group.detail, weight="unknown")]
    if not group.hits:
        return [SignalOut(signal=passed_name, detail=group.detail, weight="good")]
    return [
        SignalOut(signal=hit.name, detail=hit.detail, weight="bad", evidence=hit.evidence)
        for hit in group.hits
    ]


def _recommendation_for(verdict: str, hits: list[Hit]) -> str:
    """Base advice for the verdict, plus at most one finding-specific action."""
    base = _RECOMMENDATIONS[verdict]
    names = {hit.name for hit in hits}
    for name, extra in _SPECIFIC_ACTIONS:
        if name in names:
            return f"{extra} {base}"
    return base


def analyse(
    sender: str | None,
    subject: str,
    body: str,
    *,
    reply_to: str | None = None,
    use_intent_tier: bool = True,
) -> PhishingResult:
    """Analyse one pasted email. Pure apart from the optional Gemini call.

    ``use_intent_tier=False`` makes the whole function deterministic and
    offline, which is how the tests exercise the scoring rules without a key or
    a network.
    """
    subject = subject or ""
    body = body or ""

    # Enough text to judge? Measured on the visible words, not the raw paste —
    # 300 characters of HTML wrapper around "call us" is not 300 characters of
    # email, and rating it as though it were would be exactly the false
    # confidence this module refuses to produce.
    visible = strip_markup(f"{subject}\n{body}").strip()
    if len(visible) < MIN_BODY_CHARS:
        return PhishingResult(
            verdict="unknown",
            risk_score=0,
            confidence=0.0,
            summary=_SUMMARIES["unknown"],
            recommendation=_RECOMMENDATIONS["unknown"],
            signals=(
                SignalOut(
                    signal="insufficient_text",
                    detail=(
                        "There were fewer than "
                        f"{MIN_BODY_CHARS} characters of readable text to work with."
                    ),
                    weight="unknown",
                ),
            ),
            intent=None,
            intent_label=None,
            heuristics_only=True,
        )

    links = analyse_links(body)
    content = analyse_content(subject, body)
    sender_group = analyse_sender(sender, reply_to, subject)

    tier1 = _tier1_penalty(links, content, sender_group)

    intent: IntentVerdict | None = None
    if use_intent_tier:
        # Never raises — see ``analyze_email``. A dead Gemini costs this call
        # nothing beyond the breaker check.
        intent = analyze_email(sender, subject, body)

    score = max(0, min(100, _round_half_up(_apply_intent(tier1, intent))))
    verdict = _verdict_for(score)

    hits = [*links.hits, *content.hits, *sender_group.hits]
    signals: list[SignalOut] = []
    signals += _signals_for(links, "links_clean", "links_missing")
    signals += _signals_for(content, "wording_clean", "wording_missing")
    signals += _signals_for(sender_group, "sender_clean", "sender_missing")

    if intent is not None:
        # The model's row is labelled as a reading, not a fact, and it is
        # ranked after the deterministic rows for the same reason.
        signals.append(
            SignalOut(
                signal=f"intent_{intent.intent}",
                detail=f"AI reading of the intent: {intent.rationale}",
                weight="good" if intent.intent == "benign" else "bad",
                evidence=intent.quotes[0] if intent.quotes else None,
            )
        )
    else:
        signals.append(
            SignalOut(
                signal="intent_missing",
                detail=(
                    "The AI intent check did not run, so this verdict is based on the "
                    "pattern checks alone."
                ),
                weight="unknown",
            )
        )

    # Findings first. A user reads the top of a list, and the top of this one
    # must be what is wrong rather than what happened to be checked first.
    order = {"bad": 0, "unknown": 1, "good": 2}
    signals.sort(key=lambda s: order[s.weight])

    return PhishingResult(
        verdict=verdict,
        risk_score=score,
        confidence=_confidence(verdict, sender_group.available, intent, len(hits)),
        summary=_SUMMARIES[verdict],
        recommendation=_recommendation_for(verdict, hits),
        signals=tuple(signals),
        intent=intent.intent if intent else None,
        intent_label=intent.spec.label if intent else None,
        heuristics_only=intent is None,
    )
