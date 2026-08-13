"""Chat scam verdict — three deterministic groups, one optional intent tier.

Structurally this is Module 3's engine with a different first group, and that is
the point: the scoring rule, the missing-signal rule, and the "the model may
raise, never lower" asymmetry are all properties of the *project*, not of the
email feature, so they are reused rather than reinvented.

Three groups run:

* **conversation** — the new one. What is being asked for. Highest weight
  because it is the only group that reads the conversation *as* a conversation.
* **links** — ``analyse_links`` verbatim from Module 3. A lookalike domain in a
  WhatsApp message is the same fact it is in an email, and rewriting that logic
  here would give the product two answers to one question.
* **wording** — ``analyse_content`` verbatim. Gift cards, crypto, urgency and
  threats read identically in either medium.

Weight redistribution is the same rule as everywhere else: the denominator is
the weight that **actually answered**. A conversation group that could not run —
because everything in the request was outgoing — does not vote "fine"; its
weight moves to the groups that did run.

Nothing here touches the database. See ``routers/scam.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace

from app.services.llm.gemini import analyze_conversation
from app.services.llm.scam_prompts import ScamVerdict
from app.services.phishing.heuristics import (
    GroupResult,
    Hit,
    analyse_content,
    analyse_links,
)
from app.services.scam.heuristics import (
    MIN_CONVERSATION_CHARS,
    Message,
    analyse_conversation,
    incoming_text,
)

# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------

#: What is being asked for. Dominant, because in a chat it is almost the whole
#: story — there is no sender header to check and often no link at all.
WEIGHT_CONVERSATION = 0.50
#: Where the messages send you. Real evidence when present, and frequently
#: absent: the most dangerous chat scams contain no link whatsoever, because the
#: payload is a sentence.
WEIGHT_LINKS = 0.25
#: Pressure tactics, unusual payment methods, threats. Shared with Module 3.
WEIGHT_WORDING = 0.25
#: The share the intent tier may contribute *upward*.
WEIGHT_INTENT = 0.20

THRESHOLD_DANGEROUS = 65
THRESHOLD_SUSPICIOUS = 30

#: A group penalty at or above this is conclusive on its own, and the weighted
#: average may not talk it down. See ``_tier1_penalty`` — this constant is the
#: difference between a working feature and a broken one.
CONCLUSIVE_PENALTY = 85

#: A clean verdict never claims near-certainty. Lower than Module 3's 0.80: this
#: module reads one side of a live conversation and often only the part the user
#: happened to select, so "we found nothing" carries genuinely less weight here.
MAX_CONFIDENCE_WHEN_CLEAN = 0.75


@dataclass(frozen=True)
class SignalOut:
    """One row in the user-facing explanation. Same vocabulary as every other module."""

    signal: str
    detail: str
    weight: str
    evidence: str | None = None


@dataclass(frozen=True)
class ScamResult:
    """Everything the API returns, decided here rather than in the router."""

    verdict: str
    #: 0-100, higher means more dangerous — same direction as the phishing
    #: module and the opposite of trust_score, for the same reason.
    risk_score: int
    confidence: float
    summary: str
    recommendation: str
    signals: tuple[SignalOut, ...]
    #: Null when the intent tier did not run.
    scam_type: str | None
    scam_type_label: str | None
    #: True when the deterministic tier alone decided this.
    heuristics_only: bool


def _round_half_up(value: float) -> int:
    return int(value + 0.5)


# ---------------------------------------------------------------------------
# Copy, authored in Python
# ---------------------------------------------------------------------------
#
# No sentence below is ever written by a model and none is ever assembled from
# message content. The conversation chooses which key is looked up; it cannot
# choose what the key says.

_SUMMARIES: dict[str, str] = {
    "dangerous": "This conversation matches a known scam.",
    "suspicious": "Parts of this conversation do not add up.",
    "safe": "No scam pattern found in these messages.",
    "unknown": "There was not enough of this conversation to judge it.",
}

_RECOMMENDATIONS: dict[str, str] = {
    "dangerous": (
        "Stop replying. Do not send money, do not share any code, and do not install "
        "anything they suggest. If they claim to be from your bank, a company, or the "
        "police, hang up and contact that organisation yourself using a number you "
        "already have — not one from this chat. Then tell one person you trust what "
        "happened."
    ),
    "suspicious": (
        "Slow down and verify before you do anything they ask. If they claim to be "
        "someone you know, call that person on the number you already have for them. "
        "Nothing genuine is lost by waiting an hour."
    ),
    "safe": (
        "Nothing matched a known scam, but that is not a guarantee. Whatever anyone says "
        "in a chat, never share a one-time code and never pay a fee to receive money."
    ),
    "unknown": (
        "There was too little here to judge. Select more of the conversation — including "
        "the messages where they say what they want — and check it again."
    ),
}

#: Prepended when one finding deserves its own instruction. Ordered by severity;
#: the first match wins, so the user gets one clear action rather than a list.
_SPECIFIC_ACTIONS: tuple[tuple[str, str], ...] = (
    (
        "otp_solicitation",
        "If you have already shared a code, call your bank now and tell them — most "
        "banks can freeze a transaction in the first few minutes.",
    ),
    (
        "advance_fee",
        "If you have already paid a fee, contact your bank immediately and report it at "
        "cybercrime.gov.in or on 1930. Some transfers can still be stopped in the first "
        "few hours.",
    ),
    (
        "authority_impersonation",
        "No police force, court, or tax office in India opens a case over a chat or a "
        "video call, and none of them settle one for a payment. You are not in trouble; "
        "you are being frightened on purpose.",
    ),
    (
        "job_task_scam",
        "If you have already deposited money to unlock a task or a withdrawal, stop "
        "depositing. That money is how the scheme pays itself, and adding more never "
        "releases it.",
    ),
    (
        "payment_rail_ask",
        "If you have already paid, report it on 1930 or at cybercrime.gov.in today. UPI "
        "transfers are occasionally recoverable, but only quickly.",
    ),
)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _tier1_penalty(
    conversation: GroupResult, links: GroupResult, wording: GroupResult
) -> float:
    """Weighted average over the groups that ran, floored by any conclusive group.

    The average alone is wrong here, and the reason is worth stating because it
    is the one place this module deliberately departs from Module 3.

    Module 3 averages because its three groups answer the *same* question about
    one document from three angles — who sent it, where it points, what it says —
    and a phishing email that is genuinely dangerous almost always trips more
    than one of them. Diluting a single finding against two clean groups is the
    correct scepticism there.

    A chat is not that. The groups answer *different* questions, and the
    dominant one is routinely the only one with anything to say: the most
    dangerous conversation in this module — "I'll send you Rs 50,000, just tell
    me the OTP" — contains no link, no lookalike domain, and no unusual wording.
    Averaging its 95 against "these messages contain no web links" and "the
    wording is ordinary" yields 47, which is *suspicious*, which means the
    feature could never call an OTP solicitation dangerous unless the scammer
    also happened to send a bad URL. That inverts the point of the module.

    So the clean groups keep their say — the average still carries breadth — but
    they may not talk a conclusive finding down. That is the project's standing
    one-sided rule applied one level up: thin or absent evidence blocks a clean
    bill of health and never suppresses a warning. A group at or above
    ``CONCLUSIVE_PENALTY`` is, by the definition of its own penalty table,
    sufficient on its own; ``max`` is how "sufficient on its own" is spelled.
    """
    parts = (
        (WEIGHT_CONVERSATION, conversation),
        (WEIGHT_LINKS, links),
        (WEIGHT_WORDING, wording),
    )
    available = sum(weight for weight, group in parts if group.available)
    if available <= 0:
        return 0.0
    weighted = (
        sum(weight * group.penalty for weight, group in parts if group.available) / available
    )
    conclusive = max(
        (group.penalty for _, group in parts if group.available and group.penalty >= CONCLUSIVE_PENALTY),
        default=0.0,
    )
    return max(weighted, conclusive)


def _apply_intent(tier1: float, verdict: ScamVerdict | None) -> float:
    """Fold the intent tier in, upward only.

    If the heuristics matched an OTP solicitation and the model says "benign",
    the answer stays dangerous. The model earns the right to add a finding the
    patterns missed; it does not earn the right to talk the patterns out of one
    they proved.
    """
    if verdict is None:
        return tier1
    blended = tier1 * (1 - WEIGHT_INTENT) + verdict.spec.penalty * WEIGHT_INTENT
    return max(tier1, blended)


def _verdict_for(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:
        return "dangerous"
    if score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _confidence(
    verdict: str,
    conversation_available: bool,
    intent: ScamVerdict | None,
    hit_count: int,
) -> float:
    """How much to trust this verdict, stated rather than implied."""
    confidence = 0.55
    if conversation_available:
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
    """Turn a group into user-facing rows, including the ones with no finding."""
    if not group.available:
        return [SignalOut(signal=missing_name, detail=group.detail, weight="unknown")]
    if not group.hits:
        return [SignalOut(signal=passed_name, detail=group.detail, weight="good")]
    return [
        SignalOut(signal=hit.name, detail=hit.detail, weight="bad", evidence=hit.evidence)
        for hit in group.hits
    ]


def _recommendation_for(verdict: str, hits: list[Hit]) -> str:
    base = _RECOMMENDATIONS[verdict]
    names = {hit.name for hit in hits}
    for name, extra in _SPECIFIC_ACTIONS:
        if name in names:
            return f"{extra} {base}"
    return base


def _chat_worded(group: GroupResult, clean_detail: str) -> GroupResult:
    """Swap an email-worded "nothing found" line for a chat-worded one.

    ``analyse_links`` says "This email contains no web links", which is a true
    statement about the wrong thing when the input is a WhatsApp thread. Only
    the clean-and-available detail is replaced; findings keep their own wording,
    which is medium-neutral already.
    """
    if group.available and not group.hits:
        return replace(group, detail=clean_detail)
    return group


def analyse(
    messages: Sequence[Message],
    *,
    use_intent_tier: bool = True,
) -> ScamResult:
    """Analyse one conversation. Pure apart from the optional Gemini call.

    ``use_intent_tier=False`` makes the whole function deterministic and
    offline, which is how the tests exercise the scoring rules without a key or
    a network — and how the feature still answers on a dead conference wifi.
    """
    text = incoming_text(messages)

    # Nothing incoming, or too little of it. Returned as ``unknown`` with the
    # reason stated, never as ``safe`` — a user who selected only their own
    # messages has been told nothing, and must not read it as reassurance.
    if len(text) < MIN_CONVERSATION_CHARS:
        return ScamResult(
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
                        f"{MIN_CONVERSATION_CHARS} characters of received messages to work "
                        "with. Messages you sent yourself are never checked here."
                    ),
                    weight="unknown",
                ),
            ),
            scam_type=None,
            scam_type_label=None,
            heuristics_only=True,
        )

    conversation = analyse_conversation(messages)
    links = _chat_worded(analyse_links(text), "These messages contain no web links.")
    wording = _chat_worded(
        analyse_content("", text),
        "The wording contains no pressure tactics or requests for secrets.",
    )

    tier1 = _tier1_penalty(conversation, links, wording)

    intent: ScamVerdict | None = None
    if use_intent_tier:
        # Never raises — see ``analyze_conversation``. A dead Gemini costs this
        # call nothing beyond the breaker check.
        intent = analyze_conversation(text)

    score = max(0, min(100, _round_half_up(_apply_intent(tier1, intent))))
    verdict = _verdict_for(score)

    hits = [*conversation.hits, *links.hits, *wording.hits]
    signals: list[SignalOut] = []
    signals += _signals_for(conversation, "conversation_clean", "conversation_missing")
    signals += _signals_for(links, "links_clean", "links_missing")
    signals += _signals_for(wording, "wording_clean", "wording_missing")

    if intent is not None:
        signals.append(
            SignalOut(
                signal=f"intent_{intent.scam_type}",
                detail=f"AI reading of the conversation: {intent.rationale}",
                weight="good" if intent.scam_type == "benign" else "bad",
                evidence=intent.quotes[0] if intent.quotes else None,
            )
        )
    else:
        signals.append(
            SignalOut(
                signal="intent_missing",
                detail=(
                    "The AI reading did not run, so this verdict is based on the pattern "
                    "checks alone."
                ),
                weight="unknown",
            )
        )

    # Findings first: the top of the list must be what is wrong, not what
    # happened to be checked first.
    order = {"bad": 0, "unknown": 1, "good": 2}
    signals.sort(key=lambda s: order[s.weight])

    return ScamResult(
        verdict=verdict,
        risk_score=score,
        confidence=_confidence(verdict, conversation.available, intent, len(hits)),
        summary=_SUMMARIES[verdict],
        recommendation=_recommendation_for(verdict, hits),
        signals=tuple(signals),
        scam_type=intent.scam_type if intent else None,
        scam_type_label=intent.spec.label if intent else None,
        heuristics_only=intent is None,
    )
