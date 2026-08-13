"""Prompt formatting and JSON schema for Tier 2 review analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence
from app.schemas.review import ReviewItem

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": [
                "organic",
                "incentivised",
                "templated",
                "bot_generated",
                "competitor_attack",
                "unclear",
            ],
        },
        "ai_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "reasoning": {"type": "string"},
        "quote": {"type": "string"},
    },
    "required": ["verdict", "ai_score", "reasoning"],
}


@dataclass(frozen=True)
class ReviewVerdict:
    verdict: str
    ai_score: int
    reasoning: str
    quote: str | None = None


@dataclass(frozen=True)
class ReviewPrompt:
    system_instruction: str
    user_content: str
    sanitized: list[ReviewItem]


def build_reviews_prompt(reviews: Sequence[ReviewItem] | Sequence[str], product_title: str | None = None) -> ReviewPrompt:
    """Format reviews into a fenced prompt for Gemini."""
    items: list[ReviewItem] = []
    parts = []

    if product_title:
        parts.append(f"PRODUCT TITLE: {product_title}\n")

    parts.append("REVIEWS TO ANALYZE:")
    for idx, r in enumerate(reviews):
        if isinstance(r, str):
            item = ReviewItem(id=f"review_{idx + 1}", body=r)
        else:
            item = r
        items.append(item)

        parts.append(f"--- Review [{item.id}] ---")
        if item.rating:
            parts.append(f"Rating: {item.rating} stars")
        if item.title:
            parts.append(f"Title: {item.title}")
        parts.append(f"Body: {item.body}\n")

    sys_instruction = (
        "You are a review authenticity analyzer. Analyze the reviews for artificial manipulation, "
        "templated phrases, incentivised disclosure, or competitor attacks. Respond ONLY with the requested JSON schema."
    )
    user_content = "\n".join(parts)

    return ReviewPrompt(
        system_instruction=sys_instruction,
        user_content=user_content,
        sanitized=items,
    )


def parse_review_verdict(payload: object, reviews: Sequence[ReviewItem]) -> dict[str, Any]:
    """Parse and validate Gemini review verdict JSON.

    ``payload`` is the already-parsed Python object returned by ``_extract_json``
    in ``gemini.py`` — a dict, not a raw JSON string. This matches the convention
    of every other ``parse_*`` function in this codebase.
    """
    if not isinstance(payload, dict):
        return {"available": False, "ai_score": 0, "confidence": 0.0, "signal": None}
    verdict = payload.get("verdict", "unclear")
    ai_score = int(payload.get("ai_score", 0))
    reasoning = str(payload.get("reasoning", ""))
    quote = str(payload.get("quote", ""))

    all_text = " ".join(r.body for r in reviews)
    valid_quote = quote if quote and quote in all_text else None

    if verdict in ("incentivised", "templated", "bot_generated", "competitor_attack") and ai_score >= 40:
        signal = {
            "rule": f"ai_review_{verdict}",
            "severity": "critical" if ai_score >= 75 else "high",
            "description": f"AI model classified set as {verdict}: {reasoning}",
            "evidence": valid_quote,
        }
    else:
        signal = None

    return {
        "available": True,
        "verdict": verdict,
        "ai_score": ai_score,
        "confidence": 0.85,
        "signal": signal,
    }
