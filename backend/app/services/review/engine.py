"""Module 5 — Fake review detection engine.

Combines deterministic heuristics across language, pattern, and reviewer groups,
redistributes weights across available groups, and applies Tier 2 Gemini evaluation if enabled.
"""

from __future__ import annotations

from typing import Sequence

from app.schemas.review import (
    ReviewAnalysisRequest,
    ReviewAnalysisResponse,
    ReviewItemResult,
    ReviewSignal,
)
from app.services.review.heuristics import (
    analyse_language,
    analyse_pattern,
    analyse_reviewer,
)


def _verdict_from_score(score: int) -> str:
    """Map 0-100 score to discrete verdict band."""
    if score >= 70:
        return "manipulated"
    if score >= 40:
        return "suspicious"
    return "organic"


def analyze_reviews(
    request: ReviewAnalysisRequest, gemini_result: dict | None = None
) -> ReviewAnalysisResponse:
    """Main entrypoint for fake review evaluation."""
    reviews = request.reviews

    lang_res, lang_hits = analyse_language(reviews, request.product_title)
    pat_res, pat_hits = analyse_pattern(reviews)
    rev_res, rev_hits = analyse_reviewer(reviews)

    groups = [
        ("language", lang_res, 0.35, lang_hits),
        ("pattern", pat_res, 0.40, pat_hits),
        ("reviewer", rev_res, 0.25, rev_hits),
    ]

    available_groups = [g for g in groups if g[1].available]

    if not available_groups:
        return ReviewAnalysisResponse(
            verdict="unknown",
            risk_score=50,
            confidence=0.0,
            summary="Could not evaluate review set due to missing input data.",
            recommendation="Provide at least one non-empty review text.",
            signals=[],
            reviews=[],
            tier="heuristics_only",
        )

    total_weight = sum(g[2] for g in available_groups)
    weighted_score = sum((g[1].penalty * (g[2] / total_weight)) for g in available_groups)

    # Conclusive floor: if any available group scored critical (>=80), don't talk it down
    max_group_score = max(g[1].penalty for g in available_groups)
    heuristics_score = int(round(max(weighted_score, max_group_score if max_group_score >= 80 else weighted_score)))
    heuristics_score = max(0, min(100, heuristics_score))

    # All signals combined
    all_signals: list[ReviewSignal] = []
    per_review_signals: dict[str, list[ReviewSignal]] = {}

    for group_name, g_res, _, g_hits in available_groups:
        for s_hit in g_hits:
            sev = "critical" if s_hit.hit.penalty >= 75 else ("high" if s_hit.hit.penalty >= 45 else "medium")
            signal = ReviewSignal(
                rule=s_hit.hit.name,
                group=group_name,  # type: ignore
                severity=sev,
                description=s_hit.hit.detail,
                evidence=s_hit.hit.evidence,
                affected_review_ids=list(s_hit.review_ids),
            )
            all_signals.append(signal)

            for r_id in s_hit.review_ids:
                if r_id not in per_review_signals:
                    per_review_signals[r_id] = []
                per_review_signals[r_id].append(signal)

    # Fold in Gemini Tier 2 if present (raise-only)
    final_score = heuristics_score
    tier_name: str = "heuristics_only"
    confidence = 0.85 if len(reviews) >= 3 else 0.70

    if gemini_result and gemini_result.get("available"):
        tier_name = "full"
        ai_score = gemini_result.get("ai_score", 0)
        final_score = max(heuristics_score, ai_score)
        confidence = max(confidence, gemini_result.get("confidence", 0.8))

        if gemini_result.get("signal"):
            sig_dict = gemini_result["signal"]
            ai_sig = ReviewSignal(
                rule=sig_dict.get("rule", "ai_manipulation_detected"),
                group="ai_tier",
                severity=sig_dict.get("severity", "high"),
                description=sig_dict.get("description", "AI detected review manipulation patterns."),
                evidence=sig_dict.get("evidence"),
                affected_review_ids=[],
            )
            all_signals.append(ai_sig)

    final_verdict = _verdict_from_score(final_score)

    # Format user copy
    if final_verdict == "manipulated":
        summary = f"High risk of review manipulation detected across {len(reviews)} review(s)."
        recommendation = "Do not rely on these reviews when making a purchasing decision."
    elif final_verdict == "suspicious":
        summary = "Several suspicious patterns found in this review set."
        recommendation = "Cross-check with independent third-party product reviews."
    else:
        summary = "No obvious signs of automated or incentivised review manipulation found."
        recommendation = "Reviews appear organic based on text and structure analysis."

    # Per-review items
    item_results: list[ReviewItemResult] = []
    for idx, rev in enumerate(reviews):
        r_id = rev.id or f"review_{idx + 1}"
        r_sigs = per_review_signals.get(r_id, [])
        if r_sigs:
            r_max_penalty = max(
                85 if s.severity == "critical" else (60 if s.severity == "high" else 35)
                for s in r_sigs
            )
            r_score = min(100, max(final_score, r_max_penalty))
        else:
            r_score = 15 if final_verdict == "organic" else min(40, final_score)

        item_results.append(
            ReviewItemResult(
                id=r_id,
                verdict=_verdict_from_score(r_score),  # type: ignore
                risk_score=r_score,
                signals=r_sigs,
            )
        )

    return ReviewAnalysisResponse(
        verdict=final_verdict,  # type: ignore
        risk_score=final_score,
        confidence=confidence,
        summary=summary,
        recommendation=recommendation,
        signals=all_signals,
        reviews=item_results,
        tier=tier_name,  # type: ignore
    )
