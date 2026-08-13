"""Pydantic schemas for Module 5 — Fake Review Detection.

The unit of analysis is a *set* of reviews, because cross-review signals
(near-duplicate text, posting bursts, rating polarisation) are the strongest
evidence of manipulation and are invisible in isolation. Single reviews are
accepted; cross-review signals simply report ``available=False``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ReviewItem(BaseModel):
    """An individual review submitted as part of a set."""

    id: str | None = Field(
        default=None,
        description="Optional identifier for referencing in itemised findings.",
    )
    title: str | None = Field(default=None, description="Review headline or summary.")
    body: str = Field(..., description="The main text of the review.")
    rating: float | None = Field(
        default=None,
        ge=1.0,
        le=5.0,
        description="Star rating from 1.0 to 5.0.",
    )
    reviewer_name: str | None = Field(
        default=None, description="Display name of the author."
    )
    posted_at: str | None = Field(
        default=None, description="ISO timestamp of when the review was published."
    )
    verified_purchase: bool | None = Field(
        default=None, description="Whether the platform verified the purchase."
    )


class ReviewAnalysisRequest(BaseModel):
    """Payload for POST /api/v1/review/analyze."""

    reviews: list[ReviewItem] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="1 to 50 reviews to evaluate together.",
    )
    product_title: str | None = Field(
        default=None,
        description="Optional title of the product, used to detect brand/title stuffing.",
    )


class ReviewSignal(BaseModel):
    """An itemised finding supporting the verdict."""

    rule: str = Field(..., description="Machine-readable signal key.")
    group: Literal["language", "pattern", "reviewer", "ai_tier"] = Field(
        ..., description="Which signal group produced this hit."
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        ..., description="Severity of the detected tell."
    )
    description: str = Field(
        ..., min_length=1, description="Plain-language explanation of what was found."
    )
    evidence: str | None = Field(
        default=None, description="Excerpt from the text or pattern data."
    )
    affected_review_ids: list[str] = Field(
        default_factory=list, description="IDs of reviews demonstrating this signal."
    )


class ReviewItemResult(BaseModel):
    """Itemised verdict for a single review in the set."""

    id: str = Field(..., description="Matches the review ID provided in request.")
    verdict: Literal["manipulated", "suspicious", "organic", "unknown"] = Field(
        ..., description="Per-review verdict."
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Risk score (0 = clean, 100 = manipulated)."
    )
    signals: list[ReviewSignal] = Field(
        default_factory=list, description="Signals attributed to this specific review."
    )


class ReviewAnalysisResponse(BaseModel):
    """Schema returned by POST /api/v1/review/analyze."""

    verdict: Literal["manipulated", "suspicious", "organic", "unknown"] = Field(
        ..., description="Overall verdict for the set."
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Overall risk score (0 = clean, 100 = heavily manipulated).",
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in the verdict."
    )
    summary: str = Field(
        ..., min_length=1, description="One-sentence executive verdict."
    )
    recommendation: str = Field(
        ..., min_length=1, description="Actionable consumer advice."
    )
    signals: list[ReviewSignal] = Field(
        default_factory=list, description="All itemised findings across the set."
    )
    reviews: list[ReviewItemResult] = Field(
        default_factory=list, description="Per-review itemised findings."
    )
    tier: Literal["heuristics_only", "full"] = Field(
        ..., description="Whether Tier 2 AI analysis contributed."
    )
