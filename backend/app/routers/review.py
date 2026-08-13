"""Module 5 — Fake Review Analysis Router.

Endpoint: POST /api/v1/review/analyze
Stateless and read-only. Does not store or persist review payloads.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.review import ReviewAnalysisRequest, ReviewAnalysisResponse
from app.services.llm import gemini
from app.services.review.engine import analyze_reviews

router = APIRouter(prefix="/api/v1/review", tags=["review"])
settings = get_settings()


@router.post("/analyze", response_model=ReviewAnalysisResponse)
async def analyze_review_set(request: ReviewAnalysisRequest) -> ReviewAnalysisResponse:
    """Analyze a set of reviews for automated, incentivised, or duplicate manipulation tells.

    Stateless: stores no review text or metadata.
    """
    gemini_res = None
    if settings.gemini_tier_available:
        gemini_res = gemini.analyze_reviews(request.reviews)

    return analyze_reviews(request, gemini_res)
