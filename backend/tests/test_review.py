"""Offline unit tests for Module 5 — Fake Review Analysis."""

import pytest
from app.schemas.review import ReviewAnalysisRequest, ReviewItem
from app.services.review.engine import analyze_reviews
from app.services.review.heuristics import (
    analyse_language,
    analyse_pattern,
    analyse_reviewer,
)


def test_organic_reviews():
    reviews = [
        ReviewItem(
            id="r1",
            body="I bought this phone last week. Battery life is decent, lasts about a day. Camera is OK in daylight.",
            rating=4.0,
            verified_purchase=True,
        ),
        ReviewItem(
            id="r2",
            body="Screen brightness is good, but the speaker sounds a bit tinny at max volume.",
            rating=3.0,
            verified_purchase=True,
        ),
    ]
    req = ReviewAnalysisRequest(reviews=reviews)
    res = analyze_reviews(req)

    assert res.verdict == "organic"
    assert res.risk_score < 40
    assert res.confidence > 0.5


def test_incentivised_review_disclosure():
    reviews = [
        ReviewItem(
            id="r1",
            body="I received this product free in exchange for my honest review. Amazing build quality and fast shipping!",
            rating=5.0,
        )
    ]
    req = ReviewAnalysisRequest(reviews=reviews)
    res = analyze_reviews(req)

    assert res.verdict == "manipulated"
    assert res.risk_score >= 70
    assert any(s.rule == "language_incentive_disclosure" for s in res.signals)


def test_duplicate_reviews_pattern():
    dup_body = "This is hands down the best quality phone case I have ever owned. Fits perfectly and looks great."
    reviews = [
        ReviewItem(id="r1", body=dup_body, rating=5.0),
        ReviewItem(id="r2", body=dup_body, rating=5.0),
        ReviewItem(id="r3", body=dup_body, rating=5.0),
    ]
    req = ReviewAnalysisRequest(reviews=reviews)
    res = analyze_reviews(req)

    assert res.verdict == "manipulated"
    assert res.risk_score >= 70
    assert any(s.rule == "pattern_near_duplicates" for s in res.signals)
    assert len(res.signals[0].affected_review_ids) == 3


def test_high_unverified_purchases():
    reviews = [
        ReviewItem(id="r1", body="Great product!", verified_purchase=False),
        ReviewItem(id="r2", body="Love it so much", verified_purchase=False),
        ReviewItem(id="r3", body="Must buy now!", verified_purchase=False),
    ]
    req = ReviewAnalysisRequest(reviews=reviews)
    res = analyze_reviews(req)

    assert any(s.rule == "reviewer_high_unverified_share" for s in res.signals)
    assert res.risk_score >= 10
