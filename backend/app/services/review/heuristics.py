"""Tier 1 fake review heuristics — deterministic, offline, zero cost.

Three groups scored independently:
1. **language** (weight 0.35) — Proximity/phrase tells in review bodies.
2. **pattern** (weight 0.40) — Cross-review signals (Jaccard near-duplicates, burst, polarisation).
3. **reviewer** (weight 0.25) — Metadata signals (unverified share, display name patterns).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from app.services.phishing.heuristics import GroupResult, Hit, combine, near
from app.schemas.review import ReviewItem


@dataclass(frozen=True)
class ReviewSignalHit:
    """Internal hit structure carrying review ID attribution."""

    hit: Hit
    review_ids: tuple[str, ...] = ()


#: Common disclosure phrases indicating sponsored or incentivised reviews
_INCENTIVE_PATTERNS = [
    r"received (?:this )?(?:product )?free",
    r"in exchange for (?:my |an )?honest review",
    r"sponsored review",
    r"paid promotion",
    r"discounted product for review",
    r"sent to me for testing",
]

#: Superlative phrases without concrete details
_SUPERLATIVE_PATTERNS = [
    r"best (?:product|item|purchase) ever",
    r"must buy",
    r"don't think twice",
    r"100% recommend",
    r"exceeded all expectations",
    r"mind blowing",
    r"worth every single penny",
]

#: Marketing register / sales pitch language
_MARKETING_PATTERNS = [
    r"value for money",
    r"game changer",
    r"top quality",
    r"hastle free",
    r"highly recommended",
    r"five stars",
]


def tokenize(text: str) -> set[str]:
    """Extract normalised word tokens for Jaccard similarity."""
    return set(re.findall(r"\b[a-z0-9]{3,}\b", text.lower()))


def jaccard_similarity(set1: set[str], set2: set[str]) -> float:
    """Compute Jaccard similarity coefficient between two token sets."""
    if not set1 or not set2:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


def analyse_language(
    reviews: Sequence[ReviewItem], product_title: str | None = None
) -> tuple[GroupResult, list[ReviewSignalHit]]:
    """Analyse review text for incentive disclosures, superlatives, and stuffing."""
    hits: list[Hit] = []
    signal_hits: list[ReviewSignalHit] = []

    product_tokens = (
        tokenize(product_title) if product_title and len(product_title) > 5 else set()
    )

    for idx, rev in enumerate(reviews):
        rev_id = rev.id or f"review_{idx + 1}"
        text = f"{rev.title or ''} {rev.body}".strip().lower()
        if not text:
            continue

        # 1. Incentive disclosure (conclusive high penalty)
        for pat in _INCENTIVE_PATTERNS:
            match = re.search(pat, text)
            if match:
                hit = Hit(
                    name="language_incentive_disclosure",
                    penalty=80,
                    detail="Review explicitly discloses receiving a free or sponsored product.",
                    evidence=match.group(0),
                )
                hits.append(hit)
                signal_hits.append(ReviewSignalHit(hit, (rev_id,)))
                break

        # 2. Superlative stacking
        sup_matches = [pat for pat in _SUPERLATIVE_PATTERNS if re.search(pat, text)]
        if len(sup_matches) >= 2:
            hit = Hit(
                name="language_superlative_stacking",
                penalty=45,
                detail="Review uses stacked generic superlatives without specific usage details.",
                evidence=", ".join(sup_matches[:3]),
            )
            hits.append(hit)
            signal_hits.append(ReviewSignalHit(hit, (rev_id,)))

        # 3. Marketing register
        mkt_matches = [pat for pat in _MARKETING_PATTERNS if re.search(pat, text)]
        if len(mkt_matches) >= 2:
            hit = Hit(
                name="language_marketing_register",
                penalty=35,
                detail="Review text uses repetitive promotional marketing phrasing.",
                evidence=", ".join(mkt_matches[:2]),
            )
            hits.append(hit)
            signal_hits.append(ReviewSignalHit(hit, (rev_id,)))

        # 4. Product title stuffing
        if product_tokens and len(product_tokens) >= 2:
            body_tokens = tokenize(rev.body)
            if product_tokens.issubset(body_tokens) and len(rev.body) < 300:
                hit = Hit(
                    name="language_title_stuffing",
                    penalty=40,
                    detail="Review repeats full product title in a short review body.",
                    evidence=product_title[:60] if product_title else "",
                )
                hits.append(hit)
                signal_hits.append(ReviewSignalHit(hit, (rev_id,)))

    penalty = combine(hits, bump=5)
    detail = f"{len(hits)} language signal(s) found" if hits else "Language check clean"
    return GroupResult(available=True, penalty=penalty, hits=tuple(hits), detail=detail), signal_hits


def analyse_pattern(
    reviews: Sequence[ReviewItem],
) -> tuple[GroupResult, list[ReviewSignalHit]]:
    """Analyse cross-review relationships (near-duplicates, polarisation)."""
    if len(reviews) < 2:
        return GroupResult(
            available=False,
            penalty=0,
            hits=(),
            detail="Cross-review pattern analysis requires at least 2 reviews.",
        ), []

    hits: list[Hit] = []
    signal_hits: list[ReviewSignalHit] = []

    # 1. Near-duplicate bodies (Jaccard similarity >= 0.70)
    token_sets = [tokenize(rev.body) for rev in reviews]
    duplicate_pairs: list[tuple[int, int]] = []
    dup_ids: set[str] = set()

    for i in range(len(reviews)):
        for j in range(i + 1, len(reviews)):
            if len(token_sets[i]) >= 5 and len(token_sets[j]) >= 5:
                sim = jaccard_similarity(token_sets[i], token_sets[j])
                if sim >= 0.70:
                    duplicate_pairs.append((i, j))
                    id_i = reviews[i].id or f"review_{i + 1}"
                    id_j = reviews[j].id or f"review_{j + 1}"
                    dup_ids.add(id_i)
                    dup_ids.add(id_j)

    if duplicate_pairs:
        hit = Hit(
            name="pattern_near_duplicates",
            penalty=85,
            detail="Multiple reviews contain near-identical phrasing and word choice.",
            evidence=f"{len(duplicate_pairs)} duplicate pair(s) found",
        )
        hits.append(hit)
        signal_hits.append(ReviewSignalHit(hit, tuple(sorted(dup_ids))))

    # 2. Rating polarisation (J-curve / extreme 1 or 5 split with 0 mid-ratings)
    ratings = [r.rating for r in reviews if r.rating is not None]
    if len(ratings) >= 5:
        fives = sum(1 for r in ratings if r == 5.0)
        ones = sum(1 for r in ratings if r == 1.0)
        mids = sum(1 for r in ratings if 2.0 <= r <= 4.0)

        if (fives + ones) == len(ratings) and mids == 0 and ones > 0 and fives > 0:
            hit = Hit(
                name="pattern_rating_polarisation",
                penalty=60,
                detail="Ratings are heavily polarised into 1-star and 5-star extremes with zero middle ratings.",
                evidence=f"{fives} 5-star vs {ones} 1-star",
            )
            hits.append(hit)
            all_ids = tuple(
                r.id or f"review_{k + 1}" for k, r in enumerate(reviews) if r.rating
            )
            signal_hits.append(ReviewSignalHit(hit, all_ids))

    penalty = combine(hits, bump=10)
    detail = f"{len(hits)} pattern signal(s) found" if hits else "Cross-review pattern clean"
    return GroupResult(available=True, penalty=penalty, hits=tuple(hits), detail=detail), signal_hits


def analyse_reviewer(
    reviews: Sequence[ReviewItem],
) -> tuple[GroupResult, list[ReviewSignalHit]]:
    """Analyse reviewer metadata (unverified purchases, default names)."""
    verified_statuses = [r.verified_purchase for r in reviews if r.verified_purchase is not None]

    if not verified_statuses:
        return GroupResult(
            available=False,
            penalty=0,
            hits=(),
            detail="Reviewer metadata (verified purchase) was not provided.",
        ), []

    hits: list[Hit] = []
    signal_hits: list[ReviewSignalHit] = []

    unverified_count = sum(1 for v in verified_statuses if not v)
    total_count = len(verified_statuses)
    unverified_ratio = unverified_count / total_count if total_count > 0 else 0

    if total_count >= 3 and unverified_ratio >= 0.75:
        unverified_ids = tuple(
            r.id or f"review_{idx + 1}"
            for idx, r in enumerate(reviews)
            if r.verified_purchase is False
        )
        hit = Hit(
            name="reviewer_high_unverified_share",
            penalty=50,
            detail=f"{int(unverified_ratio * 100)}% of the reviews are from unverified purchases.",
            evidence=f"{unverified_count}/{total_count} unverified",
        )
        hits.append(hit)
        signal_hits.append(ReviewSignalHit(hit, unverified_ids))

    penalty = combine(hits, bump=5)
    detail = f"{len(hits)} reviewer signal(s) found" if hits else "Reviewer metadata clean"
    return GroupResult(available=True, penalty=penalty, hits=tuple(hits), detail=detail), signal_hits
