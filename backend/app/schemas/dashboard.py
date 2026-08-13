"""Response contract for the dashboard.

One endpoint, one round trip. The dashboard renders seven widgets and a chart;
making it assemble that from four endpoints would mean four loading states, four
error states, and a visible cascade of pop-in on every refresh.

The explainability rule applies here as it does everywhere else, and is enforced
the same way — ``headline``, ``detail``, and ``contributions`` are required
fields with ``min_length``, so a response that shows a number without showing its
arithmetic is not representable.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ContributionOut(BaseModel):
    """One component's share of the overall score."""

    component: str = Field(..., description="privacy | browsing | identity")
    score: int | None = Field(None, ge=0, le=100, description="null means this area could not be measured.")
    weight: float = Field(..., description="Nominal weight before redistribution.")
    weight_applied: float = Field(
        ..., description="Weight actually used. Higher than `weight` when another area was unavailable."
    )
    points: float = Field(..., description="Points this area contributed to the overall score.")
    detail: str = Field(..., min_length=1, description="Plain sentence. Required.")
    event_count: int = Field(..., ge=0)


class RecommendationOut(BaseModel):
    priority: str = Field(..., description="high | medium | low")
    title: str = Field(..., min_length=1)
    detail: str = Field(..., min_length=1)
    action: str = Field(..., description="Machine tag, so the UI routes a click without parsing English.")


class DriverOut(BaseModel):
    """One plain-language reason the score is what it is (Module 8)."""

    code: str = Field(..., description="Machine tag. Group and route on this, never on `sentence`.")
    sentence: str = Field(..., min_length=1, description="Plain language. Required.")
    points: int | None = Field(
        None,
        ge=0,
        description=(
            "Points the overall score would recover if this were resolved, measured by "
            "re-running the score without it. null means the cost could not be computed — "
            "never that it was zero."
        ),
    )
    severity: str = Field(..., description="high | medium | low | info")
    count: int = Field(..., ge=0, description="Rows behind this line. 0 for structural drivers.")


class LeverOut(BaseModel):
    """The single change worth making first, priced by a real counterfactual."""

    code: str = Field(..., description="The `DriverOut.code` this resolves.")
    sentence: str = Field(..., min_length=1)
    current_score: int = Field(..., ge=0, le=100)
    projected_score: int = Field(..., ge=0, le=100)
    delta: int = Field(..., ge=1, description="Always positive. A lever that changes nothing is not offered.")
    action: str = Field(..., description="Same vocabulary as RecommendationOut.action.")


class NarrativeOut(BaseModel):
    """The score, explained in sentences instead of arithmetic.

    ``headline`` and ``coverage`` are required with ``min_length`` for the same
    reason every other explanation field in this project is: a score that renders
    without saying what it is made of, or what it could not see, must not be a
    representable response.
    """

    headline: str = Field(..., min_length=1)
    coverage: str = Field(
        ...,
        min_length=1,
        description="What the score could not see, said out loud. Never reads as reassurance.",
    )
    drivers: list[DriverOut] = Field(default_factory=list)
    biggest_lever: LeverOut | None = Field(
        None,
        description="null when nothing the user can do would move the number. No filler advice.",
    )


class TimelineEventOut(BaseModel):
    """One entry in the threat timeline. PII and site events, interleaved."""

    kind: str = Field(..., description="pii | site | identity")
    occurred_at: datetime
    title: str = Field(..., min_length=1)
    detail: str = Field(..., min_length=1)
    severity: str = Field(..., description="low | medium | high | critical")
    #: Present for PII events only. Always the masked form — there is no column
    #: in the database holding the original, so this cannot leak by mistake.
    masked_preview: str | None = None
    site: str | None = None


class FlaggedSiteOut(BaseModel):
    domain: str
    verdict: str
    trust_score: int = Field(..., ge=0, le=100)
    last_seen: datetime
    visits: int = Field(..., ge=1)
    #: The itemised reasons from the site engine, carried through verbatim so the
    #: dashboard shows the same evidence the extension popup showed.
    reasons: list[dict] = Field(default_factory=list)


class TrendPointOut(BaseModel):
    captured_at: datetime
    overall: int
    privacy: int
    browsing: int


class DashboardSummary(BaseModel):
    device_id: str

    overall_score: int = Field(..., ge=0, le=100, description="100 = healthy. Same direction as site trust_score.")
    risk_level: str = Field(..., description="low | medium | high | critical")
    headline: str = Field(..., min_length=1, description="The one sentence most users read.")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Share of the model's weight that was measurable. 0.8 = one area is dark.",
    )

    privacy_score: int | None = None
    browsing_score: int | None = None
    identity_score: int | None = Field(
        None,
        description=(
            "null when this device has run no password check. That is 'not measured', "
            "never 'nothing found' — it is not rendered as a passing green."
        ),
    )

    #: Required, not optional. The arithmetic in `contributions` is correct and
    #: largely unread; this is the part most users act on.
    narrative: NarrativeOut

    contributions: list[ContributionOut] = Field(..., min_length=1)
    recommendations: list[RecommendationOut] = Field(default_factory=list)
    timeline: list[TimelineEventOut] = Field(default_factory=list)
    flagged_sites: list[FlaggedSiteOut] = Field(default_factory=list)
    trend: list[TrendPointOut] = Field(default_factory=list)

    #: Counters for the stat strip. Cheap to compute here, and saves the client
    #: from deriving them off a truncated timeline and getting them wrong.
    total_pii_events: int = 0
    total_masked: int = 0
    total_sites_flagged: int = 0
    window_days: int = Field(30, description="Everything above is scoped to this window.")
