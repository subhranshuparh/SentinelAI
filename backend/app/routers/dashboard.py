"""Module 6 endpoint — one round trip for the whole dashboard.

Thin, like every other router here: fetch rows, hand them to
``services/risk/engine.py``, shape the response. Not one scoring decision lives
in this file.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_optional_device
from app.db.models import (
    Device,
    IdentityCheck,
    PiiEvent,
    ScoreSnapshot,
    SiteCheck,
    UserAction,
    utcnow,
)
from app.db.session import get_db
from app.schemas.dashboard import (
    ContributionOut,
    DashboardSummary,
    DriverOut,
    FlaggedSiteOut,
    LeverOut,
    NarrativeOut,
    RecommendationOut,
    TimelineEventOut,
    TrendPointOut,
)
from app.services.identity.engine import breached_labels
from app.services.identity.engine import identity_detail as build_identity_detail
from app.services.identity.engine import score_identity
from app.services.risk.engine import LOOKBACK_DAYS, RiskSummary, compute

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

#: Timeline length. Enough to scroll, short enough that the payload stays small
#: and the screen stays readable — a 500-row timeline is a log file, not a UI.
TIMELINE_LIMIT = 25
FLAGGED_SITES_LIMIT = 10

#: Minimum gap between trend snapshots. The dashboard polls, and without this a
#: 10-second refresh would write 360 near-identical points an hour and turn the
#: chart into a solid block.
SNAPSHOT_MIN_INTERVAL_MINUTES = 5

#: Human labels. Duplicated from the extension popup on purpose — the dashboard
#: must render correctly with no shared bundle and no extra request.
PII_LABELS = {
    "aadhaar": "Aadhaar number",
    "pan": "PAN",
    "credit_card": "Card number",
    "bank_account": "Bank account",
    "ifsc": "IFSC code",
    "upi_id": "UPI ID",
    "passport": "Passport number",
    "phone": "Phone number",
    "email": "Email address",
    "dob": "Date of birth",
    "api_key": "API key",
    "jwt": "Access token",
    "password": "Password",
    "coordinates": "Location",
    "postal_address": "Home address",
    "security_answer": "Security answer",
    "financial_detail": "Financial detail",
    "health_detail": "Health detail",
    "travel_plan": "Travel plan",
    "workplace_identifier": "Workplace detail",
    "family_detail": "Family detail",
}

VERDICT_SEVERITY = {"dangerous": "critical", "suspicious": "medium", "unknown": "low", "safe": "low"}

#: How the value was about to leave, as the verb in the timeline headline.
#:
#: ``FieldKind`` exists to answer exactly this question — its own docstring says
#: the timeline's question is "how did this leave you", and "in a screenshot" is
#: a materially different answer from "you typed it". Three rows that all read
#: "caught on discord.com" would throw that away at the last step.
#:
#: Only the two kinds that mean something to a person are named. ``input``,
#: ``textarea`` and ``contenteditable`` are the same event told in HTML, so they
#: fall through to the default rather than leaking a tag name into a sentence a
#: senior citizen is meant to read.
FIELD_KIND_VERBS = {
    "paste": "pasted into",
    "image": "found in an image on",
}


def _resolve_device(db: Session, requested: str | None, header_device: str | None) -> str:
    """Decide whose dashboard to render.

    The extension always sends a device id; the dashboard is a separate web app
    that has never seen one. Rather than making the user copy a UUID out of the
    popup before the screen works at all, an absent id resolves to the most
    recently active device — which during a demo is always the one just used.

    This is why the route depends on ``get_optional_device`` rather than
    ``get_current_device``: the strict dependency 401s on a missing header
    *before* the route body runs, so this fallback would be unreachable.

    **Security note.** This convenience is scoped to a single-user local MVP. The
    device id is bearer-equivalent here: anyone holding one can read that
    device's history, and the fallback means a caller with no id reads the most
    recent one. That is acceptable on localhost and is exactly what the
    ``ENABLE_JWT_AUTH`` path replaces before this is ever exposed to a network.
    """
    if requested:
        return requested
    if header_device:
        return header_device

    most_recent = db.execute(
        select(Device.id).order_by(Device.last_seen_at.desc()).limit(1)
    ).scalar_one_or_none()
    if most_recent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No devices have reported yet. Use the extension once, or run the seed script.",
        )
    return most_recent


def _maybe_snapshot(db: Session, device_id: str, summary: RiskSummary, now: datetime) -> None:
    """Append a trend point, at most once every few minutes.

    Snapshots are written rather than recomputed because recomputing history from
    raw events would retroactively rewrite the chart every time a weight is
    tuned. A snapshot records what the score *was*, which is the only thing a
    trend line can honestly show.
    """
    latest = db.execute(
        select(ScoreSnapshot.captured_at)
        .where(ScoreSnapshot.device_id == device_id)
        .order_by(ScoreSnapshot.captured_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if latest is not None:
        # SQLite hands back naive datetimes even for timezone-aware columns.
        # Comparing one against an aware `now` raises, so normalise first.
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=now.tzinfo)
        if now - latest < timedelta(minutes=SNAPSHOT_MIN_INTERVAL_MINUTES):
            return

    db.add(
        ScoreSnapshot(
            device_id=device_id,
            overall=summary.overall,
            privacy=summary.privacy or 0,
            identity=summary.identity or 0,
            browsing=summary.browsing or 0,
        )
    )
    db.commit()


def _build_timeline(
    events: list[PiiEvent],
    checks: list[SiteCheck],
    identity_checks: list[IdentityCheck],
) -> list[TimelineEventOut]:
    """Interleave all three event streams, newest first.

    Interleaved rather than three separate lists because the correlation *is* the
    product: "typed a card number, then visited a flagged domain, on a password
    that is already in a breach list" only reads as one story when the three
    appear on one spine.
    """
    entries: list[TimelineEventOut] = []

    for event in events:
        label = PII_LABELS.get(event.pii_type, event.pii_type.replace("_", " ").title())
        site = event.site_origin.replace("https://", "").replace("http://", "")
        entries.append(
            TimelineEventOut(
                kind="pii",
                occurred_at=event.occurred_at,
                title=f"{label} {FIELD_KIND_VERBS.get(event.field_kind, 'caught on')} {site}",
                # The reason is carried through from the detector rather than
                # re-derived, so the dashboard and the toast never disagree.
                detail=event.reason,
                severity=event.risk_level,
                masked_preview=event.masked_preview,
                site=site,
            )
        )

    for check in checks:
        first_reason = ""
        if isinstance(check.reasons, list) and check.reasons:
            first = check.reasons[0]
            if isinstance(first, dict):
                first_reason = str(first.get("detail", ""))
        entries.append(
            TimelineEventOut(
                kind="site",
                occurred_at=check.occurred_at,
                title=f"{check.domain} rated {check.verdict}",
                detail=first_reason or f"Trust score {check.trust_score} out of 100.",
                severity=VERDICT_SEVERITY.get(check.verdict, "low"),
                site=check.domain,
            )
        )

    for identity in identity_checks:
        # The label is the only user-supplied string on this row, and there is
        # deliberately nothing else identifying here: no prefix, no hash, no
        # hint of the password itself — just what the user chose to call it.
        subject = identity.label or "A password"
        entries.append(
            TimelineEventOut(
                kind="identity",
                occurred_at=identity.occurred_at,
                title=(
                    f"{subject} found in {identity.breach_count:,} breached accounts"
                    if identity.breach_count > 0
                    else f"{subject} checked — not found in any breach"
                ),
                detail=identity.reason,
                severity=identity.risk_level,
            )
        )

    entries.sort(key=lambda e: e.occurred_at, reverse=True)
    return entries[:TIMELINE_LIMIT]


def _build_flagged_sites(checks: list[SiteCheck]) -> list[FlaggedSiteOut]:
    """Collapse repeat visits into one row per domain, worst verdict wins."""
    rank = {"dangerous": 3, "suspicious": 2, "unknown": 1, "safe": 0}
    by_domain: dict[str, FlaggedSiteOut] = {}

    for check in checks:
        if check.verdict == "safe":
            continue
        existing = by_domain.get(check.domain)
        if existing is None:
            by_domain[check.domain] = FlaggedSiteOut(
                domain=check.domain,
                verdict=check.verdict,
                trust_score=check.trust_score,
                last_seen=check.occurred_at,
                visits=1,
                reasons=check.reasons if isinstance(check.reasons, list) else [],
            )
            continue

        by_domain[check.domain] = FlaggedSiteOut(
            domain=check.domain,
            verdict=check.verdict if rank.get(check.verdict, 0) > rank.get(existing.verdict, 0) else existing.verdict,
            trust_score=min(existing.trust_score, check.trust_score),
            last_seen=max(existing.last_seen, check.occurred_at),
            visits=existing.visits + 1,
            reasons=existing.reasons or (check.reasons if isinstance(check.reasons, list) else []),
        )

    ordered = sorted(
        by_domain.values(),
        key=lambda s: (-rank.get(s.verdict, 0), s.trust_score, -s.visits),
    )
    return ordered[:FLAGGED_SITES_LIMIT]


@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Everything the dashboard renders, in one request",
    response_description="A unified score with its full arithmetic, plus the events behind it",
)
def dashboard_summary(
    device_id: str | None = Query(None, description="Defaults to the most recently active device."),
    header_device: str | None = Depends(get_optional_device),
    db: Session = Depends(get_db),
) -> DashboardSummary:
    """Aggregate Modules 1 and 2 into one score, and return the evidence with it.

    Deliberately not rate-limited on the same bucket as the typing path: a user
    hammering refresh on their own dashboard is not the abuse case the limiter
    exists to stop, and a 429 here would blank the screen mid-demo.
    """
    resolved = _resolve_device(db, device_id, header_device)
    now = utcnow()
    cutoff = now - timedelta(days=LOOKBACK_DAYS)

    events = list(
        db.execute(
            select(PiiEvent)
            .where(PiiEvent.device_id == resolved, PiiEvent.occurred_at >= cutoff)
            .order_by(PiiEvent.occurred_at.desc())
        ).scalars()
    )
    checks = list(
        db.execute(
            select(SiteCheck)
            .where(SiteCheck.device_id == resolved, SiteCheck.occurred_at >= cutoff)
            .order_by(SiteCheck.occurred_at.desc())
        ).scalars()
    )

    # Deliberately NOT windowed by `cutoff`, unlike events and checks. A breached
    # password does not become safe because the check is three weeks old — it
    # stays breached until the user changes it and re-checks, which supersedes
    # the row. Dropping old checks would let the Identity score recover by doing
    # nothing, which is exactly the behaviour this product exists to argue against.
    identity_checks = list(
        db.execute(
            select(IdentityCheck)
            .where(IdentityCheck.device_id == resolved)
            .order_by(IdentityCheck.occurred_at.desc())
        ).scalars()
    )

    # SQLite returns naive datetimes; the engine does arithmetic against an aware
    # `now`. Normalising here keeps that quirk at the storage boundary instead of
    # letting it leak into the scoring model, which must stay pure and testable.
    for row in (*events, *checks, *identity_checks):
        if row.occurred_at.tzinfo is None:
            row.occurred_at = row.occurred_at.replace(tzinfo=now.tzinfo)

    identity_score, identity_counted = score_identity(identity_checks)
    breached = breached_labels(identity_checks)

    summary = compute(
        events,
        checks,
        identity_score=identity_score,
        identity_detail=build_identity_detail(identity_score, identity_counted, len(breached)),
        identity_count=identity_counted,
        breached_passwords=breached,
        # The raw rows, not just the aggregate. The narrative's counterfactual
        # asks "what if *this* password were changed", which one number cannot
        # answer — see `build_narrative`.
        identity_checks=identity_checks,
        now=now,
    )

    _maybe_snapshot(db, resolved, summary, now)

    snapshots = list(
        db.execute(
            select(ScoreSnapshot)
            .where(ScoreSnapshot.device_id == resolved, ScoreSnapshot.captured_at >= cutoff)
            .order_by(ScoreSnapshot.captured_at.asc())
        ).scalars()
    )

    return DashboardSummary(
        device_id=resolved,
        overall_score=summary.overall,
        risk_level=summary.risk_level,
        headline=summary.headline,
        confidence=summary.confidence,
        narrative=NarrativeOut(
            headline=summary.narrative.headline,
            coverage=summary.narrative.coverage,
            drivers=[
                DriverOut(
                    code=d.code,
                    sentence=d.sentence,
                    points=d.points,
                    severity=d.severity,
                    count=d.count,
                )
                for d in summary.narrative.drivers
            ],
            biggest_lever=(
                LeverOut(
                    code=summary.narrative.biggest_lever.code,
                    sentence=summary.narrative.biggest_lever.sentence,
                    current_score=summary.narrative.biggest_lever.current_score,
                    projected_score=summary.narrative.biggest_lever.projected_score,
                    delta=summary.narrative.biggest_lever.delta,
                    action=summary.narrative.biggest_lever.action,
                )
                if summary.narrative.biggest_lever is not None
                else None
            ),
        ),
        privacy_score=summary.privacy,
        browsing_score=summary.browsing,
        identity_score=summary.identity,
        contributions=[
            ContributionOut(
                component=c.component,
                score=c.score,
                weight=c.weight,
                weight_applied=c.weight_applied,
                points=c.points,
                detail=c.detail,
                event_count=c.event_count,
            )
            for c in summary.contributions
        ],
        recommendations=[
            RecommendationOut(priority=r.priority, title=r.title, detail=r.detail, action=r.action)
            for r in summary.recommendations
        ],
        timeline=_build_timeline(events, checks, identity_checks),
        flagged_sites=_build_flagged_sites(checks),
        trend=[
            TrendPointOut(
                captured_at=s.captured_at,
                overall=s.overall,
                privacy=s.privacy,
                browsing=s.browsing,
            )
            for s in snapshots
        ],
        total_pii_events=len(events),
        total_masked=sum(1 for e in events if e.action_taken == UserAction.MASKED.value),
        total_sites_flagged=len({c.domain for c in checks if c.verdict in {"dangerous", "suspicious"}}),
        window_days=LOOKBACK_DAYS,
    )
