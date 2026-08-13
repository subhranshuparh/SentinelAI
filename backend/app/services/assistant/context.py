"""Translates user security posture into contextual knowledge cards."""

from __future__ import annotations

from datetime import timedelta, timezone
from sqlalchemy import select

from app.db.models import IdentityCheck, PiiEvent, SiteCheck, utcnow
from app.services.assistant.cards import KnowledgeCard
from app.services.identity.engine import (
    breached_labels,
    identity_detail as build_identity_detail,
    score_identity,
)
from app.services.risk.engine import compute


def build_user_posture_cards(device_id: str | None) -> list[KnowledgeCard]:
    """Retrieve user device posture and format as knowledge cards."""
    if not device_id:
        return []

    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        now = utcnow()

        events = list(
            db.scalars(
                select(PiiEvent)
                .where(PiiEvent.device_id == device_id)
                .order_by(PiiEvent.occurred_at.desc())
            )
        )
        checks = list(
            db.scalars(
                select(SiteCheck)
                .where(SiteCheck.device_id == device_id)
                .order_by(SiteCheck.occurred_at.desc())
            )
        )
        identity_checks = list(
            db.scalars(
                select(IdentityCheck)
                .where(IdentityCheck.device_id == device_id)
                .order_by(IdentityCheck.occurred_at.desc())
            )
        )

        for e in events:
            if e.occurred_at and e.occurred_at.tzinfo is None:
                e.occurred_at = e.occurred_at.replace(tzinfo=timezone.utc)
        for c in checks:
            if c.occurred_at and c.occurred_at.tzinfo is None:
                c.occurred_at = c.occurred_at.replace(tzinfo=timezone.utc)
        for ic in identity_checks:
            if ic.occurred_at and ic.occurred_at.tzinfo is None:
                ic.occurred_at = ic.occurred_at.replace(tzinfo=timezone.utc)

        identity_score, identity_counted = score_identity(identity_checks)
        breached = breached_labels(identity_checks)

        summary = compute(
            events,
            checks,
            identity_score=identity_score,
            identity_detail=build_identity_detail(identity_score, identity_counted, len(breached)),
            identity_count=identity_counted,
            breached_passwords=breached,
            identity_checks=identity_checks,
            now=now,
        )
        if not summary:
            return []

        cards = []
        # Score & headline posture card
        cards.append(
            KnowledgeCard(
                id="user_posture_summary",
                title=f"User Active Risk Score ({summary.overall}/100)",
                tags=("posture", "user", "score", "drivers", "lever", "low", "arithmetic"),
                summary=summary.headline,
                body=(
                    f"Your overall SentinelAI security score is {summary.overall}/100 "
                    f"({summary.risk_level} risk). {summary.headline} "
                    f"Privacy score: {summary.privacy}/100. "
                    f"Browsing score: {summary.browsing}/100."
                ),
            )
        )

        # Biggest lever card
        if summary.narrative and summary.narrative.biggest_lever:
            lever = summary.narrative.biggest_lever
            cards.append(
                KnowledgeCard(
                    id="user_biggest_lever",
                    title="Top Security Recommendation (Biggest Lever)",
                    tags=("posture", "recommendation", "lever", "action", "fix"),
                    summary=lever.sentence,
                    body=(
                        f"Action: {lever.sentence} "
                        f"Current score is {lever.current_score}, and fixing this raises your score to {lever.projected_score} (+{lever.delta} points)."
                    ),
                )
            )

        return cards
    except Exception:
        return []
    finally:
        db.close()
