"""Module 2 endpoint.

Thin, like the Module 1 router: validate, call one service function, persist,
return. Every decision about what makes a site trustworthy lives in
``services/site/``, where it is testable with no server and no network.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.ratelimit import rate_limit
from app.db.models import Device, SiteCheck, utcnow
from app.db.session import get_db
from app.schemas.site import ReasonOut, SiteCheckRequest, SiteCheckResponse
from app.services.site.engine import SiteResult, evaluate

router = APIRouter(prefix="/api/v1/site", tags=["site"])


def persist_site_check(db: Session, device_id: str, result: SiteResult) -> None:
    """Record the check for the dashboard's flagged-sites list and timeline.

    Only non-clean verdicts are written. A row per page view would make the
    timeline unreadable within a minute of normal browsing, and "sites that were
    fine" is not a list anyone wants. The upstream six-hour cache also means a
    reload during rehearsal does not reach this function at all.

    Public because Module 9 calls it too: a QR code that resolves to a web
    address is a site visit about to happen, and it must land in the same table
    with the same rules rather than in a parallel one that the risk engine would
    then have to learn about.
    """
    if result.verdict == "safe" or not result.domain:
        return

    device = db.get(Device, device_id)
    if device is None:
        db.add(Device(id=device_id))
    else:
        device.last_seen_at = utcnow()

    db.add(
        SiteCheck(
            device_id=device_id,
            domain=result.domain,
            trust_score=result.trust_score,
            verdict=result.verdict,
            # Stored as the plain sentences, not the machine signals: this JSON
            # is rendered directly in the dashboard, and a column full of
            # "domain_age" tokens would need a second translation table.
            reasons=[{"signal": r.signal, "detail": r.detail, "weight": r.weight} for r in result.reasons],
            domain_age_days=result.domain_age_days,
            safe_browsing_hit=result.safe_browsing_hit,
            brand_mismatch=result.brand_mismatch,
        )
    )
    db.commit()


@router.post(
    "/check",
    response_model=SiteCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Check whether a site is safe to enter details into",
    response_description="A verdict with itemised, plain-language reasons",
)
def check_site(
    payload: SiteCheckRequest,
    device_id: str = Depends(rate_limit),
    db: Session = Depends(get_db),
) -> SiteCheckResponse:
    """Evaluate a URL against three independent trust signals.

    Always ``200``. A site that could not be checked returns verdict
    ``unknown`` — using an error status for it would make "we don't know" and
    "the backend is broken" indistinguishable to the extension, which is exactly
    the ambiguity this module refuses to create anywhere else.
    """
    result = evaluate(payload.url)
    persist_site_check(db, device_id, result)

    return SiteCheckResponse(
        domain=result.domain,
        trust_score=result.trust_score,
        verdict=result.verdict,
        summary=result.summary,
        reasons=[ReasonOut(signal=r.signal, detail=r.detail, weight=r.weight) for r in result.reasons],
        confidence=result.confidence,
        domain_age_days=result.domain_age_days,
        safe_browsing_hit=result.safe_browsing_hit,
        brand_mismatch=result.brand_mismatch,
    )
