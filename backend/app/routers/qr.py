"""Module 9 endpoint — check a decoded QR code.

Thin, like the other routers: validate, call one service function, persist when
there is something honest to persist, return.

The persistence rule is the interesting line in this file. A QR code that
resolves to a **web address** is a site visit about to happen, so it writes a
``SiteCheck`` through the same function ``/site/check`` uses and feeds the
Browsing sub-score exactly like a visited page. A **UPI** QR has no domain, so
nothing is written. That is deliberate: the alternative is inventing a row —
storing ``upi`` or the VPA in a column called ``domain`` — which would put a
fabricated fact in front of the risk engine to avoid an empty space. An empty
space is the correct representation of "this event has no domain".
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.ratelimit import rate_limit
from app.db.session import get_db
from app.routers.site import persist_site_check
from app.schemas.qr import QrCheckRequest, QrCheckResponse, QrSignalOut
from app.services.qr.engine import analyse

router = APIRouter(prefix="/api/v1/qr", tags=["qr"])


@router.post(
    "/check",
    response_model=QrCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Check where a QR code actually goes before scanning it",
    response_description="A verdict, the decoded destination, and itemised plain-language reasons",
)
def check_qr(
    payload: QrCheckRequest,
    device_id: str = Depends(rate_limit),
    db: Session = Depends(get_db),
) -> QrCheckResponse:
    """Judge one decoded QR payload.

    Always ``200``. A code whose destination could not be looked up returns
    verdict ``unknown`` with the reason stated in ``signals`` — an error status
    would make "we could not check" indistinguishable from a broken backend,
    which is the ambiguity this codebase refuses to create anywhere.

    The payload is never logged and never stored. Only a resolved *domain* and
    its verdict reach the database, and only when the code was a link.
    """
    result = analyse(payload.payload)

    if result.site is not None:
        persist_site_check(db, device_id, result.site)

    return QrCheckResponse(
        kind=result.kind,
        verdict=result.verdict,
        risk_score=result.risk_score,
        confidence=result.confidence,
        summary=result.summary,
        recommendation=result.recommendation,
        destination=result.destination,
        signals=[
            QrSignalOut(
                signal=signal.signal,
                detail=signal.detail,
                weight=signal.weight,
                evidence=signal.evidence,
            )
            for signal in result.signals
        ],
        domain=result.site.domain if result.site and result.site.domain else None,
        trust_score=result.site.trust_score if result.site else None,
    )
