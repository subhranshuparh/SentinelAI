"""Module 1 endpoint.

Thin by design: validate, call one service function, return. There is no `if` in
the handler body that decides anything about detection — that all lives in
``services/pii/``, where it is testable without a server.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.ratelimit import rate_limit
from app.db.session import get_db
from app.schemas.pii import (
    DestinationOut,
    FieldKind,
    FindingOut,
    ScanRequest,
    ScanResponse,
    TextSource,
)
from app.services.pii.engine import assess_destination, persist_scan, scan

router = APIRouter(prefix="/api/v1/pii", tags=["pii"])
settings = get_settings()


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan text for sensitive information",
    response_description="Findings with confidence, reason, and a masked suggestion",
)
def scan_endpoint(
    payload: ScanRequest,
    device_id: str = Depends(rate_limit),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Scan a field's contents for PII.

    Returns ``200`` with an empty ``findings`` list when nothing is found —
    "clean" is a successful answer, not a 404. Using an error status for it
    would make "safe" and "broken" indistinguishable to the extension.

    The submitted text is never written to the database or the logs. Only the
    classification and a masked preview are persisted.
    """
    result = scan(
        payload.text,
        suppressed_types=frozenset(payload.suppressed_types),
        enable_tier_2=settings.gemini_tier_available,
        # Module 12. The flag travels as data on the request rather than being
        # inferred from `field_kind` here, because the dashboard drop-zone sends
        # OCR text with no field at all — and because a handler that guessed
        # this would be a handler that could enable character rewriting on typed
        # input by accident.
        from_ocr=payload.source is TextSource.OCR,
    )

    # The one branch in this handler, and it decides nothing about detection —
    # only whether a second, purely explanatory question gets asked. A typed
    # scan leaves `destination` null on purpose (see FindingOut).
    if payload.field_kind is FieldKind.PASTE:
        result = assess_destination(result, payload.site_origin)

    persist_scan(
        db,
        device_id=device_id,
        result=result,
        site_origin=payload.site_origin,
        field_kind=payload.field_kind.value,
    )

    return ScanResponse(
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        tier_2_available=result.tier_2_available,
        tier_2_status=result.tier_2_status,
        # Dataclass -> Pydantic. Explicit rather than `from_attributes` so that
        # adding a field to Finding cannot silently start leaking it over HTTP.
        findings=[
            FindingOut(
                pii_type=f.pii_type,
                label=f.label,
                risk_level=f.risk_level,
                confidence=f.confidence,
                detection_tier=f.detection_tier,
                reason=f.reason,
                explanation=f.explanation,
                recommendation=f.recommendation,
                start=f.start,
                end=f.end,
                masked_preview=f.masked_preview,
                suggested_replacement=f.suggested_replacement,
                destination_fit=f.destination_fit,
                destination_note=f.destination_note,
            )
            for f in result.findings
        ],
        destination=(
            None
            if result.destination is None
            else DestinationOut(
                origin=result.destination.origin,
                name=result.destination.name,
                kind=result.destination.kind.value,
                kind_label=result.destination.kind_label,
                recognised=result.destination.recognised,
            )
        ),
    )
