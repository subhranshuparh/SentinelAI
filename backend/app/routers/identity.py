"""Module 4 endpoints — the k-anonymity password-reuse check.

Two routes, deliberately split, because they do two different jobs and only one
of them touches the database:

* ``GET  /pwned-range/{prefix}`` — pure transport. Fetch the crowd this
  password's hash hides in and hand it to the client. Stateless, nothing stored.
* ``POST /password-check``      — the client reports what it matched locally;
  this scores it, persists a classification, and returns the new Identity
  sub-score.

Merging them would require the client to send its full hash, which is the one
thing the whole design exists to prevent. The split is the feature.

Thin, like every other router here: no scoring decision lives in this file.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ratelimit import rate_limit
from app.db.models import Device, IdentityCheck, utcnow
from app.db.session import get_db
from app.schemas.identity import (
    PasswordCheckRequest,
    PasswordCheckResponse,
    PwnedRangeResponse,
)
from app.services.identity.engine import evaluate_password, score_identity
from app.services.identity.pwned import count_is_plausible, fetch_range, normalise_prefix

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


@router.get(
    "/pwned-range/{prefix}",
    response_model=PwnedRangeResponse,
    summary="Fetch the k-anonymity range for a password hash prefix",
    response_description="Every breached-hash suffix sharing this 5-char prefix",
)
def pwned_range(
    prefix: str = Path(..., min_length=5, max_length=5, description="5 hex chars of SHA-1."),
    _device_id: str = Depends(rate_limit),
) -> PwnedRangeResponse:
    """Proxy one Pwned Passwords range lookup.

    ``503`` rather than an empty list when the lookup fails, because those are
    different facts and the popup renders them differently: an empty range would
    read as "your password is safe", and telling a user that because a CDN was
    down is the exact failure mode this codebase refuses everywhere else.
    """
    normalised = normalise_prefix(prefix)
    if normalised is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Prefix must be exactly 5 hexadecimal characters.",
        )

    suffixes = fetch_range(normalised)
    if suffixes is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The breach database could not be reached. Your password was not checked.",
        )

    return PwnedRangeResponse(prefix=normalised, suffixes=suffixes, count=len(suffixes))


@router.post(
    "/password-check",
    response_model=PasswordCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Record and score a locally-matched password result",
    response_description="An explainable verdict plus the recomputed Identity sub-score",
)
def password_check(
    payload: PasswordCheckRequest,
    device_id: str = Depends(rate_limit),
    db: Session = Depends(get_db),
) -> PasswordCheckResponse:
    """Score one password result and fold it into the unified risk score.

    The count arrives from the client because the match happened on the client —
    that is the point of k-anonymity, not a shortcut. It is corroborated against
    the live range where possible (see ``pwned.count_is_plausible``), which
    catches a broken client without narrowing what this server knows about the
    password from ~1,000 candidates to one.
    """
    verified = count_is_plausible(payload.hash_prefix, payload.breach_count)
    verdict = evaluate_password(payload.breach_count, verified=verified)

    device = db.get(Device, device_id)
    if device is None:
        db.add(Device(id=device_id))
    else:
        device.last_seen_at = utcnow()

    db.add(
        IdentityCheck(
            device_id=device_id,
            # Uppercased here so supersession by prefix is case-stable: the
            # schema accepts either case and a mixed-case client would otherwise
            # create a second row for the same password.
            hash_prefix=payload.hash_prefix.upper(),
            label=payload.label,
            breach_count=verdict.breach_count,
            risk_level=verdict.risk_level,
            confidence=verdict.confidence,
            reason=verdict.reason,
        )
    )
    db.commit()

    checks = list(
        db.execute(
            select(IdentityCheck).where(IdentityCheck.device_id == device_id)
        ).scalars()
    )
    identity_score, counted = score_identity(checks)

    return PasswordCheckResponse(
        breached=verdict.breached,
        breach_count=verdict.breach_count,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        reason=verdict.reason,
        explanation=verdict.explanation,
        recommendation=verdict.recommendation,
        identity_score=identity_score,
        checks_counted=counted,
    )
