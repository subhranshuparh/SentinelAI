"""Module 3 endpoint — paste an email, get an explained verdict.

The thinnest router in the project, and deliberately so: it validates, calls one
service function, and returns. There is no ``_persist`` helper here and no
database session in the signature, which is the point. Every other module in
SentinelAI writes a row; this one is the module where writing a row would be the
security incident.

Also note there is no device dependency beyond the rate limiter. Nothing about
this analysis is stored against a device, so nothing needs to identify one — the
limiter uses the header purely to bound cost.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.core.ratelimit import rate_limit
from app.schemas.phishing import EmailAnalyzeRequest, EmailAnalyzeResponse, SignalOut
from app.services.phishing.engine import analyse

router = APIRouter(prefix="/api/v1/phishing", tags=["phishing"])


@router.post(
    "/analyze",
    response_model=EmailAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Check whether a pasted email is a phishing attempt",
    response_description="A verdict with itemised, plain-language reasons and a recommended action",
)
def analyze_email_endpoint(
    payload: EmailAnalyzeRequest,
    _device_id: str = Depends(rate_limit),
) -> EmailAnalyzeResponse:
    """Analyse one email against deterministic heuristics plus an AI intent tier.

    Always ``200``. An email that could not be judged returns verdict
    ``unknown`` with the reason stated in ``signals`` — using an error status
    for "not enough text" would make it indistinguishable from a broken backend,
    which is the ambiguity this codebase refuses to create.

    The email itself is not stored, logged, or hashed. It exists in memory for
    the duration of this function and nowhere else.
    """
    result = analyse(
        sender=payload.sender,
        subject=payload.subject or "",
        body=payload.body,
        reply_to=payload.reply_to,
    )

    return EmailAnalyzeResponse(
        verdict=result.verdict,
        risk_score=result.risk_score,
        confidence=result.confidence,
        summary=result.summary,
        recommendation=result.recommendation,
        signals=[
            SignalOut(signal=s.signal, detail=s.detail, weight=s.weight, evidence=s.evidence)
            for s in result.signals
        ],
        intent=result.intent,
        intent_label=result.intent_label,
        heuristics_only=result.heuristics_only,
    )
