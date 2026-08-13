"""Module 11 endpoint — check a conversation, get an explained verdict.

The second router in the project with **no database session in its signature**,
and for the same reason as ``routers/phishing.py``, only more so. A phishing
email is one document a user chose to paste. A chat thread is a private
conversation involving a second person who never consented to anything — often a
family member, sometimes a criminal, and the backend has no way to tell which.

That absence is the enforcement, not a comment. There is no ``db`` parameter to
pass a session to, no model imported, and ``tests/test_scam.py`` asserts by
enumerating the tables that a full analysis leaves every row count unchanged.

The rate limiter still takes the device header. It uses it to bound cost and
writes nothing.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.core.ratelimit import rate_limit
from app.schemas.scam import ScamAnalyzeRequest, ScamAnalyzeResponse, SignalOut
from app.services.scam.engine import analyse
from app.services.scam.heuristics import Message

router = APIRouter(prefix="/api/v1/scam", tags=["scam"])


@router.post(
    "/analyze",
    response_model=ScamAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Check whether a chat conversation is a scam",
    response_description="A verdict with itemised, plain-language reasons and a recommended action",
)
def analyze_conversation_endpoint(
    payload: ScamAnalyzeRequest,
    _device_id: str = Depends(rate_limit),
) -> ScamAnalyzeResponse:
    """Analyse one conversation against deterministic heuristics plus an AI tier.

    Always ``200``. A conversation that could not be judged returns verdict
    ``unknown`` with the reason stated in ``signals`` — an error status for "not
    enough text" would be indistinguishable from a broken backend, which is the
    ambiguity this codebase refuses to create.

    Messages marked ``outgoing`` are dropped before analysis. They are not
    scored, not sent to the model, and not counted towards the minimum length.

    Nothing here is stored, logged, or hashed. The conversation exists in memory
    for the duration of this function and nowhere else.
    """
    result = analyse(
        [
            Message(text=message.text, incoming=message.direction == "incoming")
            for message in payload.messages
        ]
    )

    return ScamAnalyzeResponse(
        verdict=result.verdict,
        risk_score=result.risk_score,
        confidence=result.confidence,
        summary=result.summary,
        recommendation=result.recommendation,
        signals=[
            SignalOut(signal=s.signal, detail=s.detail, weight=s.weight, evidence=s.evidence)
            for s in result.signals
        ],
        scam_type=result.scam_type,
        scam_type_label=result.scam_type_label,
        heuristics_only=result.heuristics_only,
    )
