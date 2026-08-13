"""Module 7 — Security Assistant Router.

Endpoint: POST /api/v1/assistant/ask
Stateless and read-only.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.assistant import AssistantRequest, AssistantResponse
from app.services.assistant.engine import ask_assistant

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])
settings = get_settings()


@router.post("/ask", response_model=AssistantResponse)
async def ask_security_assistant(request: AssistantRequest) -> AssistantResponse:
    """Ask a cybersecurity question or inquire about security posture.

    Grounds answers in zero-dependency Okapi BM25 corpus cards and personal risk summary.
    """
    return ask_assistant(request)
