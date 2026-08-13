"""Module 7 — Grounded RAG Security Assistant Engine.

Dual-mode (Extractive vs Generative) answering over corpus knowledge cards and user security posture.
"""

from __future__ import annotations

from app.schemas.assistant import (
    AssistantRequest,
    AssistantResponse,
    AssistantSourceCard,
)
from app.services.assistant.cards import load_corpus
from app.services.assistant.context import build_user_posture_cards
from app.services.assistant.retrieval import retrieve_cards


def ask_assistant(
    request: AssistantRequest, gemini_result: dict | None = None
) -> AssistantResponse:
    """Retrieve grounded answer for a security question."""
    corpus = load_corpus()
    posture_cards = build_user_posture_cards(request.device_id)
    all_cards = posture_cards + corpus

    matches = retrieve_cards(request.question, all_cards, top_k=3)

    if not matches:
        return AssistantResponse(
            answered=False,
            answer="I do not have specific information about that topic in my security knowledge base.",
            mode="extractive",
            sources=[],
            personal_context_used=False,
            recommendation="Try asking about QR code scams, password breaches, Aadhaar privacy, or your overall security score.",
        )

    retrieved_cards = [m[0] for m in matches]
    personal_used = any(c.id.startswith("user_") for c in retrieved_cards)

    # 1. Extractive Mode (Deterministic, zero key, zero hallucination)
    top_card = retrieved_cards[0]
    extractive_answer = f"{top_card.summary}\n\n{top_card.body}"

    sources = [
        AssistantSourceCard(
            id=c.id, title=c.title, summary=c.summary, tags=list(c.tags)
        )
        for c in retrieved_cards
    ]

    # 2. Generative Mode (If Gemini answered cleanly with grounded sources)
    if gemini_result and gemini_result.get("available") and gemini_result.get("answer"):
        return AssistantResponse(
            answered=True,
            answer=gemini_result["answer"],
            mode="generated",
            sources=sources,
            personal_context_used=personal_used,
            recommendation="Check your dashboard for real-time risk updates.",
        )

    return AssistantResponse(
        answered=True,
        answer=extractive_answer,
        mode="extractive",
        sources=sources,
        personal_context_used=personal_used,
        recommendation="Review the cited security guidance above.",
    )
