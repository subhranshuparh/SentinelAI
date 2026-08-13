"""Pydantic schemas for Module 7 — Grounded RAG Security Assistant."""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


class AssistantRequest(BaseModel):
    """Payload for POST /api/v1/assistant/ask."""

    question: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="The user's security question or posture inquiry.",
    )
    device_id: str | None = Field(
        default=None,
        description="Optional device ID to ground answers in personal security posture.",
    )


class AssistantSourceCard(BaseModel):
    """Cited knowledge card or personal posture source."""

    id: str = Field(..., description="Unique card identifier.")
    title: str = Field(..., description="Card title.")
    summary: str = Field(..., description="Short summary of card contents.")
    tags: list[str] = Field(default_factory=list, description="Categorization tags.")


class AssistantResponse(BaseModel):
    """Response returned by POST /api/v1/assistant/ask."""

    answered: bool = Field(
        ..., description="True if retrieved relevant knowledge; false if below threshold."
    )
    answer: str = Field(
        ..., min_length=1, description="Grounded plain-language answer."
    )
    mode: Literal["extractive", "generated"] = Field(
        ..., description="Extractive (deterministic) vs Generative (Gemini)."
    )
    sources: list[AssistantSourceCard] = Field(
        default_factory=list, description="Cited knowledge cards used in answer."
    )
    personal_context_used: bool = Field(
        ..., description="Whether user's active posture was referenced."
    )
    recommendation: str | None = Field(
        default=None, description="Actionable next step recommendation."
    )
