"""Prompt templates and response schemas for Gemini Grounded Assistant."""

from __future__ import annotations

import json
from typing import Any, Sequence
from app.services.assistant.cards import KnowledgeCard

ASSISTANT_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "used_card_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
        "refused": {"type": "boolean"},
    },
    "required": ["answer", "used_card_ids", "refused"],
}


def build_assistant_prompt(question: str, cards: Sequence[KnowledgeCard]) -> str:
    """Format prompt constraining Gemini to retrieve knowledge cards."""
    sources_text = []
    for c in cards:
        sources_text.append(f"Card ID [{c.id}]: {c.title}\n{c.body}\n")

    return (
        "You are SentinelAI Security Assistant. Answer the question using ONLY the provided Source Cards below.\n"
        "Do NOT invent advice outside the cards.\n\n"
        f"QUESTION: {question}\n\n"
        "SOURCE CARDS:\n" + "\n".join(sources_text)
    )


def parse_assistant_verdict(raw_json: str, valid_card_ids: set[str]) -> dict[str, Any]:
    """Parse and validate Gemini assistant output."""
    data = json.loads(raw_json)
    answer = str(data.get("answer", "")).strip()
    refused = bool(data.get("refused", False))
    raw_ids = data.get("used_card_ids", [])
    used_ids = [c_id for c_id in raw_ids if c_id in valid_card_ids]

    if refused or not answer:
        return {"available": False}

    return {
        "available": True,
        "answer": answer,
        "used_card_ids": used_ids,
    }
