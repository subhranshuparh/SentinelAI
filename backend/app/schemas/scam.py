"""Request and response contracts for Module 11.

Two things are enforced structurally here rather than by convention, both
carried over from Module 3:

* **Explainability is required, not optional.** Every ``reason``-shaped field
  carries ``min_length=1``. A response with a bare verdict and no explanation
  cannot be serialised.
* **Nothing sent here is echoed back.** The response contains no field that
  could carry a message body. Evidence excerpts are the one exception, and they
  are bounded, deliberate, and drawn from text the user themselves selected.

One thing is specific to this module. ``direction`` exists so the backend can
*refuse* to look at half the input. An outgoing message is accepted by the
schema and discarded by ``incoming_text`` before any pattern, prompt, or network
call sees it. It is accepted at all only because a chat adapter reading the DOM
cannot always separate the two cleanly, and forcing it to guess would mean
either dropping context or silently scanning the user's own words — and the
second of those is the one that must never happen by accident.

There is no ``device_id`` in the response and no persistence anywhere behind
this endpoint. A chat log is the most private text a person owns; the only safe
place to keep it is nowhere.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.services.scam.heuristics import MAX_MESSAGE_CHARS, MAX_MESSAGES

#: Which app the messages came from. Free text from the extension, used only to
#: label the response and capped hard — it is never interpolated into a prompt
#: and never used to look anything up.
MAX_SURFACE_LENGTH = 40


class MessageIn(BaseModel):
    """One message in the conversation being checked."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_MESSAGE_CHARS,
        description="The message text, exactly as it appears on screen.",
    )
    direction: Literal["incoming", "outgoing"] = Field(
        default="incoming",
        description=(
            "'incoming' = received from the other party. 'outgoing' = written by the "
            "user, and never analysed — those are Module 1's job, and warning twice "
            "about one action trains people to dismiss both warnings."
        ),
    )

    @field_validator("text")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class ScamAnalyzeRequest(BaseModel):
    """One conversation, or one selected fragment of one."""

    messages: list[MessageIn] = Field(
        ...,
        min_length=1,
        max_length=MAX_MESSAGES,
        description=(
            "The conversation in the order it appears on screen, oldest first. A "
            "right-click check sends a single message containing the selected text."
        ),
    )
    surface: str | None = Field(
        default=None,
        max_length=MAX_SURFACE_LENGTH,
        description="Where this came from — 'whatsapp', 'telegram', 'selection'. Optional.",
    )

    @field_validator("surface")
    @classmethod
    def _clean_surface(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class SignalOut(BaseModel):
    """One row of the explanation.

    ``weight`` uses the project-wide vocabulary: ``good`` is "checked, nothing
    found", ``unknown`` is "could not check". Collapsing those two into one green
    row is the bug this field exists to prevent.
    """

    signal: str = Field(..., description="Stable machine key. Never shown to a user raw.")
    detail: str = Field(
        ..., min_length=1, description="Plain-language sentence explaining this row."
    )
    weight: str = Field(
        ..., description="bad = a finding | good = checked and clean | unknown = not checked"
    )
    evidence: str | None = Field(
        default=None,
        description=(
            "A short excerpt copied verbatim from the received messages, so the user can "
            "see the exact line that triggered this row. Always a literal substring of "
            "the input — anything that is not is discarded rather than shown."
        ),
    )


class ScamAnalyzeResponse(BaseModel):
    """The verdict, and the reasoning behind it."""

    verdict: str = Field(
        ...,
        description=(
            "dangerous | suspicious | safe | unknown. 'unknown' means too little was "
            "received to judge — it is never used to mean 'nothing found'."
        ),
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description=(
            "0-100 where HIGHER MEANS MORE DANGEROUS — the same direction as "
            "/phishing/analyze and the inverse of trust_score and overall_score."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="How much to trust this verdict, given how much was selected and which tiers answered.",
    )
    summary: str = Field(..., min_length=1, description="One sentence, safe to render as a headline.")
    recommendation: str = Field(
        ...,
        min_length=1,
        description=(
            "What to do about it. Always authored server-side in Python and looked up by "
            "key — never written by the language model, which only ever chooses a label."
        ),
    )
    signals: list[SignalOut] = Field(
        ...,
        description="Itemised evidence, findings first. Includes checks that passed and checks that could not run.",
    )
    scam_type: str | None = Field(
        default=None,
        description="Machine key for the AI's reading of the scam family. Null when that tier did not run.",
    )
    scam_type_label: str | None = Field(
        default=None, description="Human label for `scam_type`. Null when that tier did not run."
    )
    heuristics_only: bool = Field(
        ...,
        description=(
            "True when the AI tier did not answer and the verdict rests on the offline "
            "pattern checks alone. Surfaced so the UI can say so rather than implying a "
            "fuller analysis than actually happened."
        ),
    )
