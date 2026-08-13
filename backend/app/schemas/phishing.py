"""Request and response contracts for Module 3.

Two things are enforced structurally here rather than by convention:

* **Explainability is required, not optional.** ``reason``-shaped fields carry
  ``min_length=1``. A response with a bare verdict and no explanation cannot be
  serialised — the schema rejects it before it reaches a user. That is the
  project-wide rule made mechanical.
* **Nothing sent here is echoed back.** The response contains no field that
  could carry the email body. Evidence excerpts are the one exception and they
  are bounded, deliberate, and drawn from the input the user just pasted
  themselves.

There is no ``device_id`` in the response and no persistence anywhere behind
this endpoint. A phishing email carries the victim's name, their bank, and
often their account number; the only safe place to keep it is nowhere.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.services.phishing.heuristics import MAX_BODY_CHARS

#: RFC 5321 caps a path at 256 octets; a display name pushes the whole From
#: line longer. 400 is generous and still bounded.
MAX_SENDER_LENGTH = 400
MAX_SUBJECT_LENGTH = 500


def _strip_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


class EmailAnalyzeRequest(BaseModel):
    """One pasted email.

    Only ``body`` is required. Everything else raises confidence when present
    and produces an explicit "could not check" row when absent — never a
    silently passing one.
    """

    body: str = Field(
        ...,
        min_length=1,
        max_length=MAX_BODY_CHARS,
        description="The full message text. HTML is accepted and parsed; plain text is fine.",
    )
    sender: str | None = Field(
        default=None,
        max_length=MAX_SENDER_LENGTH,
        description='The From line, ideally complete: "Name <user@example.com>".',
    )
    reply_to: str | None = Field(
        default=None,
        max_length=MAX_SENDER_LENGTH,
        description="The Reply-To line, if the mail client shows one.",
    )
    subject: str | None = Field(
        default=None,
        max_length=MAX_SUBJECT_LENGTH,
        description="The subject line.",
    )

    @field_validator("sender", "reply_to", "subject")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return _strip_or_none(value)


class SignalOut(BaseModel):
    """One row of the explanation.

    ``weight`` uses the same vocabulary as the site module, and the distinction
    it encodes is the whole product: ``good`` is "checked, nothing found",
    ``unknown`` is "could not check". Collapsing those two into one green row is
    the bug this field exists to prevent.
    """

    signal: str = Field(..., description="Stable machine key. Never shown to a user raw.")
    detail: str = Field(
        ..., min_length=1, description="Plain-language sentence explaining this row."
    )
    weight: str = Field(..., description="bad = a finding | good = checked and clean | unknown = not checked")
    evidence: str | None = Field(
        default=None,
        description=(
            "A short excerpt copied verbatim from the email that triggered this row, "
            "so the user can see what was matched. Null when the row has no quotable span."
        ),
    )


class EmailAnalyzeResponse(BaseModel):
    """The verdict, and the reasoning behind it."""

    verdict: str = Field(
        ...,
        description=(
            "dangerous | suspicious | safe | unknown. 'unknown' means too little text was "
            "provided to judge — it is never used to mean 'nothing found'."
        ),
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description=(
            "0-100 where HIGHER MEANS MORE DANGEROUS. Note the direction: this is the "
            "inverse of trust_score on /site/check and overall_score on the dashboard, "
            "both of which run 100 = healthy. Kept this way because 'risk 90' is how a "
            "person reads a warning about an email."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="How much to trust this verdict, given how much of the email was pasted and which tiers answered.",
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
    intent: str | None = Field(
        default=None,
        description="Machine key for the AI's reading of the email's purpose. Null when that tier did not run.",
    )
    intent_label: str | None = Field(
        default=None, description="Human label for `intent`. Null when that tier did not run."
    )
    heuristics_only: bool = Field(
        ...,
        description=(
            "True when the AI tier did not answer and the verdict rests on the offline "
            "pattern checks alone. Surfaced so the UI can say so rather than implying a "
            "fuller analysis than actually happened."
        ),
    )
