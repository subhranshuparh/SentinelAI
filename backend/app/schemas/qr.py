"""Request and response contracts for Module 9.

Two things are enforced structurally rather than by convention, the same two the
phishing schema enforces:

* **Explainability is required.** ``summary``, ``recommendation``, and every
  signal's ``detail`` carry ``min_length=1``. A bare verdict with no reasoning
  cannot be serialised.
* **The payload is bounded before anything reads it.** ``MAX_PAYLOAD_CHARS`` is
  QR's own capacity ceiling, so a longer string did not come from a scannable
  code and is rejected at the edge rather than parsed defensively later.

One field here exists purely for the user rather than for the machine:
``destination``. It is the plain-language answer to "where does this actually
go", and on a QR code that is the question — the score is secondary to it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.services.qr.parse import MAX_PAYLOAD_CHARS


class QrCheckRequest(BaseModel):
    """One decoded QR payload.

    The *image* is never sent. Decoding happens in the extension's offscreen
    document and only the resulting string arrives here — so a screenshot of a
    bank statement that happens to contain a QR never leaves the machine.
    """

    payload: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PAYLOAD_CHARS,
        description=(
            "The decoded contents of the QR code, exactly as the decoder returned them. "
            f"Capped at {MAX_PAYLOAD_CHARS} characters, which is QR's own alphanumeric limit."
        ),
    )
    source_url: str | None = Field(
        default=None,
        max_length=2_048,
        description=(
            "The page the QR image was found on, when there was one. Used only to label "
            "the check; it is never scored and never stored."
        ),
    )

    @field_validator("payload")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("payload must contain something other than whitespace")
        return value


class QrSignalOut(BaseModel):
    """One row of the explanation."""

    signal: str = Field(..., description="Stable machine key. Never shown to a user raw.")
    detail: str = Field(
        ..., min_length=1, description="Plain-language sentence explaining this row."
    )
    weight: str = Field(
        ...,
        description="bad = a finding | good = checked and clean | unknown = could not be checked",
    )
    evidence: str | None = Field(
        default=None,
        description=(
            "A short excerpt of the payload that triggered this row, always a literal "
            "substring of what was scanned. Null when the row has no quotable span."
        ),
    )


class QrCheckResponse(BaseModel):
    """The verdict, and the reasoning behind it."""

    kind: str = Field(
        ...,
        description=(
            "url | upi | wifi | vcard | tel | sms | mailto | geo | crypto | text — what the "
            "code turned out to be. Determines which checks were even applicable."
        ),
    )
    verdict: str = Field(
        ...,
        description=(
            "dangerous | suspicious | safe | unknown. 'unknown' means the destination could "
            "not be checked — it is never used to mean 'nothing found'."
        ),
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description=(
            "0-100 where HIGHER MEANS MORE DANGEROUS — the same direction as the phishing "
            "risk score, and the inverse of trust_score on /site/check."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="How much to trust this verdict, given which checks could actually run.",
    )
    summary: str = Field(..., min_length=1, description="One sentence, safe to use as a headline.")
    recommendation: str = Field(
        ...,
        min_length=1,
        description="What to do about it. Authored server-side in Python, never by a model.",
    )
    destination: str = Field(
        ...,
        min_length=1,
        description=(
            "Where this code actually goes, in plain language — 'Opens example.com', "
            "'Pays INR 50,000 to someone@ybl'. The most important field in this response: "
            "a QR code is unreadable to a human, and showing the destination is most of "
            "the protection."
        ),
    )
    signals: list[QrSignalOut] = Field(
        ...,
        description=(
            "Itemised evidence, findings first. Includes checks that passed and checks "
            "that could not run."
        ),
    )
    domain: str | None = Field(
        default=None,
        description=(
            "The registrable domain, when the code resolved to a web address. Null for "
            "payments, Wi-Fi, and plain text — those have no domain, and returning an "
            "empty string instead of null would invite the UI to render one."
        ),
    )
    trust_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "The site engine's 0-100 trust score for the destination, where 100 = healthy. "
            "Null when no site lookup applied. Note the direction is the inverse of "
            "risk_score above."
        ),
    )
