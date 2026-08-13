"""Request/response contracts for Module 1.

This file is where the explainability rule stops being a convention and becomes
a constraint: ``reason`` and ``confidence`` are required fields on
``FindingOut``. FastAPI validates responses against this model, so an endpoint
that tried to return a bare verdict would raise rather than ship.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator

#: Hard cap on scanned text. The typing path never produces anything close to
#: this; a larger body is a paste or an abuse attempt, and unbounded input on an
#: endpoint that may call an LLM is a cost and latency risk.
MAX_TEXT_LENGTH = 20_000


class FieldKind(str, Enum):
    INPUT = "input"
    TEXTAREA = "textarea"
    CONTENTEDITABLE = "contenteditable"
    #: Module 10. Not an element type — an *arrival* type. Kept on the same
    #: field rather than added as a second axis because "how did this text get
    #: here" is the question the timeline and the risk narrative actually ask,
    #: and whether the target was an <input> or a <div> has never once mattered
    #: to either. It also selects the destination assessment in the router.
    PASTE = "paste"
    #: Module 12. Text that was never in a field at all — it was read out of a
    #: picture the user was about to upload. Same reasoning as PASTE: the
    #: timeline's question is "how did this leave you", and "in a screenshot" is
    #: a materially different answer from "you typed it".
    IMAGE = "image"


class TextSource(str, Enum):
    """How the text was obtained, which decides how much to trust its characters.

    Separate from ``FieldKind`` because they answer different questions and
    collapsing them would be wrong in both directions: a paste can arrive in any
    kind of field, and OCR text has no field. This axis exists for exactly one
    consumer — the engine, deciding whether to run the confusable-correction pass
    in ``services/pii/ocr_normalise.py``, which must never run on text a human
    typed. A typed ``S`` is an ``S``.
    """

    TYPED = "typed"
    PASTE = "paste"
    OCR = "ocr"


class ScanRequest(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_LENGTH, description="Field contents. Never persisted.")
    site_origin: str = Field(
        ...,
        max_length=255,
        description="Origin only, e.g. https://mail.google.com. Never a full URL.",
    )
    field_kind: FieldKind = FieldKind.INPUT
    source: TextSource = Field(
        default=TextSource.TYPED,
        description=(
            "typed | paste | ocr. Only 'ocr' enables checksum-backed correction "
            "of misread characters, and only for Aadhaar and card numbers."
        ),
    )
    suppressed_types: list[str] = Field(
        default_factory=list,
        max_length=40,
        description="Per-site 'always allow' overrides. Filtered before scanning.",
    )

    @field_validator("site_origin")
    @classmethod
    def _strip_path(cls, value: str) -> str:
        """Reduce anything URL-shaped to scheme://host.

        Defence in depth. The extension already sends an origin, but a full URL
        arriving here would be persisted, and URLs routinely carry PII in query
        parameters — which would leak the exact data this module exists to
        protect. Truncating server-side means a client bug cannot cause that.
        """
        value = value.strip()
        parts = value.split("/")
        if len(parts) >= 3 and parts[1] == "":
            return f"{parts[0]}//{parts[2]}"
        return value[:255]


class FindingOut(BaseModel):
    """One detected item. Every field below the fold is what makes it actionable."""

    pii_type: str
    label: str
    risk_level: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    detection_tier: str

    # --- Required by the explainability contract ---
    reason: str = Field(..., min_length=1, description="Which signal fired, and why.")
    explanation: str = Field(..., min_length=1, description="Plain-language risk, no jargon.")
    recommendation: str = Field(..., min_length=1, description="What to do about it.")

    # Character offsets into the submitted text, so the content script can
    # highlight and replace the exact substring without re-searching for it.
    start: int
    end: int

    masked_preview: str
    suggested_replacement: str

    # --- Module 10 ----------------------------------------------------------
    #
    # Both null on a typed scan. Not "false", not "expected", not an empty
    # string — null, because the question was never asked. Optional here and
    # required above is the whole distinction the schema is drawing: reason and
    # confidence always exist, a destination verdict only exists once something
    # assessed one.
    destination_fit: str | None = Field(
        default=None,
        description="never | rarely | expected | unknown. Null when not assessed.",
    )
    destination_note: str | None = Field(
        default=None,
        min_length=1,
        description="One sentence naming the site. Null when not assessed.",
    )


class DestinationOut(BaseModel):
    """Where a pasted value was headed.

    ``recognised`` is sent explicitly rather than left for the client to infer
    from ``kind == "unknown"``. It is the one bit the extension branches on, and
    a client that got the comparison wrong would render "we have no idea" as a
    clean bill of health — the single failure mode this project keeps designing
    against.
    """

    origin: str
    name: str = Field(..., min_length=1, description="Display name, e.g. 'Discord'.")
    kind: str
    kind_label: str = Field(..., min_length=1)
    recognised: bool


class ScanResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="0 = nothing sensitive, 100 = do not send.")
    risk_level: str
    tier_2_available: bool = Field(
        ...,
        description=(
            "False only when the semantic tier should have run and failed. The UI "
            "must distinguish 'found nothing' from 'could not fully check'."
        ),
    )
    tier_2_status: str = Field(
        ...,
        description=(
            "ran | skipped | disabled | unavailable. The boolean above is the "
            "coarse version for the extension; this is the one to show a developer."
        ),
    )
    findings: list[FindingOut]
    destination: DestinationOut | None = Field(
        default=None,
        description=(
            "Where the text was being pasted. Null on a typed scan — the "
            "question was not asked, which is not the same as a good answer."
        ),
    )
