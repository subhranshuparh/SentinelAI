"""Request/response contracts for Module 4 (password-reuse half).

The explainability rule is enforced the same way as Modules 1 and 2 — ``reason``
and ``confidence`` are required, and the prose fields carry ``min_length=1``, so
a bare "breached" is not a value this API can serialise.

One extra contract lives here that the other modules do not need: the request
model is **structurally incapable of carrying a password**. There is no password
field and no full-hash field; ``hash_prefix`` is pinned to exactly five hex
characters by a pattern, so an over-eager client cannot narrow the anonymity set
by sending six.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

#: Exactly five uppercase hex characters — see ``services/identity/pwned.py``.
HASH_PREFIX_PATTERN = r"^[0-9A-Fa-f]{5}$"

#: The corpus's most common password appears ~37 million times. A ceiling three
#: times that leaves headroom for corpus growth while rejecting a client that
#: sends a nonsense integer.
MAX_BREACH_COUNT = 100_000_000

MAX_LABEL_LENGTH = 40

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class PasswordCheckRequest(BaseModel):
    """What the popup sends *after* matching the range locally."""

    hash_prefix: str = Field(
        ...,
        pattern=HASH_PREFIX_PATTERN,
        description="First 5 hex chars of SHA-1(password). The rest never leaves the device.",
    )
    breach_count: int = Field(
        ...,
        ge=0,
        le=MAX_BREACH_COUNT,
        description="Prevalence the client matched locally. 0 means not found — a real answer.",
    )
    label: str | None = Field(
        None,
        max_length=MAX_LABEL_LENGTH,
        description="Optional nickname, e.g. 'Gmail'. Re-checking the same label supersedes it.",
    )

    @field_validator("label")
    @classmethod
    def _clean_label(cls, value: str | None) -> str | None:
        """Strip control characters and collapse whitespace.

        This string is user-supplied, persisted, and rendered on the dashboard.
        It is not an XSS boundary (React escapes, and the popup uses
        ``textContent``), but a label containing newlines would break a
        single-line UI and one containing control characters would end up in the
        database — so it is normalised at the edge rather than at every render.
        """
        if value is None:
            return None
        cleaned = _CONTROL.sub(" ", value)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned or None


class PwnedRangeResponse(BaseModel):
    """The k-anonymity range, proxied verbatim for the client to match locally."""

    prefix: str = Field(..., description="Echoed back so a client can assert it matched its request.")
    suffixes: dict[str, int] = Field(
        ...,
        description="35-char SHA-1 suffix -> breach count. Padding entries are already removed.",
    )
    count: int = Field(..., ge=0, description="Number of real suffixes returned.")


class PasswordCheckResponse(BaseModel):
    """One password's verdict. Every prose field is required."""

    breached: bool
    breach_count: int = Field(..., ge=0)
    risk_level: str = Field(..., description="low | high | critical")

    # --- Required by the explainability contract ---
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="0.95 when the count was corroborated against the live range.",
    )
    reason: str = Field(..., min_length=1, description="The signal, in one factual clause.")
    explanation: str = Field(..., min_length=1, description="Why it matters, in plain words.")
    recommendation: str = Field(..., min_length=1, description="The single next action.")

    # --- Effect on the unified score, so the popup can say so immediately ---
    identity_score: int | None = Field(
        None,
        ge=0,
        le=100,
        description="Recomputed Identity sub-score. null only if the write failed.",
    )
    checks_counted: int = Field(..., ge=0, description="Distinct passwords currently scored.")
