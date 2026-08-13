"""Request/response contracts for Module 2.

Same explainability rule as Module 1, enforced the same way: ``summary`` and
``confidence`` are required, and ``reasons`` has ``min_length=1``. There is no
representable response in which the extension is told "dangerous" with nothing
to show the user about why.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 2_048


class SiteCheckRequest(BaseModel):
    url: str = Field(..., max_length=MAX_URL_LENGTH, description="Full page URL from the extension.")

    @field_validator("url")
    @classmethod
    def _require_web_scheme(cls, value: str) -> str:
        """Reject anything that is not http(s).

        Not pedantry. ``file://`` and ``chrome-extension://`` URLs carry local
        paths that would be persisted to ``site_checks.domain`` and sent to
        Google, and neither is a site whose trust this module can speak to.
        """
        value = value.strip()
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("Only http and https URLs can be checked")
        return value


class ReasonOut(BaseModel):
    """One itemised trigger, in both registers."""

    signal: str = Field(..., description="Machine name: safe_browsing | brand | domain_age | input.")
    detail: str = Field(..., min_length=1, description="The sentence a person reads. No jargon.")
    weight: str = Field(..., description="bad | good | unknown. 'unknown' means the check did not run.")


class SiteCheckResponse(BaseModel):
    domain: str
    trust_score: int = Field(..., ge=0, le=100, description="100 = no concerns found. Not a safety guarantee.")
    verdict: str = Field(..., description="safe | suspicious | dangerous | unknown. 'unknown' is never 'safe'.")

    # --- Required by the explainability contract ---
    summary: str = Field(..., min_length=1, description="One plain sentence. Most users read only this.")
    reasons: list[ReasonOut] = Field(..., min_length=1, description="Itemised, always at least one.")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Share of the three signals that actually answered. 0.30 = offline check only.",
    )

    # --- Raw signals, for the dashboard and for a sceptical judge ---
    domain_age_days: int | None = Field(None, description="null means RDAP had no answer — not 'old'.")
    safe_browsing_hit: bool | None = Field(None, description="null means the lookup could not run.")
    brand_mismatch: bool
