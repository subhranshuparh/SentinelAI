"""SQLAlchemy models — the minimal set the MVP dashboard actually needs.

Five tables. Every one of them exists because a specific dashboard widget or
scoring input requires it; nothing is here speculatively.

The single hard rule enforced structurally: **no column anywhere holds raw
detected PII.** ``PiiEvent`` stores the classification, the confidence, the
reason, and a *masked* preview. The original substring is processed in memory
and discarded. This is why there is no ``raw_text`` column to accidentally log.

``IdentityCheck`` extends the same rule to passwords, and further: there is no
password column, and no full-hash column either. Five hex characters of a SHA-1
digest is the widest thing this schema is capable of storing about a password.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Timezone-aware UTC now.

    Used instead of ``datetime.utcnow`` (deprecated, and returns a *naive*
    datetime that silently compares wrong against aware ones — a trap when the
    dashboard computes "events in the last 24h").
    """
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------
# Controlled vocabularies
#
# Stored as plain strings rather than DB-native ENUMs: SQLite has no ENUM type,
# and adding a 15th PII type must never require a migration at hour 18.
# --------------------------------------------------------------------------


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionTier(str, enum.Enum):
    """Which layer produced a finding. Surfaced in the UI and used in scoring.

    Worth persisting rather than inferring: it is the evidence for the
    "hybrid detection" architecture claim, and it lets you answer "how often did
    the LLM tier actually earn its latency?" from real data during the pitch.
    """

    REGEX = "regex"  # Deterministic, 0ms, $0.
    LLM = "llm"  # Gemini, context-dependent only.
    # Module 12. Not a third detector: it is the regex tier run a second time
    # over text whose confusable characters were corrected, and only where an
    # arithmetic checksum could confirm the correction. Recorded distinctly
    # because a finding produced this way is a *corrected read* — the UI says so
    # out loud, and "the tool changed a digit before it matched" is exactly the
    # kind of fact that must survive into the row rather than being flattened
    # into "regex". See ``services/pii/ocr_normalise.py``.
    OCR = "ocr"


class UserAction(str, enum.Enum):
    """What the user did about a finding. Drives the false-positive story."""

    NONE = "none"  # Warned; user kept typing.
    MASKED = "masked"  # Accepted the suggestion.
    IGNORED = "ignored"  # Dismissed this one instance.
    ALLOWLISTED = "allowlisted"  # "Always allow here" — a self-reported false positive.


class SiteVerdict(str, enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"  # Signals unavailable. Explicitly NOT "safe".


# --------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------


class Device(Base):
    """One browser install. The MVP's stand-in for a user account.

    The extension generates a random UUID on first run and sends it as
    ``X-Sentinel-Device-Id``. When JWT auth is switched on, this table gains a
    nullable ``user_id`` FK and nothing else changes — every other table already
    hangs off ``device_id``, so accounts become an additive migration rather
    than a rewrite of the event tables.
    """

    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    pii_events: Mapped[list[PiiEvent]] = relationship(back_populates="device")
    site_checks: Mapped[list[SiteCheck]] = relationship(back_populates="device")
    identity_checks: Mapped[list[IdentityCheck]] = relationship(back_populates="device")


class PiiEvent(Base):
    """One piece of sensitive data caught in the typing path (Module 1).

    Feeds: the threat timeline, the Privacy sub-score, and the sensitive-data
    alerts log.
    """

    __tablename__ = "pii_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    # Origin only ("https://mail.google.com"), never the full URL: a full URL can
    # itself carry PII in query params, which would defeat the whole point.
    site_origin: Mapped[str] = mapped_column(String(255), nullable=False)
    # input|textarea|contenteditable|paste|image. The last two are arrival kinds
    # rather than element types — see schemas/pii.py:FieldKind for why they share
    # one column.
    field_kind: Mapped[str] = mapped_column(String(32), nullable=False)

    pii_type: Mapped[str] = mapped_column(String(40), nullable=False)  # "aadhaar", "credit_card", ...
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    detection_tier: Mapped[str] = mapped_column(String(16), nullable=False)

    # Required by the explainability rule: no finding may exist without a reason.
    # nullable=False is the enforcement — a bare verdict cannot be written at all.
    reason: Mapped[str] = mapped_column(String(500), nullable=False)

    # Masked form ONLY, e.g. "XXXX XXXX 9013". Never the original substring.
    masked_preview: Mapped[str] = mapped_column(String(120), nullable=False)

    action_taken: Mapped[str] = mapped_column(
        String(16), default=UserAction.NONE.value, nullable=False
    )

    device: Mapped[Device] = relationship(back_populates="pii_events")

    __table_args__ = (
        # The timeline and every "last 24h" aggregate query filter by device and
        # sort by time. Without this the dashboard degrades as the demo runs.
        Index("ix_pii_device_time", "device_id", "occurred_at"),
    )


class SiteCheck(Base):
    """One site trust evaluation (Module 2).

    Feeds: the flagged-sites list, the Browsing sub-score, and the timeline.
    """

    __tablename__ = "site_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)

    # Itemised, human-readable trigger list — the "Reasons:" block in the spec.
    # JSON rather than a child table: it is always read as a whole, never queried
    # into, and a join here would buy nothing.
    reasons: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Nullable *on purpose*. NULL means "RDAP had no answer", which the risk
    # engine treats as an absent signal to redistribute — never as "safe".
    domain_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    safe_browsing_hit: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    brand_mismatch: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    device: Mapped[Device] = relationship(back_populates="site_checks")

    __table_args__ = (
        Index("ix_site_device_time", "device_id", "occurred_at"),
        Index("ix_site_domain", "domain"),
    )


class IdentityCheck(Base):
    """One password-reuse check (Module 4, k-anonymity half).

    Feeds: the Identity sub-score, and the "change this password" recommendation.

    **What this table is physically incapable of holding.** There is no password
    column and no full-hash column. ``hash_prefix`` is the first five hex
    characters of a SHA-1 digest — roughly 800 of the corpus's 900 million
    passwords share any given value, so the column is k-anonymous by
    construction rather than by policy. Storing it (instead of nothing) is
    deliberate: it is the artefact that lets a sceptical reader see exactly how
    much this system ever knew.

    ``breach_count`` is the prevalence the *client* matched locally. The backend
    can sanity-check that some suffix in the range carries that count without
    learning which one — see ``services/identity/pwned.count_is_plausible``.
    """

    __tablename__ = "identity_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    #: Exactly 5 uppercase hex chars. See the class docstring.
    hash_prefix: Mapped[str] = mapped_column(String(5), nullable=False)

    #: Optional user-chosen nickname ("Gmail"). Display and supersession only —
    #: re-checking the same label replaces the previous verdict, which is how a
    #: user who actually changes their password sees the score recover.
    label: Mapped[str | None] = mapped_column(String(40), nullable=True)

    #: How many breached accounts used this password. 0 means "not in the corpus",
    #: which is a real answer. A check that could not run is never written at all.
    breach_count: Mapped[int] = mapped_column(Integer, nullable=False)

    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # Same explainability enforcement as PiiEvent: nullable=False means a bare
    # verdict cannot be persisted, let alone rendered.
    reason: Mapped[str] = mapped_column(String(500), nullable=False)

    device: Mapped[Device] = relationship(back_populates="identity_checks")

    __table_args__ = (Index("ix_identity_device_time", "device_id", "occurred_at"),)


class ScoreSnapshot(Base):
    """A point on the risk-trend chart.

    Denormalised on purpose. The alternative — recomputing the whole score
    history from raw events on every dashboard load — is both slower and
    *wrong*: it would retroactively rewrite history whenever the scoring weights
    are tuned, so the chart would silently change shape mid-hackathon. A snapshot
    records what the score actually was at that moment.
    """

    __tablename__ = "score_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    overall: Mapped[int] = mapped_column(Integer, nullable=False)
    privacy: Mapped[int] = mapped_column(Integer, nullable=False)
    identity: Mapped[int] = mapped_column(Integer, nullable=False)
    browsing: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (Index("ix_snapshot_device_time", "device_id", "captured_at"),)
