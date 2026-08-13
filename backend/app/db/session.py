"""Database engine, session factory, and the FastAPI dependency.

SQLite for the MVP. The Postgres migration is a ``DATABASE_URL`` change plus
installing a driver — the ``connect_args`` below are the only SQLite-specific
line, and they are skipped automatically for any other backend.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.models import Base

settings = get_settings()

# check_same_thread=False: FastAPI serves requests from a threadpool, and
# SQLite's default guard rejects a connection reused across threads. Safe here
# because each request gets its own Session from the factory below.
_connect_args = (
    {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)

engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args, future=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create any missing tables.

    ``create_all`` rather than Alembic: with a 24-hour budget and a schema that
    is only ever created fresh, migrations are pure overhead. The honest
    limitation — this does NOT alter existing tables, so a changed column means
    deleting ``sentinel.db`` and re-seeding. That is a two-second operation here
    and the right trade at this scale.
    """
    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    """Per-request session. Always closed, even when the handler raises."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
