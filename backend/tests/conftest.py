"""Test configuration.

The environment is set here, before any ``app.*`` import, because
``get_settings`` is ``lru_cache``d — the first import freezes configuration for
the whole process. Setting these afterwards would silently have no effect and
the suite would quietly run against the real ``sentinel.db``.
"""

from __future__ import annotations

import os

os.environ["DATABASE_URL"] = "sqlite:///./test_sentinel.db"
# Force Tier-1-only so the suite never makes a network call, never spends quota,
# and never fails because someone else's Wi-Fi is down.
os.environ["ENABLE_GEMINI_TIER"] = "false"
os.environ["ENABLE_JWT_AUTH"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.session import engine, init_db  # noqa: E402
from app.db.models import Base  # noqa: E402
from app.main import app  # noqa: E402

DEVICE_ID = "test-device-0000-1111"


@pytest.fixture(autouse=True)
def _fresh_db():
    """Drop and recreate tables around every test.

    Cheap on SQLite, and it keeps persistence assertions independent — a test
    that counts rows must not depend on which tests ran before it.
    """
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"X-Sentinel-Device-Id": DEVICE_ID}
