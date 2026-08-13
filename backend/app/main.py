"""SentinelAI backend — application factory.

Deliberately a *single* FastAPI service with modular routers rather than
microservices: one process to start, one log stream to read, one thing that can
be broken on stage. Module boundaries live in ``app/services/``, which is where
they actually matter.

Phase 0 scope: health only. Routers are mounted in later phases.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
from app.db.session import init_db
from app.routers import assistant, dashboard, identity, phishing, pii, qr, review, scam, site
from app.services.llm.gemini import warm_up

settings = get_settings()

#: ``backend/app/main.py`` -> repository root -> the extension's vendored assets.
VENDOR_DIR = Path(__file__).resolve().parents[2] / "extension" / "lib" / "vendor"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Create any missing tables on boot, and warm the outbound TLS connection.

    ``create_all`` is safe to run every start: it is a no-op for tables that
    exist. It does not ALTER, so a schema change means deleting sentinel.db — a
    two-second operation at this scale, and the reason Alembic is not here.

    The warm-up is fire-and-forget on a daemon thread; boot does not wait for it
    and cannot fail because of it.
    """
    init_db()
    warm_up()
    yield

app = FastAPI(
    title="SentinelAI",
    description="AI cybersecurity copilot — privacy, identity, and safe browsing.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS: an explicit allowlist. The extension's own origin
# (chrome-extension://<id>) is appended once the unpacked extension ID exists,
# in Phase 2 — Chrome assigns it at load time, so it cannot be hardcoded now.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,  # Device-header auth; no cookies to protect.
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Sentinel-Device-Id"],
)

app.include_router(pii.router)
app.include_router(site.router)
app.include_router(identity.router)
app.include_router(phishing.router)
app.include_router(qr.router)
app.include_router(scam.router)
app.include_router(review.router)
app.include_router(assistant.router)
app.include_router(dashboard.router)

# --------------------------------------------------------------------------
# Modules 9 & 12 — serving the vendored decoders to the dashboard
# --------------------------------------------------------------------------
#
# The dashboard's screenshot drop-zone needs the same Tesseract and jsQR builds
# the extension uses, and there were three ways to give it one:
#
#   * ``npm i tesseract.js`` — rejected. The package resolves its wasm core and
#     its language model from a CDN by default, so the dashboard would silently
#     stop working the moment the network is unplugged, which is precisely the
#     condition the demo has to survive. It would also mean two different
#     Tesseract builds in one product, so a bug reproducible in the browser
#     might not reproduce in the extension.
#   * copying the five files into ``dashboard/public/`` — rejected. Nine
#     megabytes duplicated in the repository, with nothing keeping the two copies
#     in step. The checksums in ``docs/INTEGRATION_NOTES.md`` would then cover
#     one of them and not the other.
#   * serving the extension's own copy read-only, which is this. One set of
#     bytes on disk, one set of checksums, offline by construction, and the
#     dashboard fallback provably runs the same engines as the extension.
#
# Read-only and inert. StaticFiles serves bytes; nothing under this mount is
# executed by the backend, and the directory contains only the five vendored
# assets listed in INTEGRATION_NOTES.md. It is *not* a general file server: the
# path is fixed in code above and no part of a request contributes to it, and
# Starlette rejects traversal outside the mounted root.
#
# Mounted conditionally so a backend-only deployment (no ``extension/``
# directory beside it) still boots. StaticFiles raises at construction time when
# its directory is missing, which would turn an absent optional asset into a
# service that will not start.
if VENDOR_DIR.is_dir():
    app.mount("/vendor", StaticFiles(directory=VENDOR_DIR, html=False), name="vendor")


@app.get("/health", tags=["system"])
def health() -> dict[str, object]:
    """Liveness probe, and the fastest way to see which tiers are armed.

    Reports *capability*, not secrets — it exposes whether a key is present, never
    the key itself. Useful mid-demo: if Tier 2 silently stopped working, this
    endpoint says so in one request.
    """
    return {
        "status": "ok",
        "version": app.version,
        "tiers": {
            "regex": True,  # Always available; needs no key and no network.
            "gemini": settings.gemini_tier_available,
            "safe_browsing": bool(settings.SAFE_BROWSING_API_KEY),
        },
    }
