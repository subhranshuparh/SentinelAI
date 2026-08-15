"""SentinelAI backend — application factory.

Deliberately a *single* FastAPI service with modular routers rather than
microservices: one process to start, one log stream to read, one thing that can
be broken on stage. Module boundaries live in ``app/services/``, which is where
they actually matter.

Railway deployment: ``start.sh`` (repo root) builds the React dashboard first,
then starts this server. The ``/assets`` mount and the SPA catch-all at the
bottom of this file serve the compiled dashboard from ``dashboard/dist/`` so
the whole product runs as one Railway service on one port.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
from app.db.session import init_db
from app.routers import assistant, dashboard, identity, phishing, pii, qr, review, scam, site
from app.services.llm.gemini import warm_up

settings = get_settings()

#: Repo root — two levels above this file (backend/app/main.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]

#: ``backend/app/main.py`` -> repository root -> the extension's vendored assets.
VENDOR_DIR = _REPO_ROOT / "extension" / "lib" / "vendor"

#: Compiled React dashboard produced by ``npm run build`` in ``dashboard/``.
#: Only present after ``start.sh`` runs (i.e. in Railway / CI, not local dev).
DASHBOARD_DIST = _REPO_ROOT / "dashboard" / "dist"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Create any missing tables on boot, warm TLS, and seed initial demo data."""
    init_db()
    warm_up()
    try:
        from app.db.models import Device
        from app.db.session import SessionLocal

        with SessionLocal() as db:
            if db.query(Device).first() is None:
                from app.db.seed import seed

                seed(reset=False)
    except Exception:
        pass
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
if VENDOR_DIR.is_dir():
    app.mount("/vendor", StaticFiles(directory=VENDOR_DIR, html=False), name="vendor")


@app.get("/health", tags=["system"])
def health() -> dict[str, object]:
    """Liveness probe, and the fastest way to see which tiers are armed."""
    return {
        "status": "ok",
        "version": app.version,
        "tiers": {
            "regex": True,  # Always available; needs no key and no network.
            "gemini": settings.gemini_tier_available,
            "safe_browsing": bool(settings.SAFE_BROWSING_API_KEY),
        },
    }


# --------------------------------------------------------------------------
# Dashboard SPA — served only when the compiled dist/ folder exists.
# --------------------------------------------------------------------------
if DASHBOARD_DIST.is_dir():
    _assets_dir = DASHBOARD_DIST / "assets"
    if _assets_dir.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=_assets_dir, html=False),
            name="dashboard-assets",
        )

    _index = DASHBOARD_DIST / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str) -> FileResponse:
        """Return the React shell for the root or client-side routes."""
        cleaned = full_path.lstrip("/")

        # Root route
        if not cleaned or cleaned == "index.html":
            if _index.is_file():
                return FileResponse(_index)
            raise HTTPException(status_code=404, detail="Not Found")

        # Static assets in dist root (favicon.svg, logo.svg, etc.)
        target_file = DASHBOARD_DIST / cleaned
        if target_file.is_file() and not cleaned.endswith(".html"):
            return FileResponse(target_file)

        # File requests with extensions or system routes that don't exist must 404
        if "." in cleaned or cleaned.startswith(("api", "vendor", "app", "docs", "redoc", "openapi", "health")):
            raise HTTPException(status_code=404, detail="Not Found")

        # Client-side SPA routes (no file extension)
        if _index.is_file():
            return FileResponse(_index)

        raise HTTPException(status_code=404, detail="Not Found")


if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
