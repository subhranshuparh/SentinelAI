#!/usr/bin/env bash
# =============================================================================
# SentinelAI — Railway Deployment Start Script
#
# Railway runs this file from the repository root.
# It installs all dependencies, builds the React dashboard, then starts the
# FastAPI backend which serves both the API *and* the compiled dashboard as
# a single unified service on the PORT Railway assigns.
#
# Environment variables Railway must have set (add in Railway dashboard):
#   PORT                   — set automatically by Railway
#   GEMINI_API_KEY         — Google AI Studio key
#   SAFE_BROWSING_API_KEY  — Google Safe Browsing key
#   DATABASE_URL           — e.g. postgresql://user:pass@host:5432/sentinelai
#   CORS_ALLOW_ORIGINS     — comma-separated allowed origins
#   ENABLE_GEMINI_TIER     — true
#   ENABLE_JWT_AUTH        — false (change to true for production)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# 0 — Resolve paths
# ---------------------------------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT/backend"
DASHBOARD_DIR="$ROOT/dashboard"
DIST_DIR="$DASHBOARD_DIR/dist"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║          SentinelAI — Railway Startup                ║"
echo "║  Privacy · Protection · Peace of Mind               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ---------------------------------------------------------------------------
# 1 — Build the React dashboard
# ---------------------------------------------------------------------------
echo "▶ Step 1/3 — Building dashboard (React + Vite)"
echo "  Installing Node dependencies..."
npm install --prefix "$DASHBOARD_DIR" --prefer-offline 2>&1

echo "  Compiling dashboard..."
# Pass the backend URL so the built JS knows where the API lives.
# On Railway both are the same domain (backend serves the SPA), so
# VITE_API_BASE should be empty or point to the Railway-assigned URL.
# If you want a separate backend URL, set VITE_API_BASE in Railway env.
VITE_API_BASE="${VITE_API_BASE:-}" npm run build --prefix "$DASHBOARD_DIR" 2>&1

echo "  ✓ Dashboard built → $DIST_DIR"
echo ""

# ---------------------------------------------------------------------------
# 2 — Install Python dependencies
# ---------------------------------------------------------------------------
echo "▶ Step 2/3 — Installing Python dependencies"
cd "$BACKEND_DIR"
pip install --no-cache-dir -r requirements.txt 2>&1
echo "  ✓ Python packages installed"
echo ""

# ---------------------------------------------------------------------------
# 3 — Start the FastAPI server
# ---------------------------------------------------------------------------
# Railway injects $PORT. Uvicorn must bind 0.0.0.0 (not 127.0.0.1) so
# Railway's reverse proxy can reach it.
PORT="${PORT:-8000}"

echo "▶ Step 3/3 — Starting SentinelAI backend on 0.0.0.0:$PORT"
echo ""

exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "$PORT" \
  --workers 1 \
  --log-level info
