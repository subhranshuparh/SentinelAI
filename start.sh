#!/usr/bin/env bash
# =============================================================================
# SentinelAI — Fast Startup Script
# =============================================================================

set -euo pipefail

PORT="${PORT:-8000}"

echo "Starting SentinelAI on 0.0.0.0:$PORT..."

if command -v python3 >/dev/null 2>&1; then
  exec python3 -m uvicorn main:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --workers 1 \
    --log-level info \
    2>&1
else
  exec uvicorn main:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --workers 1 \
    --log-level info \
    2>&1
fi