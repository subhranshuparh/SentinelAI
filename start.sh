#!/usr/bin/env bash
# =============================================================================
# SentinelAI — Fast Startup Script
# =============================================================================

set -euo pipefail

PORT="${PORT:-8000}"

echo "Starting SentinelAI on 0.0.0.0:$PORT..."

exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "$PORT" \
  --workers 1 \
  --log-level info
