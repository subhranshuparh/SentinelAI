"""Root entry point for SentinelAI.

Allows Railway (or any platform) to start the server from the repository root using:
    uvicorn main:app --host 0.0.0.0 --port $PORT
or
    python main.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add the backend folder to sys.path so app.* modules resolve cleanly
_BACKEND_DIR = Path(__file__).resolve().parent / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.main import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
