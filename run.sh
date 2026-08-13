#!/usr/bin/env bash
#
# SentinelAI — start the whole project with one command.
#
#   ./run.sh            start backend + dashboard + test page
#   ./run.sh --seed     wipe and rewrite the 21 days of demo history first
#   ./run.sh --setup    create the venv and install everything, then start
#   ./run.sh --stop     stop anything already running on 8000 / 5173 / 8080
#   ./run.sh --no-open  do not launch a browser (for headless / CI use)
#
# Ctrl+C stops all three. If anything is ever left behind, `./run.sh --stop` is
# the guaranteed cleanup — see the note on stop_ports below for why that is not
# just belt-and-braces on Windows.
#
# Every service logs to .logs/ so a crash in one does not scroll away under the
# other two.
#
# Written for Git Bash on Windows and for macOS/Linux. The only difference that
# matters is where the venv puts python, which is resolved below rather than
# assumed.

set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
LOGS="$ROOT/.logs"
mkdir -p "$LOGS"

# --- Resolve the venv interpreter -------------------------------------------
# Windows venvs use Scripts/python.exe, POSIX ones bin/python. Picking the
# wrong one is the single most common "it works for me" failure, so check.
if [ -x "$ROOT/backend/.venv/Scripts/python.exe" ]; then
  PY="$ROOT/backend/.venv/Scripts/python.exe"
elif [ -x "$ROOT/backend/.venv/bin/python" ]; then
  PY="$ROOT/backend/.venv/bin/python"
else
  PY=""
fi

PORTS="8000 5173 8080"

# --- Stop whatever is on our ports ------------------------------------------
# Killing by PID alone is not enough. `uvicorn --reload` and `npm run dev` both
# fork, so the process this script launched is a wrapper whose real server is a
# grandchild in a different process tree. If the wrapper is killed abruptly the
# trap below never runs and the grandchild keeps the port bound — which then
# surfaces as the baffling "backend did not answer" on the *next* run, because
# the stale server is still there answering with old code.
#
# So shutdown is defined by the thing we actually care about: the port. Find
# whoever holds it and terminate that tree. Idempotent, and safe to run when
# nothing is up.
#
# This is also why startup calls stop_ports before binding. Git Bash emulates
# POSIX signals over Win32 and the emulation is not reliable for a
# non-interactive background bash: measured on this repo, `timeout` delivering
# TERM ran the trap, while `kill -TERM` on the same script ran nothing at all
# and left all three ports held. Interactive Ctrl+C is the well-behaved case,
# because SIGINT goes to every member of the foreground process group, so the
# servers die of their own accord whether or not the trap fires. Rather than
# depend on which case you are in, the next run just clears the ports first —
# a leftover server can therefore never break a subsequent start.
stop_ports() {
  local found=0 port pid
  for port in $PORTS; do
    for pid in $(netstat -ano 2>/dev/null \
                 | awk -v p=":$port" '$0 ~ /LISTENING/ && $2 ~ p"$" {print $NF}' \
                 | sort -u); do
      [ -z "$pid" ] && continue
      [ "$pid" = "0" ] && continue
      found=1
      if command -v taskkill >/dev/null 2>&1; then
        MSYS_NO_PATHCONV=1 taskkill -PID "$pid" -T -F >/dev/null 2>&1
      else
        kill -9 "$pid" >/dev/null 2>&1
      fi
      echo "    stopped pid $pid (port $port)"
    done
  done
  # POSIX hosts have no netstat -ano; fall back to lsof there.
  if [ "$found" = "0" ] && command -v lsof >/dev/null 2>&1; then
    for port in $PORTS; do
      for pid in $(lsof -ti ":$port" -sTCP:LISTEN 2>/dev/null); do
        found=1; kill -9 "$pid" 2>/dev/null; echo "    stopped pid $pid (port $port)"
      done
    done
  fi
  [ "$found" = "0" ] && echo "    nothing was running on $PORTS"
  return 0
}

# --- Browser launch ---------------------------------------------------------
# Terminals do not reliably make URLs clickable, and telling someone to
# copy-paste three of them is friction for no reason. So open them.
#
# Chrome is invoked by path rather than through the OS "open" handler for one
# specific reason: `chrome://extensions` has no registered protocol handler, so
# `start chrome://extensions` fails. Only the binary itself can navigate there
# — and that page is exactly where the one manual step lives.
CHROME=""
for candidate in \
  "/c/Program Files/Google/Chrome/Application/chrome.exe" \
  "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" \
  "${LOCALAPPDATA:-}/Google/Chrome/Application/chrome.exe" \
  "/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
  "/c/Program Files/Microsoft/Edge/Application/msedge.exe"
do
  [ -n "$candidate" ] && [ -x "$candidate" ] && { CHROME="$candidate"; break; }
done

open_url() {
  local url="$1"
  if [ -n "$CHROME" ]; then
    MSYS_NO_PATHCONV=1 "$CHROME" "$url" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then          # macOS
    open "$url" >/dev/null 2>&1
  elif command -v xdg-open >/dev/null 2>&1; then      # Linux
    xdg-open "$url" >/dev/null 2>&1
  elif command -v cmd >/dev/null 2>&1; then           # Windows, no Chrome found
    MSYS_NO_PATHCONV=1 cmd //c start "" "$url" >/dev/null 2>&1
  else
    return 1
  fi
  return 0
}

SEED=0
SETUP=0
OPEN=1
for arg in "$@"; do
  case "$arg" in
    --seed)    SEED=1 ;;
    --setup)   SETUP=1 ;;
    --no-open) OPEN=0 ;;
    --stop)  echo "==> Stopping SentinelAI"; stop_ports; echo "==> Done."; trap - EXIT; exit 0 ;;
    -h|--help) sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

# --- One-time setup ---------------------------------------------------------
if [ "$SETUP" = "1" ] || [ -z "$PY" ]; then
  if [ -z "$PY" ]; then
    echo "==> No virtualenv found. Creating backend/.venv"
    python -m venv backend/.venv || { echo "python not on PATH — install Python 3.11+"; exit 1; }
    if [ -x "$ROOT/backend/.venv/Scripts/python.exe" ]; then
      PY="$ROOT/backend/.venv/Scripts/python.exe"
    else
      PY="$ROOT/backend/.venv/bin/python"
    fi
  fi
  echo "==> Installing backend dependencies"
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install -r backend/requirements.txt
  echo "==> Installing dashboard dependencies"
  ( cd dashboard && npm install )
fi

# --- Config check -----------------------------------------------------------
# Both API keys are optional by design, so a missing .env is a warning and not
# an error. The app degrades in documented ways; see README "Running without
# API keys".
if [ ! -f backend/.env ]; then
  echo "==> backend/.env missing — copying from .env.example"
  cp backend/.env.example backend/.env
  echo "    Keys are optional. Without them: Gemini tier reports 'disabled',"
  echo "    Safe Browsing reports weight 'unknown'. Everything else runs."
fi

[ -d dashboard/node_modules ] || { echo "==> dashboard deps missing"; ( cd dashboard && npm install ); }

# --- Vendored asset check ---------------------------------------------------
# The extension ships third-party decoders (jsQR for Module 9, Tesseract for
# Module 12) as committed files, because MV3 forbids loading them from a CDN and
# because remote code in a security tool is indefensible. Committed files can be
# truncated by a bad clone or a partial LFS fetch, and a half-written decoder
# fails at the least convenient moment — mid-demo, as a right-click that does
# nothing.
#
# Severity is split on purpose. Under --setup the user asked us to prepare a
# working environment, so a bad asset is an error and the script stops. On an
# ordinary run it is a loud warning: the QR and OCR features are degraded but
# typing protection, site checks and the dashboard are entirely unaffected, and
# refusing to start those would be a worse trade than running without a decoder.
check_vendor_assets() {
  local dir="$ROOT/extension/lib/vendor"
  [ -f "$dir/CHECKSUMS.sha256" ] || return 0

  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "==> sha256sum not available — skipping vendored asset verification"
    return 0
  fi

  if ( cd "$dir" && sha256sum -c --status CHECKSUMS.sha256 ); then
    return 0
  fi

  echo ""
  echo "!!  Vendored extension assets are missing or do not match their checksums."
  ( cd "$dir" && sha256sum -c CHECKSUMS.sha256 2>&1 | grep -v ': OK$' | sed 's/^/    /' )
  echo ""
  echo "    Affected: QR code checking (Module 9) and screenshot OCR (Module 12),"
  echo "    in the extension AND in the dashboard's screenshot panel — the backend"
  echo "    serves these same files to it at /vendor."
  echo "    Everything else — typing protection, site checks, the score — is fine."
  echo "    Fix: re-fetch whichever file is listed above."
  echo "      V=extension/lib/vendor"
  echo "      curl -fsSL -o \$V/jsqr.js https://unpkg.com/jsqr@1.4.0/dist/jsQR.js"
  echo "      curl -fsSL -o \$V/tesseract/tesseract.min.js https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js"
  echo "      curl -fsSL -o \$V/tesseract/worker.min.js https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js"
  echo "      curl -fsSL -o \$V/tesseract/tesseract-core-simd.wasm.js https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.1/tesseract-core-simd.wasm.js"
  echo "      curl -fsSL -o \$V/tesseract/eng.traineddata https://github.com/tesseract-ocr/tessdata_fast/raw/4.1.0/eng.traineddata"
  echo "      ( cd \$V && sha256sum -c CHECKSUMS.sha256 )"
  echo ""
  return 1
}

if ! check_vendor_assets && [ "$SETUP" = "1" ]; then
  echo "==> Refusing to continue: --setup must leave a complete install."
  trap - EXIT
  exit 1
fi

# --- Seed -------------------------------------------------------------------
# The seed writes history relative to *now* and everything decays on a 7-day
# half-life, so re-seeding right before a demo is the difference between a
# breakdown that adds up and one that does not.
if [ "$SEED" = "1" ]; then
  echo "==> Re-seeding 21 days of demo history (--reset)"
  ( cd backend && "$PY" -m app.db.seed --reset )
elif [ ! -f backend/sentinel.db ]; then
  echo "==> No database yet — seeding 21 days of demo history"
  ( cd backend && "$PY" -m app.db.seed )
fi

# --- Start everything -------------------------------------------------------
STOPPED=0
cleanup() {
  [ "$STOPPED" = "1" ] && return 0   # trap can fire twice (INT then EXIT)
  STOPPED=1
  echo ""
  echo "==> Shutting down"
  stop_ports
  echo "==> All services stopped."
}
trap cleanup INT TERM EXIT

# Anything left over from a previous run holds the ports we are about to bind,
# so clear them before starting rather than failing three times in a row.
echo "==> Clearing ports $PORTS"
stop_ports
echo ""

echo "==> Starting backend      http://localhost:8000       (log: .logs/backend.log)"
( cd backend && exec "$PY" -m uvicorn app.main:app --reload --port 8000 ) \
  > "$LOGS/backend.log" 2>&1 &

# Vite binds IPv6 loopback, so this one answers on `localhost` and on [::1] but
# NOT on 127.0.0.1. Use localhost in the browser. Both spellings are already in
# the CORS allowlist, so either works once you reach it.
echo "==> Starting dashboard    http://localhost:5173       (log: .logs/dashboard.log)"
( cd dashboard && exec npm run dev ) > "$LOGS/dashboard.log" 2>&1 &

echo "==> Starting test page    http://localhost:8080/test/harness.html"
( cd extension && exec "$PY" -m http.server 8080 ) > "$LOGS/harness.log" 2>&1 &

# --- Wait for the backend to actually answer --------------------------------
# Printing URLs before the server is listening trains people to refresh a dead
# page and conclude the project is broken. So poll /health and report the truth.
echo ""
printf "==> Waiting for the backend to answer /health "
UP=0
for _ in $(seq 1 40); do
  if "$PY" - <<'PYEOF' 2>/dev/null
import urllib.request, sys
try:
    with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=1) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PYEOF
  then UP=1; break; fi
  printf "."
  sleep 0.5
done
echo ""

if [ "$UP" = "1" ]; then
  echo "    backend is up."
else
  echo "    backend did not answer in 20s — see .logs/backend.log"
  echo "    (most common cause: port 8000 already in use by an older run)"
fi

# --- Open the pages ---------------------------------------------------------
# Only worth doing if the backend answered — opening a dashboard that cannot
# reach its API just shows an error banner and teaches the wrong lesson.
#
# chrome://extensions is opened only the FIRST time, tracked by a marker file.
# The extension stays loaded across browser restarts, so re-opening that tab on
# every run would be nagging about a step already done.
EXT_MARKER="$LOGS/.extension-loaded-once"
OPENED=0
if [ "$OPEN" = "1" ] && [ "$UP" = "1" ]; then
  echo ""
  echo "==> Opening in your browser"
  if open_url "http://localhost:5173"; then
    OPENED=1
    echo "    dashboard"
    sleep 1
    open_url "http://localhost:8080/test/harness.html" && echo "    typing test page"
    if [ ! -f "$EXT_MARKER" ]; then
      sleep 1
      if [ -n "$CHROME" ] && open_url "chrome://extensions"; then
        echo "    chrome://extensions  <- load the extension here, once"
      fi
      : > "$EXT_MARKER"
    fi
  else
    echo "    could not find a browser to launch — the links are below"
  fi
fi

cat <<'BANNER'

  ─────────────────────────────────────────────────────────────────
   SentinelAI is running.

   Dashboard      http://localhost:5173
   API docs       http://localhost:8000/docs
   Health         http://localhost:8000/health
   Typing test    http://localhost:8080/test/harness.html

   Extension — the one step that cannot be scripted, one time only:
     chrome://extensions  ->  turn on Developer mode  ->  Load unpacked
     ->  select the  extension/  folder in this project

   Try it: type  2345 6789 9014  into the typing test page.

   Ctrl+C stops all three.  If anything is left over:  ./run.sh --stop
  ─────────────────────────────────────────────────────────────────

BANNER

wait
