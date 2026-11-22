#!/usr/bin/env bash
# tracefind launcher for Linux/macOS: creates a virtual env on first run, then starts the app.
set -e
cd "$(dirname "$0")/backend"
if [ ! -d .venv ]; then
  echo "Setting up tracefind for the first time..."
  python3 -m venv .venv
  . .venv/bin/activate
  pip install --upgrade pip >/dev/null
  pip install -r requirements.txt
else
  . .venv/bin/activate
fi
[ -f ../.env ] && cp ../.env .env
exec python -m tracefind serve "$@"
