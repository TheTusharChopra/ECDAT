#!/bin/sh
set -e

echo "=== Starting ECDAT Unified Container ==="

# Start Python backend daemon on loopback port 8787
export PYTHONPATH=/app/backend
python3 -m ecdat.api --host 127.0.0.1 --port 8787 &
BACKEND_PID=$!

echo "Waiting for Python backend to initialize..."
TRIES=0
until curl -s http://127.0.0.1:8787/health > /dev/null 2>&1; do
  sleep 0.2
  TRIES=$((TRIES + 1))
  if [ $TRIES -gt 50 ]; then
    echo "Backend failed to start in 10 seconds!"
    exit 1
  fi
done

echo "Backend is ready! Preloading demo scan..."
curl -s -X POST http://127.0.0.1:8787/scan \
  -H "Content-Type: application/json" \
  -d '{"demo": true}' > /dev/null 2>&1 || true

echo "Demo scan preloaded successfully. Starting Next.js on port ${PORT:-3000}..."
cd /app/frontend
exec npx next start -p "${PORT:-3000}" -H 0.0.0.0
