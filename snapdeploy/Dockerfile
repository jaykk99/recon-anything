# All-in-one single container for SnapDeploy (or any single-container host).
# Builds the Next.js frontend and serves it on $PORT (default 3000) while
# the FastAPI backend runs on 127.0.0.1:8000. Next.js rewrites /api/* to
# the backend, so only one public port is needed. The scan worker
# (python -m app.worker_main) runs as a third process in the same
# container, so scans enqueued through the API actually execute here;
# without it, runs would sit queued forever on a one-container host.
# The worker's own health endpoint is bound to its own PORT (10000),
# never the public $PORT, so it cannot collide with the frontend.
FROM node:20-slim AS frontend-build
WORKDIR /build
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app

# node for the Next.js standalone server; dnsutils/curl/openssl/nc so
# the cmd_* command detectors (dig, curl, openssl s_client, nc) actually
# run in this image instead of skipping on missing tools.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs \
    dnsutils curl openssl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# backend
COPY backend/requirements.txt ./backend-req.txt
RUN pip install --no-cache-dir -r backend-req.txt
COPY backend/app ./app

# frontend (standalone output)
COPY --from=frontend-build /build/.next/standalone ./frontend
COPY --from=frontend-build /build/.next/static ./frontend/.next/static

ENV PYTHONUNBUFFERED=1 \
    PORT=3000 \
    RECON_API_URL=http://127.0.0.1:8000
# NOTE: DATABASE_URL is intentionally NOT set here. The backend defaults to
# sqlite:///./recon.db, which is ephemeral on Render's free tier (wiped on
# every redeploy). Set DATABASE_URL on the Render dashboard to a persistent
# Postgres (Neon/Supabase free tier) to keep scans across deploys.

EXPOSE 3000

# start backend on 8000, worker alongside it, frontend on $PORT.
# Backend and worker are backgrounded; the frontend stays in the
# foreground so the container lives as long as the frontend does.
# The worker runs in a restart loop (logs prefixed [worker]) so a
# worker crash or exit never silently stops scans: it comes back.
# PORT=10000 for the worker only: its health endpoint must not
# collide with the frontend on the public $PORT.
CMD sh -c '(while true; do PORT=10000 python -m app.worker_main 2>&1 | sed "s/^/[worker] /"; echo "[worker] exited, restarting in 5s"; sleep 5; done) & \
  uvicorn app.main:app --host 127.0.0.1 --port 8000 & \
  cd frontend && PORT=${PORT:-3000} HOSTNAME=0.0.0.0 node server.js'
