# All-in-one single container for SnapDeploy (or any single-container host).
# Builds the Next.js frontend and serves it on $PORT (default 3000) while
# the FastAPI backend runs on 127.0.0.1:8000. Next.js rewrites /api/* to
# the backend, so only one public port is needed.
FROM node:20-slim AS frontend-build
WORKDIR /build
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app

# node for the Next.js standalone server
RUN apt-get update && apt-get install -y --no-install-recommends nodejs \
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

# start backend on 8000, frontend on $PORT
CMD sh -c 'uvicorn app.main:app --host 127.0.0.1 --port 8000 & \
  cd frontend && PORT=${PORT:-3000} HOSTNAME=0.0.0.0 node server.js'
