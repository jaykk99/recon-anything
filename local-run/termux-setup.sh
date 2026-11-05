#!/data/data/com.termux/files/usr/bin/bash
# ReconAnything local setup for Termux on Android. Safe to re-run.
# The core app is pure Python + the Next.js server; heavy optional
# dependencies are installed best-effort and never block setup.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 1. Termux packages. nodejs is Node 20+ in current Termux repos.
#    clang/rust are only needed if pip has to build a wheel from source
#    (pydantic-core, cryptography); install them so those builds can work.
pkg update -y
pkg install -y python nodejs git curl openssl-tool dnsutils 2>/dev/null || \
  pkg install -y python nodejs git curl openssl
pkg install -y clang rust binutils 2>/dev/null || \
  echo "Note: clang/rust not installed; source builds may fail (see README)."

# termux-exec fixes shebang handling for venv scripts.
pkg install -y termux-exec 2>/dev/null || true

# 2. Backend venv.
python -m venv .venv
.venv/bin/pip install --upgrade pip

# 3. Core requirements first: these are what the app needs to boot.
.venv/bin/pip install \
  "fastapi==0.143.3" "uvicorn[standard]==0.54.0" "sqlalchemy==2.1.5" \
  "pydantic==2.14.1" "httpx==0.28.1" "dnspython==2.9.0" \
  "phonenumbers==9.0.15" "cryptography==50.0.2"

# 4. Optional integrations, best effort only. Each is imported lazily by
#    the app, so a failed install here never stops the app from running:
#    redis (cache), psycopg2 (Postgres), pymongo (archive), neo4j (graph),
#    bcrypt (hash candidate checks).
for extra in "redis==8.1.0" "psycopg2-binary==2.9.13" "pymongo==4.10.1" \
             "neo4j==5.28.1" "bcrypt==5.0.0"; do
  .venv/bin/pip install "$extra" || \
    echo "Optional package $extra failed to install; related feature stays off."
done

# 5. Local owner-mode env (.local-env + .local-access-code).
bash local-run/make-env.sh

# 6. Frontend: install + production build. This is the slow step on a
#    phone (several minutes); it only happens in setup, not per start.
cd frontend
npm install --no-audit --no-fund
npm run build
rm -rf .next/standalone/.next/static
cp -r .next/static .next/standalone/.next/static
cd "$ROOT"

echo
echo "Setup done. Start it with:"
echo "  bash local-run/termux-start.sh"
echo "Then open http://localhost:3000 in the phone browser and sign in"
echo "with the code in .local-access-code"
