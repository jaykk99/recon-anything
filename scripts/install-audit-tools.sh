#!/usr/bin/env bash
# Install the ReconAnything audit toolbox's external tools OUTSIDE the
# app image, under ${RECON_AUDIT_TOOLS_DIR:-~/workspace/tools/audit}.
#
# The deployed backend image stays slim and unchanged: the
# audit_toolbox plugin detects these binaries at runtime (audit dir
# first, then PATH) and skips silently when they are absent. This
# script is for VM-run analysis - the same context the 1000/1M
# contract sweeps execute in.
#
# Idempotent: re-running upgrades in place. Every step is
# best-effort with a clear FAIL line; one tool failing never blocks
# the others. Versions below are the ones the adapters were built
# and fixture-tested against (Nov 2026).
set -u

AUDIT_DIR="${RECON_AUDIT_TOOLS_DIR:-$HOME/workspace/tools/audit}"
BIN_DIR="$AUDIT_DIR/bin"
CACHE_DIR="$AUDIT_DIR/cache"
mkdir -p "$BIN_DIR" "$CACHE_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()   { echo "OK   $1"; }
fail() { echo "FAIL $1: $2"; }

# ---------------------------------------------------------------- Slither
# slither-analyzer + solc-select in their own venv; solc versions the
# adapters need; z3-solver pinned to 4.12.x because solc's SMTChecker
# dlopens exactly libz3.so.4.12 (the wheel ships it under z3/lib).
if python3 -m venv "$AUDIT_DIR/venv-slither" 2>/dev/null; then
  V="$AUDIT_DIR/venv-slither/bin"
  if "$V/pip" install --quiet --no-input slither-analyzer solc-select \
       "z3-solver==4.12.6.0" && \
     "$V/solc-select" install 0.8.26 0.8.20 0.7.6 0.6.12 0.5.17 \
       >/dev/null 2>&1 && \
     "$V/solc-select" use 0.8.26 >/dev/null 2>&1; then
    ok "slither $("$V/slither" --version 2>/dev/null) + solc-select + z3 4.12"
  else
    fail "slither" "pip/solc-select step failed"
  fi
else
  fail "slither" "could not create venv"
fi

# ---------------------------------------------------------------- Semgrep
# Own venv + the Solidity rule pack cached locally so scans do not
# depend on the semgrep registry at run time.
if python3 -m venv "$AUDIT_DIR/venv-semgrep" 2>/dev/null; then
  V="$AUDIT_DIR/venv-semgrep/bin"
  if "$V/pip" install --quiet --no-input semgrep; then
    ok "semgrep $("$V/semgrep" --version 2>/dev/null)"
  else
    fail "semgrep" "pip install failed"
  fi
else
  fail "semgrep" "could not create venv"
fi
if [ ! -d "$CACHE_DIR/semgrep-solidity/security" ]; then
  if git clone --depth 1 --filter=blob:none --sparse \
       https://github.com/semgrep/semgrep-rules "$TMP/semgrep-rules" \
       >/dev/null 2>&1 && \
     git -C "$TMP/semgrep-rules" sparse-checkout set solidity \
       >/dev/null 2>&1; then
    mkdir -p "$CACHE_DIR/semgrep-solidity"
    cp -r "$TMP/semgrep-rules/solidity/." "$CACHE_DIR/semgrep-solidity/"
    ok "semgrep solidity rules cached"
  else
    fail "semgrep-rules" "clone failed (adapter falls back to p/solidity)"
  fi
fi

# ---------------------------------------------------------------- Binaries
# Aderyn (Cyfrin static analyzer), Heimdall (bytecode disasm/CFG),
# Echidna + Medusa (property fuzzers, candidates-only lane).
dl() { # name url dest
  if curl -fsSL --max-time 300 -o "$TMP/$1.bin" "$2"; then
    cp "$TMP/$1.bin" "$3" && chmod +x "$3" && ok "$1"
  else
    fail "$1" "download failed: $2"
  fi
}

if curl -fsSL --max-time 300 -o "$TMP/aderyn.tar.xz" \
     "https://github.com/Cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-x86_64-unknown-linux-gnu.tar.xz" && \
   tar -xJf "$TMP/aderyn.tar.xz" -C "$TMP"; then
  cp "$TMP/aderyn-x86_64-unknown-linux-gnu/aderyn" "$BIN_DIR/aderyn" \
    && chmod +x "$BIN_DIR/aderyn" && ok "aderyn $("$BIN_DIR/aderyn" --version 2>/dev/null)"
else
  fail "aderyn" "download/extract failed"
fi

dl heimdall "https://github.com/Jon-Becker/heimdall-rs/releases/download/0.9.3/heimdall-linux-amd64" "$BIN_DIR/heimdall"

if curl -fsSL --max-time 300 -o "$TMP/echidna.tar.gz" \
     "https://github.com/crytic/echidna/releases/download/v2.3.3/echidna-2.3.3-x86_64-linux.tar.gz" && \
   tar -xzf "$TMP/echidna.tar.gz" -C "$TMP"; then
  cp "$TMP/echidna" "$BIN_DIR/echidna" && chmod +x "$BIN_DIR/echidna" \
    && ok "echidna $("$BIN_DIR/echidna" --version 2>/dev/null | head -1)"
else
  fail "echidna" "download/extract failed"
fi

if curl -fsSL --max-time 300 -o "$TMP/medusa.tar.gz" \
     "https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz" && \
   mkdir -p "$TMP/medusa-x" && tar -xzf "$TMP/medusa.tar.gz" -C "$TMP/medusa-x"; then
  cp "$TMP/medusa-x/medusa" "$BIN_DIR/medusa" && chmod +x "$BIN_DIR/medusa" \
    && ok "medusa $("$BIN_DIR/medusa" --version 2>/dev/null | head -1)"
else
  fail "medusa" "download/extract failed"
fi

# ------------------------------------------------------- Meta engines
# Amass + Nuclei + SpiderFoot for the meta_orchestrator plugin. Same
# rules as the toolbox above: installed OUTSIDE the app image, the
# plugin detects the binaries at runtime (audit bin dir first, then
# PATH) and skips silently when they are absent. Go installs are
# used for Amass/Nuclei (both are Go projects); if no Go toolchain
# is on PATH these two steps fail soft and the others still run.
export GOBIN="$BIN_DIR"
if command -v go >/dev/null 2>&1; then
  if go install github.com/owasp-amass/amass/v4/cmd/amass@latest \
       >/dev/null 2>&1 && [ -x "$BIN_DIR/amass" ]; then
    ok "amass ($("$BIN_DIR/amass" --version 2>/dev/null | head -1))"
  else
    fail "amass" "go install failed"
  fi
  if go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
       >/dev/null 2>&1 && [ -x "$BIN_DIR/nuclei" ]; then
    # Templates are Nuclei's data pack; fetch them once so the
    # first scan does not depend on the network.
    "$BIN_DIR/nuclei" -update-templates >/dev/null 2>&1 || true
    ok "nuclei ($("$BIN_DIR/nuclei" --version 2>&1 | head -1))"
  else
    fail "nuclei" "go install failed"
  fi
else
  fail "amass/nuclei" "no go toolchain on PATH (skipped, best-effort)"
fi

# SpiderFoot: source checkout + its own venv + a bin wrapper the
# adapter resolves as "spiderfoot".
if git clone --depth 1 https://github.com/smicallef/spiderfoot \
     "$AUDIT_DIR/spiderfoot" >/dev/null 2>&1 || \
   [ -f "$AUDIT_DIR/spiderfoot/sf.py" ]; then
  if python3 -m venv "$AUDIT_DIR/venv-spiderfoot" 2>/dev/null; then
    V="$AUDIT_DIR/venv-spiderfoot/bin"
    if "$V/pip" install --quiet --no-input \
         -r "$AUDIT_DIR/spiderfoot/requirements.txt"; then
      cat > "$BIN_DIR/spiderfoot" <<EOF
#!/usr/bin/env bash
exec "$V/python" "$AUDIT_DIR/spiderfoot/sf.py" "\$@"
EOF
      chmod +x "$BIN_DIR/spiderfoot"
      ok "spiderfoot (venv-spiderfoot)"
    else
      fail "spiderfoot" "pip install failed"
    fi
  else
    fail "spiderfoot" "could not create venv"
  fi
else
  fail "spiderfoot" "clone failed"
fi

echo
echo "Installed under: $AUDIT_DIR"
echo "The audit_toolbox and meta_orchestrator plugins pick these up"
echo "automatically (no keys, no image changes). Heavy tools run"
echo "only with RECON_HEAVY_LANE=1."
