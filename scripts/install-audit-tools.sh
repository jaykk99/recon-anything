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

# ------------------------------------------------------- Round 2 (Nov 3)
# Mythril promotion, Wake, Securify 2.0, Slitherin, node tools
# (Solhint / Surya / Scribble / SmartCheck), Foundry.

# Mythril: its own venv. setuptools<81 is REQUIRED - mythril imports
# pkg_resources at startup and crashes without it (proven live).
# The venv ships the `myth` binary; the adapter looks for both
# names (mythril / myth).
if python3 -m venv "$AUDIT_DIR/venv-mythril" 2>/dev/null; then
  V="$AUDIT_DIR/venv-mythril/bin"
  if "$V/pip" install --quiet --no-input "mythril==0.24.8" \
       "setuptools<81"; then
    ok "mythril $("$V/myth" version 2>/dev/null | head -1)"
  else
    fail "mythril" "pip install failed"
  fi
else
  fail "mythril" "could not create venv"
fi

# Slitherin (Pessimistic's extra Slither detectors) lives INSIDE the
# slither venv: its detectors auto-register via entry points, so
# every slither run includes them (hits are re-tagged tool=slitherin
# by the adapter). NOTE: a crashing pess detector can kill a whole
# slither run; the adapter retries core-only in that case.
if [ -x "$AUDIT_DIR/venv-slither/bin/pip" ]; then
  if "$AUDIT_DIR/venv-slither/bin/pip" install --quiet --no-input \
       slitherin; then
    ok "slitherin (pess-* detectors in the slither venv)"
  else
    fail "slitherin" "pip install failed"
  fi
fi

# Wake (Ackee's framework): own venv. Its solc downloads over urllib
# are unreliable on flaky egress, so pre-seed its compiler cache
# from the solc-select artifacts slither already fetched, plus the
# official list.json (curl). Versions must match _WAKE_SEEDED_SOLC
# in toolbox.py and the solc-select set installed above.
if python3 -m venv "$AUDIT_DIR/venv-wake" 2>/dev/null; then
  V="$AUDIT_DIR/venv-wake/bin"
  if "$V/pip" install --quiet --no-input eth-wake; then
    WAKE_CACHE="$HOME/.local/share/wake/compilers"
    mkdir -p "$WAKE_CACHE"
    curl -fsSL --max-time 120 -o "$WAKE_CACHE/solc.json" \
      "https://binaries.soliditylang.org/linux-amd64/list.json" \
      >/dev/null 2>&1 || true
    for ver in 0.8.26 0.8.20 0.7.6 0.6.12 0.5.17; do
      # solc-select stores artifacts under ~/.solc-select no matter
      # which venv's shim installed them
      art="$HOME/.solc-select/artifacts/solc-$ver/solc-$ver"
      if [ -f "$art" ]; then
        name="solc-linux-amd64-v$ver"
        mkdir -p "$WAKE_CACHE/$name"
        cp "$art" "$WAKE_CACHE/$name/$name" && chmod +x "$WAKE_CACHE/$name/$name"
      fi
    done
    ok "wake $("$V/wake" --version 2>/dev/null | head -1) + solc cache seeded"
  else
    fail "wake" "pip install failed"
  fi
else
  fail "wake" "could not create venv"
fi

# Securify 2.0: no PyPI distribution - install the eth-sri git
# release into its own venv. Two environment repairs are part of
# the install (both proven necessary on Python 3.12):
#  1. its vendored py-solc uses collections.Mapping (removed in
#     3.10); a small collections.abc shim is applied to the
#     installed copy.
#  2. it needs the `souffle` Datalog binary on PATH at RUNTIME
#     (apt install souffle where the mirror carries it); the
#     adapter's availability() reports securify unavailable
#     without it, honestly.
if python3 -m venv "$AUDIT_DIR/venv-securify" 2>/dev/null; then
  V="$AUDIT_DIR/venv-securify/bin"
  if "$V/pip" install --quiet --no-input requests && \
     "$V/pip" install --quiet --no-input \
       "git+https://github.com/eth-sri/securify2"; then
    SP="$AUDIT_DIR/venv-securify/lib/python3"*/site-packages/solc
    for f in $SP/utils/types.py $SP/utils/string.py $SP/compilation/compiler.py; do
      [ -f "$f" ] && sed -i \
        -e 's/collections\.Mapping/collections.abc.Mapping/g' \
        -e 's/collections\.Sequence/collections.abc.Sequence/g' \
        -e '1i import collections.abc' "$f"
    done
    ok "securify 2.0 (git) + py3.12 collections shim"
  else
    fail "securify" "git install failed"
  fi
else
  fail "securify" "could not create venv"
fi
if command -v souffle >/dev/null 2>&1; then
  ok "souffle $(souffle --version 2>/dev/null | head -1)"
else
  fail "souffle" "not on PATH - securify installed but cannot run (apt install souffle)"
fi

# Node audit tools. ONE npm invocation on purpose: parallel npm
# installs in the same directory prune each other's packages
# (proven live, repeatedly). eth-scribble and smartcheck are
# installed for operator use; neither has a toolbox adapter
# (Scribble only instruments annotated code; SmartCheck's
# jdeploy bootstrap never completes in this environment) - see
# the PR availability matrix.
mkdir -p "$AUDIT_DIR/node-tools"
if (cd "$AUDIT_DIR/node-tools" && \
    npm install --no-save --loglevel=error \
      solhint surya eth-scribble @smartdec/smartcheck \
      >/dev/null 2>&1); then
  ok "node tools: solhint, surya (adapters) + eth-scribble, smartcheck (operator-only)"
else
  fail "node-tools" "npm install failed"
fi

# Foundry (forge/cast/anvil/chisel) release binaries: installed as
# infrastructure (local chain / build tooling). No toolbox adapter
# claims forge output as detections - see the PR matrix.
if curl -fsSL --max-time 300 -o "$TMP/foundry.tar.gz" \
     "https://github.com/foundry-rs/foundry/releases/download/v1.4.4/foundry_v1.4.4_linux_amd64.tar.gz" && \
   tar -xzf "$TMP/foundry.tar.gz" -C "$TMP"; then
  for b in forge cast anvil chisel; do
    cp "$TMP/$b" "$BIN_DIR/$b" && chmod +x "$BIN_DIR/$b"
  done
  ok "foundry $("$BIN_DIR/forge" --version 2>/dev/null | head -1)"
else
  fail "foundry" "download/extract failed"
fi

echo
echo "Installed under: $AUDIT_DIR"
echo "The audit_toolbox plugin picks these up automatically (no keys,"
echo "no image changes). Heavy tools run only with RECON_HEAVY_LANE=1."
