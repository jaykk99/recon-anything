"""Agent tools pack (MCP v2.2): write / terminal / browser / crazy tools.

Extends the MCP v2.1 agent tools (agent_scan/probe/fork/trace/watch,
PR #171) with the tools the main agent actually reaches for in chat:
writing fork PoCs and verdict reports, bounded terminal wrappers
(cast / forge / anvil / slither / mythril), browser reads (fetch /
search / explorer), and the "crazy" lane (fuzz / simulate /
time-travel / deploy-fork / multicall).

Rules baked in, same as v2.1:
- Fork-only for anything state-changing; live probes are read-only.
- Fork / sim / fuzz results are ALWAYS UNVERIFIED; only a
  live-probe-verified stranger drain is VERIFIED_REAL, and this
  module can never stamp that verdict (agent_write_report refuses it).
- No broadcast, no live funds, no private keys anywhere (cast send
  only against a localhost fork, and --private-key/--mnemonic are
  refused outright). Crypto.com and Binance are never targets
  (enforced by the callers that take a target address).
- Every tool validates its inputs and enforces a timeout; external
  binaries degrade to an honest "unavailable" status instead of
  crashing when they are not installed.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

STRANGER = "0x1111111111111111111111111111111111111111"
# Anvil's well-known account #0 key. Localhost forks ONLY; never used
# against a public RPC (agent_cast refuses sends anywhere else).
ANVIL_KEY = ("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784"
             "d7bf4f3ff80")
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
MAX_OUTPUT_CHARS = 8000
MAX_URL_BYTES = 200_000

SUPPORTED_CHAINS = ("ethereum", "bsc", "polygon", "arbitrum", "base",
                    "optimism")

BLOCKSCOUT_HOSTS = {
    "ethereum": "eth.blockscout.com",
    "bsc": "bsc.blockscout.com",
    "polygon": "polygon.blockscout.com",
    "arbitrum": "arbitrum.blockscout.com",
    "base": "base.blockscout.com",
    "optimism": "optimism.blockscout.com",
}

FETCH_ALLOWED_HOSTS = (
    "etherscan.io", "bscscan.com", "basescan.org", "polygonscan.com",
    "arbiscan.io", "optimistic.etherscan.io", "blockscout.com",
    "sourcify.dev", "dexscreener.com", "api.dexscreener.com",
    "raw.githubusercontent.com", "api.github.com", "github.com",
)

FORGE_STD_CANDIDATES = (
    "/var/tmp/agent-tools-pack/lib/forge-std",
)


class AgentToolError(Exception):
    """A tool-level failure: the MCP wrapper turns it into isError."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _truncate(text: Any, limit: int = MAX_OUTPUT_CHARS) -> str:
    s = "" if text is None else str(text)
    if len(s) > limit:
        return s[:limit] + f"\n... [truncated, {len(s)} chars total]"
    return s


def _run(cmd: List[str], timeout: float, cwd: Optional[str] = None,
         env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Bounded subprocess. Never raises on timeout/non-zero exit."""
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, env=env)
        return {"rc": proc.returncode,
                "stdout": _truncate(proc.stdout),
                "stderr": _truncate(proc.stderr),
                "timed_out": False,
                "elapsed_s": round(time.time() - started, 1)}
    except subprocess.TimeoutExpired as e:
        return {"rc": None,
                "stdout": _truncate(e.stdout or ""),
                "stderr": _truncate(e.stderr or ""),
                "timed_out": True,
                "elapsed_s": round(time.time() - started, 1)}
    except FileNotFoundError:
        return {"rc": None, "stdout": "", "stderr": "binary not found",
                "timed_out": False, "elapsed_s": 0.0,
                "missing_binary": cmd[0] if cmd else ""}
    except Exception as e:  # noqa: BLE001 - report, never crash
        return {"rc": None, "stdout": "",
                "stderr": f"{type(e).__name__}: {e}",
                "timed_out": False, "elapsed_s": 0.0}


def _find_binary(name: str) -> Optional[str]:
    """foundry lives in ~/workspace/tools/audit/bin; tool venvs in /tmp."""
    candidates = [
        os.path.expanduser(f"~/workspace/tools/audit/bin/{name}"),
        f"/var/tmp/tool-libs/slither-venv/bin/{name}",
        os.path.expanduser(
            "~/workspace/wt/tool-integrations/.venv-mythril/bin/"
            f"{name}"),
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which(name)


def _scratch(sub: str) -> Path:
    """Scratch lives in /tmp: home writes are quota-blocked and /tmp is
    the sanctioned scratch area. Callers get content back inline too,
    so a reboot wipe never loses the result itself."""
    base = Path(tempfile.gettempdir()) / "recon-agent-tools" / sub
    base.mkdir(parents=True, exist_ok=True)
    return base


def _validate_chain(chain: str):
    if not isinstance(chain, str) or not chain:
        raise AgentToolError("chain is required")
    from .plugins import contract_chain as cc
    key = str(chain).lower().strip()
    aliases = getattr(cc, "ALIASES", {}) or {}
    key = aliases.get(key, key)
    cfg = cc.CHAINS.get(key)
    if cfg is None:
        raise AgentToolError(
            f"unknown chain {chain}; known: "
            f"{', '.join(sorted(cc.CHAINS))}")
    return cfg


def _validate_address(address: str, field: str = "address") -> str:
    if not isinstance(address, str) or not re.fullmatch(
            r"0x[0-9a-fA-F]{40}", address or ""):
        raise AgentToolError(f"{field} must be 0x + 40 hex characters")
    return address


def _validate_url(url: str) -> str:
    from urllib.parse import urlparse
    if not isinstance(url, str) or not url.startswith("https://"):
        raise AgentToolError("url must start with https://")
    host = (urlparse(url).hostname or "").lower()
    if not any(host == h or host.endswith("." + h)
               for h in FETCH_ALLOWED_HOSTS):
        raise AgentToolError(
            f"host {host} is not on the fetch allowlist "
            f"(explorers, Sourcify, DexScreener, GitHub)")
    if "@" in (urlparse(url).netloc or ""):
        raise AgentToolError("credentials in the URL are not allowed")
    return url


def _auto_validate():
    """scripts/auto_validate.py, imported the way the runner does it."""
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import auto_validate as av  # noqa: E402
    return av


def _cast(args: List[str], timeout: float = 25):
    """cast via auto_validate (foundry binary resolution + timeout)."""
    av = _auto_validate()
    return av._cast([str(a) for a in args], timeout=timeout)


def _rpc_for_chain(chain: str) -> str:
    cfg = _validate_chain(chain)
    urls = list(getattr(cfg, "rpc_urls", []) or [])
    if not urls:
        raise AgentToolError(f"no RPC configured for chain {chain}")
    return urls[0]


def _fetch_sourcify(chain: str, address: str) -> Optional[Dict]:
    """Verified source from Sourcify over httpx (urllib reads truncate
    through the egress proxy; trust_env=False: proxy env vars on this
    host break httpx's env parsing)."""
    try:
        from .plugins import contract_chain as cc
        import httpx
        cfg = cc.CHAINS.get(chain)
        if cfg is None:
            return None
        url = ("https://sourcify.dev/server/files/any/"
               f"{cfg.chain_id}/{address}")
        with httpx.Client(trust_env=False, timeout=25) as client:
            r = client.get(url, headers={
                "User-Agent": "recon-agent-tools"})
        if r.status_code != 200:
            return None
        d = r.json()
        files = d.get("files") or []
        parts = [f["content"] for f in files
                 if f.get("name", "").endswith(".sol")
                 and f.get("content")]
        if not parts:
            return None
        name = ""
        for f in files:
            if f.get("name") == "metadata.json":
                try:
                    meta = json.loads(f["content"])
                    targets = ((meta.get("settings") or {})
                               .get("compilationTarget") or {})
                    if targets:
                        name = str(next(iter(targets.values())))
                except Exception:  # noqa: BLE001
                    pass
        return {"source": "\n".join(parts),
                "contract_name": name, "origin": "Sourcify"}
    except Exception:  # noqa: BLE001
        return None


def _source_for(chain: str, address: str,
                inline_source: Optional[str] = None) -> Dict:
    """Inline source wins; otherwise verified source from Sourcify."""
    if inline_source:
        if len(inline_source) > 200_000:
            raise AgentToolError("source is too large (200KB cap)")
        return {"source": inline_source, "contract_name": "",
                "origin": "inline"}
    _validate_chain(chain)
    _validate_address(address)
    av = _auto_validate()
    src = None
    cache_dirs = [d for d in
                  os.environ.get("RECON_SOURCE_CACHE_DIRS", "")
                  .split(",") if d]
    try:
        src = av.load_cached_source(cache_dirs, chain, address)
    except Exception:  # noqa: BLE001
        src = None
    if src is None:
        try:
            src = av.fetch_sourcify(chain, address)
        except Exception:  # noqa: BLE001
            src = None
    if src is None:
        src = _fetch_sourcify(chain, address)
    if not src or not src.get("source"):
        raise AgentToolError(
            "no verified source available for this address "
            "(pass inline source instead)")
    return src


def _encode_calldata(signature: str,
                     args: Optional[List[Any]] = None) -> str:
    """Minimal ABI encoder for the types a hypothesis needs:
    address / uint / int / bool / bytes32 / string. Raises on anything
    else instead of guessing."""
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\((.*)\)",
                     (signature or "").strip())
    if not m:
        raise AgentToolError(
            "function must be a signature like 'mint(address,uint256)'")
    name, params = m.group(1), m.group(2).strip()
    types = [t.strip() for t in params.split(",")] if params else []
    vals = [str(a) for a in (args or [])]
    if len(vals) != len(types):
        raise AgentToolError(
            f"{name} takes {len(types)} args, got {len(vals)}")
    sel = _cast(["sig", signature], timeout=15)[0]
    if not sel or not sel.strip().startswith("0x"):
        raise AgentToolError(f"could not compute selector for {signature}")
    head = b""
    tail = b""
    dynamic = any(t in ("string", "bytes") for t in types)
    head_size = 32 * len(types)
    for typ, val in zip(types, vals):
        if typ == "address":
            if not re.fullmatch(r"0x[0-9a-fA-F]{40}", val):
                raise AgentToolError(f"bad address arg: {val}")
            head += bytes.fromhex("00" * 12 + val[2:])
        elif typ.startswith("uint") or typ.startswith("int"):
            try:
                n = int(val, 0)
            except ValueError:
                raise AgentToolError(f"bad int arg: {val}")
            head += n.to_bytes(32, "big", signed=typ.startswith("int"))
        elif typ == "bool":
            if val.lower() not in ("true", "false", "1", "0"):
                raise AgentToolError(f"bad bool arg: {val}")
            head += (1 if val.lower() in ("true", "1") else 0).to_bytes(
                32, "big")
        elif typ == "bytes32":
            if not re.fullmatch(r"0x[0-9a-fA-F]{64}", val):
                raise AgentToolError(f"bad bytes32 arg: {val}")
            head += bytes.fromhex(val[2:])
        elif typ == "string":
            if dynamic:
                off = head_size + len(tail)
                head += off.to_bytes(32, "big")
                raw = val.encode()
                tail += len(raw).to_bytes(32, "big") + raw
                tail += b"\x00" * ((32 - len(raw) % 32) % 32)
            else:
                raise AgentToolError("string args need dynamic encoding")
        else:
            raise AgentToolError(f"unsupported arg type: {typ}")
    data = bytes.fromhex(sel.strip()[2:]) + head + tail
    return "0x" + data.hex()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def _anvil_fork(chain: str, fork_block: Optional[int] = None,
                timeout_s: float = 300):
    """Start an anvil fork on localhost, yield its RPC URL, stop it.
    Fork-only: nothing here ever touches a live chain."""
    anvil = _find_binary("anvil")
    if not anvil:
        raise AgentToolError(
            "anvil is not installed (foundry: "
            "~/workspace/tools/audit/bin)")
    rpc = _rpc_for_chain(chain)
    port = _free_port()
    cmd = [anvil, "--fork-url", rpc, "--port", str(port),
           "--host", "127.0.0.1"]
    if fork_block is not None:
        cmd += ["--fork-block-number", str(int(fork_block))]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 60
        ready = False
        while time.time() < deadline:
            out, _err = _cast(["block-number", "--rpc-url", url],
                              timeout=10)
            if out and out.strip().isdigit():
                ready = True
                break
            if proc.poll() is not None:
                break
            time.sleep(1)
        if not ready:
            raise AgentToolError("anvil fork did not come up in 60s")
        yield url
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass


def _token_balance(rpc_url: str, token: str, holder: str) -> Optional[int]:
    out, _err = _cast(["call", token, "balanceOf(address)(uint256)",
                       holder, "--rpc-url", rpc_url], timeout=20)
    if not out:
        return None
    try:
        return int(out.strip().splitlines()[0], 0)
    except Exception:  # noqa: BLE001
        return None


def _native_balance(rpc_url: str, holder: str) -> Optional[int]:
    out, _err = _cast(["balance", holder, "--rpc-url", rpc_url],
                      timeout=20)
    if not out:
        return None
    try:
        return int(out.strip().splitlines()[0], 0)
    except Exception:  # noqa: BLE001
        return None


def _find_forge_std() -> Optional[str]:
    """forge-std for scratch foundry projects. Reuse an existing copy
    before ever downloading one."""
    env = os.environ.get("RECON_FORGE_STD", "")
    if env and os.path.isdir(os.path.join(env, "src", "Test.sol")):
        return env
    for cand in FORGE_STD_CANDIDATES:
        if os.path.isdir(os.path.join(cand, "src", "Test.sol")):
            return cand
    for root in ("/var/tmp", os.path.expanduser("~/workspace")):
        for dirpath, dirnames, _filenames in os.walk(root):
            if "forge-std" in dirnames:
                p = os.path.join(dirpath, "forge-std")
                if os.path.isfile(os.path.join(p, "src", "Test.sol")):
                    return p
            # do not descend into giant trees
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", ".venv", "node_modules",
                                        "target", ".cache")]
            if dirpath.count(os.sep) - root.count(os.sep) > 4:
                dirnames[:] = []
    return None
PYEOF_AGENT_TOOLS

# ---------------------------------------------------------------------------
# WRITE tools
# ---------------------------------------------------------------------------

_POC_TEMPLATE = """// SPDX-License-Identifier: MIT
// Generated by agent_write_poc. Fork-only: runs against a local Anvil
// fork, never a live chain. A pass here is UNVERIFIED, never proof.
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract AgentPoc is Test {
    address constant TARGET = {target};
    address constant STRANGER = {stranger};

    function setUp() public {{
        vm.createSelectFork(vm.envString("AGENT_FORK_RPC"));
    }}

    function testAgentPoc() public {{
        uint256 nativeBefore = STRANGER.balance;
        uint256 tokenBefore = 0;
        {token_before}
        vm.prank(STRANGER);
        (bool ok, bytes memory ret) = TARGET.call{{value: {value_wei}}}(
            {calldata});
        emit log_named_string("CALL_OK", ok ? "true" : "false");
        emit log_named_uint("STRANGER_NATIVE_BEFORE", nativeBefore);
        emit log_named_uint("STRANGER_NATIVE_AFTER", STRANGER.balance);
        {token_after}
        emit log_named_bytes("RETURN_DATA", ret);
    }}
}
"""


def _poc_calldata(hypothesis: Dict[str, Any]) -> str:
    if hypothesis.get("calldata"):
        cd = str(hypothesis["calldata"])
        if not re.fullmatch(r"0x[0-9a-fA-F]+", cd):
            raise AgentToolError("calldata must be 0x hex")
        return cd
    return _encode_calldata(str(hypothesis.get("function", "")),
                            hypothesis.get("args") or [])


def write_poc(chain: str, address: str, hypothesis: Dict[str, Any],
              test_name: str = "AgentPoc",
              timeout_s: float = 300) -> Dict[str, Any]:
    """Write a Foundry fork test for a candidate + hypothesis, run it
    on the fork, return the test path + result. Fork only."""
    cfg = _validate_chain(chain)
    _validate_address(address)
    if not isinstance(hypothesis, dict) or not hypothesis.get("function"):
        raise AgentToolError(
            "hypothesis must be an object with function + args")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", test_name or ""):
        raise AgentToolError("test_name must be a plain identifier")
    value_wei = int(hypothesis.get("value_wei") or 0)
    tokens = hypothesis.get("tokens") or []
    if not isinstance(tokens, list) or len(tokens) > 5:
        raise AgentToolError("tokens must be a list of at most 5")
    for t in tokens:
        _validate_address(str(t), "token")
    calldata = _poc_calldata(hypothesis)
    token_before = ""
    token_after = ""
    for i, t in enumerate(tokens):
        token_before += (
            f"uint256 token{i}Before = IERC20({t}).balanceOf(STRANGER);"
            f"\n        emit log_named_uint(\"STRANGER_TOKEN{i}_BEFORE"
            f"\", token{i}Before);")
        token_after += (
            f"emit log_named_uint(\"STRANGER_TOKEN{i}_AFTER\", "
            f"IERC20({t}).balanceOf(STRANGER));")
    source = _POC_TEMPLATE.format(
        target=address, stranger=STRANGER,
        value_wei=value_wei, calldata=calldata,
        token_before=token_before, token_after=token_after)
    source = ("interface IERC20 { function balanceOf(address) external "
              "view returns (uint256); }\n\n" + source)
    slug = f"{chain}-{address[:10].lower()}"
    proj = _scratch(os.path.join("poc", slug))
    (proj / "test").mkdir(exist_ok=True)
    (proj / "src").mkdir(exist_ok=True)
    test_path = proj / "test" / f"{test_name}.t.sol"
    test_path.write_text(source)
    forge_std = _find_forge_std()
    foundry_toml = "[profile.default]\nsrc = 'src'\ntest = 'test'\n"
    if forge_std:
        foundry_toml += (f"remappings = ['forge-std/={forge_std}/']\n")
    (proj / "foundry.toml").write_text(foundry_toml)
    out: Dict[str, Any] = {
        "chain": chain, "address": address,
        "test_path": str(test_path), "test_source": source,
        "verdict": "UNVERIFIED",
        "note": ("fork-only PoC. A pass is UNVERIFIED, never proof; "
                 "only a live-probe-verified stranger drain is "
                 "VERIFIED_REAL.")}
    forge = _find_binary("forge")
    if not forge:
        out["status"] = "unavailable"
        out["detail"] = ("forge is not installed; the test was written "
                         "but not run")
        return out
    if not forge_std:
        out["status"] = "written_not_run"
        out["detail"] = ("forge-std was not found on this machine; run "
                         "'forge install foundry-rs/forge-std' in "
                         f"{proj} and re-run agent_write_poc")
        return out
    env = dict(os.environ)
    env["AGENT_FORK_RPC"] = _rpc_for_chain(chain)
    run = _run([forge, "test", "--match-contract", test_name, "-vv"],
               timeout=float(timeout_s or 300), cwd=str(proj), env=env)
    passed = run["rc"] == 0
    received = None
    m = re.search(r"STRANGER_NATIVE_AFTER:\s*(\d+)", run["stdout"])
    m0 = re.search(r"STRANGER_NATIVE_BEFORE:\s*(\d+)", run["stdout"])
    if m and m0:
        received = int(m.group(1)) - int(m0.group(1))
    out["status"] = "passed" if passed else "failed"
    out["forge"] = run
    out["stranger_received_native_wei"] = received
    return out


_REPORT_VERDICTS = ("UNVERIFIED", "FALSE_POSITIVE", "TRIGGER_ONLY",
                    "NO_CANDIDATE")


def write_report(chain: str, address: str,
                 scan: Optional[Dict] = None,
                 probe: Optional[Dict] = None,
                 fork: Optional[Dict] = None,
                 verdict: str = "UNVERIFIED",
                 title: Optional[str] = None,
                 path: Optional[str] = None) -> Dict[str, Any]:
    """Write a verdict report markdown for an address from scan /
    probe / fork results. This tool can NEVER stamp VERIFIED_REAL:
    only the validator path can, with a live probe + receipt."""
    _validate_chain(chain)
    _validate_address(address)
    if verdict not in _REPORT_VERDICTS:
        raise AgentToolError(
            "verdict must be one of "
            f"{', '.join(_REPORT_VERDICTS)}; VERIFIED_REAL can only "
            "come from the validator with a live probe + receipt")
    lines = [f"# {title or 'Recon verdict'}", "",
             f"- chain: {chain}", f"- address: `{address}`",
             f"- verdict: **{verdict}**", ""]
    if scan:
        by_sev = scan.get("by_severity") or {}
        lines += ["## Scan",
                  f"- findings: {scan.get('findings_count', '?')}",
                  f"- by severity: {json.dumps(by_sev)}",
                  f"- source: {scan.get('source_status', '?')}"]
        for f in (scan.get("findings") or [])[:20]:
            lines.append(
                f"- [{f.get('severity', '?')}] "
                f"`{f.get('plugin', '?')}` "
                f"{f.get('function', '')} "
                f"{(f.get('title') or f.get('detail') or '')[:120]}")
        lines.append("")
    if probe:
        lines += ["## Live probe (read-only)",
                  f"- signature: `{probe.get('signature', '?')}`",
                  f"- probe: {json.dumps(probe.get('probe', {}))[:500]}",
                  ""]
    if fork:
        lines += ["## Fork / simulation (UNVERIFIED by design)",
                  f"- {json.dumps(fork)[:800]}", ""]
    lines += ["## Verdict",
              f"**{verdict}**. Fork and simulation results are "
              "UNVERIFIED by design; only a live-probe-verified "
              "stranger drain counts as VERIFIED_REAL.",
              "",
              "## Reproduce",
              f"cast call {address} --rpc-url <{chain} rpc>",
              ""]
    markdown = "\n".join(lines)
    if path:
        p = Path(path)
        allowed = ("/var/tmp/", os.path.expanduser("~/workspace/"))
        if not str(p).startswith(allowed):
            raise AgentToolError(
                "report path must be under /var/tmp or ~/workspace")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(markdown)
        out_path = str(p)
    else:
        out_path = str(_scratch("reports") / f"{chain}-{address[:10]}.md")
        Path(out_path).write_text(markdown)
    return {"chain": chain, "address": address, "verdict": verdict,
            "path": out_path, "markdown": markdown}


# ---------------------------------------------------------------------------
# TERMINAL tools
# ---------------------------------------------------------------------------

_CAST_READONLY = {
    "call", "balance", "code", "storage", "nonce", "block-number",
    "block", "tx", "receipt", "chain-id", "gas-price", "keccak",
    "to-wei", "from-wei", "abi-encode", "abi-decode", "sig",
    "selector", "4byte", "4byte-decode", "logs", "estimate",
    "trace", "age", "creation-code", "interface", "source",
}
_CAST_SECRET_FLAGS = ("--private-key", "--mnemonic", "--keystore",
                      "--ledger", "--trezor", "--aws", "--account")


def cast_tool(args: List[str], rpc_url: Optional[str] = None,
              timeout_s: float = 30) -> Dict[str, Any]:
    """Bounded cast wrapper. Read-only calls anywhere; `send` only
    against a localhost fork. Private keys are refused outright."""
    if not isinstance(args, list) or not args or not all(
            isinstance(a, str) for a in args):
        raise AgentToolError("args must be a non-empty list of strings")
    if len(args) > 20:
        raise AgentToolError("too many args (20 max)")
    sub = args[0]
    joined = " ".join(args)
    if any(flag in joined for flag in _CAST_SECRET_FLAGS):
        raise AgentToolError(
            "private-key / mnemonic / keystore / hardware flags are "
            "refused: this tool never signs with a real key")
    if sub == "send":
        host = ""
        if rpc_url:
            from urllib.parse import urlparse
            host = (urlparse(rpc_url).hostname or "").lower()
        if host not in ("localhost", "127.0.0.1"):
            raise AgentToolError(
                "cast send is fork-only: rpc_url must be a localhost "
                "anvil fork, never a public RPC")
    elif sub not in _CAST_READONLY:
        raise AgentToolError(
            f"cast subcommand '{sub}' is not on the read-only allowlist")
    cast = _find_binary("cast")
    if not cast:
        return {"status": "unavailable",
                "detail": "cast is not installed (foundry)"}
    cmd = [cast] + [str(a) for a in args]
    if rpc_url:
        cmd += ["--rpc-url", rpc_url]
    run = _run(cmd, timeout=float(timeout_s or 30))
    return {"status": "ok" if run["rc"] == 0 else "failed",
            "stdout": run["stdout"], "stderr": run["stderr"],
            "rc": run["rc"], "timed_out": run["timed_out"]}


def forge_tool(action: str, tree: str,
               match_test: Optional[str] = None,
               timeout_s: float = 300) -> Dict[str, Any]:
    """forge build / forge test on a given tree. The tree must live
    under /var/tmp or ~/workspace."""
    if action not in ("build", "test"):
        raise AgentToolError("action must be 'build' or 'test'")
    p = Path(tree)
    if not p.is_dir():
        raise AgentToolError(f"tree does not exist: {tree}")
    allowed = ("/var/tmp/", os.path.expanduser("~/workspace/"))
    if not str(p).startswith(allowed):
        raise AgentToolError(
            "tree must be under /var/tmp or ~/workspace")
    if not ((p / "foundry.toml").exists()
            or (p / "remappings.txt").exists()
            or (p / "src").is_dir()):
        raise AgentToolError("not a foundry tree (no foundry.toml, "
                             "remappings.txt or src/)")
    forge = _find_binary("forge")
    if not forge:
        return {"status": "unavailable",
                "detail": "forge is not installed (foundry)"}
    cmd = [forge, action]
    if action == "test" and match_test:
        cmd += ["--match-test", str(match_test)]
    run = _run(cmd, timeout=float(timeout_s or 300), cwd=str(p))
    summary = None
    m = re.search(r"(\d+) passed.*?(\d+) failed",
                  run["stdout"] + run["stderr"])
    if m:
        summary = {"passed": int(m.group(1)), "failed": int(m.group(2))}
    return {"status": "ok" if run["rc"] == 0 else "failed",
            "action": action, "tree": str(p), "summary": summary,
            "stdout": run["stdout"], "stderr": run["stderr"],
            "rc": run["rc"], "timed_out": run["timed_out"]}


def anvil_tool(chain: str, address: str, hypothesis: Dict[str, Any],
               fork_block: Optional[int] = None,
               timeout_s: float = 300) -> Dict[str, Any]:
    """Start an anvil fork at a block, run one scripted attack as the
    unfunded stranger, stop it, report what the stranger received.
    Fork only; verdict always UNVERIFIED."""
    _validate_chain(chain)
    _validate_address(address)
    if not isinstance(hypothesis, dict) or not hypothesis.get("function"):
        raise AgentToolError(
            "hypothesis must be an object with function + args")
    value_wei = int(hypothesis.get("value_wei") or 0)
    tokens = hypothesis.get("tokens") or []
    for t in tokens:
        _validate_address(str(t), "token")
    calldata = _poc_calldata(hypothesis)
    cast = _find_binary("cast")
    if not cast:
        return {"status": "unavailable",
                "detail": "cast is not installed (foundry)"}
    with _anvil_fork(chain, fork_block, timeout_s=float(timeout_s or 300)
                     ) as url:
        native_before = _native_balance(url, STRANGER)
        tok_before = {t: _token_balance(url, t, STRANGER)
                      for t in tokens}
        cmd = [cast, "send", address, "--rpc-url", url,
               "--from", STRANGER, "--unlocked"]
        if value_wei:
            cmd += ["--value", str(value_wei)]
        cmd += [calldata]
        run = _run(cmd, timeout=60)
        native_after = _native_balance(url, STRANGER)
        tok_after = {t: _token_balance(url, t, STRANGER)
                     for t in tokens}
    received_tokens = {}
    for t in tokens:
        if tok_before.get(t) is not None and tok_after.get(t) is not None:
            received_tokens[t] = tok_after[t] - tok_before[t]
    return {
        "chain": chain, "address": address,
        "fork_block": fork_block, "status": "ok",
        "call": {"rc": run["rc"], "stdout": run["stdout"],
                 "stderr": run["stderr"], "timed_out": run["timed_out"]},
        "stranger_received_native_wei": (
            None if native_before is None or native_after is None
            else native_after - native_before),
        "stranger_received_tokens": received_tokens,
        "verdict": "UNVERIFIED",
        "note": ("fork-only run. A payout here is UNVERIFIED, never "
                 "proof; only a live-probe-verified stranger drain is "
                 "VERIFIED_REAL.")}


def _slither_binary() -> Optional[str]:
    return _find_binary("slither")


def slither_tool(chain: Optional[str] = None,
                 address: Optional[str] = None,
                 source: Optional[str] = None,
                 timeout_s: float = 180) -> Dict[str, Any]:
    """Run Slither on verified source (chain+address) or inline source.
    Returns Slither detectors. Degrades honestly when Slither/solc
    is not installed."""
    src = _source_for(chain or "", address or "",
                      inline_source=source) if (source or address) \
        else None
    if src is None:
        raise AgentToolError("pass inline source or chain + address")
    slither = _slither_binary()
    if not slither:
        return {"status": "unavailable",
                "detail": ("slither is not installed; "
                           "pip install slither-analyzer")}
    slug = (src.get("contract_name") or "Contract") or "Contract"
    slug = re.sub(r"[^A-Za-z0-9_]", "_", slug)[:40] or "Contract"
    work = _scratch("slither")
    sol_path = work / f"{slug}.sol"
    sol_path.write_text(src["source"])
    out_json = work / f"{slug}.slither.json"
    run = _run([slither, str(sol_path), "--json", str(out_json)],
               timeout=float(timeout_s or 180), cwd=str(work))
    detectors: List[Dict[str, Any]] = []
    if out_json.exists():
        try:
            data = json.loads(out_json.read_text())
            for d in data.get("results", {}).get("detectors", []):
                detectors.append({
                    "check": d.get("check"),
                    "impact": d.get("impact"),
                    "confidence": d.get("confidence"),
                    "description": (d.get("description") or "")[:400],
                    "elements": [
                        (e.get("source_mapping") or {}).get("filename")
                        for e in (d.get("elements") or [])][:3]})
        except Exception as e:  # noqa: BLE001
            return {"status": "failed",
                    "detail": f"could not parse slither output: {e}",
                    "stdout": run["stdout"], "stderr": run["stderr"]}
    by_impact: Dict[str, int] = {}
    for d in detectors:
        by_impact[d.get("impact", "?")] = \
            by_impact.get(d.get("impact", "?"), 0) + 1
    return {"status": "ok" if run["rc"] == 0 else "failed",
            "contract": slug, "origin": src.get("origin", ""),
            "detectors": detectors, "count": len(detectors),
            "by_impact": by_impact,
            "stdout": run["stdout"], "stderr": run["stderr"]}


def _mythril_binary() -> Optional[str]:
    return _find_binary("myth")


def mythril_tool(chain: Optional[str] = None,
                 address: Optional[str] = None,
                 source: Optional[str] = None,
                 timeout_s: float = 300) -> Dict[str, Any]:
    """Run Mythril symbolic analysis on verified source (chain+address)
    or inline source. Detection only; verdicts are static findings,
    never proof."""
    src = _source_for(chain or "", address or "",
                      inline_source=source) if (source or address) \
        else None
    if src is None:
        raise AgentToolError("pass inline source or chain + address")
    myth = _mythril_binary()
    if not myth:
        return {"status": "unavailable",
                "detail": ("mythril is not installed; it ships in the "
                           "tool-integrations salvage venv")}
    slug = (src.get("contract_name") or "Contract") or "Contract"
    slug = re.sub(r"[^A-Za-z0-9_]", "_", slug)[:40] or "Contract"
    work = _scratch("mythril")
    sol_path = work / f"{slug}.sol"
    sol_path.write_text(src["source"])
    run = _run([myth, "analyze", str(sol_path), "-o", "json"],
               timeout=float(timeout_s or 300), cwd=str(work))
    issues: List[Dict[str, Any]] = []
    try:
        data = json.loads(run["stdout"])
        for issue in data.get("issues", []):
            issues.append({
                "title": issue.get("title"),
                "swc_id": issue.get("swc-id"),
                "severity": issue.get("severity"),
                "description": (issue.get("description") or "")[:400]})
    except Exception:  # noqa: BLE001
        pass
    return {"status": "ok" if run["rc"] == 0 else "failed",
            "contract": slug, "origin": src.get("origin", ""),
            "issues": issues, "count": len(issues),
            "stdout": run["stdout"], "stderr": run["stderr"]}
PYEOF_AGENT_TOOLS

# ---------------------------------------------------------------------------
# BROWSER tools (read-only, keyless, allowlisted hosts)
# ---------------------------------------------------------------------------

def fetch_tool(url: str, timeout_s: float = 25) -> Dict[str, Any]:
    """Fetch one URL's text: explorers, Sourcify, DexScreener, GitHub
    raw. Allowlisted hosts only, https only, capped at 200KB."""
    _validate_url(url)
    try:
        import httpx
        with httpx.Client(trust_env=False, timeout=float(timeout_s or 25),
                          follow_redirects=True, max_redirects=3) as c:
            r = c.get(url, headers={"User-Agent": "recon-agent-tools"})
        text = r.text
        return {"url": url, "status": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "chars": len(text),
                "text": text[:MAX_URL_BYTES],
                "truncated": len(text) > MAX_URL_BYTES}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "status": None,
                "detail": f"fetch failed: {type(e).__name__}: {e}"}


def search_tool(query: str, limit: int = 5,
                timeout_s: float = 30) -> Dict[str, Any]:
    """Keyless web search (DuckDuckGo html endpoint) for a contract
    address, topic or error string. No API key, no sign-in."""
    if not isinstance(query, str) or not query.strip():
        raise AgentToolError("query is required")
    limit = max(1, min(int(limit or 5), 10))
    try:
        import httpx
        from html import unescape as _unescape
        with httpx.Client(trust_env=False, timeout=float(timeout_s or 30),
                          follow_redirects=True) as c:
            r = c.get("https://html.duckduckgo.com/html/",
                      params={"q": query},
                      headers={"User-Agent": "recon-agent-tools"})
        if r.status_code != 200:
            return {"query": query, "status": r.status_code,
                    "results": [],
                    "detail": "search endpoint did not answer 200"}
        html = r.text
        results = []
        for m in re.finditer(
                r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                html, re.S):
            href = _unescape(m.group(1))
            if href.startswith("/"):
                continue
            title = re.sub(r"<[^>]+>", "", _unescape(m.group(2))).strip()
            if title and href.startswith("http"):
                results.append({"title": title[:160], "url": href})
            if len(results) >= limit:
                break
        return {"query": query, "status": 200, "results": results,
                "source": "duckduckgo-html"}
    except Exception as e:  # noqa: BLE001
        return {"query": query, "status": None, "results": [],
                "detail": f"search failed: {type(e).__name__}: {e}"}


def explorer_tool(chain: str, address: str, what: str,
                  page: int = 0, page_size: int = 25) -> Dict[str, Any]:
    """Read-only explorer reads via the keyless Blockscout v2 API:
    transactions, token transfers, logs, holders, token info."""
    _validate_chain(chain)
    _validate_address(address)
    if what not in ("transactions", "token_transfers", "logs",
                    "holders", "token_info"):
        raise AgentToolError(
            "what must be transactions | token_transfers | logs | "
            "holders | token_info")
    page = max(0, int(page or 0))
    page_size = max(1, min(int(page_size or 25), 50))
    host = BLOCKSCOUT_HOSTS[chain]
    base = f"https://{host}/api/v2"
    if what == "holders":
        url = f"{base}/tokens/{address}/holders"
    elif what == "token_info":
        url = f"{base}/tokens/{address}"
    elif what == "logs":
        url = f"{base}/addresses/{address}/logs"
    elif what == "token_transfers":
        url = f"{base}/addresses/{address}/token-transfers"
    else:
        url = f"{base}/addresses/{address}/transactions"
    try:
        import httpx
        with httpx.Client(trust_env=False, timeout=30) as c:
            r = c.get(url, params={"page": page + 1,
                                   "page_size": page_size},
                      headers={"User-Agent": "recon-agent-tools"})
        if r.status_code != 200:
            return {"chain": chain, "address": address, "what": what,
                    "status": r.status_code, "items": [],
                    "detail": "explorer did not answer 200"}
        data = r.json()
        items = data.get("items") or []
        if isinstance(data, dict) and not items and what == "token_info":
            items = [data]
        return {"chain": chain, "address": address, "what": what,
                "status": 200, "items": items[:page_size],
                "next_page_params": data.get("next_page_params")}
    except Exception as e:  # noqa: BLE001
        return {"chain": chain, "address": address, "what": what,
                "status": None, "items": [],
                "detail": f"explorer read failed: {type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# CRAZY tools (fork / sim only; verdicts always UNVERIFIED)
# ---------------------------------------------------------------------------

_FUZZ_TEMPLATE = """// SPDX-License-Identifier: MIT
// Generated by agent_fuzz. Bounded invariant fuzz on a local Anvil
// fork. A broken invariant here is UNVERIFIED, never proof.
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IERC20Fuzz {
    function balanceOf(address) external view returns (uint256);
}

contract FuzzHandler is Test {
    address constant TARGET = {target};
    address constant STRANGER = {stranger};

    function fuzzCall(bytes memory data) public {
        // every fuzzed call comes FROM the stranger, so a target
        // that pays its caller can actually move the invariant
        vm.prank(STRANGER);
        (bool ok, ) = TARGET.call(data);
        ok; // reverts are discarded by the fuzzer, not failures
    }
}

contract AgentFuzz is Test {
    FuzzHandler handler;
    address constant TARGET = {target};
    address constant STRANGER = {stranger};
    uint256 constant TOKEN = {token};

    function setUp() public {
        vm.createSelectFork(vm.envString("AGENT_FORK_RPC"));
        handler = new FuzzHandler();
    }

    function invariant_noStrangerGain() public view {
        assert(STRANGER.balance == 0);
        if (TOKEN != address(0)) {
            assert(IERC20Fuzz(TOKEN).balanceOf(STRANGER) == 0);
        }
    }
}
"""


def fuzz_tool(chain: str, address: str,
              token: Optional[str] = None, runs: int = 64,
              timeout_s: float = 300) -> Dict[str, Any]:
    """Bounded invariant fuzz on a fork: random calldata against the
    target, invariant = the unfunded stranger never gains value.
    Verdict always UNVERIFIED."""
    _validate_chain(chain)
    _validate_address(address)
    if token:
        _validate_address(token, "token")
    runs = max(1, min(int(runs or 64), 256))
    forge = _find_binary("forge")
    if not forge:
        return {"status": "unavailable",
                "detail": "forge is not installed (foundry)",
                "verdict": "UNVERIFIED"}
    forge_std = _find_forge_std()
    if not forge_std:
        return {"status": "written_not_run",
                "detail": "forge-std was not found on this machine",
                "verdict": "UNVERIFIED"}
    slug = f"{chain}-{address[:10].lower()}"
    proj = _scratch(os.path.join("fuzz", slug))
    (proj / "test").mkdir(exist_ok=True)
    (proj / "src").mkdir(exist_ok=True)
    source = _FUZZ_TEMPLATE.format(
        target=address, stranger=STRANGER,
        token=token or "address(0)")
    (proj / "test" / "AgentFuzz.t.sol").write_text(source)
    (proj / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\n"
        f"remappings = ['forge-std/={forge_std}/']\n")
    env = dict(os.environ)
    env["AGENT_FORK_RPC"] = _rpc_for_chain(chain)
    run = _run([forge, "test", "--match-contract", "AgentFuzz",
                "--fuzz-runs", str(runs)],
               timeout=float(timeout_s or 300), cwd=str(proj), env=env)
    broken = ("invariant_noStrangerGain" in run["stdout"]
              and "failed" in run["stdout"].lower())
    m = re.search(r"runs:\s*(\d+)", run["stdout"])
    return {"status": "ok" if run["rc"] == 0 else "failed",
            "chain": chain, "address": address, "runs": runs,
            "calls": int(m.group(1)) if m else None,
            "invariant_broken": bool(broken),
            "stdout": run["stdout"], "stderr": run["stderr"],
            "verdict": "UNVERIFIED",
            "note": ("fuzz on a local fork only. A broken invariant "
                     "is UNVERIFIED, never proof.")}


def _deal_token(rpc_url: str, token: str, holder: str,
                amount: int) -> bool:
    """Fork-only ERC20 deal: find the balances mapping slot (0-3),
    set the holder's balance via anvil_setStorageAt, verify it.
    Works for standard ERC20 layouts; returns False otherwise."""
    cast = _find_binary("cast")
    if not cast:
        return False
    for slot in range(4):
        key_out, _e = _cast(["keccak", f"{holder}{slot:064x}"],
                            timeout=15)
        if not key_out:
            continue
        key = key_out.strip().splitlines()[0]
        val = f"0x{int(amount):064x}"
        _run([cast, "rpc", "anvil_setStorageAt", token, key, val,
              "--rpc-url", rpc_url], timeout=15)
        bal = _token_balance(rpc_url, token, holder)
        if bal == int(amount):
            return True
    return False


def simulate_tool(chain: str, address: str, steps: List[Dict],
                  fork_block: Optional[int] = None,
                  timeout_s: float = 300) -> Dict[str, Any]:
    """Multi-step simulation on a fork (incl. flash-loan-shaped steps,
    funded on the fork only and labeled simulated). Verdict always
    UNVERIFIED, sim-only."""
    _validate_chain(chain)
    _validate_address(address)
    if not isinstance(steps, list) or not steps or len(steps) > 10:
        raise AgentToolError("steps must be a list of 1-10 steps")
    cast = _find_binary("cast")
    if not cast:
        return {"status": "unavailable",
                "detail": "cast is not installed (foundry)",
                "verdict": "UNVERIFIED"}
    tokens = set()
    for s in steps:
        if not isinstance(s, dict) or not s.get("function"):
            if not (isinstance(s, dict) and s.get("flashloan")):
                raise AgentToolError(
                    "each step needs function + args, or a flashloan")
        for t in (s.get("tokens") or []):
            _validate_address(str(t), "token")
            tokens.add(str(t))
    with _anvil_fork(chain, fork_block, timeout_s=float(timeout_s or 300)
                     ) as url:
        native_before = _native_balance(url, STRANGER)
        tok_before = {t: _token_balance(url, t, STRANGER)
                      for t in tokens}
        results = []
        for i, step in enumerate(steps):
            if step.get("flashloan"):
                fl = step["flashloan"]
                tok = _validate_address(str(fl.get("token", "")),
                                        "flashloan token")
                amt = int(fl.get("amount") or 0)
                # Fork-only simulated funding: deal the token to the
                # stranger via anvil storage slots so the rest of the
                # sequence can run. This money exists only on the fork.
                ok = _deal_token(url, tok, STRANGER, amt)
                results.append({"step": i, "kind": "flashloan",
                                "token": tok, "amount": amt,
                                "simulated_funding": True,
                                "ok": bool(ok),
                                "note": ("fork-only deal; the loan is "
                                         "simulated, not real")})
                continue
            calldata = _poc_calldata(step)
            value_wei = int(step.get("value_wei") or 0)
            sender = step.get("from") or STRANGER
            _validate_address(str(sender), "from")
            cmd = [cast, "send", address, "--rpc-url", url,
                   "--from", str(sender), "--unlocked"]
            if value_wei:
                cmd += ["--value", str(value_wei)]
            cmd += [calldata]
            r = _run(cmd, timeout=60)
            results.append({"step": i, "kind": "call",
                            "function": step.get("function"),
                            "ok": r["rc"] == 0,
                            "stdout": r["stdout"],
                            "stderr": r["stderr"]})
        native_after = _native_balance(url, STRANGER)
        tok_after = {t: _token_balance(url, t, STRANGER)
                     for t in tokens}
    received_tokens = {}
    for t in tokens:
        if tok_before.get(t) is not None and tok_after.get(t) is not None:
            received_tokens[t] = tok_after[t] - tok_before[t]
    return {"chain": chain, "address": address,
            "fork_block": fork_block, "status": "ok",
            "steps": results,
            "stranger_received_native_wei": (
                None if native_before is None or native_after is None
                else native_after - native_before),
            "stranger_received_tokens": received_tokens,
            "verdict": "UNVERIFIED",
            "note": ("simulation only, on a local fork. Nothing here "
                     "is a live result and nothing is proof.")}


def time_travel_tool(chain: str, address: str, signature: str,
                     args: Optional[List[Any]] = None,
                     blocks: Optional[List[int]] = None,
                     timeout_s: float = 120) -> Dict[str, Any]:
    """Re-run one read-only probe at historical blocks to catch
    upgrade-window bugs (a probe whose answer changed across blocks).
    Read-only eth_call; archive gaps are reported, never faked."""
    _validate_chain(chain)
    _validate_address(address)
    if not isinstance(signature, str) or "(" not in signature:
        raise AgentToolError(
            "signature must be a call signature like 'owner()(address)'")
    if not blocks or not isinstance(blocks, list) or len(blocks) > 5:
        raise AgentToolError("blocks must be a list of 1-5 block numbers")
    rpc = _rpc_for_chain(chain)
    out, _err = _cast(["block-number", "--rpc-url", rpc], timeout=15)
    latest = int(out.strip().splitlines()[0]) if out and \
        out.strip().splitlines()[0].isdigit() else None
    results = []
    for b in blocks:
        b = int(b)
        if latest is not None and b >= latest:
            results.append({"block": b, "ok": False,
                            "detail": "block is not historical"})
            continue
        out, err = _cast(["call", address, signature]
                         + [str(a) for a in (args or [])]
                         + ["--rpc-url", rpc, "--block", str(b)],
                         timeout=float(timeout_s or 120))
        if out:
            results.append({"block": b, "ok": True,
                            "return": out.strip().splitlines()[0]
                            if out.strip() else ""})
        else:
            results.append({"block": b, "ok": False,
                            "detail": _truncate(err or "no data", 300)})
    answers = {r.get("return") for r in results if r.get("ok")}
    return {"chain": chain, "address": address,
            "signature": signature, "latest_block": latest,
            "results": results, "changed_across_blocks": len(answers) > 1,
            "note": ("read-only historical eth_call. A changed answer "
                     "across blocks is an upgrade-window signal, not "
                     "proof of anything by itself.")}


def deploy_fork_tool(chain: str, address: str, patched_source: str,
                     hypothesis: Dict[str, Any],
                     timeout_s: float = 300) -> Dict[str, Any]:
    """Deploy a patched contract to a local fork and diff its behavior
    vs the original under the same hypothesis. Fork only; verdict
    always UNVERIFIED."""
    _validate_chain(chain)
    _validate_address(address)
    if not isinstance(patched_source, str) or not patched_source.strip():
        raise AgentToolError("patched_source is required")
    if len(patched_source) > 200_000:
        raise AgentToolError("patched_source is too large (200KB cap)")
    if re.search(r"import\s+[\"']https?://", patched_source):
        raise AgentToolError("URL imports are not allowed in patches")
    m = re.search(r"contract\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:is|\{)",
                  patched_source)
    if not m:
        raise AgentToolError("patched_source must declare a contract")
    name = m.group(1)
    if not isinstance(hypothesis, dict) or not hypothesis.get("function"):
        raise AgentToolError(
            "hypothesis must be an object with function + args")
    forge = _find_binary("forge")
    cast = _find_binary("cast")
    if not forge or not cast:
        return {"status": "unavailable",
                "detail": "forge + cast are required (foundry)",
                "verdict": "UNVERIFIED"}
    calldata = _poc_calldata(hypothesis)
    value_wei = int(hypothesis.get("value_wei") or 0)
    slug = f"{chain}-{address[:10].lower()}"
    proj = _scratch(os.path.join("deploy-fork", slug))
    (proj / "src").mkdir(exist_ok=True)
    (proj / "test").mkdir(exist_ok=True)
    (proj / "src" / f"{name}.sol").write_text(patched_source)
    forge_std = _find_forge_std()
    toml = "[profile.default]\nsrc = 'src'\ntest = 'test'\n"
    if forge_std:
        toml += f"remappings = ['forge-std/={forge_std}/']\n"
    (proj / "foundry.toml").write_text(toml)
    build = _run([forge, "build"], timeout=180, cwd=str(proj))
    if build["rc"] != 0:
        return {"status": "build_failed", "contract": name,
                "stdout": build["stdout"], "stderr": build["stderr"],
                "verdict": "UNVERIFIED"}
    with _anvil_fork(chain, None, timeout_s=float(timeout_s or 300)) as url:
        dep = _run([forge, "create", "--rpc-url", url,
                    "--private-key", ANVIL_KEY, "--broadcast",
                    f"src/{name}.sol:{name}"],
                   timeout=120, cwd=str(proj))
        dm = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})",
                       dep["stdout"] + dep["stderr"])
        if not dm:
            return {"status": "deploy_failed", "contract": name,
                    "stdout": dep["stdout"], "stderr": dep["stderr"],
                    "verdict": "UNVERIFIED"}
        patched = dm.group(1)

        def _probe(target: str):
            # read-only probe of the hypothesis function as a call
            # (no state change): encode and call, report ok/return.
            call = _run([cast, "call", target, calldata,
                         "--rpc-url", url, "--from", STRANGER],
                        timeout=30)
            send = _run([cast, "send", target, "--rpc-url", url,
                         "--from", STRANGER, "--unlocked"]
                        + (["--value", str(value_wei)] if value_wei
                           else []) + [calldata], timeout=60)
            return {"call": {"ok": call["rc"] == 0,
                             "stdout": call["stdout"],
                             "stderr": call["stderr"]},
                    "send": {"ok": send["rc"] == 0,
                             "stdout": send["stdout"],
                             "stderr": send["stderr"]}}
        original = _probe(address)
        patched_res = _probe(patched)
    diff = []
    for key in ("call", "send"):
        if original[key]["ok"] != patched_res[key]["ok"]:
            diff.append(f"{key}: original ok={original[key]['ok']}, "
                        f"patched ok={patched_res[key]['ok']}")
    return {"chain": chain, "address": address,
            "patched_address": patched, "contract": name,
            "status": "ok", "original": original,
            "patched": patched_res, "behavior_diff": diff,
            "verdict": "UNVERIFIED",
            "note": ("fork-only behavior diff. A difference shows the "
                     "patch changes behavior; it is not proof the "
                     "original is exploitable.")}


def multicall_tool(chain: str, calls: List[Dict],
                   block: Optional[int] = None,
                   timeout_s: float = 60) -> Dict[str, Any]:
    """Batch read-only calls in one round trip via Multicall3
    (aggregate), falling back to sequential calls when Multicall3
    is unavailable. Read-only, never a transaction."""
    _validate_chain(chain)
    if not isinstance(calls, list) or not calls or len(calls) > 25:
        raise AgentToolError("calls must be a list of 1-25 calls")
    rpc = _rpc_for_chain(chain)
    encoded_calls = []
    for c in calls:
        if not isinstance(c, dict):
            raise AgentToolError("each call must be an object")
        addr = _validate_address(str(c.get("address", "")),
                                 "call address")
        sig = str(c.get("function", ""))
        if "(" not in sig:
            raise AgentToolError(
                "each call needs a function signature")
        cd = _encode_calldata(sig, c.get("args") or [])
        encoded_calls.append((addr, cd))
    via = "sequential"
    results: List[Dict[str, Any]] = []
    # Multicall3 aggregate((address,bytes)[]) -> (uint256,(bool,bytes)[])
    try:
        payload = _encode_multicall_aggregate(encoded_calls)
        cmd = ["call", MULTICALL3, "--rpc-url", rpc, payload]
        if block is not None:
            cmd += ["--block", str(int(block))]
        out, err = _cast(cmd, timeout=float(timeout_s or 60))
        if out and out.strip().startswith("0x"):
            decoded = _decode_multicall_result(out.strip())
            if decoded is not None:
                via = "multicall3"
                for (addr, sig), (ok, ret) in zip(
                        [(c.get("address"), c.get("function"))
                         for c in calls], decoded):
                    results.append({"address": addr, "function": sig,
                                    "ok": bool(ok), "return_data": ret,
                                    "decoded": _try_decode(ret)})
    except Exception:  # noqa: BLE001 - fall back to sequential
        results = []
    if via != "multicall3":
        for c in calls:
            out, err = _cast(
                ["call", str(c["address"]), str(c["function"])]
                + [str(a) for a in (c.get("args") or [])]
                + ["--rpc-url", rpc]
                + (["--block", str(int(block))] if block is not None
                   else []),
                timeout=float(timeout_s or 60))
            results.append({"address": c.get("address"),
                            "function": c.get("function"),
                            "ok": bool(out),
                            "return_data": (out.strip() if out else ""),
                            "decoded": _try_decode(out.strip())
                            if out else None})
    return {"chain": chain, "via": via, "calls": results}


def _encode_multicall_aggregate(
        calls: List[tuple]) -> str:
    """ABI-encode aggregate((address,bytes)[]) call data by hand:
    selector 0x252dba42 + offset + length + per-call (address, offset,
    len, bytes)."""
    sel = "252dba42"
    n = len(calls)
    head = (32).to_bytes(32, "big") + n.to_bytes(32, "big")
    # each tuple: address (32) + offset to bytes (32); bytes data after
    tuple_size = 64
    data_start = 32 + 32 * n  # offset base relative to array start... 
    # offsets are relative to the start of the array encoding's data
    # section (after offset+length words); compute per-call offsets.
    body = b""
    tail = b""
    for i, (addr, cd) in enumerate(calls):
        raw = bytes.fromhex(cd[2:])
        body += bytes.fromhex("00" * 12 + addr[2:])
        body += (64 * n - 64 * i + len(tail)).to_bytes(32, "big")
        tail += len(raw).to_bytes(32, "big") + raw
        tail += b"\x00" * ((32 - len(raw) % 32) % 32)
    data = bytes.fromhex(sel) + head + body + tail
    return "0x" + data.hex()


def _decode_multicall_result(hexstr: str):
    """Decode (uint256 blockNumber, (bool,bytes)[] results). Returns
    None when the shape does not parse."""
    try:
        raw = bytes.fromhex(hexstr[2:])
        if len(raw) < 96:
            return None
        # word0 = blockNumber, word1 = offset to results array
        arr_off = int.from_bytes(raw[32:64], "big")
        n = int.from_bytes(raw[arr_off:arr_off + 32], "big")
        out = []
        pos = arr_off + 32
        for _ in range(n):
            ok = int.from_bytes(raw[pos:pos + 32], "big") != 0
            off = int.from_bytes(raw[pos + 32:pos + 64], "big")
            base = pos + off
            ln = int.from_bytes(raw[base:base + 32], "big")
            data = raw[base + 32:base + 32 + ln]
            out.append((ok, "0x" + data.hex()))
            pos += 64
        return out
    except Exception:  # noqa: BLE001
        return None


def _try_decode(hexstr: Optional[str]):
    """Best-effort decode of a 32-byte return as uint / address /
    bool; longer returns get a utf-8 attempt. Never raises."""
    if not hexstr or not isinstance(hexstr, str):
        return None
    try:
        raw = bytes.fromhex(hexstr[2:] if hexstr.startswith("0x")
                            else hexstr)
    except Exception:  # noqa: BLE001
        return None
    if len(raw) == 32:
        n = int.from_bytes(raw, "big")
        if raw[:12] == b"\x00" * 12 and raw[12:] != b"\x00" * 20:
            return {"uint256": n,
                    "address": "0x" + raw[12:].hex(),
                    "bool": n != 0}
        return {"uint256": n, "bool": n != 0}
    try:
        return {"utf8": raw.decode("utf-8", errors="strict")[:200]}
    except Exception:  # noqa: BLE001
        return None
PYEOF_AGENT_TOOLS