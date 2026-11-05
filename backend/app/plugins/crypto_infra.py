"""Crypto infrastructure attack-surface recon (live, read-only).

Why this exists (Jay's order, 2026-11-01): in crypto, theft usually
hits the infrastructure AROUND a protocol - an exposed node RPC with
the admin/personal namespaces on, a validator RPC port facing the
internet, a provider key shipped in client JS - not the contract
math. This module probes that surface. The Oct-23 crypto pack never
did: it is text-only.

Inventory of what already existed when this was written (checked
2026-11-01, registry ~640 plugins):

- cryptopack_web3.cp_web3_rpc_endpoints - inventories KNOWN provider
  hosts (Infura/Ankr/publicnode/...) appearing in served text.
  Content only: unknown/self-hosted endpoints are invisible to it,
  and nothing is ever contacted.
- cryptopack_secrets cp_apikey_infura / cp_apikey_alchemy /
  cp_apikey_quicknode, cryptopack_secrets2 cp_apikey_ankr - provider
  API keys leaked in served text. Content only.
- cryptopack_nodes.cp_node_rpc_creds - RPC URLs with userinfo
  credentials in served text. Content only.
- cryptopack_web3_gaps.cp_web3_rpc_misconfig / cp_web3_rpc_method_refs
  - insecure RPC URL shapes and dangerous method NAMES referenced in
  served text. Explicitly never probes the endpoint.
- cryptoconfig ("Crypto RPC Checker") - the only live prober: POSTs
  web3_clientVersion to 5 GUESSED hosts (domain, rpc., node., eth.,
  api.) x a fixed path list and flags ANY JSON-RPC answer as
  CRITICAL. No rpc_modules grading (an endpoint with only eth/net
  scores the same as one with admin+personal), no chain/version
  evidence, no CORS check, no Solana, no probing of endpoints the
  target actually references.
- port_audit - generic mega-sweep: 8545/8546/26657 carry static risk
  labels and banner grabs, but no JSON-RPC method probes, 8899 is
  mislabeled "Cam", and there is no Solana (8899/8900) or Cosmos
  REST (1317) protocol awareness.
- cors - thorough CORS tester, but only against the target's web
  base URL, never against an RPC endpoint.

What this module adds (the missing pieces, nothing duplicated):

1. crypto_infra_rpc - harvests EVERY RPC endpoint URL the target's
   pages/JS actually reference (any host, http/https/ws/wss), flags
   embedded provider keys and URL credentials in them, then grades
   each discovered/self-hosted endpoint with read-only calls only:
   web3_clientVersion, net_version, eth_chainId, rpc_modules (EVM)
   or getVersion/getHealth (Solana). Dangerous namespaces from
   rpc_modules (admin, debug, personal, miner, txpool, clique,
   engine) are graded findings with the full module list as
   evidence. A CORS probe (unrelated Origin on a read-only call)
   flags wildcard/reflected Access-Control-Allow-Origin on the RPC
   endpoint itself.
2. crypto_infra_ports - a bounded, crypto-specific port surface on
   the target host: 8545 (EVM RPC), 8546 (EVM WS), 8899 (Solana
   RPC), 8900 (Solana WS), 26657 (Tendermint/CometBFT RPC), 1317
   (Cosmos REST). Open ports get ONE protocol-correct read-only
   version/health probe each; closed/filtered ports stay silent.

Boundary (hard): detection only, read-only calls only. The only
JSON-RPC methods ever sent are web3_clientVersion, net_version,
eth_chainId, rpc_modules, getVersion, getHealth and (Tendermint)
GET /status. rpc_modules is a read-only listing - it invokes no
namespace. admin/personal/miner/txpool methods are NEVER called,
eth_accounts is never called, nothing is signed, sent, or unlocked.
Solana's requestAirdrop exposure cannot be verified read-only
(invoking it changes state), so it is deliberately not probed.
Findings show evidence in full: module lists, version strings, keys
found in URLs, and CORS headers are never masked.

Probe budget per target is bounded: at most MAX_PROBED_ENDPOINTS
harvested endpoints probed, 6 ports, short timeouts, so a scan
cannot hang on dead infrastructure.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import collect_texts
from .cryptopack_web3 import KNOWN_RPC_HOSTS

# ------------------------------------------------------------------
# Pure helpers (unit-tested without any network)
# ------------------------------------------------------------------

_URL_RE = re.compile(r"(?:https?|wss?)://[^\s\"'<>\)\]}]+")
_TRAILING_PUNCT = ".,;:!?"

# JSON-RPC namespaces that must never be reachable from the open
# internet, mapped to the grade their presence earns. admin/personal
# can manage accounts and the node itself (critical); miner controls
# block production on PoW/private chains; debug leaks traces and can
# be forced into expensive work; txpool exposes pending-tx content;
# clique/engine hand over consensus control on PoA/engine chains.
DANGEROUS_MODULES: Dict[str, str] = {
    "admin": "critical",
    "personal": "critical",
    "miner": "critical",
    "debug": "high",
    "txpool": "high",
    "clique": "high",
    "engine": "high",
}
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

RPC_PORTS = {8545, 8546, 8547, 8899, 8900, 26657, 1317, 9933, 9934,
             8332, 18332}
_PROVIDER_HOSTS = tuple(h.lower() for h in KNOWN_RPC_HOSTS) + (
    "infura.io", "alchemy.com", "alchemyapi.io", "quiknode.pro",
    "quicknode.pro", "quicknode.com", "ankr.com", "drpc.org",
    "helius.xyz", "helius-rpc.com", "blastapi.io", "nodereal.io",
    "chainstack.com", "getblock.io", "nownodes.io", "tatum.io",
    "moralis.io", "pokt.network", "llamarpc.com", "publicnode.com",
    "1rpc.io", "solana.com",
)

MAX_HARVESTED = 40
MAX_PROBED_ENDPOINTS = 8
PROBE_TIMEOUT = 6.0
PORT_TIMEOUT = 2.5
EVIL_ORIGIN = "https://unrelated-origin.example"


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _port_of(url: str) -> Optional[int]:
    try:
        return urlparse(url).port
    except Exception:
        return None


def is_provider_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) or h in host
               for h in _PROVIDER_HOSTS)


def looks_like_rpc_url(url: str, target_host: str = "") -> bool:
    """Is this URL plausibly a JSON-RPC endpoint (vs a web link)?"""
    try:
        p = urlparse(url)
    except Exception:
        return False
    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    port = None
    try:
        port = p.port
    except Exception:
        port = None
    if is_provider_host(host):
        return True
    if port in RPC_PORTS:
        return True
    if "rpc" in host:
        return True
    if "/rpc" in path or path.endswith("/v3") or "/ext/bc/c/rpc" in path:
        return True
    if "solana" in host or "solana" in path:
        return True
    th = (target_host or "").lower()
    if th and (host == th or host.endswith("." + th)):
        # A same-host URL is only treated as RPC when it also smells
        # like one; same-host alone would harvest the whole site.
        if "rpc" in path or "node" in host or "eth" in host:
            return True
    return False


_KEY_QUERY_PARAMS = ("api_key", "apikey", "key", "token", "auth",
                     "access_token", "project_id")


def extract_key_from_rpc_url(url: str) -> Optional[str]:
    """Return an embedded credential in an RPC URL, in full, or None.

    Covers: URL userinfo (user:pass@), provider key paths (Infura
    /v3/<id>, Alchemy /v2/<key>, QuickNode /<token>/, Ankr
    /<chain>/<token>), key-ish query parameters, and a generic long
    token path segment on an RPC-shaped URL. Placeholder values in
    docs (YOUR_KEY, "xxx", angle-bracket templates) are not keys.
    """
    try:
        p = urlparse(url)
    except Exception:
        return None
    # userinfo credentials
    if p.password:
        return f"{p.username}:{p.password}"
    if p.username and "@" in (p.netloc or ""):
        return p.username
    # query parameters
    try:
        qs = parse_qs(p.query or "")
    except Exception:
        qs = {}
    for name in _KEY_QUERY_PARAMS:
        for val in qs.get(name, []):
            if val and len(val) >= 8 and _plausible_key(val):
                return val
    segments = [s for s in (p.path or "").split("/") if s]
    # /v3/<project id>, /v2/<api key> (Infura / Alchemy shapes)
    for i, seg in enumerate(segments[:-1]):
        if seg.lower() in ("v2", "v3") and _plausible_key(segments[i + 1]):
            return segments[i + 1]
    # QuickNode / Ankr: trailing long token segment
    for seg in segments:
        if _plausible_key(seg) and len(seg) >= 32:
            return seg
    return None


def _plausible_key(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < 8:
        return False
    low = v.lower()
    if any(tok in low for tok in ("your", "example", "placeholder",
                                  "xxxx", "<", ">", "{", "}", "test")):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-\.]+", v))


def grade_modules(modules: List[str]) -> List[Tuple[str, str]]:
    """[(namespace, severity)] for each dangerous namespace enabled."""
    out: List[Tuple[str, str]] = []
    for raw in modules or []:
        ns = str(raw).strip().lower()
        if ns in DANGEROUS_MODULES:
            out.append((ns, DANGEROUS_MODULES[ns]))
    return out


def worst_severity(grades: List[Tuple[str, str]]) -> Optional[str]:
    if not grades:
        return None
    return max((sev for _, sev in grades), key=lambda s: _SEV_RANK[s])


def grade_cors(acao: Optional[str], acac: Optional[str],
               sent_origin: str) -> Optional[Tuple[str, str]]:
    """Grade an RPC endpoint's CORS answer to an unrelated origin.

    Returns (finding_key, severity) or None when the endpoint does
    not grant the unrelated origin anything.
    """
    if not acao:
        return None
    acao = acao.strip()
    creds = (acac or "").strip().lower() == "true"
    if acao == "*":
        # Any website can read this node's responses from a visitor's
        # browser. With credentials allowed it is worse (rare combo:
        # browsers reject * with credentials, flag it anyway).
        return ("rpc_cors_wildcard",
                "high" if creds else "medium")
    if acao == sent_origin:
        return ("rpc_cors_reflected",
                "high" if creds else "medium")
    return None


def parse_rpc_response(data: Any, req_id: int = 1) -> Any:
    """Pull the JSON-RPC `result` out of a decoded body (or None)."""
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("id") == req_id:
                return item.get("result")
        return None
    if isinstance(data, dict):
        return data.get("result")
    return None


class HarvestedEndpoint(Dict[str, Any]):
    """{url, host, self_hosted, provider, solana, key}"""


def harvest_endpoints(texts: List[Tuple[str, str, str]],
                      target_host: str) -> List[Dict[str, Any]]:
    """Extract the RPC endpoint URLs referenced in served content."""
    found: Dict[str, Dict[str, Any]] = {}
    th = (target_host or "").lower()
    for _where, text, _url in texts or []:
        if not text:
            continue
        for m in _URL_RE.finditer(text):
            url = m.group(0).rstrip(_TRAILING_PUNCT)
            if not looks_like_rpc_url(url, th):
                continue
            host = _host_of(url)
            low = url.lower()
            ep = {
                "url": url,
                "host": host,
                "self_hosted": bool(th and (host == th
                                            or host.endswith("." + th))),
                "provider": is_provider_host(host),
                "solana": ("solana" in low or _port_of(url) == 8899
                           or "helius" in host),
                "key": extract_key_from_rpc_url(url),
            }
            found[url] = ep
            if len(found) >= MAX_HARVESTED:
                return list(found.values())
    return list(found.values())


# ------------------------------------------------------------------
# Network plumbing (module-level so tests can patch it; read-only)
# ------------------------------------------------------------------

async def _rpc_call(ctx: Ctx, url: str, method: str,
                    params: Optional[list] = None,
                    origin: Optional[str] = None,
                    timeout: float = PROBE_TIMEOUT
                    ) -> Tuple[Optional[Any], Dict[str, str]]:
    """One read-only JSON-RPC call. Returns (result, headers).

    Never raises. Only ever invoked with the read-only method list
    documented at the top of this module.
    """
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    try:
        r = await fetch(ctx.http, ctx.limiter, "POST", url,
                        timeout=timeout, max_retries=0,
                        headers=headers,
                        json={"jsonrpc": "2.0", "id": 1,
                              "method": method, "params": params or []})
    except Exception:
        return None, {}
    hdrs = {str(k).lower(): str(v) for k, v in r.headers.items()}
    if r.status_code != 200:
        return None, hdrs
    try:
        data = r.json()
    except Exception:
        return None, hdrs
    return parse_rpc_response(data, 1), hdrs


async def _get_json(ctx: Ctx, url: str,
                    timeout: float = PROBE_TIMEOUT
                    ) -> Tuple[Optional[Any], int]:
    """One read-only GET expecting JSON. Returns (data, status)."""
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET", url,
                        timeout=timeout, max_retries=0)
    except Exception:
        return None, 0
    if r.status_code != 200:
        return None, r.status_code
    try:
        return r.json(), r.status_code
    except Exception:
        return None, r.status_code


async def _tcp_open(host: str, port: int,
                    timeout: float = PORT_TIMEOUT) -> bool:
    """Bounded TCP connect check. True only if the port accepts."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _http_variant(url: str) -> str:
    """ws:// -> http://, wss:// -> https:// for the probe calls."""
    if url.startswith("wss://"):
        return "https://" + url[len("wss://"):]
    if url.startswith("ws://"):
        return "http://" + url[len("ws://"):]
    return url


_REMEDIATION_RPC = (
    "Do not expose node RPC to the internet or to browsers that do "
    "not need it. Bind it to localhost or a private network, put an "
    "authenticated reverse proxy in front, and disable the admin, "
    "personal, miner, debug, txpool, clique and engine namespaces "
    "on any endpoint that stays reachable.")
_REMEDIATION_KEY = (
    "Treat this key as compromised: rotate it at the provider, "
    "restrict it by origin/IP where the provider allows, and move "
    "it server-side so it never ships in client code.")
_REMEDIATION_PORT = (
    "Firewall this port so only the project's own infrastructure "
    "can reach it. Node RPC ports facing the internet are scanned "
    "for constantly and are the entry point for most node theft.")


# ------------------------------------------------------------------
# Plugin 1: discovered-endpoint harvesting + grading
# ------------------------------------------------------------------

class CryptoInfraRpcPlugin(Plugin):
    id = "crypto_infra_rpc"
    label = "Crypto RPC endpoint grading"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web3"
    description = ("Harvests the RPC endpoints a crypto target's own "
                   "pages/JS reference, flags keys embedded in them, "
                   "and grades each endpoint read-only: client "
                   "version, chain, rpc_modules namespaces, CORS.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        texts = await collect_texts(ctx, target)
        endpoints = harvest_endpoints(texts, domain)
        findings: List[Finding] = []
        for ep in endpoints:
            ctx.publish("endpoints", ep["url"])
            if ep.get("key"):
                findings.append(self._f(
                    "leak", "rpc_url_embedded_key",
                    f"RPC endpoint URL with embedded key: {ep['url']} "
                    f"(key shown in full: {ep['key']})",
                    source=self.label, source_url=ep["url"],
                    confidence=90, passive=True,
                    evidence={"severity": "high",
                              "endpoint": ep["url"],
                              "key": ep["key"],
                              "provider": ep["provider"],
                              "remediation": _REMEDIATION_KEY}))
            elif ep["self_hosted"] and not ep["provider"]:
                findings.append(self._f(
                    "infra", "rpc_endpoint_self_hosted",
                    f"Self-hosted RPC endpoint referenced by the "
                    f"target's own content: {ep['url']}",
                    source=self.label, source_url=ep["url"],
                    confidence=75, passive=True,
                    evidence={"severity": "low",
                              "endpoint": ep["url"],
                              "host": ep["host"]}))

        mode = self.module_mode(ctx)
        probed = 0
        if mode == "passive":
            res = self._ok(
                findings,
                f"{len(endpoints)} RPC endpoint(s) harvested; "
                f"grading needs active mode (sends read-only probes)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Probe self-hosted first (the project's own infra is the
        # attack surface that matters), then provider endpoints.
        ordered = sorted(endpoints,
                         key=lambda e: (not e["self_hosted"],
                                        e["provider"]))
        for ep in ordered[:MAX_PROBED_ENDPOINTS]:
            probed += 1
            findings.extend(await self._probe_endpoint(ctx, ep))

        res = self._ok(
            findings,
            f"{len(endpoints)} RPC endpoint(s) harvested, "
            f"{probed} graded read-only")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _probe_endpoint(self, ctx: Ctx,
                              ep: Dict[str, Any]) -> List[Finding]:
        url = _http_variant(ep["url"])
        out: List[Finding] = []
        if ep.get("solana"):
            version, _ = await _rpc_call(ctx, url, "getVersion")
            health, _ = await _rpc_call(ctx, url, "getHealth")
            _, cors_headers = await _rpc_call(
                ctx, url, "getVersion", origin=EVIL_ORIGIN)
            if version is not None or health is not None:
                if ep["self_hosted"] and not ep["provider"]:
                    out.append(self._f(
                        "infra", "public_solana_rpc",
                        f"Public Solana RPC endpoint answering on "
                        f"project host: {ep['url']} "
                        f"(getVersion={json.dumps(version)}, "
                        f"getHealth={json.dumps(health)})",
                        source=self.label, source_url=ep["url"],
                        confidence=90, passive=False,
                        evidence={"severity": "low",
                                  "endpoint": ep["url"],
                                  "get_version": version,
                                  "get_health": health,
                                  "remediation": _REMEDIATION_RPC}))
            cors = grade_cors(
                cors_headers.get("access-control-allow-origin"),
                cors_headers.get("access-control-allow-credentials"),
                EVIL_ORIGIN)
            if cors:
                out.append(self._cors_finding(ep, cors, cors_headers))
            return out

        version, _ = await _rpc_call(ctx, url, "web3_clientVersion")
        if version is None:
            return out  # not an answering EVM RPC; nothing to grade
        chain, _ = await _rpc_call(ctx, url, "eth_chainId")
        net, _ = await _rpc_call(ctx, url, "net_version")
        modules, _ = await _rpc_call(ctx, url, "rpc_modules")
        _, cors_headers = await _rpc_call(
            ctx, url, "web3_clientVersion", origin=EVIL_ORIGIN)

        if ep["self_hosted"] and not ep["provider"]:
            out.append(self._f(
                "infra", "public_rpc_endpoint",
                f"Public EVM RPC answering on project host: "
                f"{ep['url']} (client {version}, chainId {chain}, "
                f"net_version {net})",
                source=self.label, source_url=ep["url"],
                confidence=90, passive=False,
                evidence={"severity": "low",
                          "endpoint": ep["url"],
                          "client_version": version,
                          "chain_id": chain,
                          "net_version": net,
                          "modules": modules,
                          "remediation": _REMEDIATION_RPC}))
        if isinstance(modules, dict):
            mod_names = sorted(str(k) for k in modules.keys())
            grades = grade_modules(mod_names)
            if grades:
                sev = worst_severity(grades) or "high"
                names = ", ".join(f"{n} ({s})" for n, s in grades)
                out.append(self._f(
                    "infra", "rpc_dangerous_modules",
                    f"{'CRITICAL' if sev == 'critical' else 'HIGH'}: "
                    f"dangerous RPC namespaces enabled at {ep['url']}: "
                    f"{names}. Full module list: "
                    f"{', '.join(mod_names)}. Client: {version}.",
                    source=self.label, source_url=ep["url"],
                    confidence=95, passive=False,
                    evidence={"severity": sev,
                              "endpoint": ep["url"],
                              "dangerous_modules": [n for n, _ in grades],
                              "all_modules": mod_names,
                              "client_version": version,
                              "remediation": _REMEDIATION_RPC}))
        cors = grade_cors(
            cors_headers.get("access-control-allow-origin"),
            cors_headers.get("access-control-allow-credentials"),
            EVIL_ORIGIN)
        if cors:
            out.append(self._cors_finding(ep, cors, cors_headers))
        return out

    def _cors_finding(self, ep: Dict[str, Any],
                      cors: Tuple[str, str],
                      headers: Dict[str, str]) -> Finding:
        key, sev = cors
        return self._f(
            "infra", key,
            f"RPC endpoint {ep['url']} grants cross-origin browser "
            f"access to unrelated origins "
            f"(Access-Control-Allow-Origin: "
            f"{headers.get('access-control-allow-origin')}, "
            f"Access-Control-Allow-Credentials: "
            f"{headers.get('access-control-allow-credentials')}). "
            f"Any website a user visits can make their browser talk "
            f"to this node.",
            source=self.label, source_url=ep["url"],
            confidence=90, passive=False,
            evidence={"severity": sev,
                      "endpoint": ep["url"],
                      "acao": headers.get(
                          "access-control-allow-origin"),
                      "acac": headers.get(
                          "access-control-allow-credentials"),
                      "origin_sent": EVIL_ORIGIN,
                      "remediation": _REMEDIATION_RPC})


# ------------------------------------------------------------------
# Plugin 2: bounded node-port surface with protocol probes
# ------------------------------------------------------------------

# (port, service label, probe kind, severity when open)
NODE_PORTS: List[Tuple[int, str, str, str]] = [
    (8545, "EVM JSON-RPC (geth/erigon)", "evm", "high"),
    (8546, "EVM WebSocket RPC", "evm", "high"),
    (8899, "Solana JSON-RPC", "solana", "medium"),
    (8900, "Solana WebSocket", "solana_ws", "low"),
    (26657, "Tendermint/CometBFT RPC", "tendermint", "medium"),
    (1317, "Cosmos REST API", "cosmos", "low"),
]


class CryptoInfraPortsPlugin(Plugin):
    id = "crypto_infra_ports"
    label = "Crypto node port surface"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "web3"
    description = ("Bounded connect checks on the six crypto node "
                   "ports (8545/8546/8899/8900/26657/1317) with one "
                   "read-only version/health probe per open port.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = self._host_for(target)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped(
                "needs active mode (sends connect checks)")
        states = await asyncio.gather(
            *[_tcp_open(host, port) for port, _, _, _ in NODE_PORTS])
        findings: List[Finding] = []
        open_count = 0
        for (port, label, kind, sev), is_open in zip(NODE_PORTS, states):
            if not is_open:
                continue
            open_count += 1
            findings.extend(await self._probe_port(
                ctx, host, port, label, kind, sev))
        res = self._ok(
            findings,
            f"{len(NODE_PORTS)} node ports checked on {host}: "
            f"{open_count} open")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    @staticmethod
    def _host_for(target: Target) -> Optional[str]:
        if target.type == "ip":
            raw = (target.normalized or "").strip()
            return raw.split(":")[0].split("/")[0] or None
        return domain_from_target(target.type, target.normalized)

    async def _probe_port(self, ctx: Ctx, host: str, port: int,
                          label: str, kind: str,
                          sev: str) -> List[Finding]:
        base = f"http://{host}:{port}"
        out: List[Finding] = []
        if kind == "evm":
            version, _ = await _rpc_call(ctx, base, "web3_clientVersion")
            modules, _ = await _rpc_call(ctx, base, "rpc_modules")
            chain, _ = await _rpc_call(ctx, base, "eth_chainId")
            detail = (f"client {version}, chainId {chain}"
                      if version is not None
                      else "TCP open; HTTP RPC probe unanswered")
            out.append(self._f(
                "infra", "node_rpc_port_open",
                f"Node RPC port open: {host}:{port} ({label}). "
                f"{detail}.",
                source=self.label, source_url=base,
                confidence=90 if version is not None else 70,
                passive=False,
                evidence={"severity": sev, "host": host, "port": port,
                          "service": label,
                          "client_version": version,
                          "chain_id": chain,
                          "remediation": _REMEDIATION_PORT}))
            if isinstance(modules, dict):
                mod_names = sorted(str(k) for k in modules.keys())
                grades = grade_modules(mod_names)
                if grades:
                    msev = worst_severity(grades) or "high"
                    names = ", ".join(f"{n} ({s})" for n, s in grades)
                    out.append(self._f(
                        "infra", "rpc_dangerous_modules",
                        f"{'CRITICAL' if msev == 'critical' else 'HIGH'}"
                        f": dangerous RPC namespaces enabled at "
                        f"{base}: {names}. Full module list: "
                        f"{', '.join(mod_names)}.",
                        source=self.label, source_url=base,
                        confidence=95, passive=False,
                        evidence={"severity": msev, "endpoint": base,
                                  "dangerous_modules":
                                      [n for n, _ in grades],
                                  "all_modules": mod_names,
                                  "client_version": version,
                                  "remediation": _REMEDIATION_RPC}))
            return out
        if kind == "solana":
            version, _ = await _rpc_call(ctx, base, "getVersion")
            health, _ = await _rpc_call(ctx, base, "getHealth")
            detail = (f"getVersion={json.dumps(version)}, "
                      f"getHealth={json.dumps(health)}"
                      if version is not None or health is not None
                      else "TCP open; RPC probe unanswered")
            out.append(self._f(
                "infra", "node_rpc_port_open",
                f"Node RPC port open: {host}:{port} ({label}). "
                f"{detail}.",
                source=self.label, source_url=base,
                confidence=90 if version is not None else 70,
                passive=False,
                evidence={"severity": sev, "host": host, "port": port,
                          "service": label, "get_version": version,
                          "get_health": health,
                          "remediation": _REMEDIATION_PORT}))
            return out
        if kind == "solana_ws":
            version, _ = await _rpc_call(ctx, base, "getVersion")
            detail = (f"HTTP probe answered: "
                      f"getVersion={json.dumps(version)}"
                      if version is not None
                      else "TCP open (WebSocket pubsub service)")
            out.append(self._f(
                "infra", "node_rpc_port_open",
                f"Node port open: {host}:{port} ({label}). {detail}.",
                source=self.label, source_url=base,
                confidence=80, passive=False,
                evidence={"severity": sev, "host": host, "port": port,
                          "service": label, "get_version": version,
                          "remediation": _REMEDIATION_PORT}))
            return out
        if kind == "tendermint":
            data, _status = await _get_json(ctx, f"{base}/status")
            info = None
            if isinstance(data, dict):
                info = (data.get("result") or {}).get("node_info")
            detail = (f"node_info={json.dumps(info)}"
                      if info else "TCP open; /status unanswered")
            out.append(self._f(
                "infra", "node_rpc_port_open",
                f"Node RPC port open: {host}:{port} ({label}). "
                f"{detail}.",
                source=self.label, source_url=base,
                confidence=90 if info else 70, passive=False,
                evidence={"severity": sev, "host": host, "port": port,
                          "service": label, "node_info": info,
                          "remediation": _REMEDIATION_PORT}))
            return out
        if kind == "cosmos":
            data, _status = await _get_json(
                ctx, f"{base}/cosmos/base/tendermint/v1beta1/node_info")
            info = None
            if isinstance(data, dict):
                info = data.get("default_node_info") or data.get(
                    "node_info")
            if info is None:
                data2, _s2 = await _get_json(ctx, f"{base}/node_info")
                if isinstance(data2, dict):
                    info = data2.get("node_info")
            detail = (f"node_info={json.dumps(info)}"
                      if info else "TCP open; node_info unanswered")
            out.append(self._f(
                "infra", "node_rpc_port_open",
                f"Node API port open: {host}:{port} ({label}). "
                f"{detail}.",
                source=self.label, source_url=base,
                confidence=90 if info else 70, passive=False,
                evidence={"severity": sev, "host": host, "port": port,
                          "service": label, "node_info": info,
                          "remediation": _REMEDIATION_PORT}))
            return out
        return out
