"""Plugin interface for ReconAnything.

Every capability is an isolated, hot-loadable plugin. A plugin never throws
fatally: it returns partial findings plus a per-plugin status.
"""
from __future__ import annotations

import abc
import asyncio
import datetime as dt
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# Valid plugin groups. The UI groups plugins by this value; the health
# check and tests reject anything outside it.
PLUGIN_GROUPS = ("network", "web", "api", "mobile", "identity",
                 "infra", "web3", "financial", "graph")


class PluginStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class Cost(str, Enum):
    FREE = "free"
    FREEMIUM = "freemium"
    PAID = "paid"


@dataclass
class Finding:
    plugin_id: str
    category: str  # dns | web | api | mobile | identity | infra | leak | graph
    key: str       # e.g. "subdomain", "endpoint", "tech"
    value: str
    source: str
    source_url: Optional[str] = None
    confidence: int = 80  # 0-100
    evidence: Optional[Dict[str, Any]] = None
    first_seen: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    raw: Optional[Any] = None
    passive: bool = True  # badge: which mode produced it
    bounty_value: str = "low"  # critical | high | medium | low


# Risk levels: Jay's quality gate. Every finding is Low, Medium, or High.
# No "critical", no "info" - just 3 levels. If Jay sees a finding he
# immediately knows how important it is.
RISK_LEVELS = ("low", "medium", "high")


# Exploitability: how weaponizable a finding is, independent of severity.
# weaponized   = public RCE / auth-bypass exploit exists (Metasploit,
#                nuclei template, or exploit-db entry). Patch NOW.
# public_poc   = public proof-of-concept exists; weaponization is likely.
# theoretical  = real weakness but needs chaining or manual work.
# unknown      = not assessed.
EXPLOITABILITY_LEVELS = ("unknown", "theoretical", "public_poc", "weaponized")


def normalize_exploitability(value: str) -> str:
    """Map any exploitability string to one of the 4 levels."""
    v = (value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if v in EXPLOITABILITY_LEVELS:
        return v
    # common aliases
    if v in ("exploit_public", "rce_public", "metasploit", "nuclei"):
        return "weaponized"
    if v in ("poc", "proof_of_concept", "poc_public"):
        return "public_poc"
    return "unknown"


def normalize_risk(severity: str) -> str:
    """Map any severity string to low|medium|high."""
    s = (severity or "").strip().lower()
    if s in ("critical", "high"):
        return "high"
    if s in ("medium", "med"):
        return "medium"
    return "low"


async def bounded(coro, seconds: float):
    """Await a coroutine with a hard wall-clock cap.

    httpx per-operation timeouts do not stop a slow trickle: a server
    can keep the connection alive indefinitely sending bytes (the
    Wayback CDX API does exactly this). This gives up after `seconds`
    total wall-clock and raises asyncio.TimeoutError, which callers
    fold into their normal degraded/error handling.
    """
    return await asyncio.wait_for(asyncio.ensure_future(coro),
                                  timeout=seconds)


async def gather_capped(coros, budget_s: float):
    """asyncio.gather with a hard wall-clock cap.

    The crawl loops check their time budget between batches, but one
    stalled batch (a trickling server) used to be able to blow past
    the 30s plugin ceiling on its own. This returns results for the
    fetches that finished and None for the rest; it never raises on
    timeout. Cancelled waiters on ctx.fetch_page's singleflight are
    safe: the shared inner task is shielded and keeps its cache entry.
    """
    tasks = [asyncio.ensure_future(c) for c in coros]
    if not tasks:
        return []
    try:
        done, pending = await asyncio.wait(tasks,
                                           timeout=max(0.1, budget_s))
    except Exception:
        done, pending = set(), set(tasks)
    for t in pending:
        t.cancel()
    out = []
    for t in tasks:
        if t in done:
            try:
                out.append(t.result())
            except Exception:
                out.append(None)
        else:
            out.append(None)
    # let cancellations settle so semaphore slots are released
    await asyncio.sleep(0)
    return out


def safe_json_list(resp) -> List[Dict[str, Any]]:
    """Parse an httpx response as JSON, returning a list of dicts.

    External APIs change shape, return error objects instead of arrays,
    or send garbage. Callers iterate the result directly: on ANY failure
    (bad JSON, wrong shape, non-dict items) this returns []. A malformed
    payload must degrade to "no data", never raise.
    """
    try:
        data = resp.json()
    except Exception:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def safe_json_dict(resp) -> Dict[str, Any]:
    """Parse an httpx response as JSON, returning a dict ({} on failure).

    Same contract as safe_json_list for object-shaped payloads.
    """
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


# Default "what to do about it" per finding category. Every finding must
# be actionable: if a plugin doesn't set a specific remediation, the
# category default applies so nothing is ever just "X exists".
CATEGORY_ACTIONS = {
    "dns": ("Review this DNS record. Remove stale or unclaimed records "
            "(subdomain takeover risk) and enable DNSSEC."),
    "web": ("Review this web finding. If something is exposed, remove it or "
            "restrict access. If it's a misconfiguration, apply the fix and "
            "re-scan to verify."),
    "api": ("Audit this endpoint for authorization. It must require "
            "authentication and enforce object-level access control - test "
            "with a second account to confirm."),
    "mobile": ("Review this mobile finding. Remove hardcoded secrets, "
               "enable certificate pinning, and encrypt local storage."),
    "identity": ("Investigate this identity exposure. Rotate any exposed "
                 "credential immediately and check access logs."),
    "infra": ("Review this infrastructure finding. Close unneeded ports, "
              "patch the service, and restrict management interfaces to "
              "trusted IPs."),
    "leak": ("Treat as data exposure. Remove the exposed file or secret, "
             "rotate the credential, and audit who may have accessed it."),
    "graph": ("Review this connection for unintended exposure between assets."),
}

# Bug bounty payout tiers (backend only; not shown in UI per Jay's order).
# critical = $5k+, high = $1k-5k, medium = $100-1k, low = $0-100
BOUNTY_VALUE_TIERS = {
    "critical": {"label": "CRITICAL", "range": "$5k+", "color": "#ff4444"},
    "high": {"label": "HIGH", "range": "$1k-5k", "color": "#ff8800"},
    "medium": {"label": "MEDIUM", "range": "$100-1k", "color": "#ffbb33"},
    "low": {"label": "LOW", "range": "$0-100", "color": "#888888"},
}

# Finding key -> bounty tier. Used to auto-assign value to findings.
BOUNTY_KEY_TIERS = {
    # CRITICAL ($5k+)
    "rce_time_based": "critical",
    "sqli_error_based": "critical",
    "ssrf_cloud_metadata": "critical",
    "exposed_aws_key": "critical",
    "exposed_github_token": "critical",
    "exposed_stripe_key": "critical",
    "wallet_private_key": "critical",
    "exposed_card_number": "critical",
    "exposed_steam_wallet_code": "critical",
    "exposed_amazon_claim_code": "critical",
    "exposed_amazon_claim_code_long": "critical",
    "exposed_generic_gift_code": "critical",
    "exposed_gift_card_pan": "critical",
    "s3_public_write": "critical",
    "git_exposed": "high",
    # HIGH ($1k-5k)
    "idor_candidate": "high",
    "idor_confirmed": "high",
    "sourcemap_secret": "high",
    "s3_public_read": "high",
    "exposed_env": "high",
    "hardcoded_password": "high",
    "subdomain_takeover": "high",
    "interesting_subdomain": "high",
    # MEDIUM ($100-1k)
    "xss_reflected": "medium",
    "oob_callback_sent": "low",
    "sourcemap_exposed": "medium",
    "sourcemap_internal_url": "medium",
    "sourcemap_api_route": "medium",
    "sourcemap_cred_comment": "medium",
    "sourcemap_debug_flag": "low",
    "fuzz_param_anomaly": "medium",
    "open_redirect": "medium",
    "cors_misconfig": "medium",
    "clickjacking": "medium",
    "missing_security_header": "medium",
    # Detection modules (race / stealth crawl / JWT audit)
    "race_no_ratelimit": "medium",
    "race_no_idempotency": "medium",
    "hidden_api_endpoint": "medium",
    "jwt_alg_none": "high",
    "jwt_weak_secret": "high",
    "jwt_missing_exp": "medium",
    "jwt_long_exp": "medium",
    "jwt_sensitive_claims": "medium",
    "jwt_kid_suspicious": "medium",
    # LOW ($0-100) - default
}


def bounty_tier_for(key: str, severity: str = "") -> str:
    """Get the bounty value tier for a finding key."""
    if key in BOUNTY_KEY_TIERS:
        return BOUNTY_KEY_TIERS[key]
    # Fall back to severity mapping
    sev = severity.lower() if severity else ""
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


@dataclass
class PluginResult:
    plugin_id: str
    status: PluginStatus
    reason: str = ""
    findings: List[Finding] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class Target:
    raw: str
    type: str  # domain, url, ip, ...
    normalized: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        if not self.normalized:
            self.normalized = self.raw.strip()


class CaseInsensitiveHeaders(dict):
    """A headers dict whose lookups ignore case, like httpx.Headers.

    Servers send header names in arbitrary casing ("Strict-Transport-
    Security"); plugins look them up lowercase. Plain-dict storage made
    those lookups silently miss - or crash attribute-style consumers.
    """

    def _real_key(self, key: Any) -> Any:
        lk = str(key).lower()
        for k in self.keys():
            if str(k).lower() == lk:
                return k
        return key

    def get(self, key: Any, default: Any = None) -> Any:
        return super().get(self._real_key(key), default)

    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(self._real_key(key))

    def __contains__(self, key: Any) -> bool:
        return super().__contains__(self._real_key(key))


class PageData(dict):
    """Cached page payload returned by Ctx.fetch_page.

    The payload is stored as a plain dict (status_code, headers, text,
    url) so it survives the JSON cache round-trip, and most plugins
    consume it dict-style: page["text"], page.get("headers"). A newer
    plugin family was written against fetch_page's documented contract
    ("returns the response") and uses attribute access instead -
    page.text, page.headers.get(...) - and crashed with AttributeError
    on every live scan (10 plugins, first seen in production
    2026-10-21; the unit tests stubbed fetch_page with response
    objects, so the suite never saw it). Attribute access now falls
    through to the dict keys, so both styles work on the same object.
    """

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


def _as_page(raw: Any) -> Any:
    """Wrap a raw cached/fetched page payload as PageData (idempotent)."""
    if raw is None or not isinstance(raw, dict):
        return raw
    page = raw if isinstance(raw, PageData) else PageData(raw)
    headers = page.get("headers")
    if isinstance(headers, dict) and not isinstance(
            headers, CaseInsensitiveHeaders):
        page["headers"] = CaseInsensitiveHeaders(headers)
    return page


@dataclass
class Ctx:
    """Run context handed to every plugin."""
    run_id: str
    mode: str  # "passive" | "active"
    http: Any  # shared httpx.AsyncClient
    cache: Any  # cache layer with get/set
    keys: Dict[str, str]  # decrypted API keys by name
    limiter: Any = None  # rate limiter
    emit: Any = None  # optional async callback(event dict)
    module_overrides: Dict[str, str] = field(default_factory=dict)
    evidence_dir: str = "./evidence"
    # Source type of the run: "website" | "bank" | "atm".
    # Source-type plugins (atm.py, bank.py) only do work when the run's
    # source_type matches their own; otherwise they stay silent.
    source_type: str = "website"
    # Discovery bus: plugins publish assets here so phase-2 chain
    # plugins can consume them. Keys: subdomains, js_files, endpoints,
    # tech, forms, params, emails, cert_sans.
    shared: Dict[str, List[Any]] = field(default_factory=dict)

    def publish(self, kind: str, item: Any) -> None:
        """Publish a discovered asset to the shared discovery bus."""
        bucket = self.shared.setdefault(kind, [])
        # light dedup for strings
        if isinstance(item, str):
            if item not in bucket:
                bucket.append(item)
        else:
            bucket.append(item)

    def consume(self, kind: str) -> List[Any]:
        """Read everything published under a discovery kind."""
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url: str, timeout: int = 10) -> Any | None:
        """Fetch a page with cross-plugin caching.

        Multiple plugins fetch the same homepage. This caches the
        page payload by URL so only the first plugin pays the cost.
        Singleflight: concurrent callers for the same URL share one
        in-flight request instead of thundering-herding the target.
        Returns a PageData (dict with status_code/headers/text/url,
        also readable as attributes) or None on failure.
        """
        from ..ratelimit import fetch as _fetch
        # Normalize the key: "https://host" and "https://host/" are the same
        # page, so every plugin's homepage read hits one shared cache entry
        # no matter how it spelled the base URL.
        cache_key = f"page:{url.rstrip('/')}"
        cached = self.cache.get("http", cache_key)
        if cached is not None:
            return _as_page(cached)
        inflight = self.shared.setdefault("_fetch_page_inflight", {})
        task = inflight.get(cache_key)
        if task is None:
            task = asyncio.get_running_loop().create_task(
                self._fetch_page_once(url, timeout))
            inflight[cache_key] = task
            task.add_done_callback(lambda _t: inflight.pop(cache_key, None))
        try:
            return _as_page(await asyncio.shield(task))
        except Exception:
            return None

    async def _fetch_page_once(self, url: str, timeout: int) -> Any | None:
        from ..ratelimit import fetch as _fetch
        cache_key = f"page:{url.rstrip('/')}"
        try:
            resp = await _fetch(self.http, self.limiter, "GET", url,
                                timeout=timeout, follow_redirects=True)
            # Cache lightweight response data (not the full response object)
            data = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "text": resp.text[:500000],
                "url": str(resp.url),
            }
            try:
                self.cache.set("http", cache_key, data, ttl=300)
            except Exception:
                pass
            return _as_page(data)
        except Exception:
            return None

    async def probe(self, url: str, timeout: int = 8) -> Dict[str, Any]:
        """Bulk-sweep GET with per-run response sharing.

        backup.py, artifacts.py, hiddenpaths.py and apidiscover.py probe
        overlapping path lists. This caches (status, headers, text head)
        per URL in the run's shared bus so the second plugin to probe a
        URL reuses the first plugin's response instead of re-fetching.
        Same requests, same findings, fewer packets. Failures are cached
        as status 0 (a sweep miss either way).
        """
        from ..ratelimit import fetch as _fetch
        bus = self.shared.setdefault("probe_cache", {})
        hit = bus.get(url)
        if hit is not None:
            return hit
        try:
            resp = await _fetch(self.http, self.limiter, "GET", url,
                                timeout=timeout, max_retries=1,
                                follow_redirects=True)
            data = {
                "status": resp.status_code,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "text": resp.text[:4000],
                "url": str(resp.url),
            }
            try:
                data["length"] = int(resp.headers.get("content-length", 0)) or len(resp.text)
            except Exception:
                data["length"] = len(resp.text)
        except Exception:
            data = {"status": 0, "headers": {}, "text": "", "url": url, "length": 0}
        bus[url] = data
        return data


class Plugin(abc.ABC):
    id: str = "base"
    label: str = "Base"
    accepts: List[str] = []
    requires_keys: List[str] = []
    passive: bool = True
    cost: Cost = Cost.FREE
    group: str = "network"  # one of PLUGIN_GROUPS
    description: str = ""
    # Execution phase. Phase 1 plugins run first; phase 2 "chain" plugins
    # run after, consuming the discovery bus (ctx.shared) populated by
    # phase 1. Lets findings lead to more findings.
    phase: int = 1
    # Aggressive: sends attack payloads or brute-forces paths/endpoints.
    # When the rate limiter has a host in WAF graceful mode, aggressive
    # plugins are suppressed for that host (ok with a note) so the scan
    # budget isn't burned on blocked endpoints. Lightweight checks keep
    # running. No effect on non-WAF hosts.
    aggressive: bool = False
    # Per-plugin timeout ceiling (seconds). Hard-capped by the runner
    # (MAX_PLUGIN_TIMEOUT_S, 120s since 2026-10-20): if a plugin hasn't
    # produced anything in that window it is killed gracefully. Was a 30s
    # cap under the 2026-10-18 speed-first order; Jay's 2026-10-20 order
    # (find more, consistently) raised it so enumerators finish their work
    # instead of being cut at different points every run. The scan's
    # global budget can shrink this further when the clock is running out.
    timeout_s: int = 60

    @abc.abstractmethod
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        ...

    # -- helpers ---------------------------------------------------------
    def _ok(self, findings: List[Finding], reason: str = "") -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.OK,
                            reason=reason, findings=findings)

    def _skipped(self, reason: str) -> PluginResult:
        # Jay's rule: no skips, ever. A skip is reported as ok(0) with the
        # reason as the note, so the UI always shows every plugin as ok.
        return PluginResult(plugin_id=self.id, status=PluginStatus.OK, reason=reason)

    def _degraded(self, reason: str) -> PluginResult:
        # Environmental failure (target unreachable, network blocked, API
        # down): not a code bug, so report ok(0) with an explanatory note
        # instead of an error.
        return PluginResult(plugin_id=self.id, status=PluginStatus.OK, reason=reason)

    def _rate_limited(self, reason: str) -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.RATE_LIMITED, reason=reason)

    def _error(self, reason: str) -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.ERROR, reason=reason)

    def _f(self, category: str, key: str, value: str, source: str,
           source_url: Optional[str] = None, confidence: int = 80,
           evidence: Optional[Dict[str, Any]] = None, raw: Optional[Any] = None,
           passive: bool = True, bounty_value: Optional[str] = None,
           exploitability: str = "unknown") -> Finding:
        bv = bounty_value
        ev: Dict[str, Any] = dict(evidence) if evidence else {}
        # Quality gate: normalize risk to low|medium|high (3 levels only).
        raw_sev = str(ev.get("severity", ""))
        risk = normalize_risk(raw_sev)
        ev["severity"] = risk
        ev["risk"] = risk
        # Exploitability: how weaponizable this is (independent of severity).
        # Lets Jay sort "real crazy vulnerabilities" above theoretical noise.
        ev["exploitability"] = normalize_exploitability(
            ev.get("exploitability") or exploitability)
        # Quality gate: every finding is actionable. If the plugin didn't
        # set a specific remediation, apply the category default so the
        # finding always says what to do about it.
        if not ev.get("remediation"):
            ev["remediation"] = CATEGORY_ACTIONS.get(
                category,
                "Review this finding and address the underlying issue, "
                "then re-scan to verify.")
        # Attacker impact: every finding also says what an attacker
        # could DO with it, in plain language (descriptive impact only).
        # Plugins may set their own; otherwise resolve key -> prefix ->
        # plugin -> category from app.impact.
        if not ev.get("attacker_impact"):
            try:
                from ..impact import attacker_impact_for
                ev["attacker_impact"] = attacker_impact_for(
                    key, self.id, category)
            except Exception:
                ev["attacker_impact"] = (
                    "This observation helps an attacker map or weaken "
                    "the target; see the finding detail.")
        # Hash findings: name the algorithm (from its format or the
        # plugin's own label) and what the hash is for, in the impact
        # text and as hash_type/hash_purpose fields. Identification
        # only - no cracking, ever.
        try:
            from ..impact import apply_hash_annotation
            apply_hash_annotation(ev, key=key, plugin_id=self.id,
                                  category=category, value=value)
        except Exception:
            pass
        if bv is None:
            bv = bounty_tier_for(key, raw_sev)
        return Finding(plugin_id=self.id, category=category, key=key, value=value,
                       source=source, source_url=source_url, confidence=confidence,
                       evidence=ev, raw=raw, passive=passive,
                       bounty_value=bv)

    def module_mode(self, ctx: Ctx) -> str:
        """Per-module override wins over the global mode."""
        return ctx.module_overrides.get(self.id, ctx.mode)

    def missing_keys(self, ctx: Ctx) -> List[str]:
        return [k for k in self.requires_keys if not ctx.keys.get(k)]
