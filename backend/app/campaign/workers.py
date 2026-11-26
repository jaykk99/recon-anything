"""Workers: the things a campaign actually does.

Four worker kinds, each returning an ``Attempt`` with receipts:

  recon   fetch the target once, map what it is (service, tech, links,
          parameters, cookie flags) - the asset-graph seed.
  probe   run one read-only detection probe from app/exploit_probes
          (or a legacy app/safe_tester probe) and capture the exact
          request/response that decided it.
  impact  enumerate an exposed console read-only, capped, to prove what
          it gives an unauthenticated stranger. Gated by approval.
  verify  offline/additional proof: crack a captured JWT's HMAC, list an
          object-storage bucket, confirm a receipt.

Workers never raise to the engine: anything unexpected becomes a failed
attempt with the error recorded, because one broken worker must not kill
the campaign.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List
from urllib.parse import parse_qs, urljoin, urlparse

from .graph import Graph
from .models import Attempt, Budget, digest, finding
from .scope import Scope, host_of

_UA = "ReconAnything-Campaign/1.0 (authorized security testing; read-only)"

_LINK_RE = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(
    r"""<input\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>""", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR_RE = re.compile(
    r"""<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*\bcontent\s*=\s*["']([^"']+)["']""",
    re.I)


@dataclass
class WorkerContext:
    scope: Scope
    budget: Budget
    graph: Graph
    fetch: Callable[..., Any]
    log: Callable[[str], None] = print
    sleep: Callable[[float], None] = time.sleep

    def base(self, target: str) -> str:
        t = (target or "").strip().rstrip("/")
        if not t:
            return ""
        return t if "://" in t else "https://" + t


def _receipt(resp, note: str = "") -> Dict[str, Any]:
    text = getattr(resp, "text", "") or ""
    headers = dict(getattr(resp, "headers", {}) or {})
    keep = {k: v for k, v in headers.items()
            if k.lower() in ("server", "content-type", "x-powered-by",
                             "location", "allow", "www-authenticate",
                             "x-frame-options", "content-security-policy",
                             "strict-transport-security", "set-cookie")}
    return {
        "request": f"{getattr(resp, 'method', 'GET')} {getattr(resp, 'url', '')}",
        "status": getattr(resp, "status", None),
        "headers": keep,
        "body_sha256": digest(text),
        "body_excerpt": text[:400],
        "note": note,
    }


def _start(intent, ctx: WorkerContext) -> Attempt:
    return Attempt(key=intent.key, kind=intent.kind, action=intent.action,
                   target=intent.target)


def _get(ctx: WorkerContext, url: str, **kw) -> Any:
    return ctx.fetch(url, **kw)


# ---------------------------------------------------------------------------
# recon: one fetch, one asset-graph seed
# ---------------------------------------------------------------------------
def worker_surface(intent, ctx: WorkerContext) -> Attempt:
    attempt = _start(intent, ctx)
    base = ctx.base(intent.target)
    resp = _get(ctx, base)
    if getattr(resp, "status", None) is None:
        attempt.status = "failed"
        attempt.error = getattr(resp, "error", "") or "no response"
        attempt.detail = f"{base} did not answer"
        return attempt

    text = getattr(resp, "text", "") or ""
    headers = dict(getattr(resp, "headers", {}) or {})
    host = host_of(base)
    title_m = _TITLE_RE.search(text)
    title = title_m.group(1).strip()[:160] if title_m else ""
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    gen_m = _GENERATOR_RE.search(text)
    generator = gen_m.group(1) if gen_m else ""

    attempt.assets.append({
        "type": "http_service", "value": base, "stage": "recon",
        "meta": {"status": resp.status, "server": server,
                 "powered_by": powered, "title": title,
                 "content_type": headers.get("content-type", "")},
    })
    for tech in (server, powered, generator):
        if tech:
            attempt.assets.append({"type": "tech", "value": tech,
                                   "stage": "recon",
                                   "meta": {"host": host}})

    # Same-host links -> endpoints; query strings and form inputs -> params.
    endpoints: List[str] = []
    params: List[str] = []
    for href in _LINK_RE.findall(text)[:80]:
        u = urljoin(base + "/", href)
        if host_of(u) != host:
            continue
        if u not in endpoints:
            endpoints.append(u)
        for p in parse_qs(urlparse(u).query).keys():
            if p not in params:
                params.append(p)
    for form in _FORM_RE.findall(text)[:10]:
        for name in _INPUT_RE.findall(form):
            if name not in params:
                params.append(name)
    for u in endpoints[:20]:
        attempt.assets.append({"type": "endpoint", "value": u,
                               "stage": "recon",
                               "meta": {"host": host, "found_on": base}})
    for p in params[:20]:
        attempt.assets.append({"type": "param", "value": p,
                               "stage": "recon", "meta": {"host": host}})

    for cookie in (headers.get("set-cookie", "") or "").split(","):
        name = cookie.split("=")[0].strip()
        if not name or name.lower() in ("", "set-cookie"):
            continue
        flags = cookie.lower()
        attempt.assets.append({
            "type": "cookie", "value": name, "stage": "recon",
            "meta": {"secure": "secure" in flags,
                     "httponly": "httponly" in flags,
                     "samesite": "samesite" in flags},
        })

    if server or powered or generator:
        attempt.findings.append(finding(
            action="surface", title="technology disclosed in response",
            target=base, severity="info", confidence=100,
            tags=["recon"], stage="recon",
            detail=", ".join(x for x in (server, powered, generator) if x),
            evidence=_receipt(resp, "response headers / generator meta"),
        ))
    missing = [h for h in ("content-security-policy", "strict-transport-security",
                           "x-frame-options")
               if h not in {k.lower() for k in headers}]
    if missing:
        attempt.findings.append(finding(
            action="surface", title="security headers missing",
            target=base, severity="low", confidence=100,
            tags=["hygiene"], stage="recon",
            detail="missing: " + ", ".join(missing),
            evidence=_receipt(resp, "response headers"),
        ))
    attempt.evidence.append(_receipt(resp, "surface fetch"))
    attempt.detail = (f"{resp.status} {title or '(no title)'}; "
                      f"{len(endpoints)} links, {len(params)} params")
    attempt.meta = {"endpoints": len(endpoints), "params": len(params)}
    return attempt


# ---------------------------------------------------------------------------
# probe: any read-only probe, legacy or new
# ---------------------------------------------------------------------------
def worker_probe(intent, ctx: WorkerContext) -> Attempt:
    from .. import exploit_probes

    attempt = _start(intent, ctx)
    base = ctx.base(intent.target)
    params = [a["value"] for a in ctx.graph.assets_of("param")]
    param = params[0] if params else None

    fn = exploit_probes.PROBES.get(intent.action)
    if fn is not None:
        res = exploit_probes.run_probe(intent.action, base, param=param,
                                       fetch=ctx.fetch)
        attempt.detail = res.detail
        attempt.evidence.extend(res.meta.get("receipts") or [])
        if res.evidence:
            attempt.evidence.append(res.evidence)
        attempt.assets.extend(res.assets)
        if res.meta.get("transport_failed"):
            attempt.status = "failed"
            attempt.error = str(res.meta.get("transport_error")
                                or "target did not answer")[:300]
            return attempt
        if res.works:
            attempt.findings.append(finding(
                action=intent.action, title=res.title or intent.action,
                target=base, severity=res.severity,
                confidence=res.confidence, tags=res.tags,
                evidence=res.evidence, detail=res.detail,
                stage=res.stage, meta=res.meta,
            ))
        return attempt

    # Legacy probe from safe_tester (GET/HEAD, rate-limited, tuple-returning).
    try:
        from ..safe_tester import PROBE_MAP
    except Exception as exc:  # pragma: no cover - httpx is a real dependency
        attempt.status = "failed"
        attempt.error = f"safe_tester unavailable: {exc}"
        return attempt
    legacy = PROBE_MAP.get(intent.action)
    if legacy is None:
        attempt.status = "failed"
        attempt.error = f"unknown probe {intent.action!r}"
        return attempt
    try:
        works, detail = legacy(base, {})
    except Exception as exc:
        attempt.status = "failed"
        attempt.error = str(exc)[:300]
        return attempt
    attempt.detail = detail
    attempt.evidence.append({
        "request": f"GET {base} (legacy safe_tester probe {intent.action})",
        "status": None, "body_sha256": "", "body_excerpt": "",
        "note": "legacy probe reports a marker rather than a raw exchange",
    })
    if works:
        attempt.findings.append(finding(
            action=intent.action, title=intent.action.replace("-", " "),
            target=base, severity="high", confidence=75,
            tags=[_legacy_tag(intent.action)], detail=detail,
            evidence=attempt.evidence[-1],
        ))
    return attempt


def _legacy_tag(pid: str) -> str:
    if pid in ("git-exposed", "env-secrets", "backup-files"):
        return "secret"
    if pid in ("idor", "bola", "auth-bypass"):
        return "auth_bypass"
    if pid in ("sqli", "xss-reflected", "ssti", "crlf", "host-header",
               "ssrf", "dir-traversal", "xxe", "nosql-injection"):
        return "injection"
    if pid in ("s3-open", "open-bucket"):
        return "object_storage"
    return "exposure"


# ---------------------------------------------------------------------------
# impact: read-only enumeration of an exposed console (approval required)
# ---------------------------------------------------------------------------
def worker_impact(intent, ctx: WorkerContext) -> Attempt:
    from .. import exploit_probes

    attempt = _start(intent, ctx)
    base = ctx.base(intent.target)
    console = (intent.meta.get("console")
               or intent.action.split(":", 1)[-1]).lower()
    res = exploit_probes.enumerate_exposure(console, base, fetch=ctx.fetch)
    attempt.detail = res.get("detail", "")
    attempt.evidence.extend((res.get("meta") or {}).get("receipts") or [])
    if res.get("evidence"):
        attempt.evidence.append(res["evidence"])
    if (res.get("meta") or {}).get("transport_failed"):
        attempt.status = "failed"
        attempt.error = str((res.get("meta") or {}).get("transport_error")
                            or "target did not answer")[:300]
        return attempt
    if not res.get("works"):
        return attempt
    items = res.get("items") or []
    for item in items[:10]:
        attempt.assets.append({
            "type": _console_asset_type(console), "value": str(item),
            "stage": "impact", "meta": {"console": console},
        })
    attempt.findings.append(finding(
        action=f"enumerate:{console}",
        title=f"unauthenticated {console} console exposes {len(items)} object(s)",
        target=base, severity=res.get("severity", "high"),
        confidence=res.get("confidence", 85),
        tags=["exposed_console", "exposed_data"],
        evidence=res.get("evidence") or {},
        detail=res.get("detail", "") + (
            "; visible: " + ", ".join(str(i) for i in items[:5])
            if items else ""),
        stage="impact",
        meta={"console": console, "count": len(items),
              "items": items[:25]},
    ))
    return attempt


def _console_asset_type(console: str) -> str:
    return {
        "docker": "container", "k8s": "namespace",
        "elasticsearch": "index", "jenkins": "job",
        "grafana": "dashboard", "minio": "bucket",
    }.get(console, "service")


# ---------------------------------------------------------------------------
# verify: proof that needs no (or only one) extra request
# ---------------------------------------------------------------------------
def worker_verify(intent, ctx: WorkerContext) -> Attempt:
    from .. import exploit_probes

    attempt = _start(intent, ctx)
    base = ctx.base(intent.target)
    src = intent.meta.get("finding") or (intent.why[0] if intent.why else "")
    f = ctx.graph.findings.get(src) or {}

    if intent.action == "jwt-forge":
        token = str(intent.meta.get("token")
                    or ((f.get("meta") or {}).get("token"))
                    or ((f.get("evidence") or {}).get("body_excerpt") or ""))
        res = exploit_probes.crack_jwt(token)
        attempt.detail = res["detail"]
        attempt.evidence.append({
            "request": "offline: HMAC verification of the captured token",
            "status": None, "body_sha256": digest(token[:2000]),
            "body_excerpt": token[:120] + ("..." if len(token) > 120 else ""),
            "note": res["detail"],
        })
        if res["works"]:
            attempt.findings.append(finding(
                action="jwt-forge", title="JWT signing secret recovered",
                target=base, severity="critical", confidence=res["confidence"],
                tags=["auth_bypass", "secret"], evidence=attempt.evidence[-1],
                detail=res["detail"], stage="access",
                meta={"secret": res.get("secret"), "alg": res.get("alg")},
            ))
        return attempt

    if intent.action == "bucket-list":
        url = base.rstrip("/") + "/?list-type=2&max-keys=10"
        resp = _get(ctx, url)
        receipt = _receipt(resp, "object-storage bucket listing")
        attempt.evidence.append(receipt)
        if resp.status is None:
            attempt.status = "failed"
            attempt.error = getattr(resp, "error", "") or "no response"
            return attempt
        keys = re.findall(r"<Key>([^<]+)</Key>", getattr(resp, "text", "") or "")
        attempt.detail = (f"{getattr(resp, 'status', None)} bucket listing, "
                          f"{len(keys)} key(s)")
        if keys:
            for k in keys[:10]:
                attempt.assets.append({"type": "bucket", "value": k,
                                       "stage": "impact"})
            attempt.findings.append(finding(
                action="bucket-list",
                title="object-storage bucket lists objects anonymously",
                target=base, severity="critical", confidence=90,
                tags=["object_storage", "exposed_data"], evidence=receipt,
                detail="keys: " + ", ".join(keys[:10]), stage="impact",
                meta={"keys": keys[:25]},
            ))
        return attempt

    attempt.status = "skipped"
    attempt.detail = f"no verifier for {intent.action!r}"
    return attempt


DEFAULT_WORKERS: Dict[str, Callable[[Any, WorkerContext], Attempt]] = {
    "recon": worker_surface,
    "probe": worker_probe,
    "impact": worker_impact,
    "verify": worker_verify,
}
