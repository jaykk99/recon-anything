"""IDOR surface mapper + error-response disclosure detector.

Phase-2 chain plugin. Two halves that score together:

1. IDOR SURFACE MAPPER. From data a normal scan already collects -
   the discovery bus (crawled URLs, endpoints published by phase-1
   plugins), JS bundle contents, the homepage, and OpenAPI/Swagger
   specs - it extracts API paths that carry an object identifier and
   maps the surface: endpoint pattern, ID type (sequential numeric /
   UUID / hex / path template), whether numeric IDs look sequential,
   and where the endpoint was exposed (public JS, public spec, crawl).
   Rails-style JSON reference endpoints - /reports/{id}/reference.json,
   the pattern family behind HackerOne report #3862641 (popularized by
   @someonenamenicky's "Simple IDOR bug 15 grand bounty" reel) - are
   flagged as high-risk surface.

2. ERROR-RESPONSE DISCLOSURE DETECTOR. Error bodies are a classic
   IDOR side channel: the server denies the request (401/403/422) but
   the error payload embeds the object it just refused to serve -
   H1 #3862641's 422 carried the private report in a context.subject
   field. This half inspects ONLY responses the scanner legitimately
   receives in a normal authorized scan: the shared probe cache plus
   ONE unauthenticated GET per discovered endpoint, exactly as the
   scanner requested it (the ID as published - never swapped, never
   incremented, no credentials, no bypass attempts). A 4xx body that
   carries object-shaped data (nested context/subject/data objects,
   titles, descriptions, emails, internal IDs) becomes a finding with
   the leaked fields shown in full.

3. COMBINED SCORING. An endpoint that is BOTH predictable-ID surface
   AND whose error responses leak object data is emitted as one
   highest-tier "IDOR / error-leak path" finding with both evidence
   pieces together.

Detection only: no auth bypass, no credential use, no access to
another object's data beyond what the target itself volunteered in an
error body to an unauthenticated request, no exploit confirmation.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain

# ---------------------------------------------------------------------------
# ID segment classification
# ---------------------------------------------------------------------------

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUMERIC_RE = re.compile(r"^\d{1,19}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{24,64}$")
TEMPLATE_RE = re.compile(r"^(?:\{([^}]+)\}|:([A-Za-z_][\w-]*)|\[([^\]]+)\])$")
VERSION_SEG_RE = re.compile(r"^v\d+$", re.IGNORECASE)

ID_KINDS = ("numeric", "uuid", "hex", "template")


def classify_segment(seg: str) -> Optional[Tuple[str, str]]:
    """Classify one path segment as an object ID.

    Returns (kind, value) - for templates, value is the parameter
    name; otherwise the literal segment (with a trailing .json suffix
    stripped, so /reports/3862641.json still reads as a numeric ID).
    Returns None when the segment is not ID-like.
    """
    s = seg.strip()
    if not s:
        return None
    stem = s[:-5] if s.lower().endswith(".json") else s
    m = TEMPLATE_RE.match(stem)
    if m:
        return ("template", next(g for g in m.groups() if g))
    if UUID_RE.match(stem):
        return ("uuid", stem)
    if NUMERIC_RE.match(stem):
        return ("numeric", stem)
    if HEX_RE.match(stem):
        return ("hex", stem)
    return None


def split_id_path(path: str) -> Optional[Dict[str, Any]]:
    """Find the first object-ID segment in a URL path.

    Returns a dict with the normalized pattern (ID segment replaced by
    {id}, leading /api and /vN mount segments dropped so a spec path
    /reports/{id}/reference.json and a served URL
    /api/v1/reports/3862641/reference.json land in the same group),
    the ID kind/value, the resource segment, and whether the path is
    a JSON reference-style endpoint. None when no ID segment exists or
    there is no resource segment in front of the ID.
    """
    segs = [s for s in (path or "").split("/") if s != ""]
    # Drop mount prefixes: /api, /api/v1, /v2 ...
    while segs and (segs[0].lower() == "api" or VERSION_SEG_RE.match(segs[0])):
        segs = segs[1:]
    for i, seg in enumerate(segs):
        hit = classify_segment(seg)
        if hit is None:
            continue
        kind, value = hit
        if i == 0:
            return None  # ID with no resource segment in front of it
        pattern_segs = list(segs)
        pattern_segs[i] = "{id}"
        last = segs[-1].lower()
        return {
            "pattern": "/" + "/".join(pattern_segs),
            "id_kind": kind,
            "id_value": value,
            "id_index": i,
            "resource": segs[i - 1],
            "reference_json": last == "reference.json",
            "json_endpoint": last.endswith(".json"),
        }
    return None


def ids_look_sequential(ids: List[int]) -> bool:
    """Observed numeric IDs cluster tightly => sequential assignment."""
    uniq = sorted(set(ids))
    if len(uniq) < 2:
        return False
    return (uniq[-1] - uniq[0]) <= max(50, 5 * len(uniq))


# ---------------------------------------------------------------------------
# Error-body leak analysis
# ---------------------------------------------------------------------------

# Keys whose presence alone means "generic framework error envelope".
GENERIC_KEYS = {
    "error", "errors", "message", "msg", "code", "status", "detail",
    "title", "type", "trace_id", "traceid", "request_id", "requestid",
    "timestamp", "path", "ok", "success",
}

# Container keys that, when they hold an OBJECT (not strings), mean the
# error body is carrying the denied object itself - the H1 #3862641
# shape was context.subject = {the private report}.
OBJECT_CONTAINER_KEYS = {
    "context", "subject", "data", "result", "object", "resource",
    "item", "entity", "record", "payload",
}

# Leaf field names that describe an object, not an error.
OBJECT_FIELD_HINTS = {
    "title", "name", "description", "body", "content", "summary",
    "email", "username", "user_name", "slug", "owner", "author",
    "reporter", "assignee", "created_at", "updated_at", "url",
    "address", "phone", "status_text", "visibility", "private",
}

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
MAX_FIELD_VALUE = 400


def _walk(obj: Any, prefix: str, out: List[Tuple[str, Any]]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _walk(v, p, out)
            else:
                out.append((p, v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            p = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                _walk(v, p, out)
            else:
                out.append((p, v))


def analyze_error_body(text: str) -> Optional[Dict[str, Any]]:
    """Inspect a 4xx response body for object-data disclosure.

    Returns None for a clean generic error. On a leak, returns
    {leaked_fields: {dotted.path: value-as-received}, field_paths,
    containers, sensitive: bool}. Values are shown in full (Jay's
    Oct 29 rule: findings are not masked), capped per-value only so a
    huge body cannot bloat the finding store.
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return _analyze_non_json(text)
    leaves: List[Tuple[str, Any]] = []
    _walk(data, "", leaves)
    leaked: Dict[str, Any] = {}
    containers: Set[str] = set()
    sensitive = False
    for path, value in leaves:
        parts = path.split(".")
        leaf_key = re.sub(r"\[\d+\]$", "", parts[-1]).lower()
        container = parts[0].lower() if len(parts) > 1 else ""
        in_object_container = container in OBJECT_CONTAINER_KEYS
        if path == "id" or leaf_key in ("id",) and len(parts) == 1:
            continue  # a bare top-level id in an envelope proves nothing
        is_object_field = leaf_key in OBJECT_FIELD_HINTS
        is_nested_id = leaf_key in ("id", "uuid", "guid") and len(parts) > 1
        is_email_value = isinstance(value, str) and bool(EMAIL_RE.search(value))
        # {"errors": {"title": ["can't be blank"]}} is a validation
        # envelope naming FIELDS, not the denied object's data - do not
        # count list-valued validation messages as leaked fields.
        if container == "errors" and "[" in path and not is_email_value:
            continue
        if in_object_container and len(parts) > 1:
            containers.add(container)
        if is_object_field or is_nested_id or is_email_value or (
                in_object_container and len(parts) > 1
                and leaf_key not in GENERIC_KEYS):
            v = value
            if isinstance(v, str) and len(v) > MAX_FIELD_VALUE:
                v = v[:MAX_FIELD_VALUE] + "…[truncated]"
            leaked[path] = v
            if is_email_value or leaf_key in ("email", "description", "body"):
                sensitive = True
    # A leak needs substance: at least 2 object fields, or one
    # sensitive field, or a whole object container with content.
    if len(leaked) >= 2 or sensitive or (containers and leaked):
        return {"leaked_fields": leaked,
                "field_paths": sorted(leaked.keys()),
                "containers": sorted(containers),
                "sensitive": sensitive}
    return None


def _analyze_non_json(text: str) -> Optional[Dict[str, Any]]:
    """Fallback for non-JSON (or probe-truncated) bodies.

    Only fires on the unmistakable reel shape: an object container key
    (context/subject/data) plus object data (an email or a title) in
    the same body. Lower confidence is assigned by the caller.
    """
    low = text.lower()
    container = next((k for k in ("context", "subject", "\"data\"")
                      if f'"{k.strip(chr(34))}"' in low), None)
    if not container:
        return None
    email = EMAIL_RE.search(text)
    title_m = re.search(r'"title"\s*:\s*"([^"]{1,200})"', text)
    if not email and not title_m:
        return None
    leaked: Dict[str, Any] = {}
    if title_m:
        leaked["title"] = title_m.group(1)
    if email:
        leaked["email"] = email.group(0)
    return {"leaked_fields": leaked, "field_paths": sorted(leaked.keys()),
            "containers": [container.strip('"')], "sensitive": True}


# ---------------------------------------------------------------------------
# Surface mining
# ---------------------------------------------------------------------------

PATH_STRING_RE = re.compile(r"""["'`](/(?:[A-Za-z0-9_\-./{}:$[\]=~]|%[0-9A-Fa-f]{2})+)["'`]""")
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>\)\]]+""")
SPEC_HINTS = ("openapi", "swagger", "api-docs", "api_docs", "spec.json",
              "redoc")
MAX_JS_FETCH = 6
MAX_SPEC_FETCH = 3
MAX_PROBES = 12
MAX_SURFACE_FINDINGS = 20

SURFACE_REMEDIATION = (
    "Treat every object ID in a URL as public knowledge: enforce "
    "object-level authorization on the server for each ID, prefer "
    "unguessable UUIDs for new endpoints, and never rely on the ID "
    "being unknown as the access control.")
LEAK_REMEDIATION = (
    "Strip object data from error responses: an access-denied or "
    "validation error must return a generic code and message only - "
    "never the denied object's fields (the HackerOne #3862641 bug "
    "paid out because a 422 leaked the private report in "
    "context.subject). Audit error handlers/serializers for embedded "
    "context objects.")
COMBINED_REMEDIATION = (
    "Fix both halves: (1) enforce object-level authorization and "
    "prefer unguessable IDs - these IDs are sequential, so every "
    "object is enumerable; (2) make error responses generic so a "
    "denied request returns nothing about the object. Together they "
    "currently form a working IDOR read path: guess the next ID, get "
    "its data from the error body.")


class IdorLeakPlugin(Plugin):
    id = "idorleak"
    label = "IDOR Surface & Error Leak Mapper"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    phase = 2  # consumes the discovery bus populated by phase 1
    description = ("Map IDOR surface (sequential/UUID/template object IDs, "
                   ".json reference endpoints) from JS/specs/crawl data and "
                   "flag error responses that leak the denied object's data.")

    # -- source gathering ------------------------------------------------
    def _mine_text(self, text: str, source_kind: str,
                   out: List[Tuple[str, str]]) -> None:
        for m in ABS_URL_RE.finditer(text):
            out.append((m.group(0), source_kind))
        for m in PATH_STRING_RE.finditer(text):
            out.append((m.group(1), source_kind))

    async def _gather(self, target: Target, ctx: Ctx, base: str,
                      domain: str) -> List[Tuple[str, str]]:
        """(url-or-path, source_kind) candidates from every legit source."""
        cands: List[Tuple[str, str]] = []
        for kind in ("endpoints", "urls"):
            for u in ctx.consume(kind):
                if isinstance(u, str) and u:
                    cands.append((u, "crawl"))
        # Homepage (shared cache) - links, inline fetch() calls.
        page_url = base
        try:
            page = await ctx.fetch_page(base, timeout=25)
            if page is not None:
                page_url = page.get("url") or base
                self._mine_text(page.get("text", "")[:400000], "homepage",
                                cands)
        except Exception:
            pass
        # JS bundles published to the bus.
        js_urls = [u for u in ctx.consume("js_files")
                   if isinstance(u, str) and u][:MAX_JS_FETCH]
        for ju in js_urls:
            full = urljoin(page_url, ju)
            if not same_domain(full, domain):
                continue
            try:
                jp = await ctx.fetch_page(full, timeout=15)
                if jp is not None:
                    self._mine_text(jp.get("text", "")[:400000], "js_bundle",
                                    cands)
            except Exception:
                continue
        # OpenAPI / Swagger specs: candidates are any collected string
        # whose path smells like a spec; parse their path templates.
        spec_urls: List[str] = []
        for raw, _kind in cands:
            p = urlparse(raw if "://" in raw else
                         urljoin(base, raw)).path.lower()
            if any(h in p for h in SPEC_HINTS) and p.endswith(
                    (".json", ".yaml", ".yml", "/")):
                full = raw if "://" in raw else urljoin(base, raw)
                if full not in spec_urls and same_domain(full, domain):
                    spec_urls.append(full)
        for su in spec_urls[:MAX_SPEC_FETCH]:
            try:
                sp = await ctx.fetch_page(su, timeout=15)
                if sp is None or sp.get("status_code") != 200:
                    continue
                doc = json.loads(sp.get("text", ""))
                paths = doc.get("paths")
                if not isinstance(paths, dict):
                    continue
                for path_key, ops in paths.items():
                    methods = []
                    if isinstance(ops, dict):
                        methods = [m.upper() for m in ops.keys()
                                   if m.lower() in ("get", "post", "put",
                                                    "patch", "delete")]
                    cands.append((urljoin(base, path_key), "openapi_spec"))
                    if methods:
                        cands.append((f"{path_key}\t{'/'.join(methods)}",
                                      "spec_methods"))
            except Exception:
                continue
        return cands

    # -- main ------------------------------------------------------------
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        cands = await self._gather(target, ctx, base, domain)
        spec_methods: Dict[str, List[str]] = {}
        for raw, kind in cands:
            if kind == "spec_methods" and "\t" in raw:
                pth, meths = raw.split("\t", 1)
                info = split_id_path(urlparse(pth).path or pth)
                if info:
                    spec_methods[info["pattern"]] = meths.split("/")

        # Group candidates into endpoint patterns.
        groups: Dict[str, Dict[str, Any]] = {}
        for raw, kind in cands:
            if kind == "spec_methods":
                continue
            full = raw if "://" in raw else urljoin(base, raw)
            pr = urlparse(full)
            if pr.netloc and not same_domain(full, domain):
                continue
            info = split_id_path(pr.path or "")
            if info is None:
                continue
            g = groups.setdefault(info["pattern"], {
                "info": info, "samples": [], "sources": set(),
                "numeric_ids": [], "concrete": [],
            })
            g["sources"].add(kind)
            if full not in g["samples"]:
                g["samples"].append(full)
            if info["id_kind"] == "numeric":
                try:
                    g["numeric_ids"].append(int(info["id_value"]))
                except ValueError:
                    pass
                g["concrete"].append(full)
            elif info["id_kind"] in ("uuid", "hex"):
                g["concrete"].append(full)

        findings: List[Finding] = []
        probes_left = MAX_PROBES

        for pattern in sorted(groups.keys()):
            g = groups[pattern]
            info = g["info"]
            kind = info["id_kind"]
            sequential = ids_look_sequential(g["numeric_ids"])
            predictable = kind == "numeric" or (
                kind == "template" and sequential)
            sources = sorted(g["sources"])
            methods = spec_methods.get(pattern, [])

            # --- probe for error-response disclosure ------------------
            # One unauthenticated GET per concrete sample, exactly as
            # discovered (ctx.probe shares responses across the scan).
            leak: Optional[Dict[str, Any]] = None
            leak_status = 0
            leak_url = ""
            for sample in g["concrete"][:2]:
                if probes_left <= 0:
                    break
                probes_left -= 1
                try:
                    resp = await ctx.probe(sample, timeout=10)
                except Exception:
                    continue
                status = int(resp.get("status") or 0)
                if 400 <= status < 500:
                    hit = analyze_error_body(resp.get("text", ""))
                    if hit:
                        leak, leak_status, leak_url = hit, status, sample
                        break

            sev, conf = self._surface_rating(info, sequential, leak)
            base_evidence = {
                "severity": sev,
                "endpoint_pattern": pattern,
                "id_type": kind,
                "resource": info["resource"],
                "sequential_ids": sequential,
                "observed_ids": sorted(set(g["numeric_ids"]))[:10],
                "sample_endpoints": g["samples"][:5],
                "exposure_sources": sources,
                "spec_methods": methods,
                "reference_json_endpoint": info["reference_json"],
                "json_reference_style": info["json_endpoint"],
            }
            if leak and (predictable or info["reference_json"]):
                ev = dict(base_evidence)
                ev["severity"] = "high"
                ev.update({
                    "error_status": leak_status,
                    "probed_url": leak_url,
                    "leaked_field_paths": leak["field_paths"],
                    "leaked_fields": leak["leaked_fields"],
                    "leak_containers": leak["containers"],
                    "remediation": COMBINED_REMEDIATION,
                    "exploitability": "public_poc",
                    "scope_note": "Detection only: one unauthenticated "
                                  "request, ID exactly as published; no "
                                  "ID swapping, no credentials.",
                })
                findings.append(self._f(
                    "api", "idor_error_leak_path",
                    f"HIGH: IDOR/error-leak path on '{pattern}': "
                    f"{'sequential numeric IDs' if kind == 'numeric' else kind + ' IDs'} "
                    f"are enumerable and the {leak_status} error response "
                    f"leaks the denied object "
                    f"({', '.join(leak['field_paths'][:6])}). "
                    f"Leaked: {json.dumps(leak['leaked_fields'])[:600]}",
                    source="IDOR surface map + error-body analysis",
                    source_url=leak_url, confidence=90, passive=passive,
                    evidence=ev))
                continue
            if leak:
                ev = dict(base_evidence)
                ev.update({
                    "severity": "high",
                    "error_status": leak_status,
                    "probed_url": leak_url,
                    "leaked_field_paths": leak["field_paths"],
                    "leaked_fields": leak["leaked_fields"],
                    "leak_containers": leak["containers"],
                    "remediation": LEAK_REMEDIATION,
                    "exploitability": "public_poc",
                    "scope_note": "Detection only: response volunteered "
                                  "by the target to an unauthenticated "
                                  "request for the published URL.",
                })
                findings.append(self._f(
                    "api", "error_response_disclosure",
                    f"HIGH: {leak_status} error response from "
                    f"'{leak_url}' discloses object data: "
                    f"{json.dumps(leak['leaked_fields'])[:600]}",
                    source="error-body analysis", source_url=leak_url,
                    confidence=82, passive=passive, evidence=ev))
            # --- surface finding --------------------------------------
            if len(findings) < MAX_SURFACE_FINDINGS or leak:
                ev = dict(base_evidence)
                ev["remediation"] = SURFACE_REMEDIATION
                ev["exploitability"] = "theoretical"
                if info["reference_json"]:
                    ev["pattern_family"] = (
                        "Rails-style JSON reference endpoint; same "
                        "family as HackerOne #3862641 (IDOR via "
                        "/reports/{id}/reference.json error leak).")
                findings.append(self._f(
                    "api", "idor_surface",
                    self._surface_text(pattern, info, sequential, sources),
                    source="IDOR surface mining",
                    source_url=g["samples"][0] if g["samples"] else base,
                    confidence=conf, passive=passive, evidence=ev))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(groups)} IDOR-surface patterns, "
                       f"{len(findings)} findings")
        res.duration_ms = dur
        return res

    # -- ratings / text ----------------------------------------------------
    @staticmethod
    def _surface_rating(info: Dict[str, Any], sequential: bool,
                        leak: Optional[Dict[str, Any]]) -> Tuple[str, int]:
        if info["reference_json"]:
            return "high", 78
        if info["id_kind"] == "numeric":
            return ("high", 75) if sequential else ("medium", 62)
        if info["id_kind"] == "template":
            return "medium", 65
        return "low", 55  # uuid / hex: surface exists, IDs unguessable

    @staticmethod
    def _surface_text(pattern: str, info: Dict[str, Any], sequential: bool,
                      sources: List[str]) -> str:
        kind = info["id_kind"]
        if info["reference_json"]:
            risk = ("HIGH-RISK reference endpoint (HackerOne #3862641 "
                    "pattern family)")
        elif kind == "numeric" and sequential:
            risk = "sequential numeric IDs observed - trivially enumerable"
        elif kind == "numeric":
            risk = "numeric IDs - typically sequential and enumerable"
        elif kind == "template":
            risk = "templated object ID in a published API spec/route"
        else:
            risk = f"{kind} IDs - not guessable, surface only"
        return (f"IDOR surface: '{pattern}' exposes {info['resource']} "
                f"objects by {kind} ID ({risk}); exposed via "
                f"{', '.join(sources)}. Enforce object-level "
                f"authorization per ID.")
