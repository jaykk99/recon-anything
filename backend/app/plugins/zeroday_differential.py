"""Zero-Day Candidate Hunter: web differential mutations.

Checklist scanners test inputs against KNOWN bug signatures. This
hunter works the other way: it takes a baseline response for a real
endpoint+parameter, mutates ONLY the shape of the scanner's own
request - type juggles (string to array / object / null / number),
duplicate parameters, missing parameters, malformed encodings,
malformed JSON bodies, wrong content types - and flags behavior no
checklist predicted:

- the endpoint crashes (5xx) on a shape it should simply reject,
- debug output / stack traces appear that the baseline never shows,
- an invalid input returns a DATA-shaped response (the classic
  array-parameter-returns-everything bug class) where the baseline
  returned an error or a single record,
- a confirmed >5x timing blow-up on a mutation.

Every flag is a CANDIDATE (see zeroday_util): labeled
candidate_zero_day, confidence-scored, severity capped at high,
evidence = request/response metadata + response field names. When a
mutation returns data it should not, the finding records the response
SHAPE (status, size, field names) - the returned records themselves
are never copied into the finding.

Boundary: mutations are harmless re-shapings of the scanner's own
requests. No exploit payloads, nothing written or deleted, no
credentials. GET endpoints with state-changing URL hints are skipped
(same list as param_fuzzer). Passive mode NEVER sends a mutation:
the plugin reports ok(0) with a note instead.

Relationship to param_fuzzer: that plugin ADDS unknown parameters
from a wordlist and diffs generically. This hunter mutates the VALUES
and TYPES of parameters the target actually uses, sends body-level
mutations to API endpoints, and only reports anomalies strong enough
to be candidate-worthy (crash, disclosure, data-shape, timing) -
generic length/status wiggles stay with param_fuzzer.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain
from .param_fuzzer import STATE_CHANGING_HINTS
from .zeroday_util import (candidate_evidence, mine_disclosures)

MAX_ENDPOINTS = 4
MAX_PARAMS_PER_ENDPOINT = 2
MAX_FINDINGS = 20
REQ_TIMEOUT = 8
BLOCK_STREAK = 3            # consecutive WAF/block responses -> stop
TIME_FACTOR = 5.0           # candidate needs >5x baseline ...
TIME_FLOOR_S = 1.0          # ... and at least this much slower

REMEDIATION = ("Treat this as an unproven lead, not a verdict: replay "
               "the recorded mutation by hand against a staging copy. "
               "If the behavior reproduces, the endpoint is trusting "
               "client-supplied input shape - validate parameter types "
               "server-side, reject duplicates and unexpected shapes, "
               "and make error responses uniform.")


# ---------------------------------------------------------------------
# Pure helpers (unit-tested without any network)
# ---------------------------------------------------------------------

def _params(url: str) -> List[Tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def _rebuild(url: str, params: List[Tuple[str, str]]) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(query=urlencode(params)))


def mutations_for(url: str, param: str) -> List[Dict[str, str]]:
    """Query-string mutations of one parameter of a URL.

    Returns [{name, url, description}]. Only the named parameter is
    re-shaped; every other parameter is preserved verbatim.
    """
    params = _params(url)
    base_val = next((v for k, v in params if k == param), "1")
    others = [(k, v) for k, v in params if k != param]
    out: List[Dict[str, str]] = []

    def add(name: str, new_params: List[Tuple[str, str]], desc: str,
            raw_url: Optional[str] = None) -> None:
        out.append({"name": name,
                    "url": raw_url or _rebuild(url, new_params),
                    "description": desc})

    add("array_type", others + [(param + "[]", base_val),
                                (param + "[]", base_val)],
        "parameter sent as an array (name[] twice)")
    add("duplicate_param", others + [(param, base_val),
                                     (param, base_val + "2")],
        "parameter sent twice with conflicting values")
    add("null_value", others + [(param, "null")],
        "parameter set to the literal string 'null'")
    add("empty_value", others + [(param, "")],
        "parameter emptied")
    add("negative_number", others + [(param, "-1")],
        "parameter set to -1")
    add("zero_value", others + [(param, "0")],
        "parameter set to 0")
    add("huge_number", others + [(param, "99999999999999999999999999")],
        "parameter set to a number beyond 64-bit range")
    add("object_value", others + [(param, '{"__zd":1}')],
        "parameter set to a JSON object literal")
    add("missing_param", others,
        "parameter removed entirely")
    # Malformed encoding: string surgery so the raw %C3 (a truncated
    # UTF-8 sequence) reaches the server un-re-encoded.
    parts = urlparse(url)
    raw_q = parts.query
    needle = f"{quote(param, safe='')}={quote(base_val, safe='')}"
    if needle in raw_q:
        raw = raw_q.replace(needle, f"{quote(param, safe='')}=%C3", 1)
        add("malformed_encoding", [],
            "parameter value is a truncated UTF-8 byte sequence",
            raw_url=urlunparse(parts._replace(query=raw)))
    return out


def body_mutations(params: List[Tuple[str, str]]) -> List[Dict[str, str]]:
    """JSON-body mutations built from an endpoint's real parameters."""
    if not params:
        return []
    fields = {k: v for k, v in params}
    first = params[0][0]
    juggled = dict(fields)
    juggled[first] = [fields[first], fields[first]]
    obj = dict(fields)
    obj[first] = {"__zd": 1}
    nulls = dict(fields)
    nulls[first] = None
    return [
        {"name": "json_array_value",
         "body": json.dumps(juggled),
         "content_type": "application/json",
         "description": f"JSON body: '{first}' sent as an array"},
        {"name": "json_object_value",
         "body": json.dumps(obj),
         "content_type": "application/json",
         "description": f"JSON body: '{first}' sent as an object"},
        {"name": "json_null_value",
         "body": json.dumps(nulls),
         "content_type": "application/json",
         "description": f"JSON body: '{first}' sent as null"},
        {"name": "json_truncated",
         "body": '{"' + first + '": ',
         "content_type": "application/json",
         "description": "JSON body truncated mid-value"},
        {"name": "json_wrong_content_type",
         "body": json.dumps(fields),
         "content_type": "text/plain",
         "description": "JSON body sent with a text/plain content type"},
    ]


_ERROR_KEYS = {"error", "errors", "message", "code", "status",
               "detail", "title", "trace", "exception"}


def json_shape(text: str) -> Optional[Tuple[str, Any]]:
    """Classify a body: ('object', keyset) / ('list', count) / None."""
    try:
        data = json.loads(text)
    except Exception:
        return None
    if isinstance(data, dict):
        keys = set()
        stack = [data]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                for k, v in cur.items():
                    keys.add(str(k))
                    stack.append(v)
            elif isinstance(cur, list):
                stack.extend(cur)
        return ("object", keys)
    if isinstance(data, list):
        return ("list", len(data))
    return ("scalar", None)


def _error_shaped(status: int, text: str) -> bool:
    if status >= 400:
        return True
    shape = json_shape(text)
    if shape and shape[0] == "object":
        return bool(shape[1]) and shape[1] <= _ERROR_KEYS
    return not text.strip()


def evaluate_anomaly(base: Dict[str, Any],
                     mut: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare a mutated response to baseline; return strong signals.

    base/mut: {status, text, elapsed}. Only candidate-grade signals
    are returned: crash, debug disclosure, data-shaped response to
    invalid input, field-set growth. Generic wiggles return [].
    """
    signals: List[Dict[str, Any]] = []
    b_status, m_status = base["status"], mut["status"]
    b_text, m_text = base.get("text", ""), mut.get("text", "")

    base_disc = {(d["kind"], d["match"])
                 for d in mine_disclosures(b_text)}
    new_disc = [d for d in mine_disclosures(m_text)
                if (d["kind"], d["match"]) not in base_disc]
    debug_new = [d for d in new_disc
                 if d["kind"] in ("debug_output", "internal_file_path")]

    if m_status >= 500 and b_status < 500:
        conf, sev = 65, "medium"
        if debug_new:
            conf, sev = 82, "high"
        signals.append({
            "anomaly": "crash_on_mutation", "confidence": conf,
            "severity": sev,
            "detail": f"status {b_status} -> {m_status} on a "
                      f"shape-only change"})
    elif debug_new:
        signals.append({
            "anomaly": "debug_disclosure_on_mutation", "confidence": 75,
            "severity": "high",
            "detail": "mutation surfaced debug output the baseline "
                      "never shows: " + "; ".join(
                          d["match"] for d in debug_new[:3])})

    b_shape, m_shape = json_shape(b_text), json_shape(m_text)
    if m_status == 200 and _error_shaped(b_status, b_text):
        data_keys = set()
        if m_shape and m_shape[0] == "object":
            data_keys = m_shape[1] - _ERROR_KEYS
        if data_keys or (m_shape and m_shape[0] == "list"
                         and m_shape[1] >= 2):
            signals.append({
                "anomaly": "data_shaped_response_to_invalid_input",
                "confidence": 72, "severity": "high",
                "detail": "baseline rejected the request, the mutated "
                          "shape returned data"
                          + (f" (fields: {', '.join(sorted(data_keys)[:10])})"
                             if data_keys else " (a list)")})
    elif (b_shape and m_shape and b_shape[0] == "object"
          and m_shape[0] == "object" and m_status == 200):
        new_keys = (m_shape[1] - b_shape[1]) - _ERROR_KEYS
        grew = len(m_text) > len(b_text) * 1.3
        if len(new_keys) >= 2 and grew:
            signals.append({
                "anomaly": "response_field_growth", "confidence": 60,
                "severity": "medium",
                "detail": "mutated shape returned fields the baseline "
                          "never returns: " + ", ".join(
                              sorted(new_keys)[:8])})
    elif (b_shape and m_shape and b_shape[0] == "object"
          and m_shape[0] == "list" and m_status == 200
          and m_shape[1] >= 2):
        signals.append({
            "anomaly": "data_shaped_response_to_invalid_input",
            "confidence": 70, "severity": "high",
            "detail": "baseline returned one record, the mutated "
                      "shape returned a list of records"})
    return signals


# ---------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------

class ZerodayDifferentialPlugin(Plugin):
    id = "zeroday_differential"
    label = "Zero-Day Candidate Hunter (Differential)"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    phase = 2
    timeout_s = 180
    description = ("Mutates the types/shapes of parameters a target "
                   "actually uses (arrays, duplicates, nulls, huge "
                   "numbers, malformed bodies) and flags crash, debug "
                   "disclosure, data-shaped or timing anomalies as "
                   "candidate zero-days for human review.")

    async def _send(self, ctx: Ctx, method: str, url: str,
                    **kw) -> Optional[Dict[str, Any]]:
        t0 = time.monotonic()
        try:
            resp = await fetch(ctx.http, ctx.limiter, method, url,
                               timeout=REQ_TIMEOUT, follow_redirects=True,
                               max_retries=0, **kw)
        except Exception:
            return None
        return {"status": resp.status_code, "text": resp.text or "",
                "elapsed": max(time.monotonic() - t0, 0.001),
                "headers": {k.lower(): v for k, v in resp.headers.items()}}

    @staticmethod
    def _blocked(resp: Dict[str, Any]) -> bool:
        if resp["status"] in (403, 406, 429):
            body = resp["text"][:2000].lower()
            return any(w in body for w in
                       ("blocked", "waf", "captcha", "access denied",
                        "request rejected", "security")) \
                or resp["status"] in (406, 429)
        return False

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._skipped(
                "passive mode: differential mutations are never sent "
                "in passive mode")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        # Endpoints with real parameters, same-domain, non-stateful.
        work: List[Tuple[str, str]] = []   # (endpoint, param)
        seen_ep = set()
        for eu in ctx.consume("endpoints"):
            u = str(eu)
            p = urlparse(u)
            if not p.netloc or not same_domain(u, domain):
                continue
            low = (p.path + "?" + p.query).lower()
            if any(h in low for h in STATE_CHANGING_HINTS):
                continue
            params = _params(u)
            if not params:
                continue
            if u in seen_ep:
                continue
            seen_ep.add(u)
            for name, _v in params[:MAX_PARAMS_PER_ENDPOINT]:
                work.append((u, name))
            if len(seen_ep) >= MAX_ENDPOINTS:
                break

        findings: List[Finding] = []
        tested = 0
        stopped = 0
        for endpoint in sorted({u for u, _ in work}):
            if len(findings) >= MAX_FINDINGS:
                break
            base = await self._send(ctx, "GET", endpoint)
            if base is None:
                continue
            tested += 1
            block_streak = 0
            ep_params = [pr for u, pr in work if u == endpoint]
            for param in ep_params:
                if len(findings) >= MAX_FINDINGS or block_streak >= BLOCK_STREAK:
                    break
                for mut in mutations_for(endpoint, param):
                    resp = await self._send(ctx, "GET", mut["url"])
                    if resp is None:
                        continue
                    if self._blocked(resp):
                        block_streak += 1
                        if block_streak >= BLOCK_STREAK:
                            stopped += 1
                            break
                    else:
                        block_streak = 0
                    for sig in evaluate_anomaly(base, resp):
                        findings.append(self._candidate(
                            endpoint, param, mut, base, resp, sig))
                    # timing: >5x baseline, confirmed against a
                    # FRESH baseline re-request. Elapsed time here
                    # includes rate-limiter pacing, which inflates
                    # later requests systematically (observed: a
                    # paced limiter made every 7th+ request ~1s and
                    # produced false timing candidates on a clean
                    # target). A mutation only counts as slow if it
                    # is slow while a baseline re-request, taken
                    # under the same pacing, stays fast.
                    if (resp["elapsed"] > base["elapsed"] * TIME_FACTOR
                            and resp["elapsed"] - base["elapsed"]
                            > TIME_FLOOR_S):
                        again = await self._send(ctx, "GET", mut["url"])
                        fresh = await self._send(ctx, "GET", endpoint)
                        if (again and fresh
                                and again["elapsed"]
                                > fresh["elapsed"] * TIME_FACTOR
                                and again["elapsed"] - fresh["elapsed"]
                                > TIME_FLOOR_S):
                            findings.append(self._candidate(
                                endpoint, param, mut, base, resp, {
                                    "anomaly": "timing_anomaly",
                                    "confidence": 55, "severity": "medium",
                                    "detail": f"response time "
                                              f"{base['elapsed']:.2f}s -> "
                                              f"{resp['elapsed']:.2f}s "
                                              f"(repeat {again['elapsed']:.2f}s "
                                              f"vs fresh baseline "
                                              f"{fresh['elapsed']:.2f}s)"}))
            # body mutations for API-shaped endpoints (once per endpoint)
            path = urlparse(endpoint).path.lower()
            if "/api" in path and block_streak < BLOCK_STREAK \
                    and len(findings) < MAX_FINDINGS:
                for bm in body_mutations(_params(endpoint)):
                    resp = await self._send(
                        ctx, "POST", endpoint, content=bm["body"],
                        headers={"Content-Type": bm["content_type"]})
                    if resp is None:
                        continue
                    for sig in evaluate_anomaly(base, resp):
                        findings.append(self._candidate(
                            endpoint, _params(endpoint)[0][0],
                            {"name": bm["name"], "url": endpoint,
                             "description": bm["description"]},
                            base, resp, sig))
            self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        note = f"{tested} endpoints differentially mutated, " \
               f"{len(findings)} candidate anomalies"
        if stopped:
            note += f"; {stopped} endpoint set(s) stopped on WAF/block"
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res

    def _candidate(self, endpoint: str, param: str, mut: Dict[str, str],
                   base: Dict[str, Any], resp: Dict[str, Any],
                   sig: Dict[str, Any]) -> Finding:
        shape = json_shape(resp["text"])
        shape_desc = ""
        if shape and shape[0] == "object":
            shape_desc = "object fields: " + ", ".join(
                sorted(shape[1])[:12])
        elif shape and shape[0] == "list":
            shape_desc = f"list of {shape[1]} items"
        ev = candidate_evidence(
            "differential", sig["anomaly"], sig["confidence"],
            severity=sig["severity"], extra={
                "endpoint": endpoint, "parameter": param,
                "mutation": mut["name"],
                "mutation_detail": mut["description"],
                "request_url": mut["url"],
                "baseline": {"status": base["status"],
                             "length": len(base["text"]),
                             "ms": int(base["elapsed"] * 1000)},
                "response": {"status": resp["status"],
                             "length": len(resp["text"]),
                             "ms": int(resp["elapsed"] * 1000),
                             "shape": shape_desc},
                "signal": sig["detail"],
                "remediation": REMEDIATION,
            })
        return self._f(
            "web", "candidate_zero_day",
            f"CANDIDATE (not yet verified): parameter '{param}' at "
            f"{urlparse(endpoint).path or '/'} - {sig['detail']} "
            f"[mutation: {mut['description']}]",
            source="zero-day differential hunter",
            source_url=mut["url"], confidence=sig["confidence"],
            passive=False, evidence=ev)
