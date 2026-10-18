"""AI Hunter: uncensored AI as a virtual human tester.

Automated scanners hit a wall on RCE, auth bypass, business logic flaws,
IDOR that needs an account, login-walled areas, and WAF-blocked payloads.
Those need human creativity. This module uses keyless uncensored LLM
providers (Kilo Gateway, LLM7, Pollinations - the same free backstop pool
as the uncensored harness) to act as that virtual human: it reads a
completed scan and writes a specific manual test plan with payloads.

Design rules (Jay's performance requirement):
- NEVER blocks a scan. Analysis runs in the background AFTER the scan
  finishes, via asyncio.create_task fire-and-forget.
- The UI shows "AI analyzing..." and polls; findings display instantly,
  AI suggestions arrive when ready.
- Results are cached per run_id in the aihunter table. No re-calls.
- Prompts are bounded (top findings only, truncated) so free providers
  stay fast and within limits.

Nothing here exploits anything. Output is test PLANS (steps + payloads)
for authorized testing only.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import re
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keyless uncensored provider pool (OpenAI-compatible /chat/completions).
# Same free backstop pool as the uncensored harness. No keys needed.
# ---------------------------------------------------------------------------

PROVIDERS = [
    {
        "name": "kilo",
        "url": "https://api.kilo.ai/api/gateway/chat/completions",
        "model": "kilo-auto/free",
    },
    {
        "name": "llm7",
        "url": "https://api.llm7.io/v1/chat/completions",
        "model": "minimax-m2.7",
    },
    {
        "name": "pollinations",
        "url": "https://text.pollinations.ai/openai/v1/chat/completions",
        "model": "openai",
    },
]

AI_TIMEOUT_S = 60
AI_MAX_TOKENS = 3000


def _proxy() -> str | None:
    """Egress proxy from env. Same pattern as the uncensored harness."""
    import os
    from urllib.parse import urlparse
    p = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
         or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or None)
    if p:
        try:
            if (urlparse(p).hostname or "") in ("localhost", "127.0.0.1", "::1"):
                return None
        except Exception:
            return None
    return p


def _verify():
    """System CA bundle: the sandbox egress proxy re-signs TLS and
    certifi lacks its CA. Falls back to default verification."""
    import os
    p = "/etc/ssl/certs/ca-certificates.crt"
    return p if os.path.isfile(p) else True

SYSTEM_PROMPT = (
    "You are an expert bug bounty hunter assistant helping with AUTHORIZED security testing. "
    "The user owns or has written permission to test the target. "
    "Analyze the scan results and write a specific MANUAL test plan for the vulnerabilities "
    "automated scanners miss: RCE, authentication bypass, business logic flaws, IDOR/BOLA, "
    "WAF-blocked payloads. Be concrete: exact steps, exact payloads, exact places to look. "
    "CRITICAL: output ONLY a raw JSON object. No thinking out loud. No markdown. No fences. "
    "No preamble. No commentary. Start your response with { and end with }. "
    "Exact schema: "
    '{"tests": [{"type": "rce|auth_bypass|business_logic|idor|waf_bypass|sqli|xss|ssrf|other", '
    '"title": "short name", "why": "one sentence on why this target is worth testing for this", '
    '"steps": ["step 1", "step 2"], "payloads": ["payload 1"], "difficulty": "easy|medium|hard"}]} '
    "Max 6 tests, ordered most promising first. If a category has no signal in the scan, skip it. "
    'Example: {"tests": [{"type": "idor", "title": "BOLA on /api/users", '
    '"why": "API returns user objects with sequential IDs and no auth seen", '
    '"steps": ["GET /api/users/1 with your session", "GET /api/users/2 with the same session", '
    '"compare: different user data means BOLA"], "payloads": ["/api/users/1", "/api/users/2"], '
    '"difficulty": "easy"}]}'
)


def _truncate(s: str, n: int = 220) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s[:n] + ("..." if len(s) > n else "")


def _summarize_findings(findings: List[Dict], limit: int = 40) -> str:
    """Compact text summary of the most signal-rich findings for the prompt."""
    # Prefer high-signal categories first
    prio = {"leak": 0, "vuln": 1, "api": 2, "auth": 3, "tech": 4, "config": 5}
    ordered = sorted(findings, key=lambda f: (prio.get(f.get("category"), 9), -(f.get("confidence") or 0)))
    lines = []
    for f in ordered[:limit]:
        lines.append(
            f"- [{f.get('category')}/{f.get('key')}] {_truncate(f.get('value'))} "
            f"(plugin={f.get('plugin_id') or f.get('plugin')}, conf={f.get('confidence')})"
        )
    return "\n".join(lines)


def _tech_stack(findings: List[Dict], limit: int = 15) -> str:
    techs = []
    for f in findings:
        if f.get("category") == "tech" and f.get("value"):
            techs.append(_truncate(f.get("value"), 120))
        if len(techs) >= limit:
            break
    return "; ".join(techs) or "unknown"


def _detect_waf(findings: List[Dict]) -> str:
    for f in findings:
        if f.get("plugin_id") == "waf" or f.get("key") == "waf_detected":
            return _truncate(f.get("value"), 120)
    return "none detected"


def build_analysis_prompt(target: str, findings: List[Dict],
                          candidates: List[Dict]) -> List[Dict]:
    """Build the chat messages for the AI test-plan call."""
    cand_lines = []
    for c in (candidates or [])[:5]:
        cand_lines.append(
            f"- {c.get('name')} (severity={c.get('severity')}, confidence={c.get('confidence')}): "
            f"{_truncate(c.get('why_viable'), 160)}"
        )
    user = (
        f"TARGET: {target}\n"
        f"TECH STACK: {_tech_stack(findings)}\n"
        f"WAF: {_detect_waf(findings)}\n\n"
        f"SCAN FINDINGS (top signals):\n{_summarize_findings(findings)}\n\n"
        f"HEURISTIC CANDIDATES (already flagged by the scanner):\n"
        + ("\n".join(cand_lines) if cand_lines else "(none)")
        + "\n\nWrite the manual test plan as JSON per the schema. Focus on what the "
          "automated scan could NOT confirm: RCE, auth bypass, business logic, IDOR, "
          "WAF bypasses."
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


async def ai_chat(messages: List[Dict]) -> tuple[str, str]:
    """Try each keyless provider in order. Returns (provider_name, text).

    Raises RuntimeError if every provider fails.
    """
    last_err: Optional[Exception] = None
    async with httpx.AsyncClient(timeout=AI_TIMEOUT_S, proxy=_proxy(),
                                 trust_env=False, verify=_verify()) as client:
        for p in PROVIDERS:
            try:
                r = await client.post(
                    p["url"],
                    json={
                        "model": p["model"],
                        "messages": messages,
                        "max_tokens": AI_MAX_TOKENS,
                        "temperature": 0.3,
                    },
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:150]}")
                data = r.json()
                choices = data.get("choices") or []
                if not choices:
                    raise RuntimeError("empty choices")
                msg = choices[0].get("message") or {}
                text = (msg.get("content") or "").strip()
                # Some free models put text in reasoning when content is null
                if not text:
                    text = (msg.get("reasoning") or "").strip()
                if not text:
                    raise RuntimeError("empty response")
                return p["name"], text
            except Exception as e:  # try next provider
                last_err = e
                logger.warning("ai_hunter: provider %s failed: %s", p["name"], str(e)[:120])
                continue
    raise RuntimeError(f"all AI providers failed: {str(last_err)[:200]}")


def _parse_markdown_tests(text: str) -> Optional[Dict]:
    """Fallback: extract tests from a markdown-ish test plan.

    Handles formats like:
        Test 1: Title here
        - Why: reason
        - Steps: 1. do x. 2. do y.
        - Payloads: `p1`, `p2`
    """
    tests: List[Dict] = []
    # Split on "Test N:" / "### Test N" / "**Test N**" headings
    chunks = re.split(r"(?im)^(?:#{1,4}\s*)?(?:\*\*)?test\s*\d+\s*[:\-.]?\s*(?:\*\*)?",
                      text)
    for chunk in chunks[1:]:  # [0] is preamble
        chunk = chunk.strip()
        if len(chunk) < 20:
            continue
        lines = chunk.split("\n")
        title = lines[0].strip().strip("*#: ").strip()[:140] or "Untitled"
        body = "\n".join(lines[1:])
        why = ""
        m = re.search(r"(?im)^\s*[-*]?\s*why\s*:\s*(.+)$", body)
        if m:
            why = m.group(1).strip()[:400]
        steps: List[str] = []
        m = re.search(r"(?im)^\s*[-*]?\s*steps\s*:\s*(.+?)(?=^\s*[-*]?\s*(?:payloads|why|difficulty)\s*:|\Z)",
                      body, re.S)
        if m:
            raw = m.group(1)
            steps = [s.strip(" .") for s in re.split(r"\d+\.\s+|\n\s*[-*]\s+", raw)
                     if s.strip(" .")][:10]
            steps = [s[:300] for s in steps if len(s) > 3]
        payloads: List[str] = []
        m = re.search(r"(?im)^\s*[-*]?\s*payloads\s*:\s*(.+?)(?=^\s*[-*]?\s*(?:why|steps|difficulty)\s*:|\Z)",
                      body, re.S)
        if m:
            raw = m.group(1)
            payloads = [p.strip(" `,;") for p in re.split(r"[,`\n]+", raw)
                        if p.strip(" `,;")][:10]
            payloads = [p[:300] for p in payloads if len(p) > 1]
        # Also catch inline backtick payloads anywhere in the chunk
        if not payloads:
            payloads = list(dict.fromkeys(
                p[:300] for p in re.findall(r"`([^`\n]{2,120})`", chunk)))[:10]
        diff = "medium"
        m = re.search(r"(?im)difficulty\s*:\s*(easy|medium|hard)", body)
        if m:
            diff = m.group(1).lower()
        # Guess type from title/body keywords
        blob = (title + " " + body).lower()
        vtype = "other"
        for kw, vt in (("rce", "rce"), ("remote code", "rce"),
                       ("auth bypass", "auth_bypass"), ("authentication bypass", "auth_bypass"),
                       ("business logic", "business_logic"), ("price", "business_logic"),
                       ("idor", "idor"), ("bola", "idor"),
                       ("waf", "waf_bypass"), ("bypass", "waf_bypass"),
                       ("sqli", "sqli"), ("sql injection", "sqli"),
                       ("xss", "xss"), ("cross-site", "xss"),
                       ("ssrf", "ssrf")):
            if kw in blob:
                vtype = vt
                break
        if steps or payloads or why:
            tests.append({"type": vtype, "title": title, "why": why,
                          "steps": steps, "payloads": payloads,
                          "difficulty": diff})
        if len(tests) >= 8:
            break
    return {"tests": tests} if tests else None


def _extract_json(text: str) -> Dict:
    """Pull the tests JSON out of a model response, defensively.

    Tries every '{' as a candidate start and uses raw_decode so nested
    braces and trailing chatter don't break parsing.
    """
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    decoder = json.JSONDecoder()
    best: Optional[Dict] = None
    for m in re.finditer(r"\{", t):
        try:
            obj, _ = decoder.raw_decode(t[m.start():])
        except Exception:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("tests"), list) and obj["tests"]:
            best = obj
            break
    if best is None:
        # Fallback: the model wrote a markdown test plan instead of JSON
        md = _parse_markdown_tests(text)
        if md:
            best = md
    if best is None:
        raise ValueError("no usable tests JSON in AI response")
    clean = []
    for item in best["tests"][:8]:
        if not isinstance(item, dict):
            continue
        clean.append({
            "type": str(item.get("type", "other"))[:30],
            "title": str(item.get("title", "Untitled"))[:140],
            "why": str(item.get("why", ""))[:400],
            "steps": [str(s)[:300] for s in (item.get("steps") or [])][:10],
            "payloads": [str(p)[:300] for p in (item.get("payloads") or [])][:10],
            "difficulty": str(item.get("difficulty", "medium"))[:10],
        })
    if not clean:
        raise ValueError("AI response had no usable tests")
    return {"tests": clean}


# ---------------------------------------------------------------------------
# Local (no-AI) helpers: fast, deterministic, always available.
# ---------------------------------------------------------------------------

def waf_bypass_payloads(waf: str, payload: str) -> Dict:
    """Mutate a payload with common WAF-evasion transforms.

    Local and instant. Covers generic tricks; the AI layer adds
    WAF-specific suggestions when it analyzes the scan.
    """
    w = (waf or "").lower()
    variants: List[Dict] = []

    def add(name: str, p: str, note: str):
        variants.append({"name": name, "payload": p, "note": note})

    add("original", payload, "Baseline payload, no evasion.")
    # Case variation
    if "<" in payload:
        add("case-mix", re.sub(r"[a-zA-Z]", lambda m: m.group(0).upper()
                               if hash(m.group(0)) % 2 else m.group(0).lower(), payload),
            "Mixed case defeats naive keyword filters.")
    # HTML comment injection
    if "<script" in payload.lower():
        add("comment-split",
            payload.replace("<script", "<scr<!--x-->ipt", 1),
            "Comment breaks up blocked keywords.")
    # URL double encoding
    from urllib.parse import quote
    add("double-encode", quote(quote(payload, safe=""), safe=""),
        "Double URL-encoding vs decoders that run once.")
    # Unicode overlong / alternative encodings for quotes
    if "'" in payload:
        add("quote-variants", payload.replace("'", "%u0027"),
            "Unicode quote vs filters looking for ASCII quotes.")
    # Whitespace alternatives for SQLi
    if " " in payload and any(k in payload.upper() for k in ("SELECT", "UNION", "OR ", "AND ")):
        for ws_name, ws in (("tab", "\t"), ("newline", "\n"), ("comment-ws", "/**/")):
            add(f"ws-{ws_name}", payload.replace(" ", ws),
                f"Alternate whitespace ({ws_name}) vs space blacklists.")
    # Null byte
    add("null-byte", payload + "%00",
        "Null byte truncation on older stacks.")

    notes = []
    if "cloudflare" in w:
        notes.append("Cloudflare: try JSON content-type smuggling and header case tricks; "
                     "its managed rules key on known CVE signatures more than generic payloads.")
    elif "akamai" in w:
        notes.append("Akamai Kona: tries param pollution (duplicate params) and "
                     "HTTP method override headers (X-HTTP-Method-Override).")
    elif "aws" in w or "waf" in w:
        notes.append("AWS WAF: rule groups are regex based; nested encodings and "
                     "mixed multipart boundaries often slip through.")
    if not notes:
        notes.append("Generic transforms above. Run the AI Hunter analysis for "
                     "payload ideas tuned to this target's stack.")

    return {"waf": waf or "unknown", "variants": variants, "notes": notes,
            "disclaimer": "Detection payloads for authorized testing only."}


def auth_bypass_playbook(auth_signals: List[str]) -> List[Dict]:
    """Local playbook: bypass techniques matched to detected auth signals."""
    signals = {s.lower() for s in auth_signals}
    playbook: List[Dict] = []

    def add(title: str, when: str, steps: List[str]):
        playbook.append({"title": title, "when": when, "steps": steps})

    if any("jwt" in s for s in signals) or not signals:
        add("JWT alg confusion / none",
            "JWT tokens observed",
            ["Decode the header locally (no requests).",
             "If alg is 'none', strip the signature and resend.",
             "If HS256, try common secrets (secret, password, the app name).",
             "Try alg confusion: RS256 public key as HS256 secret."])
    if any("login" in s or "form" in s for s in signals) or not signals:
        add("Login logic flaws",
            "Login form observed",
            ["Try SQLi in username: admin' -- with any password.",
             "Try response manipulation: intercept and change 'false' to 'true'.",
             "Try parameter pollution: add &role=admin to the POST body.",
             "Check for verbose errors that leak valid usernames."])
    if any("session" in s or "cookie" in s for s in signals) or not signals:
        add("Session / cookie tampering",
            "Session cookies observed",
            ["Decode the cookie: base64? JSON with a role field?",
             "Flip role/user values and re-encode.",
             "Test for fixation: does the app accept a self-set session id?",
             "Check Secure/HttpOnly/SameSite flags; missing flags widen impact."])
    if any("oauth" in s or "sso" in s for s in signals):
        add("OAuth flow abuse",
            "OAuth/SSO observed",
            ["Drop the 'state' param; some apps skip CSRF checks.",
             "Swap the redirect_uri to an attacker domain (open redirect check).",
             "Replay an old authorization code twice."])
    if any("basic" in s for s in signals):
        add("HTTP basic auth brute-force surface",
            "Basic auth observed",
            ["Enumerate with a small default-credential list only.",
             "Check for missing rate limiting (429 responses)."])
    return playbook


def business_logic_targets(findings: List[Dict]) -> List[Dict]:
    """Extract money/logic parameters from findings for manual testing."""
    targets: List[Dict] = []
    seen = set()
    patterns = [
        (re.compile(r"price|amount|total|cost", re.I), "price",
         ["Negative value (-1)", "Zero (0)", "Huge value (99999999)",
          "Decimal precision (19.999)", "Currency switch if multi-currency"]),
        (re.compile(r"quant|qty|count", re.I), "quantity",
         ["Negative quantity", "Zero quantity", "Fractional (1.5)",
          "Race two checkouts at once (double-spend check)"]),
        (re.compile(r"coupon|promo|discount|voucher", re.I), "coupon",
         ["Reuse a single-use coupon twice", "Stack two coupons",
          "Brute-force short coupon codes", "Apply expired coupon"]),
        (re.compile(r"referral|reward|points|credit|balance", re.I), "rewards",
         ["Self-referral loop", "Negative point redemption",
          "Race condition on balance deduction"]),
        (re.compile(r"role|admin|privilege|is_admin", re.I), "privilege",
         ["Add role=admin to requests", "Access admin endpoints directly",
          "IDOR across user ids on account endpoints"]),
    ]
    for f in findings:
        val = f.get("value") or ""
        for rx, kind, ideas in patterns:
            if rx.search(val):
                key = (kind, val[:80])
                if key in seen:
                    continue
                seen.add(key)
                targets.append({
                    "kind": kind,
                    "where": _truncate(val, 160),
                    "source": f.get("source_url") or f.get("source") or "",
                    "test_ideas": ideas,
                })
                if len(targets) >= 12:
                    return targets
    return targets


# ---------------------------------------------------------------------------
# Background pipeline: gather -> prompt -> AI -> parse -> store.
# ---------------------------------------------------------------------------

def _gather(run_id: str) -> tuple[str, List[Dict], List[Dict]]:
    """Load target label, findings, heuristic candidates for a run."""
    from .models import Run, Target, get_session
    from .reporting import findings_dump
    from .vuln_advisor import advise
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise ValueError("run not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id)
        label = ""
        if targets:
            label = targets[0].normalized or targets[0].raw or run_id
        summary = {"targets": [{"raw": t.raw, "normalized": t.normalized} for t in targets]}
        candidates = advise(rows, summary)
        return label or run_id, rows, candidates
    finally:
        session.close()


def _store_result(run_id: str, status: str, provider: str = "",
                  results: Optional[Dict] = None, error: str = ""):
    from .models import AIHunter, get_session
    session = get_session()
    try:
        row = session.query(AIHunter).filter_by(run_id=run_id).first()
        now = dt.datetime.now(dt.timezone.utc)
        if row:
            row.status = status
            row.provider = provider
            row.results = results or {}
            row.error = error
            row.updated_at = now
        else:
            session.add(AIHunter(run_id=run_id, status=status, provider=provider,
                                 results=results or {}, error=error,
                                 updated_at=now))
        session.commit()
    finally:
        session.close()


def get_ai_status(run_id: str) -> Dict:
    """Read cached AI Hunter state for a run."""
    from .models import AIHunter, get_session
    session = get_session()
    try:
        row = session.query(AIHunter).filter_by(run_id=run_id).first()
        if not row:
            return {"status": "idle", "results": None, "provider": "",
                    "error": "", "updated_at": None}
        return {"status": row.status, "results": row.results,
                "provider": row.provider, "error": row.error,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None}
    finally:
        session.close()


async def run_ai_analysis(run_id: str):
    """Full pipeline: gather scan data, ask the AI, store the test plan.

    Runs in the background. Never raises to the caller; failures are
    recorded in the DB so the UI can show retry.
    """
    try:
        _store_result(run_id, "analyzing")
        target, findings, candidates = await asyncio.to_thread(_gather, run_id)
        if not findings:
            _store_result(run_id, "failed", error="no findings to analyze")
            return
        messages = build_analysis_prompt(target, findings, candidates)
        provider, text = await ai_chat(messages)
        results = await asyncio.to_thread(_extract_json, text)
        # Attach local helpers so the UI has everything in one payload
        auth_signals = sorted({(f.get("key") or "") for f in findings
                               if f.get("category") == "auth" and f.get("key")})
        results["auth_playbook"] = auth_bypass_playbook(list(auth_signals))
        results["business_logic"] = business_logic_targets(findings)
        results["target"] = target
        results["disclaimer"] = ("AI-generated test plan for AUTHORIZED testing only. "
                                 "Verify every suggestion manually before use.")
        _store_result(run_id, "ready", provider=provider, results=results)
        logger.info("ai_hunter: analysis ready for run %s via %s", run_id, provider)
    except Exception as e:
        logger.warning("ai_hunter: analysis failed for run %s: %s", run_id, str(e)[:200])
        _store_result(run_id, "failed", error=str(e)[:300])


def launch_ai_analysis(run_id: str):
    """Fire-and-forget: start AI analysis without blocking the caller.

    Safe to call from sync or async contexts.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        loop.create_task(run_ai_analysis(run_id))
    else:
        # No running loop (e.g. called from a thread): run in background thread
        import threading

        def _runner():
            asyncio.run(run_ai_analysis(run_id))

        t = threading.Thread(target=_runner, daemon=True,
                             name=f"ai-hunter-{run_id}")
        t.start()
