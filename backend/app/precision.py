"""Precision gate: a claim is only presentable as a weakness when the
run's own captured evidence proves it.

The registry is wide (1200+ plugins) and every detector that fires also
writes a finding, so the failure mode that matters is not missing
something - it is asserting something that is not there: a CVE matched
against a version the page never disclosed, a "takeover" on a CNAME that
still resolves, a "missing header" report on a page that never loaded, a
backup file "found" on a 403, a sample key from documentation.

This module is the deterministic countermeasure, and it is deliberately
narrow in what it may take away:

* SUPPRESS (``claim_status="suppressed"``) only on *positive
  contradiction*: the server answered 403/404/410, the key says the port
  is closed while another row says open, the credential matches a known
  placeholder, the contract validator already adjudicated
  FALSE_POSITIVE. Nothing is deleted - the row is kept, flagged
  ``suppressed``, scored into the weak tier and sorted last, so the
  hidden count stays visible (the same contract ``confidence.py`` keeps).
* DEMOTE (``claim_status="candidate"``) when the claim is legitimate but
  the evidence that would make it real is missing. The row is never
  presented as confirmed: its score is capped in the ``likely`` band and
  ``needs_manual_verification`` names exactly what is missing.
* VERIFY (``claim_status="verified"``) when the row carries the proof its
  claim class requires: an HTTP 2xx with captured content, a version the
  page actually disclosed, an unclaimed CNAME target, a credential-shaped
  value in the target's own asset, a measured-receipt contract verdict, a
  decoded JWT, a captured payload/response marker.

Pure functions over the finding dicts ``reporting.findings_dump``
produces; read-time, so runs finalized before this existed get the same
adjudication. Never raises: a gate bug must not break a run view - the
worst case a row keeps whatever the plugin claimed.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

CLAIM_VERIFIED = "verified"
CLAIM_CANDIDATE = "candidate"
CLAIM_SUPPRESSED = "suppressed"
CLAIM_UNJUDGED = "unjudged"

CLAIM_LABELS = {
    CLAIM_VERIFIED: "Verified by captured evidence",
    CLAIM_CANDIDATE: "Candidate - evidence incomplete",
    CLAIM_SUPPRESSED: "Suppressed - contradicted by evidence",
    CLAIM_UNJUDGED: "Not graded",
}

# Score ceilings. A candidate can never sit in the "confirmed" tier
# (>= 75 in confidence.py); a suppressed row is floored into "weak".
CANDIDATE_SCORE_CAP = 70
SUPPRESSED_SCORE_CAP = 20

_STATUS_KEYS = ("status", "status_code", "http_status", "response_status",
                "code", "http_code")
_STATUS_IN_TEXT = re.compile(r"\b(?:returned|responded|response|status|"
                             r"http)\D{0,12}([1-5]\d{2})\b", re.I)

# Families. The order matters: the first match wins, and the specific
# secret / contract families must win over the generic web-vuln one.
_SECRET_RE = re.compile(
    r"(secret|password|passwd|private[_-]?key|privkey|mnemonic|"
    r"seed[_-]?phrase|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"bearer[_-]?token|credential|webhook|conn[_-]?string|keystore|"
    r"wallet[_-]?key|session[_-]?token|"
    r"(aws|gcp|azure|stripe|slack|github|openai|anthropic|binance|okx|"
    r"bybit|kucoin|paypal|twilio|sendgrid|mailgun|npm|discord)"
    r"[_-]?(key|secret|token|pass))", re.I)
# A credential name that ends in the thing: token_key, exposed_aws_key,
# hardcoded_password, private_key_base58 ...
_SECRET_SUFFIX_RE = re.compile(
    r"(_key|_keys|_token|_secret|_password|_passwd|_passphrase|"
    r"_credential|_credentials|_webhook|_dsn|_privkey|_keystore|_seed|"
    r"_mnemonic)$", re.I)
_CVE_RE = re.compile(r"(cve|kev|vuln[_-]?(js|lib|osv)|osv_)", re.I)
_TAKEOVER_RE = re.compile(r"(takeover|dangling[_-]?cname|cname[_-]?claim)",
                          re.I)
_EXPOSURE_RE = re.compile(
    r"(exposed|exposure|artifact_|git_|_git\b|\.git|dotenv|_env\b|env_|"
    r"backup_|_backup|dump|sourcemap|source_map|listing|phpinfo|"
    r"hprof|crash[_-]?dump|heap[_-]?dump|debug[_-]?symbol|pdb|wasm_|"
    r"db_|s3_|bucket|open_?dir|directory_listing|config_?leak)", re.I)
_WEB_VULN_RE = re.compile(
    r"(xss|sqli|sql[_-]?injection|rce|ssrf|cmdi|command[_-]?inj|"
    r"traversal|lfi|rfi|open[_-]?redirect|redirect|ssti|xxe|deserial|"
    r"nosqli|ldapi|prototype[_-]?poll|smuggl|idor|bola|csrf|race|"
    r"introspection|jwt_|cors|misconfig|htmli|xpathi|business[_-]?logic|"
    r"mass[_-]?assign|host[_-]?header|crlf|header[_-]?inj|log4|jndi|"
    r"oauth|saml|webauthn|graphql_?deep)", re.I)
_HYGIENE_RE = re.compile(
    r"(header|cookie|hsts|csp|clickjack|sri|mixed[_-]?content|"
    r"cache[_-]control|security[_-]?txt|tls|ssl|spf|dmarc|dkim|bimi|"
    r"mta[_-]?sts|caa|ocsp|http2|alt[_-]?svc|hsts)", re.I)
_SERVICE_RE = re.compile(r"(port_|_port|banner|service_|open_port|"
                         r"db_?expos|database_port)", re.I)
_CONTRACT_HINTS = ("drain", "reentran", "selfdestruct", "unprotected_",
                   "recipient_", "validator_verdict", "contract_",
                   "storage_", "bytecode_", "proxy_")

# Placeholder credentials documentation ships with. A finding whose value
# matches one of these is a sample, not a leak.
_PLACEHOLDER_RES = (
    re.compile(r"akiaiosfodnn7example", re.I),
    re.compile(r"(your|my|insert|add|paste)[_-]?(api|secret|access|private)"
               r"[_-]?(key|token|id)", re.I),
    re.compile(r"(changeme|change-me|dummy|placeholder|example|sample|"
               r"redacted|fake|notarealkey|test[_-]?key|xxx{4,})", re.I),
    re.compile(r"^\s*<[^>]{2,}>\s*$"),
    re.compile(r"^(?:sk|pk)_test_[A-Za-z0-9]{0,12}$"),
    re.compile(r"(?:0x)?(?:deadbeef)+0*$", re.I),
    re.compile(r"(?:0{8,}|f{8,})$", re.I),
)

# A credential-shaped token: long, mixed alphabet, not a sentence.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=.:]{16,}")
_ENTROPY_NOISE_RE = re.compile(r"^(?:[a-z]+|[A-Z][a-z]+)$")

# Markers that mean the plugin captured a payload/response, not a guess.
_PROOF_KEYS = ("payload", "canary", "marker", "reflected", "response",
               "body", "matched", "snippet", "proof", "callback", "oob",
               "executed", "signature", "timing", "diff", "echo",
               "content", "decoded", "header_value", "observed")
# Certificate / mail / header artefacts: a TLS or mail finding carries
# the certificate fields or the DNS record it read, which is its proof.
_HYGIENE_PROOF_RE = re.compile(
    r"(issuer|subject|not[_-]?after|expires|expiry|san\b|sans|cipher|"
    r"protocol|spf|dmarc|dkim|max-age|max_age|same-?site|set-cookie|"
    r"x-frame|content-security|referrer-policy|permissions-policy|"
    r"strict-transport|record\b|policy\b|txt\b)", re.I)
_PROOF_WORDS = re.compile(
    r"(reflected|canary|payload delivered|oob callback|callback "
    r"received|time delay|timing delta|introspection succeeded|"
    r"__schema|access-control-allow-origin|unauthorized|"
    r"stack trace|sql syntax|root:x:0:0)", re.I)
# Signals that the page never actually loaded - hygiene reports built on
# these are unproven, not findings.
_FETCH_FAILED_RE = re.compile(
    r"(unreachable|connection (?:refused|reset|failed)|timed out|"
    r"timeout|no response|dns failure|host not found|status 0\b|"
    r"could not fetch|fetch failed|tls handshake failed)", re.I)

# Keys that are guesses by construction.
_GUESS_KEY_RE = re.compile(
    r"(_candidate|_possible|_suspected|_maybe|_guess|_potential|"
    r"_likely|_note$|_hint$)", re.I)

_PORT_STATE = {"port_open": "open", "web_port_open": "open",
               "port_closed": "closed", "port_filtered": "filtered",
               "port_open_candidate": "open"}


def _ev(row: Dict[str, Any]) -> Dict[str, Any]:
    ev = row.get("evidence")
    return ev if isinstance(ev, dict) else {}


def _key(row: Dict[str, Any]) -> str:
    return str(row.get("key") or "")


def _plugin(row: Dict[str, Any]) -> str:
    return str(row.get("plugin") or row.get("plugin_id") or "")


def _text(row: Dict[str, Any]) -> str:
    """Value + source, as a lowercase blob. Kept small and bounded."""
    return " ".join(str(row.get(k) or "") for k in
                    ("key", "value", "source", "source_url")).lower()[:4000]


def _blob(row: Dict[str, Any]) -> str:
    """Everything the row carries, evidence included, as lowercase text."""
    base = _text(row)
    try:
        ev = _ev(row)
        if ev:
            base += " " + json.dumps(ev, default=str)[:6000].lower()
    except Exception:
        pass
    return base


def _status(row: Dict[str, Any]) -> Optional[int]:
    ev = _ev(row)
    for k in _STATUS_KEYS:
        v = ev.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int) and 0 <= v <= 599:
            return v
        if isinstance(v, str):
            m = re.search(r"\b([1-5]\d{2})\b", v)
            if m:
                return int(m.group(1))
    m = _STATUS_IN_TEXT.search(str(row.get("value") or ""))
    return int(m.group(1)) if m else None


def _has_proof(row: Dict[str, Any]) -> List[str]:
    """Names of the evidence artefacts this row captured."""
    basis: List[str] = []
    ev = _ev(row)
    for k in _PROOF_KEYS:
        if ev.get(k) not in (None, "", [], {}):
            basis.append(k)
    blob = _blob(row)
    m = _PROOF_WORDS.search(blob)
    if m:
        basis.append(m.group(1).lower())
    return basis


def _is_placeholder(value: str) -> bool:
    v = str(value or "").strip()
    if not v:
        return False
    for rx in _PLACEHOLDER_RES:
        if rx.search(v):
            return True
    return False


def _token_like(value: str) -> bool:
    v = str(value or "")
    for cand in _TOKEN_RE.findall(v):
        if _ENTROPY_NOISE_RE.match(cand):
            continue
        has_digit = any(c.isdigit() for c in cand)
        has_upper = any(c.isupper() for c in cand)
        has_lower = any(c.islower() for c in cand)
        if (has_digit and (has_upper or has_lower)) and len(cand) >= 20:
            return True
    return False


def claim_family(row: Dict[str, Any]) -> str:
    """Which claim class a row belongs to (the judge it gets)."""
    key = _key(row)
    plugin = _plugin(row)
    ev = _ev(row)
    if key == "attack_path" or plugin == "correlation":
        return "attack_path"
    verdict = ev.get("verdict")
    if isinstance(verdict, dict) and verdict.get("verdict"):
        return "contract_verdict"
    if key in _PORT_STATE:
        return "service"
    if _SECRET_RE.search(key) or _SECRET_SUFFIX_RE.search(key):
        return "secret"
    if _CVE_RE.search(key):
        return "cve"
    if _TAKEOVER_RE.search(key):
        return "takeover"
    if any(h in key.lower() for h in _CONTRACT_HINTS):
        return "contract"
    if _EXPOSURE_RE.search(key) and not _WEB_VULN_RE.search(key):
        return "exposure"
    if _WEB_VULN_RE.search(key):
        return "web_vuln"
    if _HYGIENE_RE.search(key):
        return "hygiene"
    if _SERVICE_RE.search(key):
        return "service"
    if _GUESS_KEY_RE.search(key):
        return "guess"
    return "observation"


def _result(status: str, family: str, reason: str,
            basis: Optional[List[str]] = None,
            missing: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"claim_status": status, "claim_family": family,
            "reason": reason, "basis": basis or [],
            "missing": missing or []}


def judge_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Grade one row's claim against its own evidence. Pure, never raises."""
    family = claim_family(row)
    try:
        return _JUDGES[family](row, family)
    except Exception:
        return _result(CLAIM_UNJUDGED, family,
                       "gate could not grade this row; plugin claim kept")


# ---------------------------------------------------------------------------
# Judges, one per claim family.
# ---------------------------------------------------------------------------

def _judge_secret(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    value = str(row.get("value") or "")
    ev = _ev(row)
    context = " ".join(str(ev.get(k) or "") for k in
                       ("match", "matched", "snippet", "context",
                        "content", "value"))[:2000]
    if _is_placeholder(value) or (_is_placeholder(context)
                                  and not _token_like(value)):
        return _result(CLAIM_SUPPRESSED, family,
                       "value matches a documentation placeholder / sample "
                       "credential, not a live secret",
                       basis=["placeholder pattern"])
    if _token_like(value):
        basis = ["credential-shaped value"]
        url = str(row.get("source_url") or "")
        if url:
            basis.append(f"observed in {url[:120]}")
        return _result(CLAIM_VERIFIED, family,
                       "credential-shaped value captured from the target's "
                       "own asset", basis=basis)
    basis = [b for b in _has_proof(row) if b in ("content", "body",
                                                 "snippet", "matched")]
    if basis:
        return _result(CLAIM_VERIFIED, family,
                       "secret pattern matched inside captured content",
                       basis=basis)
    return _result(CLAIM_CANDIDATE, family,
                   "looks like a credential-shaped field but no token value "
                   "was captured", missing=["the credential value itself "
                                            "(or the asset it appears in)"])


def _judge_exposure(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    key = _key(row).lower()
    status = _status(row)
    blob = _blob(row)
    if any(w in key for w in ("guarded", "protected", "blocked", "denied")):
        if status in (401, 403):
            return _result(CLAIM_VERIFIED, family,
                           f"the request was refused ({status}) - the path "
                           f"exists but is not readable",
                           basis=[f"HTTP {status}"])
    if "baseline" in blob and ("identical" in blob or "catch-all" in blob
                               or "catchall" in blob):
        return _result(CLAIM_SUPPRESSED, family,
                       "response is identical to the server's 200 catch-all "
                       "page, so nothing was actually exposed",
                       basis=["catch-all baseline match"])
    if status in (401, 403, 404, 410):
        return _result(CLAIM_SUPPRESSED, family,
                       f"server answered {status}: the asserted exposure "
                       f"does not exist", basis=[f"HTTP {status}"])
    if status is not None and 500 <= status <= 599:
        return _result(CLAIM_CANDIDATE, family,
                       f"server answered {status} (error page) - retest "
                       f"before treating this as exposed",
                       basis=[f"HTTP {status}"],
                       missing=["a 2xx response or a matching content "
                                "signature for the exposed file"])
    if status is not None and 200 <= status <= 299:
        return _result(CLAIM_VERIFIED, family,
                       f"direct probe returned {status}",
                       basis=[f"HTTP {status}"])
    basis = _has_proof(row)
    if basis:
        return _result(CLAIM_VERIFIED, family,
                       "captured content proves the exposure",
                       basis=basis)
    if key.endswith("_archived") or "archived" in key:
        # Wayback snapshots are an archive fact, not a live exposure.
        return _result(CLAIM_VERIFIED, family,
                       "archive snapshot recorded (historical, not live)",
                       basis=["wayback snapshot"])
    if _FETCH_FAILED_RE.search(blob):
        return _result(CLAIM_CANDIDATE, family,
                       "the probe did not get a usable response, so "
                       "exposure is unproven",
                       missing=["a completed request to the asserted path"])
    return _result(CLAIM_CANDIDATE, family,
                   "no HTTP outcome or content signature captured for the "
                   "asserted exposure",
                   missing=["a 2xx response or a content signature"])


def _judge_cve(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    ev = _ev(row)
    version = ""
    for k in ("detected_version", "version", "observed_version",
              "software_version"):
        v = ev.get(k)
        if v:
            version = str(v)
            break
    if not version:
        m = re.search(r"detected version ([0-9][\w.\-]*)",
                      str(row.get("value") or ""), re.I)
        version = m.group(1) if m else ""
    bad = ("", "unknown", "none", "null", "not disclosed", "n/a", "0")
    if version.strip().lower() not in bad:
        return _result(CLAIM_VERIFIED, family,
                       f"version-pinned match against observed {version}",
                       basis=[f"observed version {version}"])
    return _result(CLAIM_CANDIDATE, family,
                   "CVE matched without an observed version - the affected "
                   "range cannot be checked",
                   missing=["the product version actually served by the "
                            "target"])


def _judge_takeover(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    ev = _ev(row)
    blob = _blob(row)
    if ev.get("dangling") is True:
        return _result(CLAIM_VERIFIED, family,
                       "CNAME target does not resolve (dangling)",
                       basis=["dangling CNAME target"])
    if ev.get("fingerprint_match") is True:
        return _result(CLAIM_VERIFIED, family,
                       "provider 'nothing here' page matched on the "
                       "subdomain root", basis=["provider fingerprint"])
    if re.search(r"(nxdomain|does not resolve|unclaimed|claimable|"
                 r"no such host)", blob):
        return _result(CLAIM_VERIFIED, family,
                       "evidence records an unclaimed CNAME target",
                       basis=["unclaimed target in evidence"])
    if _key(row).lower() in ("takeover_possible", "takeover_candidate",
                             "dangling_candidate"):
        return _result(CLAIM_CANDIDATE, family,
                       "CNAME points at a takeover-prone service, but the "
                       "target still resolves - suspicious, not claimable",
                       missing=["proof the CNAME target is unclaimed "
                                "(NXDOMAIN or provider 'not found' page)"])
    return _result(CLAIM_CANDIDATE, family,
                   "no proof the CNAME target is unclaimed",
                   missing=["NXDOMAIN on the CNAME target or the provider's "
                            "own unclaimed page"])


def _judge_web_vuln(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    key = _key(row).lower()
    ev = _ev(row)
    blob = _blob(row)
    if key.startswith("jwt"):
        if ev.get("decoded") or ev.get("claims") or ev.get("header"):
            return _result(CLAIM_VERIFIED, family,
                           "token decoded and its claims inspected",
                           basis=["decoded JWT"])
        if re.search(r"eyj[a-z0-9_\-]{8,}\.eyj", blob):
            return _result(CLAIM_VERIFIED, family,
                           "JWT captured from the target and decoded",
                           basis=["decoded JWT"])
        return _result(CLAIM_CANDIDATE, family,
                       "JWT weakness asserted without the decoded token",
                       missing=["the decoded token header/claims"])
    if "cors" in key:
        if re.search(r"access-control-allow-origin", blob) and (
                ev.get("reflected") or ev.get("origin")
                or re.search(r"(reflected|echoed|wildcard)", blob)):
            return _result(CLAIM_VERIFIED, family,
                           "ACAO header captured echoing the test origin",
                           basis=["captured ACAO header"])
        return _result(CLAIM_CANDIDATE, family,
                       "CORS weakness asserted without the captured ACAO "
                       "response",
                       missing=["the Access-Control-Allow-Origin header the "
                                "server returned for the test origin"])
    if "introspection" in key:
        if re.search(r"(__schema|introspection succeeded)", blob):
            return _result(CLAIM_VERIFIED, family,
                           "introspection query returned a schema",
                           basis=["__schema in response"])
        return _result(CLAIM_CANDIDATE, family,
                       "introspection asserted without a captured schema",
                       missing=["a successful __schema response"])
    if re.search(r"(idor|bola)", key):
        if ev.get("confirmed") is True or ev.get("second_account_proof"):
            return _result(CLAIM_VERIFIED, family,
                           "confirmed with a second-account proof",
                           basis=["two-account proof"])
        return _result(CLAIM_CANDIDATE, family,
                       "IDOR/BOLA is a pattern until access is proven with a "
                       "second account - never reported as confirmed",
                       missing=["a response from a second account that "
                                "should not have had access"])
    if _has_proof(row):
        return _result(CLAIM_VERIFIED, family,
                       "captured payload/response evidence",
                       basis=_has_proof(row))
    if row.get("passive") is False and str(row.get("source_url") or ""):
        return _result(CLAIM_CANDIDATE, family,
                       "active probe reached the target but no payload or "
                       "response marker was captured",
                       missing=["the reflected payload, error signature or "
                                "response difference that proves the class"])
    return _result(CLAIM_CANDIDATE, family,
                   "pattern match without captured exploit evidence",
                   missing=["a captured payload/response proving the class"])


def _judge_hygiene(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    blob = _blob(row)
    status = _status(row)
    if status == 0 or (_FETCH_FAILED_RE.search(blob) and status is None):
        return _result(CLAIM_CANDIDATE, family,
                       "the page never loaded, so an absent header / flag is "
                       "not evidence of misconfiguration",
                       missing=["a successful response from the target"])
    if status in (401, 403) and "header" not in _key(row).lower():
        return _result(CLAIM_CANDIDATE, family,
                       f"response was {status}; the assertion may describe "
                       f"the refusal page rather than the site",
                       missing=["a 2xx response from the real page"])
    if status is None and not _HYGIENE_PROOF_RE.search(blob):
        return _result(CLAIM_CANDIDATE, family,
                       "no response headers or certificate/record data "
                       "captured to base the assertion on",
                       missing=["the response headers, certificate fields or "
                                "DNS record observed"])
    if status is None and _HYGIENE_PROOF_RE.search(blob):
        return _result(CLAIM_VERIFIED, family,
                       "assertion rests on the certificate/record captured",
                       basis=["captured certificate/record"])
    return _result(CLAIM_VERIFIED, family,
                   "assertion rests on the captured response",
                   basis=["response headers observed"])


def _judge_service(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    key = _key(row).lower()
    blob = _blob(row)
    state = _PORT_STATE.get(key)
    if state == "open" and re.search(
            r"(closed|filtered|refused|timed out|unreachable)", blob):
        return _result(CLAIM_SUPPRESSED, family,
                       "the row says the port is open while its own evidence "
                       "records it closed/filtered", basis=["contradiction"])
    if state == "open":
        if _has_proof(row) or row.get("passive") is False:
            return _result(CLAIM_VERIFIED, family,
                           "connect/banner observed on the port",
                           basis=_has_proof(row) or ["direct connect"])
        return _result(CLAIM_CANDIDATE, family,
                       "port reported open without a connect result or "
                       "banner", missing=["a successful TCP connect or "
                                          "service banner"])
    return _result(CLAIM_VERIFIED, family, "service observation recorded",
                   basis=["service observation"])


def _judge_contract(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    blob = _blob(row)
    ev = _ev(row)
    if ev.get("fuzz_confirmed") or re.search(r"fuzz_confirmed", blob):
        return _result(CLAIM_VERIFIED, family,
                       "local fuzz run produced a profitable stranger call "
                       "sequence", basis=["fuzz counterexample"])
    if re.search(r"(measured receipt|decisive_probe|stranger_received)", blob):
        return _result(CLAIM_VERIFIED, family,
                       "stranger receipt was measured, not inferred",
                       basis=["measured receipt"])
    if re.search(r"(sim_derived|simulation only|lab only)", blob):
        return _result(CLAIM_CANDIDATE, family,
                       "lab/simulation result only - a live probe is still "
                       "required", missing=["a live read-only stranger probe"])
    return _result(CLAIM_CANDIDATE, family,
                   "contract weakness asserted without a measured receipt",
                   missing=["a live stranger probe or fuzz counterexample"])


def _judge_contract_verdict(row: Dict[str, Any],
                            family: str) -> Dict[str, Any]:
    verdict = _ev(row).get("verdict") or {}
    v = str(verdict.get("verdict") or "").upper()
    reason = str(verdict.get("reason") or "")[:200]
    missing = verdict.get("missing") or []
    if v == "VERIFIED_REAL":
        return _result(CLAIM_VERIFIED, family,
                       f"validator: {reason or 'measured stranger receipt'}",
                       basis=["auto-validator VERIFIED_REAL"])
    if v == "FALSE_POSITIVE":
        return _result(CLAIM_SUPPRESSED, family,
                       f"validator: {reason or 'killed by evidence'}",
                       basis=["auto-validator FALSE_POSITIVE"])
    if v == "TRIGGER_ONLY":
        detail = reason or ("the value does not reach an unauthenticated "
                            "stranger")
        return _result(CLAIM_CANDIDATE, family,
                       f"trigger-only: {detail}",
                       missing=["a recipient path that pays the caller or a "
                                "caller-supplied address"])
    return _result(CLAIM_CANDIDATE, family,
                   f"unverified: {reason or 'evidence incomplete'}",
                   missing=[str(m) for m in missing] or
                   ["live verification evidence"])


def _judge_guess(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    return _result(CLAIM_CANDIDATE, family,
                   "generated candidate - a lead to check, not an "
                   "observation",
                   missing=["direct observation of the asserted fact"])


def _judge_observation(row: Dict[str, Any], family: str) -> Dict[str, Any]:
    # An enumeration row (a DNS record, a tech tag, an IP) is a fact
    # about the target, not a weakness claim - nothing to withhold.
    return _result(CLAIM_VERIFIED, family, "enumeration fact",
                   basis=["observed"])


_JUDGES = {
    "secret": _judge_secret,
    "exposure": _judge_exposure,
    "cve": _judge_cve,
    "takeover": _judge_takeover,
    "web_vuln": _judge_web_vuln,
    "hygiene": _judge_hygiene,
    "service": _judge_service,
    "contract": _judge_contract,
    "contract_verdict": _judge_contract_verdict,
    "guess": _judge_guess,
    "observation": _judge_observation,
    "attack_path": _judge_observation,  # refined in apply()
}


# ---------------------------------------------------------------------------
# Run-level passes
# ---------------------------------------------------------------------------

def _port_identity(row: Dict[str, Any]) -> str:
    ev = _ev(row)
    port = ev.get("port")
    if not port:
        m = re.search(r"\bport\s+(\d{1,5})\b",
                      str(row.get("value") or ""), re.I)
        port = m.group(1) if m else "?"
    host = (ev.get("host") or ev.get("target") or
            str(row.get("source_url") or row.get("value") or ""))
    host = re.sub(r"^\w+://", "", str(host)).split("/")[0].lower()
    return f"{host}:{port}"


def _apply_contradictions(rows: List[Dict[str, Any]]) -> int:
    """Rows that disagree about the same host:port become candidates."""
    by_asset: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        if _key(row) in _PORT_STATE:
            by_asset.setdefault(_port_identity(row), []).append(row)
    flagged = 0
    for asset, group in by_asset.items():
        states = {_PORT_STATE.get(_key(r)) for r in group}
        if "open" in states and ("closed" in states or "filtered" in states):
            for row in group:
                if row.get("claim_status") == CLAIM_SUPPRESSED:
                    continue
                row["claim_status"] = CLAIM_CANDIDATE
                row["needs_manual_verification"] = True
                pr = row.setdefault("precision", {})
                pr["reason"] = (f"plugins disagree about {asset}: this run "
                                f"records both open and "
                                f"{'closed' if 'closed' in states else 'filtered'}"
                                f" - verify before acting")
                pr.setdefault("missing", []).append(
                    "a fresh connect test resolving the conflict")
                flagged += 1
    return flagged


def _apply_attack_paths(rows: List[Dict[str, Any]]) -> None:
    """A path is only as proven as the weakest component it chains."""
    status_by: Dict[Tuple[str, str], str] = {}
    for row in rows:
        if row.get("claim_status") == CLAIM_UNJUDGED:
            continue
        status_by[(str(row.get("plugin") or ""), _key(row))] = \
            str(row.get("claim_status"))
        if row.get("id") is not None:
            status_by[("", str(row.get("id")))] = str(row.get("claim_status"))
    for row in rows:
        if claim_family(row) != "attack_path":
            continue
        comps = _ev(row).get("components") or []
        if not isinstance(comps, list) or not comps:
            row["claim_status"] = CLAIM_CANDIDATE
            row["needs_manual_verification"] = True
            row.setdefault("precision", {}).update({
                "reason": "attack path cites no component findings",
                "missing": ["the component findings it chains"]})
            continue
        statuses: List[str] = []
        unproven: List[str] = []
        for c in comps:
            if not isinstance(c, dict):
                continue
            st = status_by.get((str(c.get("plugin") or ""),
                                str(c.get("key") or "")))
            if st is None and c.get("id") is not None:
                st = status_by.get(("", str(c.get("id"))))
            statuses.append(st or CLAIM_CANDIDATE)
            if st != CLAIM_VERIFIED:
                unproven.append(f"{c.get('plugin')}/{c.get('key')}")
        if CLAIM_SUPPRESSED in statuses:
            row["claim_status"] = CLAIM_SUPPRESSED
            row["precision"] = {
                "claim_status": CLAIM_SUPPRESSED,
                "claim_family": "attack_path",
                "reason": "a component finding was contradicted by its own "
                          "evidence, so the chain does not hold",
                "basis": [], "missing": []}
        elif unproven:
            row["claim_status"] = CLAIM_CANDIDATE
            row["needs_manual_verification"] = True
            row["precision"] = {
                "claim_status": CLAIM_CANDIDATE,
                "claim_family": "attack_path",
                "reason": "the chain includes components that are not yet "
                          "proven",
                "basis": [], "missing": [
                    f"verified evidence for {name}" for name in unproven[:5]]}
        else:
            row["claim_status"] = CLAIM_VERIFIED
            row["precision"] = {
                "claim_status": CLAIM_VERIFIED,
                "claim_family": "attack_path",
                "reason": "every chained component is verified",
                "basis": [f"{len(statuses)} verified components"],
                "missing": []}
        row["suppressed"] = (row["claim_status"] == CLAIM_SUPPRESSED)


def apply(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Grade every row, cap scores, and sort suppressed rows last.

    Mutates the rows in place and returns the reordered list. Never
    raises: on any failure the rows come back exactly as they went in.
    """
    try:
        for row in rows:
            if not isinstance(row, dict):
                continue
            judged = judge_row(row)
            status = judged["claim_status"]
            row["claim_status"] = status
            row["claim_label"] = CLAIM_LABELS.get(status, status)
            row["needs_manual_verification"] = status == CLAIM_CANDIDATE
            row["suppressed"] = status == CLAIM_SUPPRESSED
            row["precision"] = judged
        _apply_contradictions(rows)
        _apply_attack_paths(rows)
        # Score caps run last so rows re-graded by the cross-row passes
        # (contradiction, attack-path components) get the same treatment.
        for row in rows:
            if not isinstance(row, dict):
                continue
            status = row.get("claim_status")
            try:
                score = int(row.get("confidence_score") or 0)
            except (TypeError, ValueError):
                score = 0
            pr = row.get("precision") or {}
            if status == CLAIM_CANDIDATE and score > CANDIDATE_SCORE_CAP:
                row["confidence_score"] = CANDIDATE_SCORE_CAP
                row["confidence_tier"] = "likely"
                row["confidence_label"] = "Likely"
                row["confidence_reason"] = (
                    f"{row.get('confidence_reason') or 'plugin confidence'}; "
                    f"capped until the missing evidence is captured")
            elif status == CLAIM_SUPPRESSED:
                row["confidence_score"] = min(score, SUPPRESSED_SCORE_CAP)
                row["confidence_tier"] = "weak"
                row["confidence_label"] = "Weak signal"
                row["confidence_reason"] = (
                    f"suppressed by the precision gate: "
                    f"{pr.get('reason') or 'contradicted by evidence'}")
        # Stable partition: suppressed rows stay in the row set (never
        # silently dropped) but sort behind everything the run can act on.
        return sorted(rows, key=lambda r: 1 if isinstance(r, dict)
                      and r.get("suppressed") else 0)
    except Exception:
        return rows


annotate = apply


def is_suppressed(row: Dict[str, Any]) -> bool:
    return bool(row.get("suppressed"))


def verified_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in rows if r.get("claim_status") == CLAIM_VERIFIED]


def summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run-level precision block: how much of the run's surface is proven."""
    claims = {CLAIM_VERIFIED: 0, CLAIM_CANDIDATE: 0,
              CLAIM_SUPPRESSED: 0, CLAIM_UNJUDGED: 0}
    suppressed: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = row.get("claim_status")
        if status not in claims:
            claims[CLAIM_UNJUDGED] += 1
            continue
        claims[status] += 1
        if status == CLAIM_SUPPRESSED and len(suppressed) < 25:
            suppressed.append({
                "id": row.get("id"), "plugin": row.get("plugin"),
                "key": row.get("key"),
                "value": str(row.get("value") or "")[:160],
                "reason": (row.get("precision") or {}).get("reason", "")})
        elif status == CLAIM_CANDIDATE and len(candidates) < 25:
            pr = row.get("precision") or {}
            candidates.append({
                "id": row.get("id"), "plugin": row.get("plugin"),
                "key": row.get("key"),
                "value": str(row.get("value") or "")[:160],
                "missing": list(pr.get("missing") or [])[:3]})
    graded = (claims[CLAIM_VERIFIED] + claims[CLAIM_CANDIDATE]
              + claims[CLAIM_SUPPRESSED])
    return {
        "applied": True,
        "claims": claims,
        "graded": graded,
        "verified_share": round(claims[CLAIM_VERIFIED] / graded, 3)
        if graded else 0.0,
        "suppressed": suppressed,
        "candidates": candidates,
        "guard": ("Every claim is graded against the run's own captured "
                  "evidence. Candidates are never presented as confirmed, "
                  "and suppressed rows stay visible with the reason they "
                  "were taken out of the actionable set."),
    }
