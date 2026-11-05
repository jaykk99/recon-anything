"""Cross-finding correlation: the attack-path synthesizer.

The plugins each see one slice of the target. A JWT auditor knows the
token is forgeable; a crawler knows there is an admin endpoint; neither
knows that *together* they are an authentication bypass. This module
runs once, after every plugin and every hunter pass has settled, over
the whole finding set for a run. It reasons across findings and emits
new, composite "attack path" findings that no single plugin could
produce - the exploitable sequences, with a plain-language narrative of
how the pieces chain.

DESIGN RULES (match the rest of the codebase)
---------------------------------------------
* Detection / analysis only. A path *describes* how findings chain; it
  never sends a payload, never generates an exploit, never includes a
  step-by-step weaponization recipe. The narrative says what an attacker
  *could* do and what to fix - the same descriptive-impact contract the
  plugins already follow (see app/impact.py, "a chain never sends an
  exploit").
* Pure stdlib. No fastapi / sqlalchemy / httpx imports, so this module
  loads and unit-tests on its own and can never break the app import or
  a live scan. The runner calls it lazily inside finalize.
* Robust to dynamic keys. Plugins build finding keys dynamically, so
  rules match on *semantic signals* (key/category/value patterns), not
  exact key strings. New plugins light up the correct signals for free.
* Deterministic. Same findings in -> same paths and same exposure score
  out. No clocks, no randomness, stable ordering.

OUTPUT
------
``correlate(rows)`` returns ``(paths, exposure)`` where each path is a
finding-shaped dict ready for the runner to persist as a FindingRow
(plugin_id "correlation", key "attack_path", category "graph") and
``exposure`` is the run-level exposure score block for the summary.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from .commands import commands_for as _commands_for
except Exception:  # pragma: no cover - keeps the module import-safe
    def _commands_for(finding, host_hint=None):  # type: ignore
        return []

# ---------------------------------------------------------------------------
# Signals: the abstract vocabulary rules reason over. Each finding is mapped
# to zero or more signals by matching its key / category / value. A signal
# is a lightweight record pointing back at the finding that raised it, so a
# synthesized path can cite its real evidence.
# ---------------------------------------------------------------------------

# severity rank for comparisons / scoring (3-level model: critical folds
# into high for the UI, but we keep a 4th internal tier for scoring weight).
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# exploitability weight (how weaponizable), used to boost a path's score.
_EXPL_RANK = {"unknown": 0, "theoretical": 1, "public_poc": 2, "weaponized": 3}


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _row_plugin(r: Dict[str, Any]) -> str:
    return str(r.get("plugin") or r.get("plugin_id") or "")


def _row_sev(r: Dict[str, Any]) -> str:
    ev = r.get("evidence") or {}
    sev = _norm(ev.get("severity") or ev.get("risk"))
    if sev in _SEV_RANK:
        return sev
    # bounty tier is a reasonable severity proxy when evidence is thin
    bv = _norm(r.get("bounty_value"))
    if bv in _SEV_RANK:
        return bv
    return "low"


def _row_expl(r: Dict[str, Any]) -> str:
    ev = r.get("evidence") or {}
    e = _norm(ev.get("exploitability"))
    return e if e in _EXPL_RANK else "unknown"


# Signal detectors. Order doesn't matter; a finding can raise several.
# Each entry: signal name -> predicate(key, value, category, plugin) -> bool.
# Patterns are deliberately broad (substring / regex) to survive dynamic
# key generation across 200+ plugins.

_CLOUD_CRED_KEY = re.compile(
    r"(aws_?access|aws_?secret|aws_?key|gcp_?key|google_?api_?key|"
    r"azure_?key|exposed_?env|laravel_?env|actuator_?env|dotenv|"
    r"exposed_?github_?token|github_?token|exposed_?stripe|stripe_?sk|"
    r"private_?key|service_?account|hardcoded_?password|"
    r"sourcemap_?secret|sourcemap_?cred|js_?secret|secret_?key|"
    r"slack_?token|api_?key|bearer_?token|access_?token)")
_STORAGE_KEY = re.compile(
    r"(s3_?public|s3_?bucket|open_?bucket|bucket_?listable|"
    r"azure_?blob|gcs_?bucket|storage_?bucket|public_?bucket)")
_STORAGE_VAL = re.compile(
    r"(s3://|\.s3[.-]|s3\.amazonaws|blob\.core\.windows|"
    r"storage\.googleapis|\.r2\.cloudflarestorage|digitaloceanspaces)")
_JWT_FORGE_KEY = re.compile(r"(jwt_?alg_?none|jwt_?weak|jwt_?none|"
                            r"jwt_?confusion|jwt_?kid)")
_PRIV_ENDPOINT = re.compile(
    r"(admin|/internal|internal[_-]?api|actuator|/manage|/management|"
    r"/console|/dashboard|/debug|phpmyadmin|/wp-admin|graphql|/api/v)")
_AUTH_ENDPOINT = re.compile(
    r"(/login|/signin|/sign-in|/oauth|/auth|/token|/session|/sso|"
    r"/account|/password|/reset)")
_SSRF_KEY = re.compile(r"ssrf")
_SSRF_META_KEY = re.compile(r"(ssrf_?cloud_?metadata|metadata|169\.254)")
_CLOUD_HOST_VAL = re.compile(
    r"(amazonaws|aws|ec2|gcp|googleusercontent|google cloud|azure|"
    r"azurewebsites|cloudfront|\bgce\b|compute\.internal|digitalocean|"
    r"linode|hetzner|oracle cloud)")
_IDOR_KEY = re.compile(r"(idor|bola|object[_-]?level|insecure_?direct)")
_CORS_KEY = re.compile(r"cors")
_TAKEOVER_KEY = re.compile(
    r"(subdomain_?takeover|dangling|unclaimed|interesting_?subdomain|"
    r"cname_?dangling|nxdomain_?cname)")
_SOURCE_EXPOSED = re.compile(
    r"(git_?exposed|\.git|svn_?exposed|\.svn|hg_?exposed|"
    r"sourcemap_?exposed|source_?map|bzr_?exposed|ds_?store|"
    r"backup_?exposed|\.bak|sql_?dump|db_?dump|exposed_?repo)")
_BREACH_KEY = re.compile(r"(breach|hibp|pwned|leaked_?cred|combolist|"
                         r"haveibeenpwned|credential_?leak)")
_EMAIL_KEY = re.compile(r"(email|mailbox|smtp_?user)")
_OPEN_MGMT_PORT = re.compile(
    r"(ssh_?open|rdp_?open|mysql_?open|postgres_?open|mongodb_?open|"
    r"redis_?open|elastic_?open|elasticsearch_?open|kibana_?open|"
    r"ftp_?open|telnet_?open|vnc_?open|smb_?open|rsync_?open|"
    r"docker_?open|kubelet_?open|memcached_?open)")
_DEFAULT_CREDS = re.compile(
    r"(default_?cred|default_?password|iot_?default|plaintext_?password|"
    r"weak_?password|known_?credential)")
_API_DOCS = re.compile(
    r"(openapi|swagger|graphql_?introspection|wadl|api_?docs|"
    r"redoc|apiblueprint|graphql_?schema)")
_WALLET_KEY = re.compile(r"(wallet_?private|seed_?phrase|mnemonic|keystore|"
                         r"xprv|private_?key_?hex)")
_MISSING_HDR = re.compile(r"(missing_?security_?header|clickjack|"
                          r"missing_?hsts|csp_?missing|x_?frame)")
_OPEN_REDIRECT = re.compile(r"open_?redirect")
_OAUTH = re.compile(r"(oauth|/callback|redirect_?uri|sso|openid|saml)")
_INTERNAL_HOST = re.compile(
    r"(internal_?host|internal_?url|private_?ip|rfc1918|\.internal\b|"
    r"\.corp\b|\.local\b|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|"
    r"intranet|staging_?url|dev_?endpoint)")
_CI_CONFIG = re.compile(
    r"(github_?workflow|\.github/|gitlab[-_]?ci|\.gitlab-ci|circleci|"
    r"\.circleci|jenkinsfile|azure-?pipelines|travis|bitbucket-?pipelines|"
    r"drone\.yml|pipeline_?config)")
_PKG_MANIFEST = re.compile(
    r"(package\.json|composer\.json|requirements\.txt|gemfile|go\.mod|"
    r"pom\.xml|yarn\.lock|package-?lock|pipfile|internal_?package|"
    r"private_?scope|npmrc)")
_DEBUG_MODE = re.compile(r"(debug_?mode|debug_?enabled|stack_?trace|"
                         r"error_?debug|django_?debug|rails_?console|"
                         r"symfony_?profiler|laravel_?telescope|whoops)")

# A finding counts as "high-value credential material" if its key hits the
# cloud-cred or wallet pattern. These are what blast-radius rules pivot on.
_PORT_VAL_META = re.compile(r"\b(22|3389|3306|5432|27017|6379|9200|21|23|"
                            r"445|5900|2375|10250|11211)\b")


def _detect_signals(r: Dict[str, Any]) -> Set[str]:
    """Map one finding to the set of abstract signals it raises."""
    key = _norm(r.get("key"))
    val = _norm(r.get("value"))
    cat = _norm(r.get("category"))
    blob = f"{key} {val}"
    sig: Set[str] = set()

    if _CLOUD_CRED_KEY.search(key) or _WALLET_KEY.search(key):
        sig.add("credential")
    if _WALLET_KEY.search(key):
        sig.add("wallet_key")
    if _STORAGE_KEY.search(key) or _STORAGE_VAL.search(val):
        sig.add("storage")
        if re.search(r"(public_?write|writable|list.*write)", key):
            sig.add("storage_writable")
    if _JWT_FORGE_KEY.search(key):
        sig.add("forgeable_token")
    if _PRIV_ENDPOINT.search(blob) and cat in ("api", "web", "graph", ""):
        sig.add("privileged_endpoint")
    if _AUTH_ENDPOINT.search(blob):
        sig.add("auth_surface")
    if _SSRF_KEY.search(key):
        sig.add("ssrf")
        if _SSRF_META_KEY.search(blob):
            sig.add("ssrf_metadata")
    if _CLOUD_HOST_VAL.search(blob) and cat in ("infra", "dns", "network", ""):
        sig.add("cloud_hosted")
    if _IDOR_KEY.search(key):
        sig.add("idor")
    if _CORS_KEY.search(key):
        sig.add("cors")
    if _TAKEOVER_KEY.search(key):
        sig.add("takeover_candidate")
    if _SOURCE_EXPOSED.search(blob):
        sig.add("source_exposed")
    if _BREACH_KEY.search(blob):
        sig.add("breach")
    if _OPEN_MGMT_PORT.search(key) or (
            key in ("port_open", "open_port") and _PORT_VAL_META.search(val)):
        sig.add("mgmt_port")
    # Weaponized known-CVE: a finding with a public exploit (from the CVE
    # matcher or any plugin that rates exploitability). These are the
    # crown-jewel findings - a working exploit against a reachable service.
    if _row_expl(r) == "weaponized" or (
            _row_plugin(r) == "cves" and _row_sev(r) in ("high", "critical")):
        sig.add("weaponized_cve")
    if _DEFAULT_CREDS.search(key):
        sig.add("default_creds")
    if _API_DOCS.search(blob):
        sig.add("api_docs")
    if _MISSING_HDR.search(key):
        sig.add("weak_headers")
    if cat == "leak" or re.search(r"(exposed|leak|secret|password|token)",
                                  key):
        sig.add("exposure")
    if _OPEN_REDIRECT.search(key):
        sig.add("open_redirect")
    if _OAUTH.search(blob):
        sig.add("oauth")
    if _INTERNAL_HOST.search(blob):
        sig.add("internal_host")
    if _CI_CONFIG.search(blob):
        sig.add("ci_config")
    if _PKG_MANIFEST.search(blob):
        sig.add("pkg_manifest")
    if _DEBUG_MODE.search(key):
        sig.add("debug_mode")
    return sig


# ---------------------------------------------------------------------------
# Component citation: a compact, safe reference to the real finding(s)
# behind a synthesized path. We never paste a raw secret into the path;
# values are truncated and credential-like values are redacted.
# ---------------------------------------------------------------------------

def _cite(r: Dict[str, Any], redact: bool = False) -> Dict[str, Any]:
    # `redact` is retained for API compatibility but secrets are shown in
    # full to the operator (that is the product intent - an exposed secret
    # IS the finding). Values are only length-capped for display sanity;
    # the full value always lives on the underlying finding in the
    # Secrets/Creds surfaces.
    val = str(r.get("value") or "")
    if len(val) > 240:
        val = val[:237] + "…"
    out = {
        "plugin": _row_plugin(r),
        "key": r.get("key"),
        "value": val,
        "category": r.get("category"),
        "severity": _row_sev(r),
        "confidence": r.get("confidence", 80),
    }
    if r.get("source_url"):
        out["source_url"] = r["source_url"]
    if r.get("id") is not None:
        out["finding_id"] = r["id"]
    return out


def _path_id(name: str, comps: List[Dict[str, Any]]) -> str:
    """Stable id for a path from its name + the findings it chains.

    Lets the UI key paths and the runner dedup across re-finalizes.
    """
    h = hashlib.sha1()
    h.update(name.encode())
    for c in sorted(f"{c.get('plugin')}:{c.get('key')}:{c.get('value')}"
                    for c in comps):
        h.update(c.encode())
    return h.hexdigest()[:12]


def _path_commands(components: List[Dict[str, Any]],
                   host_hint: Optional[str]) -> List[Dict[str, str]]:
    """Verification commands for a path: the read-only command(s) to
    confirm each stage, deduped and capped. Read-only only (same contract
    as app.commands)."""
    out: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for c in components:
        for cmd in _commands_for(c, host_hint):
            key = cmd.get("cmd", "")
            if key and key not in seen:
                seen.add(key)
                out.append(cmd)
            if len(out) >= 8:
                return out
    return out


def _complexity(components: List[Dict[str, Any]], steps: List[str]) -> str:
    """How many distinct moving parts the path chains."""
    plugins = {c.get("plugin") for c in components}
    n = max(len(components), len(steps))
    if len(plugins) >= 3 or n >= 4:
        return "multi-stage"
    if len(plugins) == 2 or n >= 2:
        return "two-stage"
    return "single-stage"


def _mk_path(*, name: str, severity: str, exploitability: str,
             summary: str, attacker_impact: str, remediation: str,
             steps: List[str], components: List[Dict[str, Any]],
             confidence: int, tags: Optional[List[str]] = None,
             redact_components: bool = False,
             kill_chain: Optional[List[str]] = None,
             host_hint: Optional[str] = None) -> Dict[str, Any]:
    """Build one attack-path finding (finding-shaped dict)."""
    cites = [_cite(c) for c in components]
    pid = _path_id(name, cites)
    # bounty value tracks severity (critical -> critical tier)
    bounty = "critical" if severity == "critical" else (
        "high" if severity == "high" else (
            "medium" if severity == "medium" else "low"))
    ev: Dict[str, Any] = {
        "severity": severity,
        "risk": "high" if severity in ("critical", "high") else severity,
        "exploitability": exploitability,
        "attack_path": True,
        "path_id": pid,
        "path_name": name,
        "narrative": summary,
        "chain_steps": steps,
        "kill_chain": kill_chain or steps,
        "complexity": _complexity(components, steps),
        "components": cites,
        "component_count": len(cites),
        "attacker_impact": attacker_impact,
        "remediation": remediation,
        "commands": _path_commands(components, host_hint),
        "tags": tags or [],
    }
    return {
        "category": "graph",
        "key": "attack_path",
        "value": name,
        "source": "correlation",
        "source_url": None,
        "confidence": max(1, min(confidence, 100)),
        "evidence": ev,
        "passive": True,
        "bounty_value": bounty,
    }


# ---------------------------------------------------------------------------
# Rules. Each takes the signal index and returns 0+ paths. A rule is a pure
# function; add a rule by appending it to RULES.
#
# The signal index: signals -> list of findings that raised that signal,
# already deduped and severity-sorted (strongest evidence first).
# ---------------------------------------------------------------------------

SignalIndex = Dict[str, List[Dict[str, Any]]]


def _top(idx: SignalIndex, signal: str, n: int = 3) -> List[Dict[str, Any]]:
    return idx.get(signal, [])[:n]


def _has(idx: SignalIndex, *signals: str) -> bool:
    return all(idx.get(s) for s in signals)


def _rule_cloud_cred_blast(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Exposed cloud credential -> live infrastructure access."""
    creds = idx.get("credential")
    if not creds:
        return []
    comps = list(creds[:3])
    tags = ["cloud", "credential"]
    # blast radius: a reachable bucket / cloud host makes it concrete
    extra = _top(idx, "storage", 2) + _top(idx, "cloud_hosted", 1)
    if extra:
        comps += extra
    writable = bool(idx.get("storage_writable"))
    sev = "critical"
    expl = "weaponized" if (idx.get("storage_writable")
                            or any("aws" in _norm(c.get("key"))
                                   for c in creds)) else "public_poc"
    name = "Exposed cloud credential grants live infrastructure access"
    summary = (
        "A usable cloud/service credential was found exposed on the target. "
        "An attacker who collects it can authenticate to the provider as the "
        "target"
        + (", and a reachable storage bucket in the same scope shows the "
           "blast radius is real data, not just an API key"
           if extra else "")
        + (". At least one bucket is world-writable, so the path also allows "
           "planting or defacing content." if writable else "."))
    impact = (
        "Full read (and in some cases write) access to the target's cloud "
        "account or storage: data exfiltration, resource abuse, and "
        "potential lateral movement into connected services.")
    remediation = (
        "Revoke and rotate the exposed credential immediately, audit the "
        "provider's access logs for use, scope replacement keys to least "
        "privilege, and remove the artifact that leaked it from every "
        "cache/mirror. Lock down any public bucket.")
    steps = [
        "A plugin recovered a cloud/service credential from the target.",
        "The same run observed cloud-hosted infrastructure or a storage "
        "bucket the credential's provider controls.",
        "Those two facts together mean the credential is not inert - it "
        "maps to reachable resources.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability=expl,
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=90, tags=tags, redact_components=True)]


def _rule_jwt_authbypass(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Forgeable token + reachable privileged/auth surface -> auth bypass."""
    if not idx.get("forgeable_token"):
        return []
    targets = _top(idx, "privileged_endpoint", 2) + _top(idx, "auth_surface", 1)
    if not targets:
        return []
    comps = _top(idx, "forgeable_token", 1) + targets
    name = "Forgeable session token reaches a privileged endpoint (auth bypass path)"
    summary = (
        "The application accepts JSON Web Tokens that can be forged (alg:none, "
        "a weak/guessable signing secret, or a key-confusion weakness), and "
        "the run also found a privileged or authentication-gated endpoint on "
        "the same host. An attacker can mint a token for any user or role and "
        "present it to that endpoint.")
    impact = ("Authentication bypass and privilege escalation: act as an "
              "administrator or any chosen user without valid credentials.")
    remediation = (
        "Reject alg:none and enforce a single expected algorithm server-side, "
        "replace weak signing secrets with a high-entropy key (or move to "
        "asymmetric keys and pin the public key), and verify the token's "
        "signature, issuer, audience and expiry on every privileged route.")
    steps = [
        "JWT audit flagged the token as forgeable.",
        "Discovery found a privileged / auth-gated endpoint on the target.",
        "A forged token presented to that endpoint would pass signature "
        "checks, so the authorization boundary collapses.",
    ]
    return [_mk_path(name=name, severity="high", exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=80, tags=["auth", "jwt"])]


def _rule_source_to_secret(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Exposed source/VCS + a secret found -> source leaks credentials."""
    if not idx.get("source_exposed"):
        return []
    secrets = idx.get("credential") or []
    comps = _top(idx, "source_exposed", 2)
    sev = "high"
    if secrets:
        comps = comps + secrets[:2]
        summary = (
            "Application source or a version-control directory is exposed, and "
            "the run recovered live secrets. The exposed source is the most "
            "likely origin of those secrets and almost certainly hides more.")
        expl = "public_poc"
        conf = 85
    else:
        summary = (
            "Application source or a version-control directory (.git/.svn, a "
            "source map, or a backup/dump) is publicly readable. Attackers "
            "routinely reconstruct the full codebase from it and mine it for "
            "credentials, internal endpoints and logic flaws.")
        expl = "theoretical"
        conf = 75
    name = "Exposed source code leaks application secrets"
    impact = ("Recovery of the server-side codebase and any credentials, "
              "internal URLs or signing keys committed into it.")
    remediation = (
        "Block public access to .git/.svn/.hg, source maps and backup/dump "
        "files at the web server or CDN, purge any committed secrets from "
        "history and rotate them, and add a CI check that fails on secrets "
        "in the tree.")
    steps = [
        "A plugin found publicly readable source / VCS data.",
        "Secrets recovered elsewhere in the run trace back to that source."
        if secrets else
        "The exposed tree can be downloaded and mined offline for secrets.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability=expl,
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=conf, tags=["exposure", "source"],
                     redact_components=True)]


def _rule_ssrf_metadata(idx: SignalIndex) -> List[Dict[str, Any]]:
    """SSRF on cloud-hosted target -> instance metadata / credential theft."""
    if not idx.get("ssrf"):
        return []
    cloud = idx.get("cloud_hosted") or []
    meta = idx.get("ssrf_metadata") or []
    if not (cloud or meta):
        return []
    comps = _top(idx, "ssrf", 1) + cloud[:1] + meta[:1]
    sev = "critical" if meta else "high"
    name = "SSRF on cloud-hosted target can reach instance metadata"
    summary = (
        "A server-side request forgery vector was found on a target hosted in "
        "a cloud provider. On most clouds, SSRF can reach the instance "
        "metadata service (169.254.169.254) and read temporary IAM "
        "credentials, turning a request-forgery bug into cloud account "
        "access.")
    impact = ("Theft of the instance's cloud credentials and pivot into the "
              "cloud account; internal service access behind the perimeter.")
    remediation = (
        "Enforce IMDSv2 (or disable instance metadata), add an egress "
        "allow-list so the app cannot call link-local/internal ranges, and "
        "validate/resolve user-supplied URLs against an allow-list before "
        "fetching.")
    steps = [
        "An SSRF-prone parameter was identified.",
        "The target resolves to cloud-hosted infrastructure.",
        "SSRF from inside that host can address the metadata endpoint and "
        "read short-lived credentials.",
    ]
    return [_mk_path(name=name, severity=sev,
                     exploitability="public_poc" if meta else "theoretical",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=78, tags=["ssrf", "cloud"])]


def _rule_subdomain_takeover(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Dangling / unclaimed DNS target -> subdomain takeover."""
    cands = idx.get("takeover_candidate")
    if not cands:
        return []
    comps = cands[:3]
    name = "Unclaimed DNS target enables subdomain takeover"
    summary = (
        "One or more subdomains point (via CNAME/alias) at a service or bucket "
        "that is no longer claimed. An attacker can register the dangling "
        "target and serve content from a hostname the organization owns.")
    impact = (
        "Host attacker content on a trusted subdomain: phishing with a real "
        "domain, cookie theft if session cookies are scoped to the parent "
        "domain, and OAuth/callback abuse.")
    remediation = (
        "Remove the dangling DNS record, or re-claim the pointed-to resource. "
        "Audit all CNAMEs for unclaimed third-party targets and monitor for "
        "new dangling records.")
    steps = [
        "DNS enumeration found a subdomain aliased to an unclaimed target.",
        "The target service allows anyone to claim that name/bucket.",
        "Claiming it lets the attacker serve content from the org's "
        "subdomain.",
    ]
    return [_mk_path(name=name, severity="high", exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=82, tags=["dns", "takeover"])]


def _rule_cors_data_theft(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Permissive CORS + credentialed/privileged API -> cross-origin theft."""
    if not idx.get("cors"):
        return []
    api = _top(idx, "privileged_endpoint", 1) + _top(idx, "auth_surface", 1)
    comps = _top(idx, "cors", 1) + api
    sev = "high" if api else "medium"
    name = "Permissive CORS over an authenticated API enables cross-origin data theft"
    summary = (
        "The target reflects arbitrary origins (or allows credentials with a "
        "wildcard) in its CORS policy" + (
            ", and the run found an authenticated/privileged API on the same "
            "host" if api else "") +
        ". A malicious page the victim visits can read authenticated "
        "responses from the API using the victim's own session.")
    impact = ("Read the victim's authenticated API data from any attacker "
              "website the victim opens while logged in.")
    remediation = (
        "Never reflect the Origin header blindly; allow-list exact origins, "
        "and never combine Access-Control-Allow-Credentials: true with a "
        "wildcard or reflected origin.")
    steps = [
        "CORS audit found an over-permissive policy.",
        "An authenticated/privileged endpoint shares that origin."
        if api else "The permissive policy applies to data endpoints.",
        "A cross-origin page can read the victim's authenticated responses.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=72, tags=["web", "cors"])]


def _rule_mgmt_port(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Open management service (+ default creds) -> direct access."""
    ports = idx.get("mgmt_port")
    if not ports:
        return []
    creds = idx.get("default_creds") or []
    comps = ports[:3] + creds[:1]
    sev = "high"
    if creds:
        expl = "weaponized"
        conf = 88
        summary = (
            "A management/database service is exposed to the internet AND the "
            "run found default or weak credentials for the stack. That is "
            "direct, hands-on-keyboard access.")
    else:
        expl = "theoretical"
        conf = 70
        summary = (
            "A management or database service (SSH, RDP, a database, Redis, "
            "Elasticsearch, Docker/kubelet, etc.) is reachable from the "
            "internet. These are high-value brute-force and known-CVE targets "
            "and usually should sit behind a VPN/allow-list.")
    name = "Internet-exposed management service"
    impact = ("Direct administrative or database access to the host, or a "
              "strong brute-force / known-exploit target.")
    remediation = (
        "Restrict the service to a VPN or IP allow-list, require key-based "
        "auth and MFA, change any default credentials, and patch to a "
        "current version.")
    steps = [
        "A port scan found a management/database service open to the "
        "internet.",
        ("Default or weak credentials for that service were also found - "
         "login is immediate." if creds else
         "The service is a prime brute-force / known-CVE target."),
    ]
    return [_mk_path(name=name, severity=sev, exploitability=expl,
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=conf, tags=["infra", "ports"])]


def _rule_breach_credstuff(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Breached credentials + reachable login -> credential stuffing."""
    if not idx.get("breach"):
        return []
    login = _top(idx, "auth_surface", 1)
    if not login:
        return []
    comps = _top(idx, "breach", 2) + login
    name = "Breached credentials plus a reachable login (credential-stuffing path)"
    summary = (
        "Email addresses / credentials tied to the target appear in known "
        "breach data, and the run found a live login surface. Attackers replay "
        "breached passwords against that login, and reused passwords let them "
        "straight in.")
    impact = ("Account takeover of any user who reused a breached password, "
              "including staff with elevated access.")
    remediation = (
        "Force a password reset for affected accounts, enforce MFA on the "
        "login, add breached-password screening at sign-in, and rate-limit / "
        "add bot defenses to the auth endpoint.")
    steps = [
        "Breach data references the target's accounts.",
        "A live login endpoint was discovered.",
        "Breached passwords are replayed against the login; reused ones "
        "succeed.",
    ]
    return [_mk_path(name=name, severity="medium", exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=68, tags=["identity", "breach"],
                     redact_components=True)]


def _rule_idor_surface(idx: SignalIndex) -> List[Dict[str, Any]]:
    """IDOR/BOLA candidate + enumerated API/privileged surface."""
    if not idx.get("idor"):
        return []
    api = _top(idx, "privileged_endpoint", 2) + _top(idx, "api_docs", 1)
    comps = _top(idx, "idor", 2) + api
    sev = "high" if api else "medium"
    name = "Object-level authorization gap across the API surface"
    summary = (
        "An IDOR/BOLA candidate was found" + (
            ", and the run mapped a broad API/privileged surface it can be "
            "walked across" if api else "") +
        ". If object identifiers are not authorization-checked, an attacker "
        "enumerates other users' objects by changing an id.")
    impact = ("Read or modify other users' records by iterating object ids "
              "across the API.")
    remediation = (
        "Enforce object-level authorization on every record access (check the "
        "requester owns or may access the object), not just authentication; "
        "test each endpoint with a second account.")
    steps = [
        "A request with a swapped object id returned another object (IDOR "
        "candidate).",
        "The API surface exposes many such id-addressed endpoints."
        if api else "The endpoint is id-addressed.",
        "Iterating ids walks other users' data.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps,
                     components=comps, confidence=74, tags=["api", "authz"])]


def _rule_secret_sprawl(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Many distinct secrets exposed -> systemic secrets-management failure."""
    creds = idx.get("credential") or []
    # distinct by (plugin,key) so one noisy plugin doesn't inflate it
    distinct = {(_row_plugin(c), _norm(c.get("key"))) for c in creds}
    if len(distinct) < 3:
        return []
    comps = creds[:5]
    name = f"Secret sprawl: {len(distinct)} distinct secret types exposed"
    summary = (
        f"The target exposed {len(distinct)} different classes of secret "
        "across the run. This is a systemic secrets-management failure, not a "
        "one-off slip, and strongly predicts more undiscovered exposure.")
    impact = ("Multiple independent credentials are available to an attacker; "
              "any one may unlock a critical system.")
    remediation = (
        "Move all secrets into a managed secrets store, rotate everything "
        "found, add pre-commit and CI secret scanning, and audit build "
        "artifacts (env files, source maps, bundles) for embedded secrets.")
    steps = [
        "Multiple plugins recovered different kinds of secret.",
        "The breadth indicates secrets are committed/baked in broadly.",
        "An attacker collects them wholesale.",
    ]
    return [_mk_path(name=name, severity="high", exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=80, tags=["exposure", "secrets"],
                     redact_components=True)]


def _rule_api_docs_exposed(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Full API documentation/introspection exposed -> mapped surface."""
    if not idx.get("api_docs"):
        return []
    comps = _top(idx, "api_docs", 2) + _top(idx, "privileged_endpoint", 1)
    name = "Full API surface is self-documenting to attackers"
    summary = (
        "An API schema is publicly readable (OpenAPI/Swagger, GraphQL "
        "introspection, or similar). It hands an attacker the complete map of "
        "endpoints, parameters and object types to probe for authz and input "
        "flaws - the reconnaissance is done for them.")
    impact = ("A complete, machine-readable endpoint map that accelerates "
              "authz testing, injection and IDOR discovery.")
    remediation = (
        "Disable schema introspection and public API docs in production, or "
        "put them behind authentication; ensure every documented endpoint "
        "still enforces its own authz.")
    steps = [
        "The API publishes its own schema/introspection.",
        "Every endpoint, parameter and type is now known to the attacker.",
        "Testing for authz/injection flaws is guided directly by the schema.",
    ]
    return [_mk_path(name=name, severity="medium", exploitability="theoretical",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=70, tags=["api", "exposure"])]


def _rule_open_redirect_oauth(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Open redirect on an OAuth/SSO flow -> token/account takeover."""
    if not idx.get("open_redirect"):
        return []
    oauth = _top(idx, "oauth", 2)
    if not oauth:
        return []
    comps = _top(idx, "open_redirect", 1) + oauth
    name = "Open redirect on an OAuth/SSO flow enables account takeover"
    summary = (
        "An open redirect was found on a host that also runs an OAuth/SSO "
        "login flow. Attackers abuse the redirect to steal the authorization "
        "code or access token mid-flow (the token is appended to a URL that "
        "now points at attacker infrastructure), taking over the account.")
    impact = ("Capture a victim's OAuth code/token during login and sign in "
              "as them — full account takeover with no password needed.")
    remediation = (
        "Strictly allow-list redirect targets (exact match, no open "
        "parameters), validate OAuth redirect_uri against a fixed registered "
        "list server-side, and never reflect a user-controlled 'next'/'return' "
        "URL without validation.")
    steps = [
        "An endpoint redirects to an attacker-controlled URL (open redirect).",
        "The same host runs an OAuth/SSO flow that carries a code/token in a "
        "redirect.",
        "Chaining them routes the victim's token to the attacker.",
    ]
    return [_mk_path(name=name, severity="high", exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=73, tags=["auth", "oauth"])]


def _rule_internal_host_ssrf(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Leaked internal hostnames + an SSRF vector -> internal pivot."""
    if not idx.get("internal_host"):
        return []
    ssrf = _top(idx, "ssrf", 1)
    comps = _top(idx, "internal_host", 2) + ssrf
    sev = "high" if ssrf else "medium"
    if ssrf:
        summary = (
            "Internal hostnames/URLs leaked into client-side code or "
            "responses, and an SSRF vector was found. The leaked names are "
            "exactly the internal targets an attacker points the SSRF at — "
            "the reconnaissance for an internal pivot is already done.")
        expl = "public_poc"
    else:
        summary = (
            "Internal hostnames, private IPs or staging/dev URLs leaked into "
            "client-facing code or responses. They map the internal network "
            "and become the target list for any future SSRF or access to a "
            "mistakenly exposed internal service.")
        expl = "theoretical"
    name = "Leaked internal hostnames expand the internal attack surface"
    impact = ("A map of internal services an attacker can target via SSRF or "
              "a misconfigured gateway to reach systems behind the perimeter.")
    remediation = (
        "Strip internal hostnames, private IPs and staging URLs from "
        "client-side bundles and error responses; segment internal services "
        "so a leaked name is not directly reachable.")
    steps = [
        "Internal hostnames/IPs were found in client-facing content.",
        ("An SSRF vector can be pointed at those internal names."
         if ssrf else "They become the target list for a future SSRF."),
        "Internal services become reachable from outside.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability=expl,
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=68, tags=["infra", "ssrf"])]


def _rule_ci_supply_chain(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Exposed CI config / package manifest -> supply-chain exposure."""
    ci = idx.get("ci_config") or []
    pkg = idx.get("pkg_manifest") or []
    if not (ci or pkg):
        return []
    comps = (ci[:2] + pkg[:2])
    creds = idx.get("credential") or []
    if ci and creds:
        sev, expl, conf = "high", "public_poc", 78
        summary = (
            "CI/CD pipeline configuration is exposed AND secrets were "
            "recovered. Pipeline configs routinely reference deploy keys, "
            "registry tokens and environment secrets — an attacker reads the "
            "build to learn where the keys are and what they unlock.")
        comps = ci[:2] + creds[:2]
        tags = ["supply-chain", "ci", "secrets"]
        name = "Exposed CI/CD config leaks pipeline secrets (supply-chain risk)"
    elif pkg:
        sev, expl, conf = "medium", "theoretical", 64
        summary = (
            "A dependency manifest is exposed and references internal/private "
            "package scopes. If those scoped names are not reserved on the "
            "public registry, an attacker can publish a malicious package "
            "under the same name (dependency confusion) and have the build "
            "pull it.")
        tags = ["supply-chain", "dependency-confusion"]
        name = "Exposed manifest enables a dependency-confusion attack"
    else:
        sev, expl, conf = "medium", "theoretical", 62
        summary = (
            "CI/CD pipeline configuration is publicly readable. It reveals the "
            "build and deploy process, referenced secrets and infrastructure — "
            "a roadmap for supply-chain and deployment attacks.")
        tags = ["supply-chain", "ci"]
        name = "Exposed CI/CD configuration (supply-chain reconnaissance)"
    impact = ("Insight into (or direct access to) the build/deploy pipeline "
              "and its secrets — a route to poisoning releases.")
    remediation = (
        "Remove CI config and manifests from the public web root, reserve all "
        "internal package names on the public registry, rotate any secret the "
        "pipeline references, and scope CI tokens to least privilege.")
    steps = [
        "A CI config or dependency manifest is publicly readable.",
        "It exposes the pipeline's secrets / internal package names.",
        "An attacker targets the build to reach production.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability=expl,
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=conf, tags=tags)]


def _rule_debug_disclosure(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Debug mode / stack traces + any secret or internal detail."""
    if not idx.get("debug_mode"):
        return []
    extra = (idx.get("credential") or [])[:1] + (idx.get("internal_host") or [])[:1]
    comps = _top(idx, "debug_mode", 2) + extra
    sev = "high" if idx.get("credential") else "medium"
    name = "Production debug mode leaks internals (and secrets)"
    summary = (
        "The application runs with debug mode on / verbose error pages in "
        "production" + (
            ", and secrets were recovered from exactly that kind of output"
            if idx.get("credential") else "") +
        ". Debug pages expose stack traces, environment variables, framework "
        "internals and often live credentials to anyone who triggers an "
        "error.")
    impact = ("Disclosure of source paths, environment variables, framework "
              "versions and frequently live secrets via error pages.")
    remediation = (
        "Turn off debug mode in production, return generic error pages, and "
        "rotate anything that appeared in a debug/stack-trace response.")
    steps = [
        "Debug mode / verbose errors are on in production.",
        "Triggering an error dumps internals (and sometimes secrets).",
        "An attacker harvests that output.",
    ]
    return [_mk_path(name=name, severity=sev, exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=steps, components=comps,
                     confidence=70, tags=["web", "disclosure"])]


def _rule_weaponized_cve(idx: SignalIndex) -> List[Dict[str, Any]]:
    """A weaponized public exploit against a reachable service = top finding.

    The CVE matcher (and some detectors) rate exploitability. A weaponized
    rating means a public exploit exists. That is the single most valuable
    thing a scan can surface, so it becomes a critical attack path on its
    own - and if the same run shows the service is privileged/auth-gated or
    internet-exposed, the narrative says so."""
    cves = idx.get("weaponized_cve")
    if not cves:
        return []
    # one path per distinct weaponized finding (top few by severity)
    out: List[Dict[str, Any]] = []
    reach = (_top(idx, "privileged_endpoint", 1) + _top(idx, "mgmt_port", 1)
             + _top(idx, "auth_surface", 1))
    seen_val: Set[str] = set()
    for cve in cves[:4]:
        v = _norm(cve.get("value"))[:120]
        if v in seen_val:
            continue
        seen_val.add(v)
        comps = [cve] + reach[:1]
        reached = ("the same run found a reachable privileged/management "
                   "entry point on this host, so the exploit has somewhere "
                   "to land" if reach else
                   "confirm the affected service is reachable from your "
                   "testing position")
        name = f"Weaponized exploit available: {cve.get('value', 'known CVE')}"[:140]
        summary = (
            "A fingerprinted service matches a CVE with a public, working "
            f"exploit. {reached[0].upper() + reached[1:]}. Weaponized bugs "
            "are the highest-value finding in a scan - treat this as an "
            "active, exploitable entry point until patched.")
        impact = ("Direct compromise of the affected service using a "
                  "publicly available exploit - frequently unauthenticated "
                  "code execution.")
        remediation = (cve.get("evidence", {}) or {}).get("remediation") or (
            "Patch or upgrade the affected software to a fixed version "
            "immediately and restrict the service's exposure.")
        steps = [
            "Version/product fingerprint matched a CVE with a public exploit.",
            ("A reachable privileged/management endpoint was also found."
             if reach else "Confirm the service is reachable."),
            "A known exploit turns the match into code execution / takeover.",
        ]
        out.append(_mk_path(
            name=name, severity="critical",
            exploitability="weaponized", summary=summary,
            attacker_impact=impact, remediation=remediation, steps=steps,
            components=comps, confidence=int(cve.get("confidence") or 85),
            tags=["cve", "weaponized"]))
    return out


def _rule_kill_chain(idx: SignalIndex) -> List[Dict[str, Any]]:
    """Compound path: when several high-value stages co-occur, synthesize a
    single multi-stage kill chain from foothold -> escalation -> impact.

    This is the "more complex finding" - it does not just report each weak
    spot, it orders them into the sequence an attacker would actually walk.
    """
    # Stage buckets, in kill-chain order. Each maps to a short stage line
    # and the findings that satisfy it.
    stages: List[Tuple[str, str, List[Dict[str, Any]]]] = []

    def add(label: str, desc: str, *signals: str):
        found: List[Dict[str, Any]] = []
        for s in signals:
            found += idx.get(s, [])
        if found:
            stages.append((label, desc, found[:2]))

    add("Recon / surface", "map the surface from exposed docs and sources",
        "api_docs", "source_exposed", "internal_host", "ci_config")
    add("Foothold", "obtain a credential or forge a token",
        "credential", "forgeable_token", "default_creds", "breach")
    add("Access", "reach a privileged/management entry point",
        "privileged_endpoint", "mgmt_port", "auth_surface")
    add("Escalation / pivot", "pivot into cloud or internal infrastructure",
        "storage", "cloud_hosted", "ssrf", "takeover_candidate")

    # Only fire when the chain spans at least 3 of the 4 stages AND there is
    # real severity behind it (a foothold or an escalation stage present).
    labels = [s[0] for s in stages]
    has_foothold = "Foothold" in labels
    has_escalation = "Escalation / pivot" in labels
    if len(stages) < 3 or not (has_foothold or has_escalation):
        return []

    comps: List[Dict[str, Any]] = []
    for _l, _d, found in stages:
        comps += found
    # dedup components by (plugin,key,value)
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for c in comps:
        k = (_row_plugin(c), _norm(c.get("key")), _norm(c.get("value")))
        if k not in seen:
            seen.add(k)
            uniq.append(c)

    # severity: critical if the chain reaches escalation off a real foothold
    sev = "critical" if (has_foothold and has_escalation) else "high"
    kill_chain = [f"{i+1}. {lbl}: {desc}"
                  for i, (lbl, desc, _f) in enumerate(stages)]
    name = f"Full kill chain across {len(stages)} stages"
    summary = (
        "Several findings line up into one end-to-end attack sequence, not "
        "just isolated weak spots. An attacker can walk it from initial "
        "recon through a foothold to real impact: "
        + " → ".join(lbl for lbl, _d, _f in stages) + ".")
    impact = ("A complete, chainable route from outside the perimeter to "
              "privileged access / infrastructure control — the findings "
              "reinforce each other rather than standing alone.")
    remediation = (
        "Break the chain at any stage: close the earliest/cheapest links "
        "first (remove exposed docs/source, rotate the foothold credential), "
        "then the escalation links (lock down the privileged entry point and "
        "segment cloud/internal infra). Breaking one link defeats the whole "
        "path.")
    return [_mk_path(name=name, severity=sev, exploitability="public_poc",
                     summary=summary, attacker_impact=impact,
                     remediation=remediation, steps=kill_chain,
                     kill_chain=kill_chain, components=uniq,
                     confidence=76, tags=["kill-chain", "compound"])]


RULES = [
    _rule_weaponized_cve,
    _rule_kill_chain,
    _rule_cloud_cred_blast,
    _rule_jwt_authbypass,
    _rule_source_to_secret,
    _rule_ssrf_metadata,
    _rule_internal_host_ssrf,
    _rule_subdomain_takeover,
    _rule_cors_data_theft,
    _rule_open_redirect_oauth,
    _rule_mgmt_port,
    _rule_breach_credstuff,
    _rule_idor_surface,
    _rule_ci_supply_chain,
    _rule_debug_disclosure,
    _rule_secret_sprawl,
    _rule_api_docs_exposed,
]


# ---------------------------------------------------------------------------
# Exposure score: one 0-100 number for the whole run, so Jay can compare
# runs at a glance and sort a fleet. Deterministic, bounded, explainable.
# ---------------------------------------------------------------------------

def _exposure_score(rows: List[Dict[str, Any]],
                    paths: List[Dict[str, Any]]) -> Dict[str, Any]:
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    worst = 0
    expl_boost = 0
    for r in rows:
        s = _row_sev(r)
        sev_counts[s] = sev_counts.get(s, 0) + 1
        worst = max(worst, _SEV_RANK.get(s, 1))
        expl_boost = max(expl_boost, _EXPL_RANK.get(_row_expl(r), 0))

    # Base: the single worst finding sets the floor (one critical already
    # means you are badly exposed). Then counts and attack paths add on,
    # with diminishing returns so a noisy run doesn't peg at 100 on lows.
    floor = {4: 70, 3: 45, 2: 22, 1: 6}.get(worst, 0)
    import math
    vol = (18 * math.log1p(sev_counts["critical"] * 3
                           + sev_counts["high"] * 2
                           + sev_counts["medium"]))
    path_pts = min(len(paths) * 6, 24)
    # weaponized evidence anywhere pushes it up
    weapon_pts = {3: 10, 2: 6, 1: 2, 0: 0}[expl_boost]
    score = int(round(min(100, floor + vol + path_pts + weapon_pts)))
    if worst == 0:
        score = 0

    band = ("critical" if score >= 80 else "high" if score >= 55
            else "medium" if score >= 30 else "low" if score > 0 else "clean")
    headline = {
        "critical": "Critical exposure — act now.",
        "high": "High exposure — prioritize remediation.",
        "medium": "Moderate exposure — several issues to fix.",
        "low": "Low exposure — minor findings only.",
        "clean": "No material exposure found.",
    }[band]
    return {
        "score": score,
        "band": band,
        "headline": headline,
        "severity_counts": sev_counts,
        "attack_path_count": len(paths),
        "worst_severity": {4: "critical", 3: "high", 2: "medium",
                           1: "low", 0: "none"}[worst],
    }


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------

def _build_index(rows: List[Dict[str, Any]]) -> SignalIndex:
    idx: SignalIndex = {}
    for r in rows:
        # never correlate on our own output (idempotent across re-finalize)
        if _row_plugin(r) == "correlation" or _norm(r.get("key")) == "attack_path":
            continue
        for s in _detect_signals(r):
            idx.setdefault(s, []).append(r)
    # strongest evidence first within each signal: severity, then confidence
    for s, lst in idx.items():
        lst.sort(key=lambda r: (-_SEV_RANK.get(_row_sev(r), 1),
                                -int(r.get("confidence") or 0)))
    return idx


def correlate(rows: List[Dict[str, Any]], host_hint: Optional[str] = None
              ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Synthesize attack paths and an exposure score from a run's findings.

    ``rows`` are finding dicts (as produced by reporting.findings_dump, or
    any dict with key/value/category/evidence/plugin fields).
    ``host_hint`` is the run's primary target, used to resolve verification
    commands where a finding carries no host of its own. Returns
    ``(paths, exposure)``: ``paths`` is a list of finding-shaped dicts to
    persist (plugin_id "correlation"), ``exposure`` is the summary block.

    Pure and deterministic. Never raises on bad input - a malformed row is
    skipped, the worst case is fewer paths.
    """
    safe_rows = [r for r in rows if isinstance(r, dict)]
    idx = _build_index(safe_rows)
    paths: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for rule in RULES:
        try:
            for p in rule(idx):
                pid = p["evidence"]["path_id"]
                if pid in seen:
                    continue
                seen.add(pid)
                # fill verification commands with the real host hint
                try:
                    p["evidence"]["commands"] = _path_commands(
                        p["evidence"].get("components", []), host_hint)
                except Exception:
                    pass
                paths.append(p)
        except Exception:
            # one bad rule never sinks the pass
            continue
    # highest severity / exploitability first, stable
    paths.sort(key=lambda p: (
        -_SEV_RANK.get(_norm(p["evidence"].get("severity")), 1),
        -_EXPL_RANK.get(_norm(p["evidence"].get("exploitability")), 0),
        -int(p.get("confidence") or 0),
        p["value"]))
    exposure = _exposure_score(safe_rows, paths)
    return paths, exposure
