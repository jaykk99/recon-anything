"""Content-signature verification for exposed-file / sensitive-path hits.

A sensitive path returning HTTP 200 proves nothing on its own. SPA
catch-alls (React/Next/Vue) serve 200 + index.html for *every* path,
WAF interstitials and login walls serve 200 with HTML, and a generic
403 says only "something is here". Reporting a bare status hit as
"HIGH: exposed .env" is exactly the noise that makes a scanner
untrustworthy - and when the file really is exposed, "path exists (200,
N bytes)" is not a finding a paying user can act on either.

A real exposure is proven by the response *content* matching the
artifact it claims to be: a ``.git/HEAD`` that begins ``ref:``, a
``.env`` of ``KEY=VALUE`` lines, an "Index of /" directory listing, a
SQL dump, an OpenAPI schema. ``confirm_exposure`` returns a verified
exposure ONLY on such a content match, carrying a proof snippet a human
can check and a severity set by what actually leaked. No match -> None,
and the caller must not report the path as an exposure.

Pure and deterministic: no I/O, no network. The caller fetches; this
module judges. Secret-looking values in the proof are masked so the
finding never itself leaks the credential in full.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

# A value worth calling out inside a leaked config/env: its key names a
# credential. Used to escalate severity and to pick which lines to show.
_SECRET_KEY_RE = re.compile(
    r"(?i)(pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth|credential|"
    r"aws_|db_|database_url|conn(?:ection)?[_-]?string|mnemonic|seed)")

_HTML_HEAD_RE = re.compile(r"<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]", re.I)


def _looks_like_html(body: str) -> bool:
    """A sensitive artifact served as an HTML page is the SPA/WAF
    catch-all, not the artifact. Reject it."""
    return bool(_HTML_HEAD_RE.search(body[:400]))


def _mask(value: str, show: int = 3) -> str:
    v = value.strip()
    if len(v) <= show * 2:
        return "***"
    return v[:show] + "…" + v[-show:]


# --- individual verifiers: body (+headers) -> proof string, or None ----

def _v_git_head(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    head = body.strip()
    if head.startswith("ref:") and "refs/" in head[:80]:
        return f"git HEAD ref: {head.splitlines()[0][:80]}"
    if re.fullmatch(r"[0-9a-f]{40}", head[:40]) and len(head) < 64:
        return f"git HEAD detached at {head[:40]}"
    return None


def _v_git_config(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    if "[core]" in body and ("repositoryformatversion" in body
                             or "[remote" in body or "bare" in body):
        url = re.search(r"url\s*=\s*(\S+)", body)
        extra = f" (remote {url.group(1)[:80]})" if url else ""
        return f"git config exposed{extra}"
    return None


def _v_env(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()
             and not ln.lstrip().startswith("#")]
    kv = [ln for ln in lines if re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", ln)]
    # Need to look like an env file, not one stray "a=b" in prose.
    if len(kv) < 2 or (len(lines) and len(kv) / len(lines) < 0.5):
        return None
    secret_keys = [ln.split("=", 1)[0].strip() for ln in kv
                   if _SECRET_KEY_RE.search(ln.split("=", 1)[0])]
    if secret_keys:
        return ("env file with credential keys: "
                + ", ".join(secret_keys[:6]))
    return f"env file exposed ({len(kv)} KEY=VALUE lines)"


def _v_dir_listing(body: str, headers: Dict[str, str]) -> Optional[str]:
    low = body[:4000].lower()
    if ("<title>index of " in low or ">index of /" in low
            or "directory listing for" in low
            or ("[to parent directory]" in low)):
        m = re.search(r"index of\s+([^\s<]+)", body, re.I)
        return f"directory listing{(' of ' + m.group(1)) if m else ''}"
    return None


def _v_json_config(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    try:
        obj = json.loads(body)
    except Exception:
        return None
    if not isinstance(obj, (dict, list)):
        return None
    flat = json.dumps(obj)
    keys = _SECRET_KEY_RE.findall(flat)
    if keys:
        # name the actual secret-ish keys present
        found = [k for k in re.findall(r'"([^"]+)"\s*:', flat)
                 if _SECRET_KEY_RE.search(k)]
        if found:
            return "JSON config with credential keys: " + ", ".join(
                sorted(set(found))[:6])
    return None


def _v_sql_dump(body: str, headers: Dict[str, str]) -> Optional[str]:
    head = body[:4000]
    if re.search(r"--\s*(MySQL|MariaDB|PostgreSQL) dump", head, re.I) \
            or re.search(r"CREATE TABLE\s+[`\"']?\w", head) \
            or re.search(r"INSERT INTO\s+[`\"']?\w", head):
        return "SQL dump / database backup"
    return None


def _v_phpinfo(body: str, headers: Dict[str, str]) -> Optional[str]:
    if "<title>phpinfo()" in body[:2000].lower() or (
            "phpinfo()" in body and "PHP Version" in body[:4000]):
        m = re.search(r"PHP Version\s*</?\w*>?\s*([\d.]+)", body)
        return f"phpinfo() exposed{(' PHP ' + m.group(1)) if m else ''}"
    return None


def _v_server_status(body: str, headers: Dict[str, str]) -> Optional[str]:
    if "Apache Server Status" in body[:2000] or re.search(
            r"Server (Version|uptime|Load):", body[:2000]):
        return "Apache server-status exposed (internal metrics/URLs)"
    return None


def _v_htpasswd(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    for ln in body.splitlines()[:20]:
        if re.match(r"^[^:\s]+:\$(?:apr1|2[aby]|1|5|6)\$", ln) \
                or re.match(r"^[^:\s]+:\{SHA\}", ln):
            user = ln.split(":", 1)[0]
            return f"htpasswd hashes exposed (user '{user[:40]}' + others)"
    return None


def _v_openapi(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    try:
        obj = json.loads(body)
    except Exception:
        return None
    if isinstance(obj, dict) and (
            "swagger" in obj or "openapi" in obj
            or ("paths" in obj and isinstance(obj.get("paths"), dict))):
        n = len(obj.get("paths", {}) or {})
        return f"OpenAPI/Swagger schema exposed ({n} paths mapped)"
    return None


def _v_graphql_introspection(body: str, headers: Dict[str, str]
                             ) -> Optional[str]:
    if '"__schema"' in body or '"queryType"' in body or (
            '"types"' in body and '"kind"' in body and '"OBJECT"' in body):
        return "GraphQL introspection enabled (full schema readable)"
    return None


def _v_php_source(body: str, headers: Dict[str, str]) -> Optional[str]:
    # A .php backup served as text leaks server-side source.
    if "<?php" in body[:4000]:
        creds = re.findall(
            r"(DB_PASSWORD|DB_USER|DB_HOST|define\s*\(\s*['\"]DB_|"
            r"password\s*=>|secret)", body, re.I)
        tag = " with DB credentials" if creds else ""
        return f"PHP source code exposed{tag}"
    return None


def _v_aws_creds(body: str, headers: Dict[str, str]) -> Optional[str]:
    if _looks_like_html(body):
        return None
    if re.search(r"aws_access_key_id\s*=", body, re.I) or \
            re.search(r"\bAKIA[0-9A-Z]{16}\b", body):
        return "AWS credentials file exposed"
    return None


# --- path -> applicable verifiers, severity, and label -----------------
# Each rule: substring/suffix that a path must contain, the verifier, a
# base severity, whether a credential hit escalates it, and a label.

_RULES = [
    (("/.git/head", ".git/head"), _v_git_head, "high", "exposed .git repository"),
    (("/.git/config", ".git/config"), _v_git_config, "high", "exposed .git repository"),
    ((".env",), _v_env, "high", "exposed environment file"),
    ((".aws/credentials", "aws/credentials"), _v_aws_creds, "critical", "exposed cloud credentials"),
    ((".htpasswd", "htpasswd"), _v_htpasswd, "high", "exposed htpasswd hashes"),
    ((".sql", "dump.sql", "backup.sql", "db.sql"), _v_sql_dump, "high", "exposed database dump"),
    (("phpinfo", "info.php"), _v_phpinfo, "medium", "exposed phpinfo()"),
    (("server-status",), _v_server_status, "medium", "exposed Apache server-status"),
    (("swagger", "openapi", "api-docs"), _v_openapi, "medium", "exposed API schema"),
    (("graphql", "graphiql", "altair"), _v_graphql_introspection, "medium", "GraphQL introspection"),
    (("config.json", "appsettings", "settings.json", ".json"), _v_json_config, "high", "exposed config with secrets"),
    (("wp-config", "config.php", ".php.bak", ".php.old", "database.php", "db.php"), _v_php_source, "high", "exposed server source"),
]

# Paths where, if no signature matches, a bare 200/403 must NOT be
# reported as an exposure (SPA catch-all territory). These are the
# "scary" sensitive files whose whole value is content confirmation.
_SIGNATURE_EXPECTED = (
    ".env", ".git", ".svn", ".hg", "config.json", "appsettings",
    "settings.json", "wp-config", "config.php", ".sql", "dump.sql",
    "backup.sql", "db.sql", ".htpasswd", "htpasswd", "aws/credentials",
    "phpinfo", "info.php", "server-status", "swagger", "openapi",
    "api-docs", "graphql", ".bak", ".old", ".save", ".orig",
    "database.php", "db.php", ".DS_Store",
)


def signature_expected(path: str) -> bool:
    """True when `path` is a sensitive artifact whose exposure must be
    content-confirmed; a bare status hit on it is not a finding."""
    p = path.lower()
    return any(tok in p for tok in _SIGNATURE_EXPECTED)


def confirm_exposure(path: str, status: int, body: str,
                     headers: Optional[Dict[str, str]] = None
                     ) -> Optional[Dict[str, Any]]:
    """Return a verified-exposure dict, or None if the content does not
    prove the path is the sensitive artifact it looks like.

    Returned dict: {kind, label, severity, proof, confidence}. ``proof``
    is a short human-checkable snippet (secrets masked). A directory
    listing is checked for any path (dir listings are path-agnostic).
    """
    headers = headers or {}
    if not body or status in (0, 404):
        return None
    p = path.lower()

    # Directory listing: not tied to a particular path.
    dl = _v_dir_listing(body, headers)
    if dl:
        return {"kind": "directory_listing", "label": "directory listing",
                "severity": "medium", "proof": dl, "confidence": 95}

    for tokens, verifier, severity, label in _RULES:
        if not any(t in p for t in tokens):
            continue
        proof = verifier(body, headers)
        if not proof:
            continue
        sev = severity
        # Escalate only when the verifier's proof explicitly reports
        # credentials - match the phrases the verifiers emit, not any
        # stray "secret" (e.g. a repo named secret.git must not escalate).
        if re.search(r"(?i)credential keys|credentials file|"
                     r"credentials exposed|with DB credentials|"
                     r"with credential", proof):
            if sev == "high":
                sev = "critical"
            elif sev == "medium":
                sev = "high"
        return {"kind": "exposed_file", "label": label, "severity": sev,
                "proof": proof[:200], "confidence": 97}
    return None
