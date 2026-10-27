"""Per-finding verification commands ("how do I confirm this myself?").

A finding people can act on tells them the exact command to run to
reproduce / confirm it. This module turns a finding into a small set of
copy-pasteable commands.

SCOPE — read-only verification only
-----------------------------------
Every command here *confirms the finding exists* or *identifies its
scope*: a curl of an exposed file, a dig for a dangling CNAME, an
openssl handshake, a JWT base64-decode, an `sts get-caller-identity`
that just names whose key it is. None of them read or modify target
data at scale, drop a shell, dump a database, or pivot. That is the
same detection-only line the plugins and the correlation engine already
hold ("a chain never sends an exploit"): ReconAnything tells you what is
exposed and how to prove it — not how to weaponize it.

Pure stdlib, read-time: hung onto findings in reporting.findings_dump so
old runs get commands too, and baked into attack paths at correlation
time. Never raises; worst case a finding gets no command.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


def _host_of(url: str) -> str:
    try:
        n = urlsplit(url if "://" in url else "https://" + url).netloc
        return n or ""
    except Exception:
        return ""


_HOST_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b",
                      re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_PORT_RE = re.compile(r"\b(\d{2,5})\b")
_BUCKET_RE = re.compile(r"(?:s3://|//)?([a-z0-9][a-z0-9.\-]{1,61})"
                        r"(?:\.s3[.\-]|\.s3\.amazonaws)", re.I)
_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)


def _target(finding: Dict[str, Any], host_hint: Optional[str]) -> str:
    """Best host/URL token for a command: source_url host, then a host in
    the value, then the run's target hint, then a placeholder."""
    for src in (finding.get("source_url"),):
        if src:
            h = _host_of(str(src))
            if h:
                return h
    val = str(finding.get("value") or "")
    m = _HOST_RE.search(val) or _IP_RE.search(val)
    if m:
        return m.group(1)
    if host_hint:
        h = _host_of(host_hint) or host_hint
        if h:
            return h
    return "TARGET"


def _one(label: str, cmd: str, confirms: str) -> Dict[str, str]:
    return {"label": label, "cmd": cmd, "confirms": confirms, "safe": True}


def commands_for(finding: Dict[str, Any],
                 host_hint: Optional[str] = None) -> List[Dict[str, str]]:
    """Return read-only verification commands for one finding.

    ``host_hint`` is the run's primary target, used when the finding
    itself carries no host.
    """
    try:
        return _commands_for(finding, host_hint)
    except Exception:
        return []


def _commands_for(finding: Dict[str, Any],
                   host_hint: Optional[str]) -> List[Dict[str, str]]:
    key = str(finding.get("key") or "").lower()
    val = str(finding.get("value") or "")
    cat = str(finding.get("category") or "").lower()
    src = str(finding.get("source_url") or "")
    host = _target(finding, host_hint)
    base = f"https://{host}" if not host.startswith(("http://", "https://")) else host
    blob = f"{key} {val}".lower()
    out: List[Dict[str, str]] = []

    def k(*subs: str) -> bool:
        return any(s in key for s in subs)

    # --- exposed source / VCS / config files ---------------------------
    if k("git_exposed", "git") and "git" in blob:
        out.append(_one("Read the exposed Git config",
                        f"curl -s {base}/.git/config",
                        "returns repo config = .git is served publicly"))
        out.append(_one("Reconstruct the repo (read-only)",
                        f"git clone {base}/.git ra-exposed-git",
                        "a full working tree means the source is recoverable"))
    if k("env", "dotenv", "laravel_env") and "env" in blob:
        out.append(_one("Fetch the exposed .env",
                        f"curl -s {base}/.env",
                        "returns KEY=VALUE lines = secrets are served"))
    if k("actuator") and "env" in blob:
        out.append(_one("Read Spring Actuator /env",
                        f"curl -s {base}/actuator/env",
                        "returns property sources incl. secrets"))
    if k("backup", "sql_dump", "db_dump", "bak"):
        tgt = src or f"{base}/<path>"
        out.append(_one("Download the exposed backup/dump",
                        f"curl -s -o dump.out '{tgt}'",
                        "a non-empty, parseable dump confirms exposure"))

    # --- cloud storage -------------------------------------------------
    if k("s3", "bucket"):
        mb = _BUCKET_RE.search(val)
        bucket = mb.group(1) if mb else "BUCKET"
        out.append(_one("List the bucket unauthenticated",
                        f"aws s3 ls s3://{bucket} --no-sign-request",
                        "a file listing = public read"))
        out.append(_one("Or over HTTP",
                        f"curl -s https://{bucket}.s3.amazonaws.com/",
                        "XML key listing = public read"))

    # --- cloud / service credentials -----------------------------------
    if k("aws_access", "aws_secret", "aws_key"):
        out.append(_one("Identify the key (read-only, no data touched)",
                        f"AWS_ACCESS_KEY_ID={_short(val)} "
                        "AWS_SECRET_ACCESS_KEY=<secret> "
                        "aws sts get-caller-identity",
                        "returns an account/ARN = the key is live"))
    if k("github_token") or ("ghp_" in val or "github_pat" in blob):
        out.append(_one("Identify the token owner & scope",
                        f'curl -s -H "Authorization: token {_short(val)}" '
                        "https://api.github.com/user",
                        "returns a user = the token is live; check -I for scopes"))
    if k("stripe") or val.startswith(("sk_live", "sk_test", "rk_live")):
        out.append(_one("Check the Stripe key (read-only account read)",
                        f"curl -s https://api.stripe.com/v1/account -u {_short(val)}:",
                        "returns account JSON = the key is live"))
    if k("slack_token") or val.startswith("xox"):
        out.append(_one("Test the Slack token",
                        f"curl -s https://slack.com/api/auth.test "
                        f'-d token={_short(val)}',
                        '"ok":true = the token is live'))
    if k("google_api_key") or val.startswith("AIza"):
        out.append(_one("Probe the Google API key",
                        f"curl -s 'https://maps.googleapis.com/maps/api/"
                        f"geocode/json?address=test&key={_short(val)}'",
                        "a non-error status = the key is usable"))

    # --- JWT -----------------------------------------------------------
    if k("jwt") or re.match(r"^eyJ[\w-]+\.[\w-]+\.", val):
        tok = val if re.match(r"^eyJ", val) else "<token>"
        out.append(_one("Decode the JWT header + payload",
                        "python3 -c \"import base64,sys;"
                        "p=sys.argv[1].split('.');"
                        "print(*[base64.urlsafe_b64decode(x+'=='*(-len(x)%4))"
                        f".decode() for x in p[:2]])\" '{tok}'",
                        "reveals alg/claims; alg:none or a weak secret = forgeable"))

    # --- DNS / subdomain takeover --------------------------------------
    if k("takeover", "dangling", "unclaimed") or ("cname" in blob and k("takeover")):
        sub = _HOST_RE.search(val)
        sub = sub.group(1) if sub else host
        out.append(_one("Check the dangling CNAME",
                        f"dig CNAME {sub} +short",
                        "a CNAME to an unclaimed service = takeover candidate"))
        out.append(_one("See what the host serves",
                        f"curl -sI https://{sub}",
                        "a provider 'no such app/bucket' page confirms it"))
    elif k("subdomain") and cat == "dns":
        sub = val.strip().split()[0] if val.strip() else host
        out.append(_one("Resolve the subdomain",
                        f"dig {sub} +short",
                        "confirms the subdomain resolves"))

    # --- ports / services ----------------------------------------------
    if k("_open", "open_port", "port_open") or cat == "infra" and "port" in blob:
        mp = _PORT_RE.search(val)
        port = mp.group(1) if mp else "PORT"
        iphost = _IP_RE.search(val)
        iphost = iphost.group(1) if iphost else host
        out.append(_one("Fingerprint the open service",
                        f"nmap -sV -Pn -p {port} {iphost}",
                        "a service/version banner confirms it is reachable"))
        out.append(_one("Quick reachability check",
                        f"nc -vz {iphost} {port}",
                        "'succeeded' = the port is open to you"))

    # --- TLS -----------------------------------------------------------
    if k("tls", "ssl", "cert", "hsts") and cat in ("web", "network", ""):
        out.append(_one("Inspect the TLS certificate & protocol",
                        f"openssl s_client -connect {host}:443 -servername {host} "
                        "</dev/null 2>/dev/null | openssl x509 -noout -text",
                        "shows protocol, expiry, SANs to confirm the finding"))

    # --- CORS ----------------------------------------------------------
    if k("cors"):
        path = _path_of(src) or "/"
        out.append(_one("Replay with a foreign Origin",
                        f'curl -s -I -H "Origin: https://example.org" {base}{path}',
                        "ACAO reflects example.org (esp. with ACAC:true) = misconfig"))

    # --- GraphQL / API docs --------------------------------------------
    if k("graphql"):
        out.append(_one("Run introspection (read-only)",
                        f"curl -s -X POST {base}/graphql "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"query\":\"{__schema{types{name}}}\"}'",
                        "a full type list = introspection is enabled"))
    if k("openapi", "swagger"):
        out.append(_one("Fetch the API schema",
                        f"curl -s {base}/openapi.json || curl -s {base}/swagger.json",
                        "a JSON schema = the full API surface is published"))

    # --- actuator / debug / admin surfaces -----------------------------
    if k("phpinfo"):
        out.append(_one("Read the phpinfo page",
                        f"curl -s {base}/phpinfo.php | head -40",
                        "PHP config disclosure confirmed"))
    if k("server_status"):
        out.append(_one("Read Apache server-status",
                        f"curl -s {base}/server-status",
                        "a request table = server-status is public"))

    # --- breach / identity ---------------------------------------------
    if k("breach", "hibp", "pwned") or cat == "identity":
        me = _EMAIL_RE.search(val)
        if me:
            out.append(_one("Enumerate where the account exists",
                            f"holehe {me.group(0)}",
                            "lists sites the email is registered on"))

    # --- fallback: re-fetch the exposed artifact -----------------------
    if not out and src:
        out.append(_one("Re-fetch the exposed artifact",
                        f"curl -s '{src}'",
                        "reproduces exactly what the scanner saw"))
    elif not out and cat in ("web", "api", "leak") and host != "TARGET":
        path = _path_of(src) or "/"
        out.append(_one("Request the affected URL",
                        f"curl -s -i {base}{path}",
                        "reproduces the response the finding is based on"))
    return out


def _path_of(url: str) -> str:
    try:
        p = urlsplit(url).path
        return p or ""
    except Exception:
        return ""


def _short(v: str, n: int = 80) -> str:
    """Keep command values usable but not absurdly long. Full values are
    shown in the Secrets/Creds surfaces; a command just needs to be
    runnable, so cap pathological lengths."""
    v = v.strip().splitlines()[0] if v else v
    return v if len(v) <= n else v[:n]


def annotate_commands(rows: List[Dict[str, Any]],
                      host_hint: Optional[str] = None) -> None:
    """Attach ``evidence.commands`` to each finding row in place.

    Idempotent and safe: a row that already has commands keeps them, and
    any failure on one row leaves the others untouched.
    """
    for r in rows:
        try:
            ev = r.get("evidence")
            if not isinstance(ev, dict):
                ev = {}
                r["evidence"] = ev
            if ev.get("commands"):
                continue
            cmds = commands_for(r, host_hint)
            if cmds:
                ev["commands"] = cmds
        except Exception:
            continue
