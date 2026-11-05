"""Target authorization for the agent.

Detection only, on authorized targets only. Jay's own assets are
pre-authorized. Any other target needs an explicit allowlist entry added
through the app (owner-gated) before a scan starts. crypto.com is
NEVER a scan target, allowlist or not.

Note: a run's own targets are authorized by the scan's scope gating at
run creation, so investigate_run does not re-check this list for them.
This list gates the agent's NEW probes: chat fetches, direct target
investigation, and asset expansion on arbitrary URLs.
"""

from __future__ import annotations

import json
import os
import urllib.parse

ALLOWLIST_PATH = os.environ.get(
    "RECON_AGENT_ALLOWLIST_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "agent-allowlist.json"),
)

# Jay's own assets: pre-authorized, no entry needed.
PRE_AUTHORIZED_HOSTS = {
    "error-inbox.onrender.com",
    "recon-anything.onrender.com",
    "bro-agent.onrender.com",
    "termux-code.pages.dev",
    "guttergenie.pages.dev",
    "move-and-metal-site.pages.dev",
    "winnipeg-web-works.onrender.com",
    "quonset-place.onrender.com",
    "bnb-media.onrender.com",
    "demoboss.onrender.com",
    "jaykk99.github.io",
    "mega-db-dashboard.pages.dev",
    "wholesale-stack.onrender.com",
    "monico-agent-docker.onrender.com",
    "uncensored-harness-production.up.railway.app",
}

PRE_AUTHORIZED_GITHUB_OWNERS = {"jaykk99"}

NEVER_TARGETS = {"crypto.com", "www.crypto.com"}


def _host_of(target: str) -> str:
    target = (target or "").strip()
    if "://" in target:
        return (urllib.parse.urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


def _extra_allowlist() -> set[str]:
    try:
        with open(ALLOWLIST_PATH) as f:
            data = json.load(f)
        hosts = data.get("hosts", []) if isinstance(data, dict) else []
        return {str(h).lower() for h in hosts}
    except Exception:
        return set()


def add_allowlist_host(host: str) -> None:
    host = host.lower().strip()
    if host in NEVER_TARGETS:
        raise ValueError("that host can never be a target")
    path = ALLOWLIST_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    hosts = _extra_allowlist()
    hosts.add(host)
    with open(path, "w") as f:
        json.dump({"hosts": sorted(hosts)}, f, indent=2)


def is_authorized(target: str) -> tuple[bool, str]:
    """Returns (ok, reason)."""
    host = _host_of(target)
    if not host:
        return False, "empty target"
    if host in NEVER_TARGETS or host.endswith(".crypto.com"):
        return False, "crypto.com is never a scan target"
    if host in PRE_AUTHORIZED_HOSTS:
        return True, "pre-authorized: Jay's own asset"
    if host in _extra_allowlist():
        return True, "allowlisted by the owner"
    if host.endswith(".github.io"):
        return False, "GitHub Pages host: allowlist the exact owner first"
    return False, f"{host} is not authorized: add it to the allowlist first"


def is_authorized_github_repo(owner: str, repo: str) -> tuple[bool, str]:
    if owner in PRE_AUTHORIZED_GITHUB_OWNERS:
        return True, "pre-authorized: Jay's own repo"
    return False, f"github.com/{owner}/{repo} is not authorized"
