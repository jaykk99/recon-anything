"""Terminal for the agent: detection commands only, no shell.

Allowlist: curl, dig, nslookup, whois, host, openssl s_client, and
python3 analysis scripts (script file only, never -c code). No pipes,
no redirects, no file writes, no package installs, no listeners, no
miners, no background jobs. curl URLs pass the SSRF host check.
"""

from __future__ import annotations

import shlex
import subprocess
import urllib.parse

from .ssrf import SSRFBlocked, check_host

ALLOWED = {"curl", "dig", "nslookup", "whois", "host", "openssl", "python3"}

# Flags that write files, upload, or change the host. Refused anywhere.
DENIED_FLAGS = {
    "-o", "--output", "-O", "--remote-name", "-T", "--upload-file",
    "--data", "-d", "--form", "-F", "--dump-header", "-D", "--output-dir",
    "-c", "--create-dirs", "-K", "--config", "--libcurl", "-w",
}

TIMEOUT = 30
MAX_OUTPUT = 64 * 1024


def _check_curl_urls(argv: list[str]) -> None:
    for arg in argv[1:]:
        if arg.startswith("http://") or arg.startswith("https://"):
            host = urllib.parse.urlparse(arg).hostname or ""
            check_host(host)


def run_terminal(command: str) -> dict:
    """Run one allowlisted detection command. Returns stdout/stderr/returncode."""
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return {"error": f"cannot parse command: {e}", "returncode": None}
    if not argv:
        return {"error": "empty command", "returncode": None}
    prog = argv[0]
    if prog not in ALLOWED:
        return {"error": f"{prog} is not an allowed terminal command", "returncode": None}
    for arg in argv[1:]:
        if arg in DENIED_FLAGS or any(arg.startswith(f + "=") for f in DENIED_FLAGS):
            return {"error": f"flag {arg} is not allowed", "returncode": None}
    if prog == "openssl":
        if argv[1:2] != ["s_client"]:
            return {"error": "openssl is limited to s_client", "returncode": None}
    if prog == "python3":
        if argv[1:2] == ["-c"] or not argv[1:]:
            return {"error": "python3 runs script files only, never -c code", "returncode": None}
    if prog == "curl":
        try:
            _check_curl_urls(argv)
        except SSRFBlocked as e:
            return {"error": f"SSRF blocked: {e}", "returncode": None}
    argv = argv + (["-brief"] if prog == "openssl" else [])
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT,
                           stdin=subprocess.DEVNULL)
        out = (p.stdout or "")[:MAX_OUTPUT]
        err = (p.stderr or "")[:MAX_OUTPUT]
        return {"stdout": out, "stderr": err, "returncode": p.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "command timed out", "returncode": None}
    except Exception as e:
        return {"error": str(e)[:300], "returncode": None}
