"""Harness-side sandbox guard for the ReconAnything agent harness.

This is the harness implementation of
``agent_sandbox_syscall_deterministic_guard`` (the plugin of the same
name audits a sandbox config; this module ENFORCES one around a
plugin run).

What it enforces, in-process and honestly:
- resource limits (CPU seconds, memory, open files, file size) via
  ``resource.setrlimit`` in the child (preexec);
- environment scrubbing (a fixed allowlist of env vars; secrets and
  proxy/auth material never leak into the child);
- cwd jail (the child runs in a scratch dir, never the repo root);
- wall-clock timeout (kills the child, reports the kill);
- deterministic guards (fixed seed env, ``PYTHONHASHSEED`` pinned,
  no wall-clock-dependent temp names in the audit log);
- an audit log of every guarded invocation (argv, limits, exit,
  duration, violations).

What it does NOT claim: true seccomp-bpf syscall filtering. That
needs a supervisor process with real seccomp support, which this
VM's agent harness does not run. The guard reports that gap as a
violation of kind ``unenforceable_here`` instead of pretending the
syscall surface is filtered. A config that asks for syscall
filtering without a supervisor is a finding, not a pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

# Env vars a guarded child is allowed to see. Everything else is
# stripped, so keys and proxy/auth material never leak into a plugin.
ALLOWED_ENV = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "TZ", "PYTHONHASHSEED",
    "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED", "RECON_SEED",
    "TMPDIR", "TEMP", "TMP",
})

# Syscall families the guard wants restricted. The in-process guard
# cannot filter syscalls; it records the requirement and reports
# it as unenforceable_here so the audit is honest.
WANTED_SYSCALL_FILTERS = (
    "execve", "socket", "connect", "ptrace", "mount", "keyctl",
    "bpf", "perf_event_open",
)


@dataclass
class SandboxConfig:
    """A sandbox config, as audited by the plugin and enforced here."""

    allowed_syscalls: List[str] = field(default_factory=list)
    blocked_syscalls: List[str] = field(default_factory=list)
    allow_network: bool = False
    allow_wall_clock: bool = False
    fixed_seed: Optional[int] = None
    cpu_seconds: int = 60
    memory_mb: int = 512
    max_open_files: int = 64
    max_file_bytes: int = 10 * 1024 * 1024
    timeout_s: int = 60
    workdir: Optional[str] = None


@dataclass
class GuardViolation:
    kind: str
    detail: str
    severity: str = "medium"


@dataclass
class GuardResult:
    ok: bool
    violations: List[GuardViolation]
    audit: Dict[str, Any]


def validate_config(cfg: SandboxConfig) -> List[GuardViolation]:
    """Audit a sandbox config. Returns the violations (empty = clean).

    This is the same check the ``agent_sandbox_syscall_deterministic_guard``
    plugin runs over a supplied config file.
    """
    out: List[GuardViolation] = []
    if not cfg.blocked_syscalls and not cfg.allowed_syscalls:
        out.append(GuardViolation(
            "no_syscall_restriction",
            "no syscall allowlist or blocklist: the agent can invoke "
            "any syscall, including execve/socket/ptrace",
            "high"))
    else:
        missing = [s for s in WANTED_SYSCALL_FILTERS
                   if s not in cfg.blocked_syscalls
                   and s not in cfg.allowed_syscalls]
        if missing:
            out.append(GuardViolation(
                "syscall_filter_incomplete",
                "syscall filter does not cover: " + ", ".join(missing),
                "medium"))
    if cfg.allow_network:
        out.append(GuardViolation(
            "network_allowed",
            "network is allowed inside the sandbox: the agent can "
            "reach the network from a guarded run",
            "high"))
    if cfg.allow_wall_clock:
        out.append(GuardViolation(
            "wall_clock_allowed",
            "wall-clock reads are allowed: runs are not "
            "deterministic (timing-dependent behavior possible)",
            "medium"))
    if cfg.fixed_seed is None:
        out.append(GuardViolation(
            "no_fixed_seed",
            "no fixed seed: runs are not reproducible",
            "low"))
    if cfg.cpu_seconds <= 0 or cfg.memory_mb <= 0:
        out.append(GuardViolation(
            "no_resource_caps",
            "CPU or memory cap is missing/zero: a run can exhaust "
            "the host",
            "high"))
    # True syscall filtering needs a seccomp supervisor. If the config
    # asks for it, say plainly it is not enforceable in-process.
    if cfg.allowed_syscalls or cfg.blocked_syscalls:
        out.append(GuardViolation(
            "unenforceable_here",
            "syscall allowlist/blocklist requested but this harness "
            "has no seccomp supervisor: the filter is recorded, not "
            "enforced, by the in-process guard",
            "medium"))
    return out


def _scrub_env(seed: Optional[int]) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ALLOWED_ENV}
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    if seed is not None:
        env["RECON_SEED"] = str(seed)
    return env


def _preexec_limits(cfg: SandboxConfig):
    def _apply() -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CPU,
                               (cfg.cpu_seconds, cfg.cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS,
                               (cfg.memory_mb * 1024 * 1024,
                                cfg.memory_mb * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_NOFILE,
                               (cfg.max_open_files, cfg.max_open_files))
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (cfg.max_file_bytes, cfg.max_file_bytes))
        except Exception:
            pass
    return _apply


def run_guarded(argv: Sequence[str], cfg: SandboxConfig,
                audit_path: Optional[str] = None) -> GuardResult:
    """Run argv under the sandbox guard. Returns the result + audit.

    Never raises for a child failure: a timeout, a non-zero exit, or
    a resource-limit kill is reported in the audit, not thrown.
    """
    violations = validate_config(cfg)
    workdir = cfg.workdir or tempfile.mkdtemp(prefix="recon-sandbox-")
    t0 = time.monotonic()
    audit: Dict[str, Any] = {
        "argv_sha256": hashlib.sha256(
            " ".join(argv).encode()).hexdigest(),
        "workdir": workdir,
        "cpu_seconds": cfg.cpu_seconds,
        "memory_mb": cfg.memory_mb,
        "timeout_s": cfg.timeout_s,
        "fixed_seed": cfg.fixed_seed,
        "allow_network": cfg.allow_network,
        "violations": [{"kind": v.kind, "detail": v.detail,
                        "severity": v.severity} for v in violations],
    }
    try:
        proc = subprocess.run(
            list(argv), cwd=workdir, env=_scrub_env(cfg.fixed_seed),
            preexec_fn=_preexec_limits(cfg),
            timeout=cfg.timeout_s, capture_output=True, text=True)
        audit["returncode"] = proc.returncode
        audit["stdout_tail"] = proc.stdout[-2000:]
        audit["stderr_tail"] = proc.stderr[-2000:]
        audit["timed_out"] = False
        ok = proc.returncode == 0
    except subprocess.TimeoutExpired as exc:
        audit["returncode"] = None
        audit["timed_out"] = True
        audit["stdout_tail"] = (exc.stdout or "")[-2000:] \
            if isinstance(exc.stdout, str) else ""
        audit["stderr_tail"] = (exc.stderr or "")[-2000:] \
            if isinstance(exc.stderr, str) else ""
        ok = False
        violations.append(GuardViolation(
            "timeout", f"guarded run exceeded {cfg.timeout_s}s and "
            "was killed", "medium"))
    except Exception as exc:  # noqa: BLE001 - guard must never raise
        audit["returncode"] = None
        audit["timed_out"] = False
        audit["error"] = str(exc)
        ok = False
    audit["duration_ms"] = int((time.monotonic() - t0) * 1000)
    if audit_path:
        try:
            with open(audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(audit) + "\n")
        except OSError:
            pass
    return GuardResult(ok=ok, violations=violations, audit=audit)
