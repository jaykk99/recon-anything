"""Firmware hardcoded API keys (variant of secrets): secrets mines
pages and JS bundles with its pattern set. This runs the same class of
patterns over an OPERATOR-SUPPLIED extracted firmware rootfs (scripts,
configs, binary strings) instead of web content, reporting service,
file (artifact) name, and masked + fingerprinted value per hit.
Supplied artifacts only; full secrets never leave the analysis.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, mask_secret, strings_only

_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic API key assignment", re.compile(
        r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
        r"client[_-]?secret)\s*[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-./+]"
        r"{12,})[\"']")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]"
                       r"{10,}\.[A-Za-z0-9_\-]{8,}\b")),
]


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    seen = set()
    for label, rx in _PATTERNS:
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            fp_key = (label, value[:24])
            if fp_key in seen:
                continue
            seen.add(fp_key)
            masked, fp = mask_secret(value)
            hits.append({
                "key": "fw_hardcoded_api_key", "severity": "high",
                "value": f"Hardcoded {label} in supplied firmware "
                         f"artifact {name or 'rootfs'} (masked "
                         f"{masked}, fp {fp})",
                "evidence": {"service": label, "fingerprint": fp,
                             "artifact": name}})
            if len(hits) >= 10:
                return hits
    return hits


class FirmwareHardcodedApiKeysPlugin(Plugin):
    id = "firmware_hardcoded_api_keys"
    label = "Firmware Hardcoded API Keys"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of secrets: the API-key pattern set run "
                   "over a supplied extracted firmware rootfs instead "
                   "of web content. Masked + fingerprinted evidence "
                   "only.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
