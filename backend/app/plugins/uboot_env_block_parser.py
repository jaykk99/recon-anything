"""U-Boot env block parser: locate the environment partition in an
operator-supplied firmware image or raw env block (CRC32 header when
present), parse key=value pairs, flag maintenance exposure. Credentials
masked + fingerprinted. Offline, keyless.
"""
from __future__ import annotations

import re
import struct
import zlib
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, mask_secret

_KNOWN = (b"bootargs=", b"bootcmd=", b"bootdelay=", b"ipaddr=",
          b"serverip=", b"ethaddr=", b"stdin=", b"stdout=")
_PAIR_RE = re.compile(rb"([A-Za-z_][A-Za-z0-9_.-]{1,40})=([^\x00\r\n]{0,200})")
_CRED_KEYS = ("passwd", "password", "pwd", "secret", "token", "psk")


def parse_env(data: bytes) -> Dict[str, str]:
    """Best-effort U-Boot env extraction. Verifies the CRC32 header when
    a plausible one is found; otherwise falls back to a NUL-separated
    key=value region anchored on known variable names."""
    # CRC-verified block: u32 LE crc32 of the bytes that follow it.
    # Bounded scan of plausible header offsets only.
    for off in range(0, min(len(data) - 8, 8192), 4):
        head = data[off + 4:off + 132]
        if b"=" not in head or not all(
                9 <= b < 127 or b == 0 for b in head[:16]):
            continue
        (crc,) = struct.unpack_from("<I", data, off)
        body = data[off + 4:off + 4 + 65536]
        nul = body.find(b"\x00\x00")
        if nul < 16:
            continue
        region = body[:nul]
        if zlib.crc32(region) & 0xFFFFFFFF == crc:
            pairs = _pairs(region)
            if len(pairs) >= 2:
                return pairs
    anchor = -1
    for marker in _KNOWN:
        anchor = data.find(marker)
        if anchor >= 0:
            break
    if anchor < 0:
        return {}
    start = data.rfind(b"\x00", 0, anchor)
    region = data[start + 1:anchor + 8192]
    nul = region.find(b"\x00\x00")
    if nul >= 0:
        region = region[:nul]
    pairs = _pairs(region)
    return pairs if len(pairs) >= 2 else {}


def _pairs(region: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for chunk in region.split(b"\x00"):
        m = _PAIR_RE.match(chunk.strip())
        if m:
            out[m.group(1).decode("ascii", "ignore")] = \
                m.group(2).decode("utf-8", "ignore")
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    env = parse_env(data)
    if not env:
        return hits
    bootargs = env.get("bootargs", "")
    if "init=/bin/sh" in bootargs or " single" in bootargs \
            or bootargs.endswith("single"):
        hits.append({"key": "uboot_bootargs_shell", "severity": "high",
                     "value": "U-Boot bootargs drop to a shell / single-"
                              "user mode (init=/bin/sh or single)",
                     "evidence": {"variable": "bootargs"}})
    elif "console=" in bootargs:
        hits.append({"key": "uboot_serial_console", "severity": "medium",
                     "value": "U-Boot bootargs enable a serial console: "
                              + bootargs.split("console=")[1].split(" ")[0],
                     "evidence": {"variable": "bootargs"}})
    bootcmd = env.get("bootcmd", "")
    if any(w in bootcmd for w in ("tftp", "nfs", "bootp", "dhcp")):
        hits.append({"key": "uboot_network_boot", "severity": "medium",
                     "value": "U-Boot bootcmd loads the kernel over the "
                              "network (tftp/nfs/bootp) - unauthenticated "
                              "boot image source",
                     "evidence": {"variable": "bootcmd"}})
    if env.get("serverip"):
        hits.append({"key": "uboot_serverip_set", "severity": "low",
                     "value": "U-Boot env hardcodes a serverip "
                              "(maintenance/TFTP server)",
                     "evidence": {"variable": "serverip"}})
    for key, val in env.items():
        if any(c in key.lower() for c in _CRED_KEYS) and val:
            masked, fp = mask_secret(val)
            hits.append({"key": "uboot_env_credential", "severity": "high",
                         "value": f"Credential embedded in U-Boot env "
                                  f"variable {key} ({masked})",
                         "evidence": {"variable": key,
                                      "fingerprint": fp}})
    return hits[:12]


class UbootEnvBlockParserPlugin(Plugin):
    id = "uboot_env_block_parser"
    label = "U-Boot Env Block Parser"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Parses U-Boot environment blocks in supplied firmware; "
                   "flags shell bootargs, network boot and embedded "
                   "credentials (masked).")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
