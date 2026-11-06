"""UART baudrate autosniff (offline): detect an enabled serial console
in an operator-supplied firmware image (bootargs console=ttyS*, getty /
inittab lines, DT console node, baud rate) OR analyse an operator-
supplied serial capture/log (boot log text, login prompt, root shell).
No live bus tapping. Keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, parse_dtb, prop_str, text_of

_CONSOLE_RE = re.compile(r"console=(ttyS\d+|ttyAMA\d+|ttyUSB\d+|ttymxc\d+)"
                         r"(?:,(\d+))?")
_GETTY_RE = re.compile(r"(getty|agetty)[^\n]{0,60}(ttyS\d+|ttyAMA\d+)")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = text_of(data)
    m = _CONSOLE_RE.search(text)
    dtb = parse_dtb(data)
    dt_console = ""
    for node in dtb.get("nodes", []):
        if node["name"] == "chosen":
            ba = prop_str(node["props"].get("bootargs", b""))
            mm = _CONSOLE_RE.search(ba)
            if mm:
                dt_console = mm.group(0)
    if m or dt_console:
        baud = (m.group(2) if m and m.group(2) else "default")
        hits.append({
            "key": "uart_serial_console_enabled", "severity": "medium",
            "value": f"Serial console enabled in firmware "
                     f"({(m.group(0) if m else dt_console)}"
                     f"{'' if baud == 'default' else ''}) - UART login/"
                     "boot console exposed on the board header",
            "evidence": {"baud": baud,
                         "device": (m.group(1) if m else "dt-chosen")}})
    if _GETTY_RE.search(text):
        hits.append({
            "key": "uart_getty_login", "severity": "medium",
            "value": "getty login running on a serial line (inittab/"
                    "systemd) - interactive UART login surface",
            "evidence": {"detection": "getty-line"}})
    if re.search(r"(root@[^\s#]{0,40}#|/ #|~ #)\s*$", text, re.M) \
            or "login:" in text and "Password:" not in text:
        if re.search(r"(root@[^\s#]{0,40}#|/ #)\s*$", text, re.M):
            hits.append({
                "key": "uart_root_shell_capture", "severity": "high",
                "value": "Supplied serial capture reaches a root shell "
                         "prompt with no login - unauthenticated UART "
                         "root console",
                "evidence": {"detection": "root-prompt-in-capture"}})
    low = text.lower()
    if "u-boot" in low and "hit any key to stop autoboot" in low:
        hits.append({
            "key": "uart_uboot_interrupt", "severity": "low",
            "value": "Supplied serial capture shows an interruptible "
                    "U-Boot autoboot prompt on the UART console",
            "evidence": {"detection": "uboot-prompt-in-capture"}})
    return hits[:10]


class UartBaudrateAutosniffPlugin(Plugin):
    id = "uart_baudrate_autosniff"
    label = "UART Console Autosniff (offline)"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Offline UART posture: serial console / getty / baud "
                   "from supplied firmware, root-shell evidence in "
                   "supplied serial captures.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
