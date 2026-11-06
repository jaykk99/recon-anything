"""WebView file-access settings scan (Cat-7 #205, VARIANT of binex).

DEX string/code-pattern scan of an operator-supplied APK for
WebView settings calls: setAllowFileAccess, the far more dangerous
setAllowUniversalAccessFromFileURLs, setJavaScriptEnabled combined
with addJavascriptInterface, and file:// URL loading.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

CALLER_RE = re.compile(r"L([a-zA-Z][a-zA-Z0-9_/]*);")


def analyze_webview(text: str) -> List[Dict]:
    out: List[Dict] = []
    if not text or "WebView" not in text and "webview" not in text.lower():
        # Settings method names alone are still a signal.
        if "setAllowUniversalAccessFromFileURLs" not in (text or "") and \
                "setAllowFileAccess" not in (text or ""):
            return out
    if "setAllowUniversalAccessFromFileURLs" in text:
        out.append(finding(
            "webview_universal_file_access",
            "setAllowUniversalAccessFromFileURLs referenced - "
            "file:// pages can read arbitrary local files via XHR "
            "when enabled",
            "high", source="DEX strings", confidence=82))
    if "setAllowFileAccessFromFileURLs" in text:
        out.append(finding(
            "webview_file_url_access",
            "setAllowFileAccessFromFileURLs referenced - file:// "
            "content can access other file:// URLs",
            "medium", source="DEX strings", confidence=80))
    if "setAllowFileAccess" in text:
        out.append(finding(
            "webview_allow_file_access",
            "setAllowFileAccess referenced - WebView can load "
            "file:// URLs; dangerous combined with untrusted content",
            "medium", source="DEX strings", confidence=78))
    if "addJavascriptInterface" in text and \
            "setJavaScriptEnabled" in text:
        out.append(finding(
            "webview_js_interface",
            "addJavascriptInterface + setJavaScriptEnabled: native "
            "bridge exposed to web content - RCE if the WebView ever "
            "loads attacker-influenced pages",
            "high", source="DEX strings", confidence=80))
    if "file:///android_asset" in text or "file:///" in text:
        out.append(finding(
            "webview_file_url_loading",
            "file:// URL loading strings present in DEX",
            "low", source="DEX strings", confidence=65))
    return out


class AndroidWebviewAllowFileAccessPlugin(Cat7Plugin):
    id = "android_webview_allow_file_access"
    label = "Android WebView Allow File Access"
    description = ("Scans DEX strings of an operator-supplied APK "
                   "for dangerous WebView settings (file access, "
                   "universal file URLs, JS interfaces).")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_webview(art.get("all_text") or "")
