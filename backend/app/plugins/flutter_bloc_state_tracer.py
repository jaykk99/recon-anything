"""Flutter / BLoC state tracer (Cat-7 #202, SHIP).

Input: operator-supplied APK/IPA containing Flutter (libapp.so /
App.framework + flutter_assets). Extracts AOT snapshot strings and
asset JSON/env files; inventories routes, API base URLs, feature
flags and BLoC class names; embedded secrets reported MASKED.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, extract_strings, finding, mask_value

URL_RE = re.compile(r"https?://[a-zA-Z0-9.\-]+\.[a-z]{2,24}(?:/[^\s\"'<>]*)?")
BLOC_RE = re.compile(r"\b[A-Z][A-Za-z0-9]{2,40}(?:Bloc|Cubit)\b")
ROUTE_RE = re.compile(r"(?<![\w/])/(?:[a-z][a-z0-9_\-]*/){0,3}"
                      r"[a-z][a-z0-9_\-]{1,30}")
SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|secret|token|password|private[_-]?key)", re.I)


def is_flutter(art: Dict) -> bool:
    for name in (art.get("files") or {}):
        low = name.lower()
        if "libapp.so" in low or "flutter_assets" in low or \
                "app.framework" in low:
            return True
    return False


def analyze_flutter(art: Dict) -> List[Dict]:
    if not is_flutter(art):
        return []
    out: List[Dict] = []
    strings: List[str] = list(art.get("strings") or [])
    for name, blob in (art.get("files") or {}).items():
        if "libapp.so" in name.lower() or name.endswith("/app"):
            strings.extend(extract_strings(blob))
    blob_text = "\n".join(strings)
    urls = sorted(set(URL_RE.findall(blob_text)))[:25]
    blocs = sorted(set(BLOC_RE.findall(blob_text)))[:25]
    routes = sorted(set(ROUTE_RE.findall(blob_text)))[:25]
    if urls or blocs or routes:
        out.append(finding(
            "flutter_surface_inventory",
            f"Flutter surface: {len(urls)} API URLs, {len(blocs)} "
            f"BLoC/Cubit classes, {len(routes)} routes visible in the "
            f"AOT snapshot strings",
            "low", source="libapp.so / flutter_assets", confidence=80,
            urls=urls, blocs=blocs, routes=routes))
    # Asset JSON / env files: feature flags + embedded secrets (masked).
    for name, text in (art.get("texts") or {}).items():
        if "flutter_assets" not in name.lower() and \
                not name.lower().endswith((".env", ".json")):
            continue
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and v and SECRET_KEY_RE.search(str(k)):
                    out.append(finding(
                        "flutter_embedded_secret",
                        f"Embedded secret in Flutter asset {name}: "
                        f"key '{k}' = {mask_value(v)}",
                        "high", source=name, confidence=88,
                        asset_key=str(k), masked_value=mask_value(v)))
        for m in re.finditer(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*"
                             r"[\"']([^\"']{8,})[\"']", text or ""):
            out.append(finding(
                "flutter_embedded_secret",
                f"Embedded secret in Flutter asset {name}: "
                f"key '{m.group(1)}' = {mask_value(m.group(2))}",
                "high", source=name, confidence=85,
                asset_key=m.group(1), masked_value=mask_value(m.group(2))))
    return out[:45]


class FlutterBlocStateTracerPlugin(Cat7Plugin):
    id = "flutter_bloc_state_tracer"
    label = "Flutter BLoC State Tracer"
    description = ("Inventories routes, API URLs, feature flags and "
                   "BLoC classes from Flutter AOT snapshot strings and "
                   "flutter_assets in an operator-supplied APK/IPA; "
                   "secrets masked.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_flutter(art)
