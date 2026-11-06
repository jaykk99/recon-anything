"""ContentProvider authority audit (Cat-7 #207, VARIANT of binex).

binex lists exported providers by name only. Delta: per-provider
audit - authorities strings, grantUriPermissions=true, missing
read/writePermission split, world-readable pathPermissions, and
FileProvider mis-scope (root-path ".") in file_paths XML.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, manifest_components


def analyze_providers(manifest: str, texts: Dict[str, str]) -> List[Dict]:
    out: List[Dict] = []
    for comp in manifest_components(manifest or ""):
        if comp["tag"] != "provider":
            continue
        attrs = comp["attrs"]
        name = attrs.get("android:name", "?")
        exported = str(attrs.get("android:exported", "")).lower() == "true"
        authorities = attrs.get("android:authorities", "")
        if str(attrs.get("android:grantUriPermissions", "")).lower() \
                == "true" and exported:
            out.append(finding(
                "provider_grant_uri_permissions",
                f"Provider {name} (authorities: {authorities}) is "
                f"exported with grantUriPermissions=true - any app "
                f"can be granted read/write to its URIs",
                "high", source="AndroidManifest.xml", confidence=87,
                component=name, authorities=authorities))
        if exported and not attrs.get("android:readPermission") and \
                not attrs.get("android:writePermission") and \
                not attrs.get("android:permission"):
            out.append(finding(
                "provider_exported_no_permission_split",
                f"Provider {name} (authorities: {authorities}) is "
                f"exported with NO read/writePermission split - data "
                f"is world-accessible",
                "high", source="AndroidManifest.xml", confidence=87,
                component=name, authorities=authorities))
        if "path-permission" in comp["segment"] and \
                'android:pathPrefix="/"' in comp["segment"]:
            out.append(finding(
                "provider_world_readable_path",
                f"Provider {name} declares a path-permission "
                f"covering '/' - the whole provider tree is exposed",
                "medium", source="AndroidManifest.xml", confidence=75,
                component=name))
    for fname, text in (texts or {}).items():
        if "file_paths" in fname or fname.endswith("paths.xml"):
            if "<root-path" in text:
                out.append(finding(
                    "fileprovider_root_path_scope",
                    f"FileProvider paths file {fname} uses <root-path> "
                    f"- the ENTIRE filesystem root is shareable "
                    f"through this provider",
                    "high", source=fname, confidence=88))
            if "<external-path" in text and 'path="."' in text:
                out.append(finding(
                    "fileprovider_external_root_scope",
                    f"FileProvider paths file {fname} shares all of "
                    f"external storage (<external-path path=\".\">)",
                    "medium", source=fname, confidence=82))
    return out[:30]


class BadProviderAuthorityCheckerPlugin(Cat7Plugin):
    id = "bad_provider_authority_checker"
    label = "Bad Provider Authority Checker"
    description = ("Per-provider audit of an operator-supplied APK: "
                   "exported providers, grantUriPermissions, missing "
                   "permission splits, FileProvider mis-scope.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_providers(art.get("manifest") or "",
                                 art.get("texts") or {})
