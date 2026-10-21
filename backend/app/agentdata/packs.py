"""Bundled knowledge packs, served to hunters through the data service.

Packs live in app/hunters/knowledge/ as plain .txt (one entry per line,
'#' comments) or .json files. They are small, derived from lists and
patterns already shipped in this repo's plugins (factored, not copied
from outside), so they are safe to bundle. Big external lists are NOT
bundled: those live in the resource registry and are fetched + cached
with attribution (see resources.py).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "hunters" / "knowledge"

PACK_FILES = {
    "subdomain_wordlist": "subdomain_wordlist.txt",
    "sensitive_paths": "sensitive_paths.txt",
    "secret_patterns": "secret_patterns.json",
    "tech_fingerprints": "tech_fingerprints.json",
    "cloud_patterns": "cloud_patterns.json",
}


def _load_pack(name: str):
    fn = PACK_FILES.get(name)
    if not fn:
        return None
    path = KNOWLEDGE_DIR / fn
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if fn.endswith(".json"):
        return json.loads(text)
    entries = [ln.strip() for ln in text.splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    return entries


def pack_entries(name: str) -> List:
    """Entries of one pack as a list (dicts stay dicts)."""
    data = _load_pack(name)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("patterns", "fingerprints"):
            if isinstance(data.get(key), list):
                return data[key]
        if isinstance(data.get("bucket_templates"), list):
            return data["bucket_templates"]
    return []


def pack_raw(name: str):
    return _load_pack(name)


def pack_inventory() -> List[Dict]:
    """Name, entry count, and on-disk size per pack (no content dump)."""
    out = []
    for name, fn in sorted(PACK_FILES.items()):
        path = KNOWLEDGE_DIR / fn
        entries = pack_entries(name)
        out.append({
            "name": name,
            "entries": len(entries),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "file": fn,
        })
    return out
