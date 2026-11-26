"""Campaign persistence: one JSON document per campaign.

No database, no migrations: a campaign result is already a
JSON-serialisable graph plus metadata, so it is written atomically to
``data/campaigns/<id>.json`` and can be loaded, resumed or diffed
later. The path is overridable with ``RECON_CAMPAIGN_DIR`` for
tests and deployments.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def default_root() -> Path:
    env = os.environ.get("RECON_CAMPAIGN_DIR")
    if env:
        return Path(env)
    # backend/app/campaign/store.py -> repo root
    return Path(__file__).resolve().parents[3] / "data" / "campaigns"


class CampaignStore:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else default_root()

    def _path(self, campaign_id: str) -> Path:
        if not _ID_RE.match(campaign_id or ""):
            raise ValueError("invalid campaign id")
        return self.root / f"{campaign_id}.json"

    def save(self, result: Dict[str, Any]) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(str(result.get("id") or ""))
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(result, indent=2, default=str))
        tmp.replace(path)
        return path

    def evidence_path(self, campaign_id: str) -> Path:
        self._path(campaign_id)  # validate the id before composing a path
        return self.root / f"{campaign_id}.evidence.jsonl"

    def save_evidence(self, campaign_id: str, recorder: Any) -> Path:
        return recorder.save(self.evidence_path(campaign_id))

    def load_evidence(self, campaign_id: str) -> List[Dict[str, Any]]:
        try:
            path = self.evidence_path(campaign_id)
        except ValueError:
            return []
        if not path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            return []
        return rows

    def load(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        try:
            path = self._path(campaign_id)
        except ValueError:
            return None
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def list(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.root.exists():
            return []
        rows: List[Dict[str, Any]] = []
        for path in sorted(self.root.glob("*.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            rows.append({
                "id": data.get("id") or path.stem,
                "objective": data.get("objective", ""),
                "status": data.get("status", ""),
                "reason": data.get("reason", ""),
                "created": data.get("created"),
                "updated": data.get("updated"),
                "summary": data.get("summary") or {},
            })
            if len(rows) >= max(1, limit):
                break
        return rows

    def approve(self, campaign_id: str, intent_key: str) -> Optional[Dict[str, Any]]:
        """Record an approval; the caller resumes the campaign."""
        data = self.load(campaign_id)
        if data is None:
            return None
        approved = set(data.get("approved") or ())
        approved.add(intent_key)
        data["approved"] = sorted(approved)
        data["updated"] = time.time()
        self.save(data)
        return data

    def delete(self, campaign_id: str) -> bool:
        """Remove one stored campaign (explicit user action only)."""
        try:
            path = self._path(campaign_id)
        except ValueError:
            return False
        if path.exists():
            path.unlink()
            return True
        return False
