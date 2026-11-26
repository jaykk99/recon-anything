"""Complete, redacted exchange capture for a campaign.

ARTEX records traffic through a MITM proxy with its own certificate
authority. This module records the same thing in-process, at the only
point campaign traffic already flows: the injected ``fetch`` callable.
Nothing is installed on a target, no certificate is minted, and the
archive is portable JSONL plus a HAR 1.2 export.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .models import digest

BODY_CAP = 64 * 1024

# Request/response headers that must never land in an archive in clear.
REDACT_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
}


def _redact(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key)
        out[name] = "[redacted]" if name.lower() in REDACT_HEADERS else str(value)
    return out


class _FailedResponse:
    """Stand-in recorded when the transport itself raised."""

    def __init__(self, error: str) -> None:
        self.url = ""
        self.method = ""
        self.status = None
        self.headers: Dict[str, str] = {}
        self.text = ""
        self.error = error


class EvidenceRecorder:
    """Thread-safe recorder of every request/response pair.

    Workers run in parallel, so recording takes a lock; reads for saving
    take a snapshot under the same lock.
    """

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []
        self.bytes = 0
        self._lock = threading.Lock()

    def record(self, url: str, resp: Any,
               request: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        text = getattr(resp, "text", "") or ""
        raw = text.encode("utf-8", "replace")
        entry = {
            "at": round(time.time(), 3),
            "request": {
                "method": (getattr(resp, "method", None)
                           or (request or {}).get("method") or "GET"),
                "url": getattr(resp, "url", None) or url,
                "headers": _redact((request or {}).get("headers")),
            },
            "response": {
                "status": getattr(resp, "status", None),
                "headers": _redact(getattr(resp, "headers", {})),
                "body": text[:BODY_CAP],
                "body_bytes": len(raw),
                "body_sha256": digest(text),
                "truncated": len(raw) > BODY_CAP,
            },
            "error": getattr(resp, "error", "") or "",
        }
        with self._lock:
            self.entries.append(entry)
            self.bytes += len(entry["response"]["body"].encode("utf-8", "replace"))
        return entry

    def wrap(self, fetch: Callable[..., Any]) -> Callable[..., Any]:
        """Return a fetch that records every exchange and failure."""

        def recording(url: str, **kw: Any) -> Any:
            try:
                resp = fetch(url, **kw)
            except Exception as exc:
                self.record(url, _FailedResponse(str(exc)[:300]), kw)
                raise
            self.record(url, resp, kw)
            return resp

        return recording

    def summary(self) -> Dict[str, Any]:
        return {
            "entries": len(self.entries),
            "bytes": self.bytes,
            "body_cap": BODY_CAP,
        }

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            rows = list(self.entries)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            "\n".join(json.dumps(row, default=str) for row in rows)
            + ("\n" if rows else ""))
        tmp.replace(path)
        return path


def _iso(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts or 0),
                                      tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return datetime.now(tz=timezone.utc).isoformat()


def to_har(entries: List[Dict[str, Any]], *,
           campaign_id: str = "", creator: str = "ReconAnything") -> Dict[str, Any]:
    """Render recorded exchanges as HAR 1.2."""
    har_entries: List[Dict[str, Any]] = []
    for entry in entries or ():
        req = entry.get("request") or {}
        res = entry.get("response") or {}
        req_headers = [{"name": k, "value": v}
                       for k, v in (req.get("headers") or {}).items()]
        res_headers = [{"name": k, "value": v}
                       for k, v in (res.get("headers") or {}).items()]
        mime = next((h["value"] for h in res_headers
                     if h["name"].lower() == "content-type"), "")
        har_entries.append({
            "startedDateTime": _iso(entry.get("at")),
            "time": 0,
            "request": {
                "method": req.get("method") or "GET",
                "url": req.get("url") or "",
                "httpVersion": "HTTP/1.1",
                "headers": req_headers,
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": 0,
            },
            "response": {
                "status": res.get("status") or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": res_headers,
                "cookies": [],
                "content": {
                    "size": res.get("body_bytes") or 0,
                    "mimeType": mime,
                    "text": res.get("body") or "",
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": res.get("body_bytes") or 0,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
            "comment": entry.get("error") or "",
        })
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "1.0",
                        "comment": campaign_id},
            "entries": har_entries,
        }
    }
