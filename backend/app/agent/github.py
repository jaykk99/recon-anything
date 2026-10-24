"""Native GitHub API integration (read-only).

Searches public exposure and reads repo files on authorized targets.
GITHUB_TOKEN env extends access to what the token allows; without it,
only unauthenticated public reads work. No writes.
"""

from __future__ import annotations

import base64
import os

from .http_client import client as http_client

API = "https://api.github.com"


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json",
         "User-Agent": "recon-anything-agent/1.0"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def search_repos(query: str) -> dict:
    with http_client(30) as c:
        r = c.get(f"{API}/search/repositories", params={"q": query, "per_page": 10},
                  headers=_headers())
    if r.status_code != 200:
        return {"status": r.status_code, "error": r.text[:300]}
    return {"status": 200, "repos": [
        {"full_name": x["full_name"], "description": (x.get("description") or "")[:200],
         "url": x["html_url"], "stars": x.get("stargazers_count")}
        for x in r.json().get("items", [])]}


def search_code(query: str) -> dict:
    with http_client(30) as c:
        r = c.get(f"{API}/search/code", params={"q": query, "per_page": 10},
                  headers=_headers())
    if r.status_code != 200:
        return {"status": r.status_code, "error": r.text[:300]}
    return {"status": 200, "results": [
        {"repo": x["repository"]["full_name"], "path": x["path"],
         "url": x["html_url"]}
        for x in r.json().get("items", [])]}


def read_repo_file(owner: str, repo: str, path: str) -> dict:
    with http_client(30) as c:
        r = c.get(f"{API}/repos/{owner}/{repo}/contents/{path}",
                  headers=_headers())
    if r.status_code != 200:
        return {"status": r.status_code, "error": r.text[:300]}
    data = r.json()
    if data.get("encoding") == "base64" and data.get("content"):
        try:
            text = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            text = ""
        return {"status": 200, "path": path, "size": data.get("size"),
                "content": text[:8000]}
    return {"status": 200, "path": path, "note": "not a file or not base64"}
