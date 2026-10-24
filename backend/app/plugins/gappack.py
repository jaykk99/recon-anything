"""Completeness pack (gx_*): detectors closing the four gaps Jay listed
2026-10-23 - SaaS/source-control metadata, cloud & IAM misconfiguration
beyond signed URLs, AI & LLM infrastructure, and internal routing /
service meshes.

Deduped against the 552-plugin registry that existed when this pack
was built (ids AND patterns read, not assumed):

- Gap 1: gitleaks_scan scans pages/JS but never git HISTORY; git.py and
  git_exposed.py flag an exposed /.git but never parse a single object.
  Nothing mined a target's pages for public Trello boards, public Jira /
  Confluence surfaces, or Google Drive/Docs share links. -> gx_trello_
  board, gx_jira_public_link, gx_confluence_public_page,
  gx_google_share_link, gx_git_history_secrets.
- Gap 2: cloud_buckets / cloud_enum guess bucket NAMES and s3.py mines
  bucket refs and probes bucket roots. What none of them did: Azure
  CONTAINER-level listing (s3.py probes the account root, the wrong
  level), Firebase Storage listing (mined by s3.py, never tested), and
  object-level public reads of the exact object URLs a site references.
  -> gx_azure_container_public, gx_firebase_storage_public,
  gx_public_object_read.
- Gap 3: no AI-infra exposure detection existed at all (no vector DB,
  MLflow, Ollama, Triton, TorchServe probes anywhere; Pinecone keys
  matched no rule - hf_ tokens were already covered by gitleaks_scan /
  secrets / jsminer and are deliberately NOT repeated).
  -> gx_chroma_open, gx_qdrant_open, gx_weaviate_open, gx_milvus_open,
  gx_mlflow_open, gx_ollama_open, gx_triton_open, gx_torchserve_open,
  gx_pinecone_key, gx_training_data_refs.
- Gap 4: pf_consul_agent_info reads /v1/agent/self and pf_etcd_version
  reads /version, but the Consul SERVICE CATALOG, Eureka, Nacos and
  Istio/Pilot debug endpoints were unprobed. graphql / graphql_probe /
  graphql_deep cover fixed paths and bus endpoints from those paths;
  none DISCOVERS GraphQL endpoints from page/JS content (custom paths,
  Hasura, cross-host api hosts) or reports full-schema type/field
  counts. -> gx_consul_catalog, gx_eureka_registry, gx_nacos_registry,
  gx_istio_debug, gx_graphql_schema_exposure.

Detection only, authorized targets only. Nothing here uses a found
credential. Secrets are stored MASKED (secretutils.redact) plus a
SHA-256 fingerprint; the full value never reaches a Finding. Bucket
proof = the listing itself + object count + up to 3 key names - object
bodies are never downloaded (object-read proof is a HEAD). GraphQL
proof = schema summary counts, never a data query.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import zlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import collect_texts
from .gitleaks_scan import RULES as _GIT_RULES
from .secretutils import is_placeholder, redact

_REMEDIATION = (
    "Remove the exposure from the public surface, treat any secret or "
    "internal detail it revealed as compromised (rotate/revoke), and "
    "audit access logs. Detection only: nothing found was used.")

_LOGIN_MARKERS = ("log in to continue", "you need to log in",
                  'id="login"', "name=\"os_password\"", "signin",
                  "sign in to continue")


def _fingerprint(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", "ignore")).hexdigest()


def _host_of(target: Target) -> Optional[str]:
    if target.type == "url":
        return urlparse(target.normalized).hostname
    return domain_from_target(target.type, target.normalized)


async def _origin(ctx: Ctx, target: Target) -> Optional[str]:
    """The target's own web origin (scheme://netloc)."""
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
        return target.normalized.rstrip("/")
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return None
    return (await web_base(ctx, target, domain)).rstrip("/")


async def _service_bases(ctx: Ctx, target: Target,
                         ports: List[int]) -> List[str]:
    """Origin first, then the service's conventional ports on the host."""
    origin = await _origin(ctx, target)
    host = _host_of(target)
    bases: List[str] = []
    if origin:
        bases.append(origin)
    if host:
        for p in ports:
            b = f"http://{host}:{p}"
            if b not in bases:
                bases.append(b)
    return bases


async def _req(ctx: Ctx, method: str, url: str, timeout: int = 6,
               **kw) -> Any:
    try:
        return await fetch(ctx.http, ctx.limiter, method, url,
                           timeout=timeout, max_retries=0, **kw)
    except Exception:
        return None


async def _get_json(ctx: Ctx, url: str, timeout: int = 6) -> Tuple[int, Any]:
    r = await _req(ctx, "GET", url, timeout=timeout,
                   follow_redirects=True)
    if r is None:
        return 0, None
    try:
        return r.status_code, json.loads(r.text)
    except Exception:
        return r.status_code, None


def _looks_like_login(text: str, final_url: str) -> bool:
    if "accounts.google.com" in (final_url or ""):
        return True
    low = (text or "")[:6000].lower()
    return any(m in low for m in _LOGIN_MARKERS)


# ---------------------------------------------------------------------------
# Gap 1a: public collaboration links mined from the target's own pages/JS
# ---------------------------------------------------------------------------

class _LinkMiner(Plugin):
    """Mine links of one SaaS family from homepage + same-domain JS.

    Emits a reference finding per distinct link (the link itself, on the
    target's own public pages, is the exposure lead) and - in active
    mode - a verified finding when the link answers its own public
    surface without a login wall.
    """

    id = None  # abstract
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 90

    LINK_RE = ""
    KEY = ""
    LABEL = ""
    SEVERITY = "medium"
    CONF = 75

    _rx: Optional[re.Pattern] = None

    def _compiled(self) -> re.Pattern:
        if type(self)._rx is None:
            type(self)._rx = re.compile(self.LINK_RE, re.I)
        return type(self)._rx

    async def verify(self, ctx: Ctx, url: str) -> Optional[Dict[str, Any]]:
        """Return evidence extras when the link is confirmed public."""
        return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        rx = self._compiled()
        links: Dict[str, Tuple[str, str]] = {}
        for where, text, url in texts:
            for m in rx.finditer(text):
                link = (m.group(1) if m.groups() else m.group(0))
                link = link.strip().rstrip("'\").,;")
                if link and link not in links:
                    links[link] = (where, url)
                if len(links) >= 8:
                    break
            if len(links) >= 8:
                break
        findings: List[Finding] = []
        active = self.module_mode(ctx) != "passive"
        for link, (where, url) in links.items():
            verified = await self.verify(ctx, link) if active else None
            if verified is not None:
                ev = {"severity": self.SEVERITY, "detector": self.id,
                      "link": link, "verified_public": True,
                      "remediation": _REMEDIATION}
                ev.update(verified)
                findings.append(self._f(
                    "leak", self.KEY,
                    f"{self.LABEL} is PUBLIC: {link} (linked from {where})",
                    source=f"completeness pack: {self.LABEL}",
                    source_url=link, confidence=92, passive=not active,
                    evidence=ev))
            else:
                findings.append(self._f(
                    "leak", f"{self.KEY}_link",
                    f"{self.LABEL} linked from the target's {where}: {link} "
                    f"- if this link is public, anyone holding it reaches "
                    f"the content",
                    source=f"completeness pack: {self.LABEL}",
                    source_url=url, confidence=self.CONF,
                    passive=not active,
                    evidence={"severity": "low", "detector": self.id,
                              "link": link, "verified_public": False,
                              "remediation": _REMEDIATION}))
        res = self._ok(findings, f"{len(links)} {self.LABEL} link(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class GxTrelloBoard(_LinkMiner):
    id = "gx_trello_board"
    label = "Public Trello Board"
    description = ("Public Trello boards linked from the target's pages; "
                   "verified via the board's own public .json view.")
    LINK_RE = r"(https?://trello\.com/b/[A-Za-z0-9]{8,}(?:/[^\s\"'<>]*)?)"
    KEY = "public_trello_board"
    LABEL = "Trello board"
    SEVERITY = "medium"

    async def verify(self, ctx: Ctx, url: str) -> Optional[Dict[str, Any]]:
        m = re.search(r"trello\.com/b/([A-Za-z0-9]{8,})", url)
        if not m:
            return None
        # A public board serves its full JSON unauthenticated; a
        # private board 404s. This is Trello's own public surface.
        status, data = await _get_json(
            ctx, f"https://trello.com/b/{m.group(1)}.json", timeout=8)
        if status == 200 and isinstance(data, dict) and data.get("name"):
            return {"board_name": str(data["name"])[:120],
                    "board_id": m.group(1)}
        return None


class GxJiraPublic(_LinkMiner):
    id = "gx_jira_public_link"
    label = "Public Jira Surface"
    description = ("Jira boards/dashboards/filters/projects linked from "
                   "the target's pages and reachable without a login.")
    LINK_RE = (r"(https?://[A-Za-z0-9.\-]+\.atlassian\.net/"
               r"(?:jira|browse|secure|issues)[^\s\"'<>]*)")
    KEY = "public_jira_surface"
    LABEL = "Jira surface"
    SEVERITY = "medium"

    async def verify(self, ctx: Ctx, url: str) -> Optional[Dict[str, Any]]:
        r = await _req(ctx, "GET", url, timeout=8, follow_redirects=True)
        if r is None or r.status_code != 200:
            return None
        if _looks_like_login(r.text, str(r.url)):
            return None
        if "atlassian" in (r.text or "").lower() or "jira" in \
                (r.text or "").lower():
            return {"surface_url": url}
        return None


class GxConfluencePublic(_LinkMiner):
    id = "gx_confluence_public_page"
    label = "Public Confluence Page"
    description = ("Confluence pages linked from the target's pages and "
                   "reachable without a login.")
    LINK_RE = (r"(https?://[A-Za-z0-9.\-]+\.atlassian\.net/wiki/"
               r"[^\s\"'<>]*)")
    KEY = "public_confluence_page"
    LABEL = "Confluence page"
    SEVERITY = "medium"

    async def verify(self, ctx: Ctx, url: str) -> Optional[Dict[str, Any]]:
        r = await _req(ctx, "GET", url, timeout=8, follow_redirects=True)
        if r is None or r.status_code != 200:
            return None
        if _looks_like_login(r.text, str(r.url)):
            return None
        if "confluence" in (r.text or "").lower() or \
                "atlassian" in (r.text or "").lower():
            return {"surface_url": url}
        return None


class GxGoogleShare(_LinkMiner):
    id = "gx_google_share_link"
    label = "Public Google Drive/Docs Link"
    description = ("Google Drive folders/files and Docs/Sheets/Slides "
                   "share links in the target's pages; verified when "
                   "they resolve without a Google sign-in wall.")
    LINK_RE = (r"(https?://(?:drive|docs)\.google\.com/"
               r"[^\s\"'<>]+)")
    KEY = "public_google_share_link"
    LABEL = "Google share link"
    SEVERITY = "medium"

    async def verify(self, ctx: Ctx, url: str) -> Optional[Dict[str, Any]]:
        r = await _req(ctx, "GET", url, timeout=8, follow_redirects=True)
        if r is None or r.status_code != 200:
            return None
        final = str(r.url)
        if "accounts.google.com" in final:
            return None  # bounced to sign-in: not public
        body = r.text or ""
        if "google" in body.lower() and not _looks_like_login(body, final):
            kind = ("drive" if "drive.google.com" in url else "docs")
            return {"surface_url": url, "kind": kind}
        return None


# ---------------------------------------------------------------------------
# Gap 1b: secrets that live only in git HISTORY of an exposed repo
# ---------------------------------------------------------------------------

class GxGitHistorySecrets(Plugin):
    id = "gx_git_history_secrets"
    label = "Git History Secret Scan"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("When /.git is exposed, walks the loose-object "
                   "history (reflog -> commits -> trees -> blobs) and "
                   "scans blobs - including secrets deleted at HEAD "
                   "that still live in history.")
    timeout_s = 120

    _MAX_COMMITS = 14
    _MAX_OBJECTS = 220
    _MAX_BLOBS = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "history walk is active-mode only")
        if target.type == "url":
            base = target.normalized.rstrip("/")
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain for this target type")
            base = (await web_base(ctx, target, domain)).rstrip("/")

        async def get_text(path: str) -> Optional[str]:
            r = await _req(ctx, "GET", base + path, timeout=8,
                           follow_redirects=False)
            if r is None or r.status_code != 200:
                return None
            return r.text

        head_txt = await get_text("/.git/HEAD")
        if not head_txt or ("ref:" not in head_txt
                            and not re.search(r"\b[0-9a-f]{40}\b", head_txt)):
            res = self._ok([], "no exposed .git/HEAD")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Commit SHAs: HEAD ref first, then the reflog (oldest secret
        # carriers are usually reflog-only ancestors of HEAD).
        head_sha: Optional[str] = None
        m = re.search(r"ref:\s*(\S+)", head_txt)
        if m:
            ref_txt = await get_text("/.git/" + m.group(1).strip())
            if ref_txt:
                mm = re.search(r"\b[0-9a-f]{40}\b", ref_txt)
                if mm:
                    head_sha = mm.group(0)
        if not head_sha:
            mm = re.search(r"\b[0-9a-f]{40}\b", head_txt)
            if mm:
                head_sha = mm.group(0)
        commit_order: List[str] = []
        log_txt = await get_text("/.git/logs/HEAD")
        if log_txt:
            for line in log_txt.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.fullmatch(r"[0-9a-f]{40}",
                                                    parts[1]):
                    if parts[1] not in commit_order:
                        commit_order.append(parts[1])
        if head_sha and head_sha not in commit_order:
            commit_order.append(head_sha)
        if not commit_order:
            res = self._ok([], ".git exposed but no commit SHAs readable")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        obj_count = 0
        obj_cache: Dict[str, Optional[Tuple[str, bytes]]] = {}

        async def get_obj(sha: str) -> Optional[Tuple[str, bytes]]:
            nonlocal obj_count
            if sha in obj_cache:
                return obj_cache[sha]
            if obj_count >= self._MAX_OBJECTS:
                obj_cache[sha] = None
                return None
            obj_count += 1
            r = await _req(ctx, "GET",
                           f"{base}/.git/objects/{sha[:2]}/{sha[2:]}",
                           timeout=8, follow_redirects=False)
            out: Optional[Tuple[str, bytes]] = None
            if r is not None and r.status_code == 200:
                try:
                    raw = zlib.decompress(r.content)
                    hdr, _, payload = raw.partition(b"\x00")
                    typ = hdr.split(b" ")[0].decode("ascii", "ignore")
                    if typ in ("commit", "tree", "blob", "tag"):
                        out = (typ, payload)
                except Exception:
                    out = None
            obj_cache[sha] = out
            return out

        async def walk_tree(tree_sha: str, prefix: str,
                            acc: Dict[str, str], depth: int = 0) -> None:
            if depth > 6:
                return
            got = await get_obj(tree_sha)
            if not got or got[0] != "tree":
                return
            data = got[1]
            i = 0
            while i < len(data):
                try:
                    sp = data.index(b" ", i)
                    mode = data[i:sp].decode("ascii", "ignore")
                    nul = data.index(b"\x00", sp)
                    name = data[sp + 1:nul].decode("utf-8", "ignore")
                    sha = data[nul + 1:nul + 21].hex()
                except Exception:
                    return
                i = nul + 21
                path = f"{prefix}{name}"
                if mode == "40000":
                    await walk_tree(sha, path + "/", acc, depth + 1)
                else:
                    acc[sha] = path

        async def commit_tree(sha: str) -> Optional[str]:
            got = await get_obj(sha)
            if not got or got[0] != "commit":
                return None
            m2 = re.search(rb"tree ([0-9a-f]{40})", got[1])
            return m2.group(1).decode() if m2 else None

        # HEAD's blob set: a secret blob outside it lives only in
        # history (deleted or changed before HEAD).
        head_blobs: Dict[str, str] = {}
        if head_sha:
            ts = await commit_tree(head_sha)
            if ts:
                await walk_tree(ts, "", head_blobs)

        # BFS over commits (newest first), collecting their blobs.
        seen_commits: List[str] = []
        queue = list(reversed(commit_order))
        commit_blobs: Dict[str, Dict[str, str]] = {}
        while queue and len(seen_commits) < self._MAX_COMMITS:
            sha = queue.pop(0)
            if sha in commit_blobs:
                continue
            got = await get_obj(sha)
            if not got or got[0] != "commit":
                continue
            seen_commits.append(sha)
            blobs: Dict[str, str] = {}
            ts = await commit_tree(sha)
            if ts:
                await walk_tree(ts, "", blobs)
            commit_blobs[sha] = blobs
            for pm in re.finditer(rb"parent ([0-9a-f]{40})", got[1]):
                p = pm.group(1).decode()
                if p not in commit_blobs and p not in queue:
                    queue.append(p)

        # Scan blobs: history-only blobs first (highest signal).
        ordered: List[Tuple[str, str, str]] = []  # (blob, path, commit)
        seen_blob: set = set()
        for sha in seen_commits:
            for bsha, path in commit_blobs.get(sha, {}).items():
                if bsha in seen_blob:
                    continue
                seen_blob.add(bsha)
                ordered.append((bsha, path, sha))
        ordered.sort(key=lambda x: 0 if x[0] not in head_blobs else 1)

        findings: List[Finding] = []
        emitted: set = set()
        scanned = 0
        for bsha, path, csha in ordered:
            if scanned >= self._MAX_BLOBS or len(findings) >= 10:
                break
            got = await get_obj(bsha)
            if not got or got[0] != "blob":
                continue
            scanned += 1
            try:
                text = got[1][:200000].decode("utf-8", "ignore")
            except Exception:
                continue
            for name, pat, conf, sev in _GIT_RULES:
                try:
                    for mm in re.finditer(pat, text):
                        val = (mm.group(1) if mm.groups() and
                               name.startswith(("generic_", "hardcoded_"))
                               else mm.group(0))
                        val = (val or "").strip()[:300]
                        if not val or is_placeholder(val):
                            continue
                        dedup = (name, _fingerprint(val))
                        if dedup in emitted:
                            continue
                        emitted.add(dedup)
                        in_head = bsha in head_blobs
                        key = ("git_repo_secret" if in_head
                               else "git_history_secret")
                        where = ("still present at HEAD" if in_head
                                 else "DELETED at HEAD - lives only in "
                                      "git history")
                        findings.append(self._f(
                            "leak", key,
                            f"{sev.upper()}: {name.replace('_', ' ')} "
                            f"{redact(val)} in repo file '{path}' "
                            f"({where}, commit {csha[:10]})",
                            source="git history scan",
                            source_url=f"{base}/.git/objects/"
                                       f"{bsha[:2]}/{bsha[2:]}",
                            confidence=conf, passive=False,
                            evidence={
                                "severity": sev, "detector": self.id,
                                "rule": name,
                                "match_redacted": redact(val),
                                "fingerprint_sha256": _fingerprint(val),
                                "commit": csha, "path": path,
                                "in_head": in_head,
                                "remediation": _REMEDIATION}))
                        if len(findings) >= 10:
                            break
                except re.error:
                    continue
            if len(findings) >= 10:
                break

        res = self._ok(
            findings,
            f"walked {len(seen_commits)} commits, scanned {scanned} "
            f"blobs, {len(findings)} secret(s) in history")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Gap 2: cloud misconfiguration beyond signed URLs / bucket-root probes
# ---------------------------------------------------------------------------

_AZURE_RE = re.compile(
    r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/"
    r"([a-z0-9][a-z0-9\-]{1,62})/", re.I)
_FIREBASE_RE = re.compile(
    r"firebasestorage\.googleapis\.com/v0/b/([A-Za-z0-9\-_.]+)", re.I)


class GxAzureContainer(Plugin):
    id = "gx_azure_container_public"
    label = "Azure Container Public Listing"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Azure Blob CONTAINERS referenced by the target "
                   "(account + container from real URLs - the level "
                   "bucket-root probes miss), tested for anonymous "
                   "listing.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        pairs: Dict[Tuple[str, str], str] = {}
        for _where, text, url in texts:
            for m in _AZURE_RE.finditer(text):
                pairs.setdefault((m.group(1).lower(),
                                  m.group(2).lower()), url)
        findings: List[Finding] = []
        active = self.module_mode(ctx) != "passive"
        for (acct, container), url in list(pairs.items())[:6]:
            list_url = (f"https://{acct}.blob.core.windows.net/"
                        f"{container}?restype=container&comp=list")
            verified = False
            blob_count = 0
            names: List[str] = []
            if active:
                r = await _req(ctx, "GET", list_url, timeout=8,
                               follow_redirects=False)
                if (r is not None and r.status_code == 200
                        and "EnumerationResults" in r.text):
                    verified = True
                    blob_count = r.text.count("<Blob>")
                    names = re.findall(r"<Blob><Name>([^<]+)</Name>",
                                       r.text)[:3]
            if verified:
                findings.append(self._f(
                    "leak", "azure_container_public_list",
                    f"CRITICAL: Azure container '{container}' on account "
                    f"'{acct}' is PUBLICLY LISTABLE ({blob_count} blobs "
                    f"in first page). Anyone can enumerate its files.",
                    source="azure container probe", source_url=list_url,
                    confidence=95, passive=False,
                    evidence={"severity": "critical", "detector": self.id,
                              "account": acct, "container": container,
                              "blob_count_first_page": blob_count,
                              "sample_names": names,
                              "remediation": _REMEDIATION}))
            else:
                findings.append(self._f(
                    "leak", "azure_container_ref",
                    f"Azure Blob container referenced: {acct}/"
                    f"{container} - confirm its access level is private",
                    source="azure container mining", source_url=url,
                    confidence=65, passive=not active,
                    evidence={"severity": "low", "detector": self.id,
                              "account": acct, "container": container,
                              "remediation": _REMEDIATION}))
        res = self._ok(findings, f"{len(pairs)} azure container ref(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class GxFirebaseStorage(Plugin):
    id = "gx_firebase_storage_public"
    label = "Firebase Storage Public Listing"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Firebase Storage buckets referenced by the target, "
                   "tested for anonymous listing via the storage JSON "
                   "API (s3.py mines these refs but never tests them).")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        buckets: Dict[str, str] = {}
        for _where, text, url in texts:
            for m in _FIREBASE_RE.finditer(text):
                buckets.setdefault(m.group(1), url)
        findings: List[Finding] = []
        active = self.module_mode(ctx) != "passive"
        for bucket, url in list(buckets.items())[:6]:
            list_url = (f"https://firebasestorage.googleapis.com/v0/b/"
                        f"{bucket}/o")
            verified = False
            count = 0
            names: List[str] = []
            if active:
                status, data = await _get_json(ctx, list_url, timeout=8)
                if status == 200 and isinstance(data, dict) \
                        and isinstance(data.get("items"), list):
                    verified = True
                    count = len(data["items"])
                    names = [str(i.get("name"))[:120]
                             for i in data["items"][:3]
                             if isinstance(i, dict)]
            if verified:
                findings.append(self._f(
                    "leak", "firebase_bucket_public_list",
                    f"CRITICAL: Firebase Storage bucket '{bucket}' is "
                    f"PUBLICLY LISTABLE ({count} objects in first "
                    f"page) - storage rules allow anonymous reads.",
                    source="firebase storage probe", source_url=list_url,
                    confidence=95, passive=False,
                    evidence={"severity": "critical", "detector": self.id,
                              "bucket": bucket,
                              "object_count_first_page": count,
                              "sample_names": names,
                              "remediation": _REMEDIATION}))
            else:
                findings.append(self._f(
                    "leak", "firebase_bucket_ref",
                    f"Firebase Storage bucket referenced: {bucket} - "
                    f"confirm storage rules deny anonymous listing",
                    source="firebase mining", source_url=url,
                    confidence=65, passive=not active,
                    evidence={"severity": "low", "detector": self.id,
                              "bucket": bucket,
                              "remediation": _REMEDIATION}))
        res = self._ok(findings, f"{len(buckets)} firebase bucket ref(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


_OBJ_URL_RES = [
    # NB: the region segment is OPTIONAL - the common region-less
    # forms (bucket.s3.amazonaws.com, s3.amazonaws.com/bucket) must
    # match too; a mandatory [.-][region] group silently misses them.
    re.compile(r"https?://[a-z0-9][a-z0-9\-.]{1,61}[a-z0-9]\.s3"
               r"(?:[.-][a-z0-9\-]+)?\.amazonaws\.com/[^\s\"'<>]+",
               re.I),
    re.compile(r"https?://s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com/"
               r"[a-z0-9][a-z0-9\-.]{1,61}[a-z0-9]/[^\s\"'<>]+", re.I),
    re.compile(r"https?://storage\.googleapis\.com/"
               r"[a-z0-9][a-z0-9\-_.]{1,61}/[^\s\"'<>]+", re.I),
    re.compile(r"https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net/"
               r"[a-z0-9][a-z0-9\-]{1,62}/[^\s\"'<>]+", re.I),
    re.compile(r"https?://[a-z0-9][a-z0-9\-.]{1,61}\."
               r"[a-z0-9]+\.digitaloceanspaces\.com/[^\s\"'<>]+", re.I),
    re.compile(r"https?://firebasestorage\.googleapis\.com/v0/b/"
               r"[^\s\"'<>]+", re.I),
]
_SENSITIVE_FILE = re.compile(
    r"(backup|dump|export|snapshot|database|prod|users|customers|"
    r"secret|private|config)", re.I)
_SENSITIVE_EXT = re.compile(
    r"\.(sql|dump|bak|db|sqlite3?|env|jsonl|parquet|zip|tar|tgz|gz|7z)$",
    re.I)
_ANY_URL = re.compile(r"https?://[^\s\"'<>]+|href=[\"']([^\"']+)[\"']", re.I)


class GxPublicObjectRead(Plugin):
    id = "gx_public_object_read"
    label = "Public Object Read"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Object-level public access: the exact storage "
                   "object URLs (and sensitive-file links) the target "
                   "references, HEAD-probed anonymously. A bucket can "
                   "be non-listable while its objects are world-"
                   "readable. Proof is headers only - bodies are "
                   "never downloaded.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "object probing is active-mode only")
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        origin = await _origin(ctx, target)
        candidates: Dict[str, str] = {}
        for _where, text, url in texts:
            for rx in _OBJ_URL_RES:
                for m in rx.finditer(text):
                    u = m.group(0).rstrip("'\").,;")
                    candidates.setdefault(u, "storage object URL")
            for m in _ANY_URL.finditer(text):
                u = (m.group(1) or m.group(0)).rstrip("'\").,;")
                full = urljoin(url, u)
                if origin and not full.startswith(origin):
                    continue  # same-origin links only for the file gate
                base_name = urlparse(full).path.rsplit("/", 1)[-1]
                if _SENSITIVE_EXT.search(base_name) and \
                        _SENSITIVE_FILE.search(base_name):
                    candidates.setdefault(full, "sensitive file link")
        findings: List[Finding] = []
        probed = 0
        for u, kind in list(candidates.items())[:10]:
            probed += 1
            r = await _req(ctx, "HEAD", u, timeout=8,
                           follow_redirects=True)
            if r is None or r.status_code != 200:
                continue
            final = str(r.url)
            if "accounts.google.com" in final:
                continue
            findings.append(self._f(
                "leak", "public_object_readable",
                f"HIGH: {kind} is PUBLICLY READABLE without any "
                f"credentials: {u}",
                source="object access probe", source_url=u,
                confidence=90, passive=False,
                evidence={"severity": "high", "detector": self.id,
                          "content_type":
                              r.headers.get("content-type", ""),
                          "content_length":
                              r.headers.get("content-length", ""),
                          "proof": "anonymous HEAD returned 200; body "
                                   "not downloaded",
                          "remediation": _REMEDIATION}))
        res = self._ok(findings,
                       f"{probed} object URL(s) HEAD-probed, "
                       f"{len(findings)} publicly readable")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Gap 3: AI & LLM infrastructure sitting public without auth
# ---------------------------------------------------------------------------

class _ServiceProbe(Plugin):
    """Base for unauthenticated-service probes.

    Tries the target origin first, then the service's conventional
    port(s) on the target host. A finding requires the service's own
    response shape (never a bare 200), and the evidence is metadata
    (names/counts) only.
    """

    id = None  # abstract
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    timeout_s = 90

    PORTS: List[int] = []
    KEY = ""
    LABEL = ""
    SEVERITY = "high"

    async def probe(self, ctx: Ctx, bases: List[str]) -> Optional[Dict[str, Any]]:
        return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "service probing is active-mode only")
        bases = await _service_bases(ctx, target, self.PORTS)
        if not bases:
            return self._skipped("no host for this target type")
        hit = await self.probe(ctx, bases)
        findings: List[Finding] = []
        if hit:
            ev = {"severity": self.SEVERITY, "detector": self.id,
                  "remediation": _REMEDIATION}
            ev.update(hit.get("evidence", {}))
            findings.append(self._f(
                "infra", self.KEY,
                f"{self.LABEL}: {hit['value']}",
                source=f"completeness pack: {self.LABEL}",
                source_url=hit.get("url"), confidence=hit.get("conf", 92),
                passive=False, evidence=ev))
        res = self._ok(findings,
                       f"{self.LABEL}: {'exposed' if hit else 'not found'}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class GxChroma(_ServiceProbe):
    id = "gx_chroma_open"
    label = "Chroma Vector DB Open"
    description = ("Chroma vector database answering its API with no "
                   "authentication - collections listable by anyone.")
    PORTS = [8000]
    KEY = "chroma_unauthenticated"
    LABEL = "Chroma vector DB unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            for path in ("/api/v1/collections",
                         "/api/v2/tenants/default_tenant/databases/"
                         "default_database/collections"):
                status, data = await _get_json(ctx, base + path)
                if status == 200 and isinstance(data, list):
                    names = [str(c.get("name"))[:80] for c in data[:5]
                             if isinstance(c, dict) and c.get("name")]
                    return {"value": f"{base} lists {len(data)} "
                                     f"collection(s) with NO auth: "
                                     f"{', '.join(names) or '(unnamed)'}",
                            "url": base + path,
                            "evidence": {"collections": names,
                                         "collection_count": len(data)}}
            status, data = await _get_json(ctx, base + "/api/v1/heartbeat")
            if status == 200 and isinstance(data, dict) \
                    and "heartbeat" in json.dumps(data):
                return {"value": f"{base} answers Chroma heartbeat "
                                 f"with NO auth (collections API not "
                                 f"listable from here)",
                        "url": base + "/api/v1/heartbeat", "conf": 80,
                        "evidence": {"service": "chroma"}}
        return None


class GxQdrant(_ServiceProbe):
    id = "gx_qdrant_open"
    label = "Qdrant Vector DB Open"
    description = ("Qdrant vector database answering /collections "
                   "with no API key - anyone can enumerate (and query) "
                   "the stored embeddings.")
    PORTS = [6333]
    KEY = "qdrant_unauthenticated"
    LABEL = "Qdrant vector DB unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(ctx, base + "/collections")
            if status == 200 and isinstance(data, dict):
                cols = ((data.get("result") or {}).get("collections")
                        if isinstance(data.get("result"), dict) else None)
                if isinstance(cols, list):
                    names = [str(c.get("name"))[:80] for c in cols[:5]
                             if isinstance(c, dict) and c.get("name")]
                    return {"value": f"{base} lists {len(cols)} "
                                     f"collection(s) with NO auth: "
                                     f"{', '.join(names) or '(unnamed)'}",
                            "url": base + "/collections",
                            "evidence": {"collections": names,
                                         "collection_count": len(cols)}}
        return None


class GxWeaviate(_ServiceProbe):
    id = "gx_weaviate_open"
    label = "Weaviate Vector DB Open"
    description = ("Weaviate vector database exposing its full "
                   "schema (/v1/schema) with no authentication.")
    PORTS = [8080]
    KEY = "weaviate_unauthenticated"
    LABEL = "Weaviate vector DB unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(ctx, base + "/v1/schema")
            if status == 200 and isinstance(data, dict) \
                    and isinstance(data.get("classes"), list):
                classes = data["classes"]
                names = [str(c.get("class"))[:80] for c in classes[:5]
                         if isinstance(c, dict) and c.get("class")]
                props = sum(len(c.get("properties") or [])
                            for c in classes if isinstance(c, dict))
                return {"value": f"{base} exposes its schema with NO "
                                 f"auth: {len(classes)} class(es), "
                                 f"{props} properties: "
                                 f"{', '.join(names) or '(unnamed)'}",
                        "url": base + "/v1/schema",
                        "evidence": {"classes": names,
                                     "class_count": len(classes),
                                     "property_count": props}}
        return None


class GxMilvus(_ServiceProbe):
    id = "gx_milvus_open"
    label = "Milvus Vector DB Open"
    description = ("Milvus vector database: health endpoint and the "
                   "REST collection list answering with no auth.")
    PORTS = [9091, 19530]
    KEY = "milvus_unauthenticated"
    LABEL = "Milvus vector DB unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            r = await _req(ctx, "POST", base +
                           "/v2/vectordb/collections/list",
                           timeout=6, json={}, follow_redirects=True)
            if r is not None and r.status_code == 200:
                try:
                    data = json.loads(r.text)
                except Exception:
                    data = None
                if isinstance(data, dict) \
                        and data.get("code") in (0, 200) \
                        and isinstance(data.get("data"), list):
                    names = [str(x)[:80] for x in data["data"][:5]]
                    return {"value": f"{base} lists {len(data['data'])} "
                                     f"collection(s) with NO auth: "
                                     f"{', '.join(names) or '(none)'}",
                            "url": base + "/v2/vectordb/collections/list",
                            "evidence": {"collections": names,
                                         "collection_count":
                                             len(data["data"])}}
        for base in bases:
            r = await _req(ctx, "GET", base + "/healthz", timeout=6,
                           follow_redirects=True)
            if r is not None and r.status_code == 200 \
                    and "healthy" in (r.text or "").lower() \
                    and len(r.text) < 2000:
                return {"value": f"{base} answers Milvus healthz with "
                                 f"NO auth (collection list not "
                                 f"confirmed from here)",
                        "url": base + "/healthz", "conf": 75,
                        "evidence": {"service": "milvus"}}
        return None


class GxMlflow(_ServiceProbe):
    id = "gx_mlflow_open"
    label = "MLflow Tracking Server Open"
    description = ("MLflow tracking server listing experiments (and "
                   "their artifact locations - where training data "
                   "and models live) with no authentication.")
    PORTS = [5000]
    KEY = "mlflow_unauthenticated"
    LABEL = "MLflow tracking server unauthenticated"
    SEVERITY = "high"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(
                ctx, base + "/ajax-api/2.0/mlflow/experiments/list")
            if status == 200 and isinstance(data, dict) \
                    and isinstance(data.get("experiments"), list):
                exps = data["experiments"]
                names = [str(e.get("name"))[:80] for e in exps[:5]
                         if isinstance(e, dict) and e.get("name")]
                loci = [str(e.get("artifact_location"))[:160]
                        for e in exps[:3] if isinstance(e, dict)
                        and e.get("artifact_location")]
                return {"value": f"{base} lists {len(exps)} ML "
                                 f"experiment(s) with NO auth: "
                                 f"{', '.join(names) or '(unnamed)'}",
                        "url": base + "/ajax-api/2.0/mlflow/experiments/list",
                        "evidence": {"experiments": names,
                                     "experiment_count": len(exps),
                                     "artifact_locations": loci}}
            r = await _req(ctx, "GET", base + "/", timeout=6,
                           follow_redirects=True)
            if r is not None and r.status_code == 200 \
                    and "mlflow" in (r.text or "").lower():
                return {"value": f"{base} serves the MLflow UI with "
                                 f"NO auth",
                        "url": base + "/", "conf": 80,
                        "evidence": {"service": "mlflow"}}
        return None


class GxOllama(_ServiceProbe):
    id = "gx_ollama_open"
    label = "Ollama LLM Server Open"
    description = ("Ollama LLM server answering /api/tags with no "
                   "auth - anyone can run inference on (and pull "
                   "models to) the host.")
    PORTS = [11434]
    KEY = "ollama_unauthenticated"
    LABEL = "Ollama LLM server unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(ctx, base + "/api/tags")
            if status == 200 and isinstance(data, dict) \
                    and isinstance(data.get("models"), list):
                names = [str(m.get("name"))[:80] for m in data["models"][:5]
                         if isinstance(m, dict) and m.get("name")]
                return {"value": f"{base} lists {len(data['models'])} "
                                 f"local model(s) with NO auth: "
                                 f"{', '.join(names) or '(none)'}",
                        "url": base + "/api/tags",
                        "evidence": {"models": names,
                                     "model_count": len(data["models"])}}
        return None


class GxTriton(_ServiceProbe):
    id = "gx_triton_open"
    label = "Triton Inference Server Open"
    description = ("NVIDIA Triton inference server listing its "
                   "models (/v2/models) with no authentication.")
    PORTS = [8000]
    KEY = "triton_unauthenticated"
    LABEL = "Triton inference server unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(ctx, base + "/v2/models")
            if status == 200 and isinstance(data, list) and data \
                    and isinstance(data[0], dict) and "name" in data[0]:
                names = [str(m.get("name"))[:80] for m in data[:5]
                         if isinstance(m, dict) and m.get("name")]
                return {"value": f"{base} lists {len(data)} served "
                                 f"model(s) with NO auth: "
                                 f"{', '.join(names) or '(unnamed)'}",
                        "url": base + "/v2/models",
                        "evidence": {"models": names,
                                     "model_count": len(data)}}
            status, data = await _get_json(ctx, base + "/v2")
            if status == 200 and isinstance(data, dict) \
                    and "triton" in str(data.get("name", "")).lower():
                return {"value": f"{base} identifies as a Triton "
                                 f"inference server with NO auth",
                        "url": base + "/v2", "conf": 80,
                        "evidence": {"service": "triton",
                                     "version": data.get("version")}}
        return None


class GxTorchServe(_ServiceProbe):
    id = "gx_torchserve_open"
    label = "TorchServe Management API Open"
    description = ("TorchServe management API listing registered "
                   "models and their config - the management port "
                   "also allows registering/unregistering models.")
    PORTS = [8081]
    KEY = "torchserve_unauthenticated"
    LABEL = "TorchServe management API unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(ctx, base + "/models")
            if status == 200 and isinstance(data, dict) \
                    and isinstance(data.get("models"), list) \
                    and (not data["models"] or isinstance(
                        data["models"][0], dict) and
                        "modelName" in data["models"][0]):
                names = [str(m.get("modelName"))[:80]
                         for m in data["models"][:5]
                         if isinstance(m, dict) and m.get("modelName")]
                return {"value": f"{base} management API lists "
                                 f"{len(data['models'])} model(s) "
                                 f"with NO auth: "
                                 f"{', '.join(names) or '(none)'}",
                        "url": base + "/models",
                        "evidence": {"models": names,
                                     "model_count": len(data["models"])}}
        return None


class GxPineconeKey(Plugin):
    id = "gx_pinecone_key"
    label = "Pinecone API Key Exposed"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Pinecone vector DB API keys (pcsk_ format) in "
                   "pages/JS - a leaked key hands over the account's "
                   "indexes. hf_ tokens are covered elsewhere and are "
                   "not repeated here.")
    timeout_s = 45
    _RX = re.compile(r"pcsk_[A-Za-z0-9_\-]{20,}")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        hits: Dict[str, Tuple[str, str]] = {}
        for where, text, url in texts:
            for m in self._RX.finditer(text):
                if m.group(0) not in hits:
                    hits[m.group(0)] = (where, url)
        findings: List[Finding] = []
        for value, (where, url) in list(hits.items())[:5]:
            findings.append(self._f(
                "leak", "pinecone_api_key_exposed",
                f"CRITICAL: Pinecone API key {redact(value)} in "
                f"{where} - full access to the account's vector "
                f"indexes",
                source="completeness pack: Pinecone API key",
                source_url=url, confidence=92, passive=True,
                evidence={"severity": "critical", "detector": self.id,
                          "match_redacted": redact(value),
                          "fingerprint_sha256": _fingerprint(value),
                          "remediation": _REMEDIATION}))
        res = self._ok(findings, f"{len(findings)} Pinecone key(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class GxTrainingDataRefs(Plugin):
    id = "gx_training_data_refs"
    label = "Training Data References"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Training-data exposure leads in the target's "
                   "pages/JS: public Hugging Face dataset links, "
                   "load_dataset() calls, and direct dataset file "
                   "URLs (jsonl/parquet/arrow) - the raw material AI "
                   "features are trained on, left public.")
    timeout_s = 45
    _PATTERNS = [
        ("hf_dataset", re.compile(
            r"https?://huggingface\.co/datasets/[A-Za-z0-9_.\-]+/"
            r"[A-Za-z0-9_.\-]+")),
        ("load_dataset", re.compile(
            r"load_dataset\(\s*[\"']([^\"']{3,120})[\"']")),
        ("dataset_file", re.compile(
            r"https?://[^\s\"'<>]+\.(?:jsonl|parquet|arrow)"
            r"(?:\?[^\s\"'<>]*)?", re.I)),
    ]

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        hits: Dict[Tuple[str, str], Tuple[str, str]] = {}
        for where, text, url in texts:
            for kind, rx in self._PATTERNS:
                for m in rx.finditer(text):
                    value = (m.group(1) if m.groups() else m.group(0))
                    value = value.strip().rstrip("'\").,;")
                    if kind == "dataset_file" and not re.search(
                            r"train|dataset|corpus|finetune|fine-tune",
                            value, re.I):
                        continue
                    if value and (kind, value) not in hits:
                        hits[(kind, value)] = (where, url)
        findings: List[Finding] = []
        for (kind, value), (where, url) in list(hits.items())[:8]:
            findings.append(self._f(
                "leak", "training_data_reference",
                f"Training data reference ({kind}) in {where}: "
                f"{value[:160]} - confirm this dataset is meant to "
                f"be public; training corpora often contain scraped "
                f"PII and licensed text",
                source="completeness pack: training data references",
                source_url=url, confidence=70, passive=True,
                evidence={"severity": "medium", "detector": self.id,
                          "kind": kind, "reference": value[:200],
                          "remediation": _REMEDIATION}))
        res = self._ok(findings,
                       f"{len(findings)} training-data reference(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Gap 4: internal routing & service meshes
# ---------------------------------------------------------------------------

class GxConsulCatalog(_ServiceProbe):
    id = "gx_consul_catalog"
    label = "Consul Service Catalog Open"
    description = ("Consul SERVICE CATALOG (/v1/catalog/services) "
                   "readable with no token - the full internal "
                   "service inventory. (The pf pack reads agent info; "
                   "the catalog is the map of everything.)")
    PORTS = [8500]
    KEY = "consul_catalog_open"
    LABEL = "Consul service catalog unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            status, data = await _get_json(ctx,
                                           base + "/v1/catalog/services")
            if status == 200 and isinstance(data, dict) and data:
                names = [str(k)[:80] for k in list(data.keys())[:8]
                         if k != "consul"]
                return {"value": f"{base} exposes the Consul service "
                                 f"catalog with NO auth: "
                                 f"{len(data)} service(s): "
                                 f"{', '.join(names) or '(only consul)'}",
                        "url": base + "/v1/catalog/services",
                        "evidence": {"services": names,
                                     "service_count": len(data)}}
        return None


class GxEurekaRegistry(_ServiceProbe):
    id = "gx_eureka_registry"
    label = "Eureka Service Registry Open"
    description = ("Netflix Eureka registry (/eureka/apps) readable "
                   "with no auth - every registered service instance, "
                   "host and port.")
    PORTS = [8761]
    KEY = "eureka_registry_open"
    LABEL = "Eureka service registry unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            r = await _req(ctx, "GET", base + "/eureka/apps", timeout=6,
                           headers={"Accept": "application/json"},
                           follow_redirects=True)
            if r is None or r.status_code != 200:
                continue
            text = r.text or ""
            names: List[str] = []
            count = 0
            try:
                data = json.loads(text)
                apps = ((data.get("applications") or {})
                        .get("application") or [])
                if isinstance(apps, dict):
                    apps = [apps]
                count = len(apps)
                names = [str(a.get("name"))[:80] for a in apps[:8]
                         if isinstance(a, dict) and a.get("name")]
            except Exception:
                if "<applications>" in text:
                    count = text.count("<application>")
                    names = re.findall(r"<name>([^<]+)</name>",
                                       text)[:8]
            if count:
                return {"value": f"{base} exposes the Eureka "
                                 f"registry with NO auth: {count} "
                                 f"application(s): "
                                 f"{', '.join(names) or '(unnamed)'}",
                        "url": base + "/eureka/apps",
                        "evidence": {"applications": names,
                                     "application_count": count}}
        return None


class GxNacosRegistry(_ServiceProbe):
    id = "gx_nacos_registry"
    label = "Nacos Service Registry Open"
    description = ("Nacos discovery catalog listing services with "
                   "no auth - the internal service map of Spring "
                   "Cloud / Alibaba stacks.")
    PORTS = [8848]
    KEY = "nacos_registry_open"
    LABEL = "Nacos service registry unauthenticated"

    async def probe(self, ctx, bases):
        for base in bases:
            for path, key in (
                    ("/nacos/v1/ns/catalog/services?pageNo=1&pageSize=20",
                     "list"),
                    ("/nacos/v1/ns/service/list?pageNo=1&pageSize=20",
                     "doms")):
                status, data = await _get_json(ctx, base + path)
                if status == 200 and isinstance(data, dict) \
                        and isinstance(data.get(key), list):
                    items = data[key]
                    names = []
                    for it in items[:8]:
                        if isinstance(it, dict):
                            n = it.get("name") or it.get("serviceName")
                            if n:
                                names.append(str(n)[:80])
                        elif isinstance(it, str):
                            names.append(it[:80])
                    return {"value": f"{base} lists Nacos services "
                                     f"with NO auth: "
                                     f"{data.get('count', len(items))} "
                                     f"service(s): "
                                     f"{', '.join(names) or '(unnamed)'}",
                            "url": base + path,
                            "evidence": {"services": names,
                                         "service_count":
                                             data.get("count",
                                                      len(items))}}
        return None


class GxIstioDebug(_ServiceProbe):
    id = "gx_istio_debug"
    label = "Istio Pilot Debug Exposed"
    description = ("Istio Pilot debug endpoints (/debug/configz) "
                   "reachable - they dump the full Envoy config: "
                   "every internal cluster, listener and route.")
    PORTS = [15014]
    KEY = "istio_debug_exposed"
    LABEL = "Istio Pilot debug endpoint exposed"
    SEVERITY = "high"

    async def probe(self, ctx, bases):
        for base in bases:
            for path in ("/debug/configz", "/debug/endpointz"):
                r = await _req(ctx, "GET", base + path, timeout=6,
                               follow_redirects=True)
                if r is None or r.status_code != 200:
                    continue
                text = r.text or ""
                clusters = text.count("cluster_name")
                if clusters or "config_dump" in text or \
                        '"configs"' in text:
                    return {"value": f"{base}{path} dumps Istio "
                                     f"config with NO auth "
                                     f"({len(text)} bytes, "
                                     f"{clusters} cluster refs) - "
                                     f"the full internal service map",
                            "url": base + path,
                            "evidence": {"path": path,
                                         "response_bytes": len(text),
                                         "cluster_refs": clusters,
                                         "body_sha256":
                                             _fingerprint(text)}}
        return None


_FULL_INTROSPECTION = (
    "query GxIntrospection { __schema { queryType { name } "
    "mutationType { name } subscriptionType { name } "
    "types { name kind fields(includeDeprecated: false) { name } "
    "inputFields { name } enumValues(includeDeprecated: false) "
    "{ name } } } }")
_GQL_URL_RE = re.compile(
    r"https?://[^\s\"'<>\\]+?(?:graphql|gql|hasura)[^\s\"'<>\\]*", re.I)
_GQL_REL_RE = re.compile(
    r"[\"'](/[A-Za-z0-9._\-/]*(?:graphql|gql)[A-Za-z0-9._\-/]*)[\"']", re.I)
# The fixed paths the graphql / graphql_probe plugins already cover;
# this detector's surface is endpoints DISCOVERED in content instead.
_CANONICAL_SUFFIXES = ("/graphql", "/api/graphql")


class GxGraphqlSchema(Plugin):
    id = "gx_graphql_schema_exposure"
    label = "GraphQL Schema Exposure (Discovered Endpoints)"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "api"
    description = ("Discovers GraphQL endpoints from the target's "
                   "pages/JS (custom paths, Hasura, cross-host API "
                   "hosts the fixed-path probes never see) and runs "
                   "the standard introspection query: a returned "
                   "schema is reported with total type/field counts.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "introspection probing is active-mode "
                                "only")
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        origin = await _origin(ctx, target)
        endpoints: Dict[str, None] = {}
        for _where, text, url in texts:
            for m in _GQL_URL_RE.finditer(text):
                u = m.group(0).rstrip("'\").,;")
                if u:
                    endpoints.setdefault(u)
            for m in _GQL_REL_RE.finditer(text):
                endpoints.setdefault(urljoin(url, m.group(1)))
        # Skip the exact canonical fixed paths on the target's own
        # origin (already covered by the graphql/graphql_probe/
        # graphql_deep trio) - custom paths like /api/v2/graphql and
        # cross-host endpoints are this detector's surface.
        todo: List[str] = []
        for u in endpoints:
            path = urlparse(u).path.rstrip("/")
            if path in _CANONICAL_SUFFIXES \
                    and origin and u.startswith(origin):
                continue
            todo.append(u)
        findings: List[Finding] = []
        for u in todo[:4]:
            ctx.publish("endpoints", u)
            r = await _req(ctx, "POST", u, timeout=10,
                           json={"query": _FULL_INTROSPECTION},
                           follow_redirects=True)
            if r is None or r.status_code != 200:
                continue
            try:
                data = json.loads(r.text)
            except Exception:
                continue
            schema = ((data.get("data") or {}).get("__schema")
                      if isinstance(data, dict) else None)
            if not isinstance(schema, dict):
                continue
            types = [t for t in (schema.get("types") or [])
                     if isinstance(t, dict)
                     and not str(t.get("name", "")).startswith("__")]
            if not types:
                continue
            field_count = sum(len(t.get("fields") or []) for t in types)
            type_names = [str(t.get("name"))[:60] for t in types[:8]]
            mut = (schema.get("mutationType") or {}).get("name")
            sub = (schema.get("subscriptionType") or {}).get("name")
            findings.append(self._f(
                "api", "graphql_full_schema_exposed",
                f"HIGH: full GraphQL schema exposed via introspection "
                f"at {u}: {len(types)} types, {field_count} fields"
                f"{f', mutation root {mut}' if mut else ''}"
                f"{f', subscription root {sub}' if sub else ''} - "
                f"the entire API (often the database shape) is "
                f"public",
                source="graphql discovered-endpoint introspection",
                source_url=u, confidence=95, passive=False,
                evidence={"severity": "high", "detector": self.id,
                          "type_count": len(types),
                          "field_count": field_count,
                          "sample_types": type_names,
                          "mutation_root": mut,
                          "subscription_root": sub,
                          "proof": "standard introspection query "
                                   "only; no data was queried",
                          "remediation": _REMEDIATION}))
        res = self._ok(findings,
                       f"{len(todo)} discovered endpoint(s), "
                       f"{len(findings)} schema(s) exposed")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


GAP_IDS: List[str] = [
    "gx_trello_board", "gx_jira_public_link",
    "gx_confluence_public_page", "gx_google_share_link",
    "gx_git_history_secrets",
    "gx_azure_container_public", "gx_firebase_storage_public",
    "gx_public_object_read",
    "gx_chroma_open", "gx_qdrant_open", "gx_weaviate_open",
    "gx_milvus_open", "gx_mlflow_open", "gx_ollama_open",
    "gx_triton_open", "gx_torchserve_open", "gx_pinecone_key",
    "gx_training_data_refs",
    "gx_consul_catalog", "gx_eureka_registry", "gx_nacos_registry",
    "gx_istio_debug", "gx_graphql_schema_exposure",
]
