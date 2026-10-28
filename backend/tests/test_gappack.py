"""Unit gate for the gx_* completeness pack (23 detectors).

Every gx plugin runs through the REAL Ctx against a canary served via
httpx MockTransport (tests/gappack_samples.py): each detector must
fire on the canary, stay silent on the clean site, and no full planted
secret may appear in any finding (masked + fingerprint only). The git
fixture is a REAL git repo built with the git CLI: the fake key is
committed, then deleted - it exists only in history.
"""
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gappack_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.gappack import GAP_IDS  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
CLEAN = "clean.test"

# ---------------------------------------------------------------------------
# Real git fixture: secret committed in c1, deleted in c2 (HEAD)
# ---------------------------------------------------------------------------

_GIT_DIR: Path | None = None
_GIT_C1 = ""


def _git_fixture() -> Path:
    global _GIT_DIR, _GIT_C1
    if _GIT_DIR is not None:
        return _GIT_DIR
    root = Path(tempfile.mkdtemp(prefix="gx-git-fixture-"))
    repo = root / "repo"
    repo.mkdir()
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "GX Canary",
           "GIT_AUTHOR_EMAIL": "gx@canary.test",
           "GIT_COMMITTER_NAME": "GX Canary",
           "GIT_COMMITTER_EMAIL": "gx@canary.test"}

    def git(*args: str) -> str:
        out = subprocess.run(["git", "-C", str(repo), *args],
                             capture_output=True, text=True, env=env,
                             check=True)
        return out.stdout.strip()

    git("init", "-q", "-b", "main")
    (repo / "app_config.txt").write_text(
        f"# canary config\naws_access_key_id = {samples.GIT_KEY}\n")
    git("add", ".")
    git("commit", "-q", "-m", "add config")
    _GIT_C1 = git("rev-parse", "HEAD")
    (repo / "app_config.txt").unlink()
    (repo / "README.md").write_text("# gx canary\n")
    git("add", "-A")
    git("commit", "-q", "-m", "remove config")
    _GIT_DIR = repo / ".git"
    return _GIT_DIR


def _serve_git(path: str) -> httpx.Response | None:
    git_dir = _git_fixture()
    rel = path[len("/.git/"):]
    target = (git_dir / rel).resolve()
    if not str(target).startswith(str(git_dir.resolve())):
        return httpx.Response(403, content="nope")
    if not target.is_file():
        return None
    return httpx.Response(200, content=target.read_bytes(),
                          headers={"Content-Type":
                                   "application/octet-stream"})


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path or "/"
    raw = unquote(urlsplit(str(request.url)).path)
    method = request.method.upper()

    if host == CLEAN:
        if path in ("/", "/index.html"):
            return httpx.Response(200, content=samples.CLEAN_HTML,
                                  headers={"Content-Type": "text/html"},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)

    if host in (CANARY, "api.canary.test"):
        if path.startswith("/.git/"):
            resp = _serve_git(path)
            if resp is not None:
                resp.request = request
                return resp
            return httpx.Response(404, content="no object",
                                  request=request)
        if method == "POST" and path in samples.POST_ROUTES:
            return httpx.Response(
                200, content=json.dumps(samples.POST_ROUTES[path]),
                headers={"Content-Type": "application/json"},
                request=request)
        if path in ("/", "/index.html"):
            return httpx.Response(200, content=samples.CANARY_HTML,
                                  headers={"Content-Type": "text/html"},
                                  request=request)
        route = samples.ROUTES.get(path)
        if route is not None:
            ctype, body = route
            return httpx.Response(200, content=body,
                                  headers={"Content-Type": ctype},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)

    ext = samples.EXTERNAL.get(host)
    if ext is not None:
        for cand in (path, raw):
            route = ext.get(cand)
            if route is not None:
                ctype, body = route
                return httpx.Response(
                    200, content=body,
                    headers={"Content-Type": ctype,
                             "Content-Length": str(len(body))},
                    request=request)
        return httpx.Response(404, content="not found", request=request)

    return httpx.Response(404, content="", request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="gappack-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(pid: str, host: str):
    cls = discover()[pid]
    ctx = _ctx()
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx))
    finally:
        asyncio.run(ctx.http.aclose())


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


# ---------------------------------------------------------------------------

def test_exactly_23_new_detectors_registered():
    gx = sorted(k for k in discover() if k.startswith("gx_"))
    assert gx == sorted(GAP_IDS)
    assert len(gx) == 23
    # 575 when the gx pack landed; +12 fx_* (format & graph pack);
    # +5 xml_* (XML reader pack); +10 da_* (deep-artifacts pack);
    # +5 ai_* (AI-crawler surface pack)
    assert len(discover()) == 625  # 624 master + 1 passive_subdomains (detection-expand, rebased 2026-10-27)


def test_trello_board_verified_public():
    r = _run("gx_trello_board", CANARY)
    hits = _by_key(r, "public_trello_board")
    assert hits, r.reason
    assert hits[0].evidence["board_name"] == "GX Canary Board"


def test_jira_surface_verified_public():
    r = _run("gx_jira_public_link", CANARY)
    assert _by_key(r, "public_jira_surface"), r.reason


def test_confluence_page_verified_public():
    r = _run("gx_confluence_public_page", CANARY)
    assert _by_key(r, "public_confluence_page"), r.reason


def test_google_share_links_verified_public():
    r = _run("gx_google_share_link", CANARY)
    hits = _by_key(r, "public_google_share_link")
    assert len(hits) >= 2, r.reason  # drive folder + docs sheet


def test_git_history_secret_found_masked_with_commit():
    _git_fixture()
    r = _run("gx_git_history_secrets", CANARY)
    hits = _by_key(r, "git_history_secret")
    assert hits, r.reason
    ev = hits[0].evidence
    assert ev["commit"] == _GIT_C1
    assert ev["in_head"] is False
    assert ev["fingerprint_sha256"] == hashlib.sha256(
        samples.GIT_KEY.encode()).hexdigest()
    blob = json.dumps([f.value for f in r.findings]) + json.dumps(
        [f.evidence for f in r.findings], default=str)
    assert samples.GIT_KEY not in blob


def test_azure_container_public_list():
    r = _run("gx_azure_container_public", CANARY)
    hits = _by_key(r, "azure_container_public_list")
    assert hits, r.reason
    assert hits[0].evidence["blob_count_first_page"] == 2
    assert hits[0].evidence["container"] == "gxcontainer"


def test_firebase_bucket_public_list():
    r = _run("gx_firebase_storage_public", CANARY)
    hits = _by_key(r, "firebase_bucket_public_list")
    assert hits, r.reason
    assert hits[0].evidence["object_count_first_page"] == 2


def test_public_object_read():
    r = _run("gx_public_object_read", CANARY)
    hits = _by_key(r, "public_object_readable")
    assert len(hits) >= 3, r.reason
    urls = {f.source_url for f in hits}
    assert samples.S3_OBJECT_URL in urls
    assert samples.AZURE_OBJECT_URL in urls


def test_chroma_open():
    r = _run("gx_chroma_open", CANARY)
    hits = _by_key(r, "chroma_unauthenticated")
    assert hits and hits[0].evidence["collection_count"] == 1


def test_qdrant_open():
    r = _run("gx_qdrant_open", CANARY)
    hits = _by_key(r, "qdrant_unauthenticated")
    assert hits and hits[0].evidence["collection_count"] == 1


def test_weaviate_open():
    r = _run("gx_weaviate_open", CANARY)
    hits = _by_key(r, "weaviate_unauthenticated")
    assert hits and hits[0].evidence["class_count"] == 1
    assert hits[0].evidence["property_count"] == 2


def test_milvus_open():
    r = _run("gx_milvus_open", CANARY)
    hits = _by_key(r, "milvus_unauthenticated")
    assert hits and hits[0].evidence["collection_count"] == 2


def test_mlflow_open():
    r = _run("gx_mlflow_open", CANARY)
    hits = _by_key(r, "mlflow_unauthenticated")
    assert hits and hits[0].evidence["experiment_count"] == 1


def test_ollama_open():
    r = _run("gx_ollama_open", CANARY)
    hits = _by_key(r, "ollama_unauthenticated")
    assert hits and hits[0].evidence["model_count"] == 1


def test_triton_open():
    r = _run("gx_triton_open", CANARY)
    hits = _by_key(r, "triton_unauthenticated")
    assert hits and hits[0].evidence["model_count"] == 1


def test_torchserve_open():
    r = _run("gx_torchserve_open", CANARY)
    hits = _by_key(r, "torchserve_unauthenticated")
    assert hits and hits[0].evidence["model_count"] == 1


def test_pinecone_key_masked():
    r = _run("gx_pinecone_key", CANARY)
    hits = _by_key(r, "pinecone_api_key_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert ev["fingerprint_sha256"] == hashlib.sha256(
        samples.PINECONE_KEY.encode()).hexdigest()
    assert samples.PINECONE_KEY not in hits[0].value
    assert samples.PINECONE_KEY not in json.dumps(ev, default=str)


def test_training_data_refs():
    r = _run("gx_training_data_refs", CANARY)
    hits = _by_key(r, "training_data_reference")
    kinds = {f.evidence["kind"] for f in hits}
    assert {"hf_dataset", "load_dataset", "dataset_file"} <= kinds, kinds


def test_consul_catalog_open():
    r = _run("gx_consul_catalog", CANARY)
    hits = _by_key(r, "consul_catalog_open")
    assert hits and hits[0].evidence["service_count"] == 3
    assert "gx-api" in hits[0].evidence["services"]


def test_eureka_registry_open():
    r = _run("gx_eureka_registry", CANARY)
    hits = _by_key(r, "eureka_registry_open")
    assert hits and hits[0].evidence["application_count"] == 1


def test_nacos_registry_open():
    r = _run("gx_nacos_registry", CANARY)
    hits = _by_key(r, "nacos_registry_open")
    assert hits and hits[0].evidence["service_count"] == 2


def test_istio_debug_exposed():
    r = _run("gx_istio_debug", CANARY)
    hits = _by_key(r, "istio_debug_exposed")
    assert hits and hits[0].evidence["cluster_refs"] == 2


def test_graphql_schema_exposure_counts():
    r = _run("gx_graphql_schema_exposure", CANARY)
    hits = _by_key(r, "graphql_full_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert ev["type_count"] == 4       # __Type excluded
    assert ev["field_count"] == 8
    assert ev["mutation_root"] == "Mutation"


@pytest.mark.parametrize("pid", sorted(GAP_IDS))
def test_clean_site_silence(pid):
    r = _run(pid, CLEAN)
    assert r.status.value == "ok", f"{pid}: {r.status} {r.reason}"
    assert not r.findings, f"{pid} fired on the clean site: " \
                           f"{[f.key for f in r.findings]}"
