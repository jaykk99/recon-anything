"""ReconAnything API (FastAPI).

Routes:
  GET  /api/health
  POST /api/classify            single + batch input classification
  GET  /api/plugins             plugin registry with key status
  POST /api/runs                start a run (returns run_id)
  GET  /api/runs/{id}/stream    SSE live progress + findings
  GET  /api/runs                list runs
  GET  /api/runs/{id}           run detail + findings + summary
  GET  /api/runs/{id}/graph     correlation graph payload
  GET  /api/runs/{id}/apimap    assembled API map
  GET  /api/runs/{id}/export    ?format=json|csv|md|html
  GET  /api/diff?a=&b=          diff two runs
  GET/POST/DELETE /api/keys     API key vault
  GET/POST/DELETE /api/schedules

Single-user gate: if RECON_ACCESS_CODE is set, every /api route except
/api/health requires header X-Access-Code.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel
from typing import Dict, List, Optional

from . import config
from . import net
from .classifier import classify, classify_batch
from .diff import diff_runs
from .graph import graph_payload
from .keys import encrypt, key_status, load_all
from .models import ApiKey, Finding, Run, Schedule, Target, get_session, init_db
from .plugins.registry import describe
from .reporting import executive_summary, findings_dump, to_csv, to_html, to_markdown
from .runner import launch_run, subscribe

app = FastAPI(title="ReconAnything", version="0.1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=False,
)


def gate(x_access_code: Optional[str] = Header(default=None),
         code: Optional[str] = Query(default=None)):
    # EventSource cannot set headers, so accept ?code= as a fallback
    provided = x_access_code or code
    if config.ACCESS_CODE and provided != config.ACCESS_CODE:
        raise HTTPException(status_code=401, detail="bad access code")
    return True


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/api/health")
def health():
    return {"ok": True, "service": "recon-anything"}


# -- classify ------------------------------------------------------------
class ClassifyIn(BaseModel):
    text: str


@app.post("/api/classify", dependencies=[Depends(gate)])
def api_classify(body: ClassifyIn):
    if "\n" in body.text.strip():
        return {"results": classify_batch(body.text)}
    return classify(body.text)


# -- plugins --------------------------------------------------------------
@app.get("/api/plugins", dependencies=[Depends(gate)])
def api_plugins():
    session = get_session()
    try:
        status = key_status(session)
    finally:
        session.close()
    plugins = describe()
    for p in plugins:
        p["key_status"] = {k: status.get(k, {"configured": False})
                           for k in p["requires_keys"]}
    return {"plugins": plugins}


# -- runs -----------------------------------------------------------------
class RunIn(BaseModel):
    targets: str
    mode: str = "passive"
    plugins: Optional[List[str]] = None
    module_overrides: Optional[Dict[str, str]] = None
    source_type: str = "website"  # website | bank | atm


@app.post("/api/runs", dependencies=[Depends(gate)])
async def api_start_run(body: RunIn):
    if not body.targets.strip():
        raise HTTPException(400, "targets required")
    if body.mode not in ("passive", "active"):
        raise HTTPException(400, "mode must be passive|active")
    if body.source_type not in ("website", "bank", "atm"):
        raise HTTPException(400, "source_type must be website|bank|atm")
    run_id = uuid.uuid4().hex[:12]
    session = get_session()
    try:
        session.add(Run(id=run_id, mode=body.mode, status="running"))
        session.commit()
        keys = load_all(session)
    finally:
        session.close()
    # Bank/ATM source types imply explicit authorization: the user picked
    # the mode on purpose. Record it as an audit finding in the run.
    overrides = dict(body.module_overrides or {})
    if body.source_type == "bank":
        overrides["bank"] = "authorized"
    elif body.source_type == "atm":
        overrides["atm"] = "authorized"
    await launch_run(run_id, body.targets, body.mode,
                     body.plugins, overrides, keys,
                     source_type=body.source_type)
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}/stream", dependencies=[Depends(gate)])
async def api_run_stream(run_id: str):
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise HTTPException(404, "run not found")
    finally:
        session.close()
    return StreamingResponse(subscribe(run_id), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/runs", dependencies=[Depends(gate)])
def api_list_runs(limit: int = Query(30, le=200)):
    session = get_session()
    try:
        runs = session.query(Run).order_by(Run.created_at.desc()).limit(limit).all()
        return {"runs": [
            {"id": r.id, "mode": r.mode, "status": r.status,
             "created_at": r.created_at.isoformat() if r.created_at else None,
             "summary": r.summary or {}} for r in runs]}
    finally:
        session.close()


@app.get("/api/runs/{run_id}", dependencies=[Depends(gate)])
def api_run_detail(run_id: str, show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
        return {
            "run": {"id": run.id, "mode": run.mode, "status": run.status,
                    "created_at": run.created_at.isoformat() if run.created_at else None,
                    "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    "summary": run.summary or {}},
            "targets": [{"id": t.id, "raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
            "findings": rows,
            "executive_summary": executive_summary(rows),
        }
    finally:
        session.close()


@app.get("/api/runs/{run_id}/graph", dependencies=[Depends(gate)])
def api_graph(run_id: str):
    session = get_session()
    try:
        return graph_payload(session, run_id)
    finally:
        session.close()


@app.get("/api/runs/{run_id}/apimap", dependencies=[Depends(gate)])
def api_apimap(run_id: str):
    session = get_session()
    try:
        rows = session.query(Finding).filter_by(run_id=run_id).all()
        entries = {}
        for f in rows:
            if f.key in ("endpoint",) or (f.category == "api" and f.raw):
                raw = f.raw or {}
                amap = raw.get("map") if isinstance(raw, dict) else None
                if amap:
                    entries.update(amap)
                else:
                    entries[f.value] = {"note": f.source}
        # also fold api_map_entries raw
        for f in rows:
            if f.key == "api_map_entries" and f.raw and isinstance(f.raw, dict):
                entries.update(f.raw.get("map", {}))
        return {"entries": entries, "count": len(entries)}
    finally:
        session.close()


@app.get("/api/runs/{run_id}/export", dependencies=[Depends(gate)])
def api_export(run_id: str, format: str = "json", show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
    finally:
        session.close()
    if format == "json":
        return {"run_id": run_id, "findings": rows}
    if format == "csv":
        return PlainTextResponse(to_csv(rows), media_type="text/csv",
                                 headers={"Content-Disposition":
                                          f"attachment; filename=recon-{run_id}.csv"})
    if format == "md":
        return PlainTextResponse(to_markdown(run, targets, rows),
                                 media_type="text/markdown",
                                 headers={"Content-Disposition":
                                          f"attachment; filename=recon-{run_id}.md"})
    if format == "html":
        return PlainTextResponse(to_html(run, targets, rows), media_type="text/html",
                                 headers={"Content-Disposition":
                                          f"attachment; filename=recon-{run_id}.html"})
    raise HTTPException(400, "format must be json|csv|md|html")


@app.get("/api/runs/{run_id}/fetch", dependencies=[Depends(gate)])
async def api_fetch_file(run_id: str, url: str = Query(..., max_length=2000)):
    """Fetch a URL found during a run so Jay can view file contents.
    Only allows URLs that appeared in this run's findings (SSRF guard)."""
    from urllib.parse import urlparse
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        rows = findings_dump(session, run_id)
    finally:
        session.close()
    allowed = set()
    for r in rows:
        for k in ("source_url", "value"):
            v = r.get(k) or ""
            if v.startswith("http"):
                # value may contain extra text, extract first URL
                candidate = v.split()[0] if k == "value" else v
                if candidate.startswith("http"):
                    allowed.add(candidate)
    if url not in allowed:
        raise HTTPException(403, "URL was not found in this run")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "only http/https allowed")
    import httpx
    try:
        async with net.async_client(timeout=20, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ReconAnything/1.0"})
        body = resp.text[:200000]
        return {"url": url, "status": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "size": len(resp.content),
                "last_modified": resp.headers.get("last-modified", ""),
                "headers": dict(resp.headers),
                "body": body,
                "truncated": len(resp.content) > 200000}
    except Exception as e:
        raise HTTPException(502, f"fetch failed: {str(e)[:200]}")


@app.get("/api/runs/{run_id}/vulns", dependencies=[Depends(gate)])
def api_vulns(run_id: str):
    """Possible-vulnerabilities advisor: ranked attack paths from scan findings.

    Heuristic only (no LLM). PoCs are detection-only and non-destructive.
    """
    from .vuln_advisor import advise
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        rows = findings_dump(session, run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        summary = {
            "targets": [{"raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
        }
        return {"run_id": run_id, "candidates": advise(rows, summary)}
    finally:
        session.close()


class DryRunIn(BaseModel):
    candidate_id: str
    base: str = ""


@app.post("/api/runs/{run_id}/vulns/test", dependencies=[Depends(gate)])
def api_vuln_test(run_id: str):
    """Real safe testing: run non-destructive detection probes against the
    actual target. GET/HEAD only, rate-limited, nothing modified.

    Runs in the background. Returns only the candidates that were confirmed.
    Only use against targets you are authorized to test.
    """
    from .safe_tester import run_real_tests
    from .vuln_advisor import advise
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        rows = findings_dump(session, run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        summary = {
            "targets": [{"raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
        }
        candidates = advise(rows, summary)
        base = ""
        if targets:
            base = targets[0].normalized or targets[0].raw or ""
        report = run_real_tests(base, candidates)
        report["run_id"] = run_id
        return report
    finally:
        session.close()


@app.post("/api/runs/{run_id}/vulns/dry-run", dependencies=[Depends(gate)])
def api_vuln_dry_run(run_id: str, body: DryRunIn):
    """Safe-test terminal: narrates what a detection check WOULD do.

    Sends zero requests. Pure dry-run simulation for authorized testing prep.
    """
    from .vuln_advisor import dry_run
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
    finally:
        session.close()
    base = body.base or "TARGET"
    return {"candidate_id": body.candidate_id,
            "lines": dry_run(body.candidate_id, base)}


# -- actionable findings ------------------------------------------------------
# Subdomain liveness verification + single port probing. Both are SSRF-guarded:
# they only touch hosts/ports that appeared in the run's own findings.


class SubVerifyIn(BaseModel):
    force: bool = False


@app.post("/api/runs/{run_id}/subdomains/verify", dependencies=[Depends(gate)])
async def api_subdomain_verify(run_id: str, body: SubVerifyIn):
    """Probe every subdomain from this run's findings for HTTP liveness.

    Returns {host: {live, status, url, server, title}}. Results are cached
    in the run summary for 24h. Only hosts from this run's findings are
    probed (SSRF guard). Read-only GET requests, 8s timeout each.
    """
    import asyncio
    import re
    import time as _time
    import httpx

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        rows = findings_dump(session, run_id)
        summary = dict(run.summary or {})
    finally:
        session.close()

    hosts: List[str] = []
    for r in rows:
        if r.get("key") == "subdomain":
            v = (r.get("value") or "").split()[0].strip().lower().rstrip(".")
            if v and re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$", v) and v not in hosts:
                hosts.append(v)
    hosts = hosts[:100]

    cached = summary.get("subdomain_status") or {}
    now = _time.time()

    async def check(host: str):
        c = cached.get(host)
        if c and not body.force and now - c.get("ts", 0) < 86400:
            return host, c
        result: Dict = {"live": False, "status": 0, "url": "",
                        "server": "", "title": "", "ts": now}
        for scheme in ("https", "http"):
            try:
                async with net.async_client(
                        timeout=8, follow_redirects=True,
                        headers={"User-Agent": "ReconAnything/1.0"}) as client:
                    resp = await client.get(f"{scheme}://{host}")
                title = ""
                if resp.status_code < 400:
                    m = re.search(r"<title[^>]*>(.*?)</title>",
                                  resp.text[:50000], re.I | re.S)
                    if m:
                        title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                result = {"live": resp.status_code < 400,
                          "status": resp.status_code,
                          "url": str(resp.url),
                          "server": resp.headers.get("server", "")[:60],
                          "title": title, "ts": now}
                if resp.status_code < 400:
                    break
            except Exception:
                continue
        return host, result

    sem = asyncio.Semaphore(10)

    async def guarded(h: str):
        async with sem:
            return await check(h)

    out = dict(cached)
    for host, res in await asyncio.gather(*[guarded(h) for h in hosts]):
        out[host] = res

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        s = dict(run.summary or {})
        s["subdomain_status"] = out
        run.summary = s
        session.commit()
    finally:
        session.close()
    live_count = sum(1 for v in out.values() if v.get("live"))
    return {"hosts": out, "count": len(out), "live": live_count}


@app.get("/api/runs/{run_id}/probe/port", dependencies=[Depends(gate)])
async def api_probe_port(run_id: str, host: str = Query(...), port: int = Query(...)):
    """Probe a single host:port for banner/service info.

    SSRF-guarded: host must be a run target or a subdomain from this run's
    findings, and the port must appear in this run's port findings.
    Read-only: TCP connect + short banner read, plus an HTTP GET on
    web-ish ports. Nothing is written.
    """
    import asyncio
    import re
    import httpx

    host = host.strip().lower().rstrip(".")
    if not re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$", host) or not (1 <= port <= 65535):
        raise HTTPException(400, "bad host or port")

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
        rows = findings_dump(session, run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
    finally:
        session.close()

    allowed_hosts = set()
    for t in targets:
        for cand in (t.normalized or "", t.raw or ""):
            m = re.search(r"([a-z0-9]([a-z0-9.\-]*[a-z0-9])?)", cand.lower())
            if m:
                allowed_hosts.add(m.group(1).rstrip("."))
    for r in rows:
        if r.get("key") == "subdomain":
            v = (r.get("value") or "").split()[0].strip().lower().rstrip(".")
            if v:
                allowed_hosts.add(v)
    allowed_ports = set()
    for r in rows:
        if r.get("key") in ("port_open", "port_suggestion"):
            m = re.search(r"port (\d+)", (r.get("value") or "").lower())
            if m:
                allowed_ports.add(int(m.group(1)))
    if host not in allowed_hosts:
        raise HTTPException(403, "host was not found in this run")
    if port not in allowed_ports:
        raise HTTPException(403, "port was not found in this run")

    result: Dict = {"host": host, "port": port, "open": False,
                    "banner": "", "http": None}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5)
        result["open"] = True
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=3)
            result["banner"] = data.decode("utf-8", "replace").strip()[:200]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)[:100]
        return result

    # Web-ish ports: grab server header + title
    if port in (80, 443, 8000, 8080, 8443, 3000, 5000, 9000, 9200, 5601):
        scheme = "https" if port in (443, 8443) else "http"
        try:
            async with net.async_client(
                    timeout=8, follow_redirects=True,
                    headers={"User-Agent": "ReconAnything/1.0"}) as client:
                resp = await client.get(f"{scheme}://{host}:{port}/")
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:50000], re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            result["http"] = {"status": resp.status_code,
                              "server": resp.headers.get("server", "")[:60],
                              "title": title,
                              "url": str(resp.url)}
            if not result["banner"]:
                result["banner"] = f"HTTP {resp.status_code} {result['http']['server']}".strip()
        except Exception as e:
            result["http"] = {"error": str(e)[:100]}
    return result


# -- ai hunter ---------------------------------------------------------------
# Uncensored AI as a virtual human tester. Analysis NEVER blocks the scan:
# it runs in the background after the scan finishes and the UI polls for it.

@app.post("/api/runs/{run_id}/ai-hunter", dependencies=[Depends(gate)])
def api_ai_hunter_start(run_id: str):
    """Trigger background AI analysis of a completed run.

    Returns immediately with status=analyzing. Poll GET for results.
    """
    from .ai_assistant import get_ai_status, launch_ai_analysis
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise HTTPException(404, "run not found")
    finally:
        session.close()
    state = get_ai_status(run_id)
    if state["status"] == "analyzing":
        return {"run_id": run_id, "status": "analyzing"}
    if state["status"] == "ready" and state["results"]:
        return {"run_id": run_id, "status": "ready",
                "provider": state["provider"]}
    launch_ai_analysis(run_id)
    return {"run_id": run_id, "status": "analyzing"}


@app.get("/api/runs/{run_id}/ai-hunter", dependencies=[Depends(gate)])
def api_ai_hunter_status(run_id: str):
    """Poll AI Hunter state: idle | analyzing | ready | failed."""
    from .ai_assistant import get_ai_status
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise HTTPException(404, "run not found")
    finally:
        session.close()
    state = get_ai_status(run_id)
    state["run_id"] = run_id
    return state


@app.get("/api/runs/{run_id}/ai-hunter/waf-bypass", dependencies=[Depends(gate)])
def api_ai_hunter_waf_bypass(run_id: str, payload: str = Query(..., max_length=2000)):
    """Instant WAF-bypass payload mutations for a given payload.

    Local and instant (no AI call). Detects the WAF from the run's findings.
    """
    from .ai_assistant import waf_bypass_payloads
    from .reporting import findings_dump
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise HTTPException(404, "run not found")
        rows = findings_dump(session, run_id)
    finally:
        session.close()
    waf = ""
    for r in rows:
        if r.get("plugin_id") == "waf" or r.get("key") == "waf_detected":
            waf = r.get("value") or ""
            break
    return waf_bypass_payloads(waf, payload)


@app.get("/api/diff", dependencies=[Depends(gate)])
def api_diff(a: str, b: str):
    session = get_session()
    try:
        return diff_runs(session, a, b)
    finally:
        session.close()


# -- ATM ---------------------------------------------------------------------
class AtmLocateIn(BaseModel):
    query: str
    authorized: bool = False


_ATM_AUTH_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "atm_auth.log")
_ATM_LATLON_RE = re.compile(
    r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*(?:,\s*(\d+(?:\.\d+)?))?\s*$")
_OSM_UA = "ReconAnything/1.0 (ATM security assessment module; contact: owner)"


def _atm_log_auth(run_id: str, query: str) -> None:
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        with open(_ATM_AUTH_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{ts}\trun={run_id}\tquery={query}\tauthorized=true\n")
    except Exception:
        pass


def _atm_geocode(text: str):
    """Text -> (lat, lon) via public Nominatim (no key)."""
    import httpx
    try:
        r = httpx.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": text, "format": "json", "limit": 1,
                    "email": "recon-atm@example.com"},
            headers={"User-Agent": _OSM_UA}, timeout=15)
        if r.status_code != 200:
            return None, f"geocode failed (HTTP {r.status_code})"
        items = r.json()
        if not items:
            return None, "geocode found nothing for that query"
        return (float(items[0]["lat"]), float(items[0]["lon"])), None
    except Exception as e:
        return None, f"geocode error: {e}"


def _atm_overpass(lat: float, lon: float, radius_m: float):
    """amenity=atm nodes near (lat, lon) via public Overpass API."""
    import httpx
    ql = (f'[out:json][timeout:25];'
          f'node["amenity"="atm"](around:{int(radius_m)},{lat},{lon});'
          f'out center 50;')
    try:
        r = httpx.post("https://overpass-api.de/api/interpreter",
                       data={"data": ql},
                       headers={"User-Agent": _OSM_UA}, timeout=15)
        if r.status_code != 200:
            return None, f"Overpass failed (HTTP {r.status_code})"
        out = []
        for el in (r.json().get("elements") or [])[:50]:
            tags = el.get("tags") or {}
            out.append({
                "name": tags.get("name", ""),
                "operator": tags.get("operator") or tags.get("brand") or
                            tags.get("network") or "",
                "lat": el.get("lat"),
                "lon": el.get("lon"),
            })
        return out, None
    except Exception as e:
        return None, f"Overpass error: {e}"


@app.post("/api/runs/{run_id}/atm/locate", dependencies=[Depends(gate)])
def api_atm_locate(run_id: str, body: AtmLocateIn):
    """Public ATM locations via OpenStreetMap (read-only).

    Hard gate: body.authorized must be true, else 403. The claim is
    logged server-side for the audit trail.
    """
    if not body.authorized:
        raise HTTPException(
            status_code=403,
            detail="ATM location lookup requires explicit written "
                   "authorization (authorized=true)")
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise HTTPException(404, "run not found")
    finally:
        session.close()

    _atm_log_auth(run_id, body.query)

    q = (body.query or "").strip()
    if not q:
        raise HTTPException(400, "query required")
    m = _ATM_LATLON_RE.match(q)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        radius = float(m.group(3)) if m.group(3) else 2000
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise HTTPException(400, "latitude/longitude out of range")
        radius = max(100, min(radius, 20000))
    else:
        (lat, lon), err = _atm_geocode(q)
        if err:
            raise HTTPException(502, err)
        radius = 2000

    results, err = _atm_overpass(lat, lon, radius)
    if err:
        raise HTTPException(502, err)
    return {"run_id": run_id, "lat": lat, "lon": lon,
            "radius_m": int(radius), "atms": results}


# -- api key vault ----------------------------------------------------------
class KeyIn(BaseModel):
    name: str
    label: str = ""
    secret: str


@app.get("/api/keys", dependencies=[Depends(gate)])
def api_keys():
    session = get_session()
    try:
        return {"keys": key_status(session),
                "encrypted": bool(config.MASTER_KEY)}
    finally:
        session.close()


@app.post("/api/keys", dependencies=[Depends(gate)])
def api_key_add(body: KeyIn):
    session = get_session()
    try:
        row = session.query(ApiKey).filter_by(name=body.name).first()
        if row:
            row.secret_enc = encrypt(body.secret)
            row.label = body.label or row.label
        else:
            session.add(ApiKey(name=body.name, label=body.label or body.name,
                               secret_enc=encrypt(body.secret)))
        session.commit()
        return {"ok": True}
    finally:
        session.close()


@app.delete("/api/keys/{name}", dependencies=[Depends(gate)])
def api_key_del(name: str):
    session = get_session()
    try:
        session.query(ApiKey).filter_by(name=name).delete()
        session.commit()
        return {"ok": True}
    finally:
        session.close()


# -- schedules ---------------------------------------------------------------
class SchedIn(BaseModel):
    target_raw: str
    cron: str
    mode: str = "passive"
    enabled: bool = True


@app.get("/api/schedules", dependencies=[Depends(gate)])
def api_sched_list():
    session = get_session()
    try:
        rows = session.query(Schedule).all()
        return {"schedules": [
            {"id": s.id, "target_raw": s.target_raw, "cron": s.cron,
             "mode": s.mode, "enabled": s.enabled,
             "last_run_id": s.last_run_id} for s in rows]}
    finally:
        session.close()


@app.post("/api/schedules", dependencies=[Depends(gate)])
def api_sched_add(body: SchedIn):
    session = get_session()
    try:
        sid = uuid.uuid4().hex[:12]
        session.add(Schedule(id=sid, target_raw=body.target_raw,
                             cron=body.cron, mode=body.mode,
                             enabled=body.enabled))
        session.commit()
        return {"ok": True, "id": sid}
    finally:
        session.close()


@app.delete("/api/schedules/{sid}", dependencies=[Depends(gate)])
def api_sched_del(sid: str):
    session = get_session()
    try:
        session.query(Schedule).filter_by(id=sid).delete()
        session.commit()
        return {"ok": True}
    finally:
        session.close()
