"""Reporting / export (Milestone 8).

Export JSON, CSV, Markdown, and a self-contained HTML report:
executive summary, asset inventory, tech stack, API map, exposed
artifacts, leaked secrets (masked by default), timeline.
"""
from __future__ import annotations

import csv
import html
import io
from typing import Dict, List

from .models import Finding, Run, RunEvent, Target

SECRET_KEYS = {"aws_access_key", "apk_aws_access_key", "private_key",
               "apk_private_key", "slack_token", "github_token",
               "stripe_sk_hint", "google_api_key", "jwt_token",
               # broadened so the masked (free-tier) view is consistent -
               # these are all full-secret keys plugins emit:
               "exposed_aws_access_key", "exposed_aws_key",
               "exposed_github_token", "exposed_stripe_key",
               "exposed_private_key", "exposed_env", "laravel_env",
               "hardcoded_password", "exposed_hardcoded_password",
               "plaintext_password", "exposed_card_number",
               "wallet_private_key", "seed_phrase", "mnemonic",
               "js_secret", "sourcemap_secret", "slack_webhook",
               "bearer_token", "api_key", "secret_key"}


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + "***"


def findings_dump(session, run_id: str, show_secrets: bool = False) -> List[Dict]:
    rows: List[Finding] = session.query(Finding).filter_by(run_id=run_id).all()
    # Impact scoring is read-time so old runs get it too (never raises).
    try:
        from .prioritizer import annotate_impact
    except Exception:
        annotate_impact = None
    # Attacker-impact text is likewise backfilled at read time so old
    # runs and findings built outside Plugin._f carry it too.
    try:
        from .impact import annotate_attacker_impact
    except Exception:
        annotate_attacker_impact = None
    out = []
    for f in rows:
        v = f.value
        if not show_secrets and f.key in SECRET_KEYS:
            v = _mask(v)
        row = {"id": f.id, "target_id": f.target_id, "plugin": f.plugin_id,
               "category": f.category, "key": f.key, "value": v,
               "source": f.source, "source_url": f.source_url,
               "evidence": f.evidence,
               "confidence": f.confidence, "passive": f.passive,
               "bounty_value": getattr(f, "bounty_value", "low"),
               "first_seen": f.first_seen.isoformat() if f.first_seen else None}
        out.append(row)
    if annotate_impact:
        try:
            annotate_impact(out)
        except Exception:
            pass
    if annotate_attacker_impact:
        try:
            annotate_attacker_impact(out)
        except Exception:
            pass
    # Verification commands: every actionable finding gets the exact
    # read-only command(s) to reproduce/confirm it. Read-time, so old
    # runs get them too. Host hint = the run's primary target.
    try:
        from .commands import annotate_commands
        _t = session.query(Target).filter_by(run_id=run_id).first()
        annotate_commands(out, host_hint=(_t.normalized if _t else None))
    except Exception:
        pass
    # Crypto-class runs (Jay's order, 2026-10-23): exposed private
    # keys, seed phrases and keystores are THE findings - they sort
    # to the top of the run, flagged critical, ahead of generic
    # findings. Stable sort: the rest keep their order. Read-time,
    # so it applies to every surface findings_dump feeds (run
    # detail, JSON/CSV/MD/HTML exports).
    try:
        run_row = session.query(Run).filter_by(id=run_id).first()
        qmeta = ((run_row.summary or {}).get("queue_meta", {})
                 if run_row else {}) or {}
        if qmeta.get("crypto_target"):
            from .cryptotarget import is_exposed_key_finding
            for row in out:
                if is_exposed_key_finding(row):
                    row["crypto_key_finding"] = True
                    row["bounty_value"] = "critical"
                    ev = row.get("evidence")
                    if isinstance(ev, dict):
                        ev["severity"] = "critical"
                        ev["crypto_key_finding"] = True
            out.sort(key=lambda r: 0 if r.get("crypto_key_finding")
                     else 1)
    except Exception:
        pass
    return out


def to_csv(rows: List[Dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["plugin", "category", "key", "value",
                                        "source", "confidence", "passive"])
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in w.fieldnames})
    return buf.getvalue()


def _attack_paths(rows: List[Dict]) -> List[Dict]:
    """Pull the synthesized attack-path findings out of a findings dump."""
    return [r for r in rows
            if r.get("key") == "attack_path" or r.get("plugin") == "correlation"]


def _exposure(run: Run) -> Dict:
    return ((run.summary or {}).get("exposure") or {}) if run else {}


def to_markdown(run: Run, targets: List[Target], rows: List[Dict]) -> str:
    by_cat: Dict[str, List[Dict]] = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r)
    exp = _exposure(run)
    paths = _attack_paths(rows)
    L = ["# ReconAnything report", "",
         f"Run: {run.id} | mode: {run.mode} | status: {run.status}",
         f"Targets: {', '.join(t.normalized for t in targets)}", ""]
    if exp:
        L += ["## Exposure score",
              f"**{exp.get('score', 0)}/100 — {str(exp.get('band','')).upper()}**  "
              f"{exp.get('headline','')}",
              f"- Attack paths: {exp.get('attack_path_count', 0)}",
              f"- Worst severity: {exp.get('worst_severity','none')}", ""]
    if paths:
        L += [f"## Attack paths ({len(paths)})",
              "_Exploitable sequences synthesized across findings — what a "
              "real attacker chains together._", ""]
        for p in sorted(paths, key=lambda r: {"critical": 0, "high": 1,
                        "medium": 2, "low": 3}.get(
                        (r.get("evidence") or {}).get("severity", "low"), 3)):
            ev = p.get("evidence") or {}
            L.append(f"### [{str(ev.get('severity','')).upper()}] "
                     f"{ev.get('path_name') or p.get('value')}")
            if ev.get("exploitability") and ev["exploitability"] != "unknown":
                L.append(f"- Exploitability: **{ev['exploitability']}**")
            if ev.get("narrative"):
                L.append(f"- {ev['narrative']}")
            if ev.get("attacker_impact"):
                L.append(f"- What an attacker can do: {ev['attacker_impact']}")
            for step in (ev.get("chain_steps") or []):
                L.append(f"  1. {step}")
            comps = ev.get("components") or []
            if comps:
                L.append(f"- Chained from {len(comps)} finding(s): " +
                         ", ".join(f"`{c.get('key')}` ({c.get('plugin')})"
                                   for c in comps[:6]))
            if ev.get("remediation"):
                L.append(f"- Fix: {ev['remediation']}")
            cmds = ev.get("commands") or []
            if cmds:
                L.append("- Verify (read-only):")
                for cm in cmds[:6]:
                    L.append(f"  - {cm.get('label','')}: `{cm.get('cmd','')}`")
            L.append("")
    L += ["## Executive summary",
          f"- {len(rows)} findings across {len(by_cat)} categories",
          f"- {sum(1 for r in rows if r['category'] == 'leak')} leak/exposure findings",
          f"- {sum(1 for r in rows if r['category'] == 'api')} API findings", ""]
    for cat in sorted(by_cat):
        L.append(f"## {cat}")
        for r in sorted(by_cat[cat], key=lambda x: -x["confidence"])[:100]:
            badge = "passive" if r["passive"] else "ACTIVE"
            L.append(f"- [{r['confidence']}] `{r['key']}` {r['value'][:160]} "
                     f"({r['plugin']}, {badge})")
            if r.get("attacker_impact"):
                L.append(f"  - What an attacker can do: {r['attacker_impact']}")
            if r.get("source"):
                src = f"  - Source: {r['source']}"
                if r.get("source_url"):
                    src += f" ({r['source_url']})"
                L.append(src)
        L.append("")
    L.append("_Generated by ReconAnything. Passive recon needs no permission; "
             "active probing should be rate-limited and polite._")
    return "\n".join(L)


_SEV_HTML = {"critical": "#ff4d4d", "high": "#ff7a45",
             "medium": "#fbbf24", "low": "#64748b"}


def _attack_paths_html(run: Run, rows: List[Dict]) -> str:
    exp = _exposure(run)
    paths = _attack_paths(rows)
    if not exp and not paths:
        return ""
    out = []
    if exp:
        band = str(exp.get("band", "low"))
        col = "#22c55e" if band == "clean" else _SEV_HTML.get(band, "#ff7a45")
        out.append(
            f'<div class="expo" style="border-color:{col}">'
            f'<div class="score" style="color:{col}">{exp.get("score",0)}'
            f'<span>/100</span></div>'
            f'<div class="expo-txt"><strong style="color:{col}">'
            f'{html.escape(band.upper())} EXPOSURE</strong><br>'
            f'{html.escape(str(exp.get("headline","")))}<br>'
            f'<small>{exp.get("attack_path_count",0)} attack paths · '
            f'worst severity {html.escape(str(exp.get("worst_severity","none")))}'
            f'</small></div></div>')
    if paths:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        out.append(f"<h2>Attack paths ({len(paths)})</h2>"
                   "<p class='sub'>Exploitable sequences synthesized across "
                   "findings — what a real attacker chains together.</p>")
        for p in sorted(paths, key=lambda r: order.get(
                (r.get("evidence") or {}).get("severity", "low"), 3)):
            ev = p.get("evidence") or {}
            sev = str(ev.get("severity", "low"))
            col = _SEV_HTML.get(sev, "#64748b")
            steps = "".join(f"<li>{html.escape(str(s))}</li>"
                            for s in (ev.get("chain_steps") or []))
            comps = ev.get("components") or []
            comp_html = "".join(
                f"<span class='chip'>{html.escape(str(c.get('key')))} "
                f"<em>{html.escape(str(c.get('plugin')))}</em></span>"
                for c in comps[:8])
            expl = ev.get("exploitability", "unknown")
            expl_badge = (f"<span class='expl'>{html.escape(str(expl))}</span>"
                          if expl and expl != "unknown" else "")
            cmds = ev.get("commands") or []
            cmd_html = ""
            if cmds:
                items = "".join(
                    f"<li><span class='clabel'>{html.escape(str(c.get('label','')))}</span>"
                    f"<code>{html.escape(str(c.get('cmd','')))}</code></li>"
                    for c in cmds[:6])
                cmd_html = (f"<div class='cmds'><div class='chd'>Verify "
                            f"(read-only)</div><ul>{items}</ul></div>")
            comp = str(ev.get("complexity") or "")
            comp_badge = (f"<span class='cplx'>{html.escape(comp)}</span>"
                          if comp else "")
            out.append(
                f'<div class="path" style="border-left-color:{col}">'
                f'<div class="path-h"><span class="sev" '
                f'style="background:{col}">{html.escape(sev.upper())}</span>'
                f'<strong>{html.escape(str(ev.get("path_name") or p.get("value")))}'
                f'</strong>{expl_badge}{comp_badge}</div>'
                f'<p>{html.escape(str(ev.get("narrative","")))}</p>'
                f'<p class="imp"><strong>Attacker impact:</strong> '
                f'{html.escape(str(ev.get("attacker_impact","")))}</p>'
                + (f'<ol>{steps}</ol>' if steps else "")
                + (f'<div class="comps">Chained from: {comp_html}</div>'
                   if comp_html else "")
                + cmd_html
                + f'<p class="fix"><strong>Fix:</strong> '
                f'{html.escape(str(ev.get("remediation","")))}</p>'
                '</div>')
    return "".join(out)


def to_html(run: Run, targets: List[Target], rows: List[Dict]) -> str:
    by_cat: Dict[str, List[Dict]] = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r)
    cards = []
    for cat in sorted(by_cat):
        items = "".join(
            f"<tr><td>{r['confidence']}</td><td><code>{html.escape(r['key'])}</code></td>"
            f"<td>{html.escape(r['value'][:220])}</td>"
            f"<td>{html.escape(r['plugin'])}</td>"
            f"<td>{html.escape(r.get('attacker_impact') or '')}</td>"
            f"<td>{'passive' if r['passive'] else 'ACTIVE'}</td></tr>"
            for r in sorted(by_cat[cat], key=lambda x: -x["confidence"])[:150])
        cards.append(f"<h2>{html.escape(cat)} ({len(by_cat[cat])})</h2>"
                     f"<table><tr><th>conf</th><th>key</th><th>value</th>"
                     f"<th>plugin</th><th>what an attacker can do</th>"
                     f"<th>mode</th></tr>{items}</table>")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>ReconAnything report {html.escape(run.id)}</title>
<style>body{{background:#0b0e14;color:#e6e6e6;font-family:system-ui,sans-serif;
max-width:1100px;margin:2rem auto;padding:0 1rem}}
h1,h2{{color:#7dd3fc}}table{{border-collapse:collapse;width:100%;margin-bottom:2rem}}
td,th{{border:1px solid #243044;padding:.4rem .6rem;text-align:left;font-size:.85rem}}
code{{color:#fbbf24}}
.sub{{color:#94a3b8;font-size:.85rem;margin-top:-.4rem}}
.expo{{display:flex;gap:1rem;align-items:center;border:2px solid #333;
border-radius:14px;padding:1rem 1.25rem;margin:1rem 0 2rem;background:#0f1420}}
.expo .score{{font-size:2.6rem;font-weight:800;line-height:1}}
.expo .score span{{font-size:1rem;color:#64748b;font-weight:500}}
.expo-txt{{font-size:.9rem;color:#cbd5e1}}
.path{{border:1px solid #243044;border-left:4px solid #666;border-radius:10px;
padding:.8rem 1rem;margin:.8rem 0;background:#0f1420}}
.path-h{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin-bottom:.4rem}}
.path-h strong{{font-size:1rem}}
.sev{{color:#0b0e14;font-weight:800;font-size:.7rem;padding:.15rem .5rem;
border-radius:6px;letter-spacing:.03em}}
.expl{{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;
color:#fca5a5;border:1px solid #7f1d1d;border-radius:6px;padding:.1rem .45rem}}
.path p{{font-size:.86rem;margin:.35rem 0;color:#d6dde8}}
.path .imp{{color:#fcd9b6}}.path .fix{{color:#a7f3d0}}
.path ol{{font-size:.82rem;color:#b6c2d2;margin:.4rem 0 .4rem 1.1rem}}
.comps{{margin:.4rem 0;font-size:.78rem;color:#94a3b8}}
.chip{{display:inline-block;background:#1e293b;border:1px solid #334155;
border-radius:6px;padding:.08rem .45rem;margin:.12rem;font-size:.72rem}}
.chip em{{color:#7dd3fc;font-style:normal}}
.cplx{{font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;
color:#a5b4fc;border:1px solid #3730a3;border-radius:6px;padding:.1rem .45rem}}
.cmds{{margin:.5rem 0;background:#0a0f1a;border:1px solid #1e293b;
border-radius:8px;padding:.5rem .7rem}}
.cmds .chd{{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;
color:#7dd3fc;margin-bottom:.35rem}}
.cmds ul{{list-style:none;margin:0;padding:0}}
.cmds li{{margin:.3rem 0}}
.cmds .clabel{{display:block;font-size:.72rem;color:#94a3b8;margin-bottom:.1rem}}
.cmds code{{display:block;background:#11161f;border:1px solid #243044;
border-radius:5px;padding:.35rem .5rem;font-size:.76rem;color:#86efac;
overflow-x:auto;white-space:pre}}</style></head><body>
<h1>ReconAnything report</h1>
<p>Run {html.escape(run.id)} | mode {html.escape(run.mode)} |
targets: {html.escape(", ".join(t.normalized for t in targets))}</p>
{_attack_paths_html(run, rows)}
{''.join(cards)}
<p><em>Generated by ReconAnything.</em></p></body></html>"""


def run_progress(session, run_id: str) -> Dict:
    """Live progress for a run.

    Preferred source: the plugin_jobs queue table (exact done/total,
    works across processes and restarts). Falls back to the durable
    event log for pre-queue runs.

    The UI's 4s poll fallback uses this when SSE is unavailable.
    Read-only, no migration needed.
    """
    # Queue-backed progress: exact counts straight from Postgres.
    try:
        from .models import PluginJob
        total = session.query(PluginJob).filter_by(run_id=run_id).count()
        if total:
            try:
                from . import config as _config
                _concurrency = max(getattr(_config, "MAX_CONCURRENCY", 5), 1)
            except Exception:
                _concurrency = 5
            done = (session.query(PluginJob)
                    .filter(PluginJob.run_id == run_id,
                            PluginJob.status.in_(("done", "skipped",
                                                  "failed"))).count())
            running = [r.plugin_id for r in
                       session.query(PluginJob)
                       .filter_by(run_id=run_id, status="running").all()]
            ms_vals = [r.result.get("ms", 0) for r in
                       session.query(PluginJob)
                       .filter(PluginJob.run_id == run_id,
                               PluginJob.status.in_(("done", "failed")))
                       .all()
                       if isinstance(r.result, dict)
                       and (r.result.get("ms") or 0) > 0]
            eta_s = None
            if done < total and ms_vals:
                avg = sum(ms_vals) / len(ms_vals) / 1000.0
                eta_s = round(max(total - done, 0) * avg / _concurrency, 1)
            return {"done": done, "total": total, "eta_s": eta_s,
                    "estimated_s": None, "running": sorted(set(running))[:10]}
    except Exception:
        pass
    # Fallback: event-log progress for pre-queue runs.
    try:
        from . import config as _config
        _concurrency = max(getattr(_config, "MAX_CONCURRENCY", 5), 1)
    except Exception:
        _concurrency = 5
    total = 0
    done = 0
    estimated_s: float | None = None
    durations: List[float] = []
    started: Dict[str, bool] = {}
    finished = set()
    try:
        rows = (session.query(RunEvent).filter_by(run_id=run_id)
                .order_by(RunEvent.seq).all())
    except Exception:
        return {"done": 0, "total": 0, "eta_s": None,
                "estimated_s": None, "running": []}
    for r in rows:
        d = r.data or {}
        if r.event == "run_start":
            total = (d.get("plugin_count") or 0) * max(d.get("target_count") or 1, 1)
            est = d.get("estimated_s")
            if isinstance(est, (int, float)) and est > 0:
                # Last run_start wins (geo/bank runs emit a placeholder
                # first, then the real counts).
                estimated_s = float(est)
        elif r.event == "plugin_start":
            if d.get("plugin"):
                started[d["plugin"]] = True
        elif r.event == "plugin_done":
            if d.get("plugin"):
                finished.add(d["plugin"])
            done += 1
            ms = d.get("ms") or 0
            if ms > 0:
                durations.append(ms / 1000.0)
        elif r.event == "progress":
            if isinstance(d.get("done"), int):
                done = max(done, d["done"])
            if isinstance(d.get("total"), int) and d["total"] > 0:
                total = d["total"]
    running = sorted(p for p in started if p not in finished)[:10]
    eta_s = None
    if total > 0 and done < total:
        if durations:
            # Observed speed wins: extrapolate from real plugin durations.
            avg = sum(durations) / len(durations)
            eta_s = round(max(total - done, 0) * avg / _concurrency, 1)
        elif estimated_s:
            # No plugin has finished yet: burn the pre-run estimate down
            # linearly so the UI shows "~Z left" from the first poll.
            eta_s = round(estimated_s * max(total - done, 0) / total, 1)
    return {"done": done, "total": total, "eta_s": eta_s,
            "estimated_s": estimated_s, "running": running}


def executive_summary(rows: List[Dict]) -> Dict:
    techs = sorted({r["value"] for r in rows if r["key"] == "tech"})
    leaks = [r for r in rows if r["category"] == "leak"]
    interesting = [r for r in rows if r["key"] in (
        "artifact_exposed", "graphql_introspection", "cors_misconfig",
        "jwt_weak", "spf_weak", "dmarc_weak")]
    return {
        "total_findings": len(rows),
        "tech_stack": techs[:20],
        "leak_count": len(leaks),
        "interesting_count": len(interesting),
        "interesting": [{"key": r["key"], "value": r["value"][:160],
                         "plugin": r["plugin"]} for r in interesting[:20]],
    }
