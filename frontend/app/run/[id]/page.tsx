"use client";
import { useEffect, useRef, useState } from "react";
import { getCode } from "../../../lib/api";

interface Finding {
  plugin: string; category: string; key: string; value: string;
  source: string; source_url?: string; confidence: number; passive: boolean;
}
interface PluginState { plugin: string; label?: string; status: string; reason: string; findings: number }

const CATS = ["dns", "web", "api", "mobile", "identity", "infra", "leak", "graph"];

export default function RunPage({ params }: { params: { id: string } }) {
  const id = params.id;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [plugins, setPlugins] = useState<Record<string, PluginState>>({});
  const [status, setStatus] = useState("running");
  const [tab, setTab] = useState("findings");
  const [summary, setSummary] = useState<any>(null);
  const [graph, setGraph] = useState<any>(null);
  const [apiMap, setApiMap] = useState<any>(null);
  const [cat, setCat] = useState("all");
  const [q, setQ] = useState("");
  const done = useRef(false);

  useEffect(() => {
    const es = new EventSource(`/api/runs/${id}/stream?code=${encodeURIComponent(getCode())}`);
    const on = (ev: string, fn: (e: MessageEvent) => void) => es.addEventListener(ev, fn as EventListener);
    on("plugin_start", (e) => {
      const d = JSON.parse(e.data);
      setPlugins((p) => ({ ...p, [d.plugin]: { plugin: d.plugin, status: "running", reason: "" } }));
    });
    on("plugin_done", (e) => {
      const d = JSON.parse(e.data);
      setPlugins((p) => ({ ...p, [d.plugin]: { plugin: d.plugin, status: d.status, reason: d.reason, findings: d.findings } }));
    });
    on("plugin_skip", (e) => {
      const d = JSON.parse(e.data);
      setPlugins((p) => ({ ...p, [d.plugin]: { plugin: d.plugin, status: "skipped", reason: d.reason } }));
    });
    on("finding", (e) => {
      const d = JSON.parse(e.data);
      setFindings((f) => [...f, d]);
    });
    on("run_done", async (e) => {
      const d = JSON.parse(e.data);
      setSummary(d); setStatus("done"); done.current = true; es.close();
      const h = { "X-Access-Code": getCode() };
      try {
        const g = await fetch(`/api/runs/${id}/graph`, { headers: h }).then((r) => r.json());
        setGraph(g);
        const m = await fetch(`/api/runs/${id}/apimap`, { headers: h }).then((r) => r.json());
        setApiMap(m);
      } catch {}
    });
    es.onerror = () => { if (!done.current) { /* keep trying briefly */ } };
    // also poll detail in case we opened mid-run or stream ended
    const poll = setInterval(async () => {
      try {
        const d = await fetch(`/api/runs/${id}`, { headers: { "X-Access-Code": getCode() } }).then((r) => r.json());
        if (d.run?.status === "done") {
          setStatus("done"); setFindings(d.findings || []); setSummary(d.run.summary);
          clearInterval(poll); es.close();
          const h = { "X-Access-Code": getCode() };
          const g = await fetch(`/api/runs/${id}/graph`, { headers: h }).then((r) => r.json());
          setGraph(g);
          const m = await fetch(`/api/runs/${id}/apimap`, { headers: h }).then((r) => r.json());
          setApiMap(m);
        }
      } catch {}
    }, 4000);
    return () => { es.close(); clearInterval(poll); };
  }, [id]);

  const filtered = findings.filter((f) =>
    (cat === "all" || f.category === cat) &&
    (!q || (f.key + f.value + f.plugin).toLowerCase().includes(q.toLowerCase())));

  const byCat: Record<string, Finding[]> = {};
  filtered.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });

  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }

  const pill = (s: string) =>
    s === "ok" ? "pill-ok" : s === "error" ? "pill-err" : s === "running" ? "pill-info" : "pill-warn";

  return (
    <div className="space-y-4">
      <div className="card p-4 flex items-center gap-3 flex-wrap">
        <h1 className="font-mono text-sm text-sky-300">run {id}</h1>
        <span className={`text-xs px-2 py-1 rounded ${status === "done" ? "pill-ok" : "pill-info"}`}>{status}</span>
        <span className="text-xs text-slate-500">{findings.length} findings</span>
        <div className="ml-auto flex gap-2 text-xs">
          {(["json", "csv", "md", "html"] as const).map((f) => (
            <a key={f} className="chip px-2 py-1 hover:bg-slate-800"
              href={`/api/runs/${id}/export?format=${f}`}>{f.toUpperCase()}</a>
          ))}
        </div>
      </div>

      <div className="card p-4">
        <h2 className="text-xs uppercase text-slate-500 mb-2">Plugins</h2>
        <div className="flex gap-2 flex-wrap">
          {Object.values(plugins).map((p) => (
            <span key={p.plugin} title={p.reason} className={`text-xs px-2 py-1 rounded ${pill(p.status)}`}>
              {p.plugin}: {p.status}{p.findings ? ` (${p.findings})` : ""}
            </span>
          ))}
          {Object.keys(plugins).length === 0 && <span className="text-xs text-slate-500">starting...</span>}
        </div>
      </div>

      <div className="flex gap-2 text-sm">
        {(["findings", "subdomains", "files", "graph", "apimap", "raw"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`chip px-3 py-1 ${tab === t ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}>{t}</button>
        ))}
        <div className="ml-auto flex gap-2">
          <select className="input text-xs px-2 py-1" value={cat} onChange={(e) => setCat(e.target.value)}>
            <option value="all">all categories</option>
            {CATS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <input className="input text-xs px-2 py-1 w-40" placeholder="filter..." value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>

      {tab === "findings" && Object.keys(byCat).sort().map((c) => (
        <div key={c} className="card p-4">
          <h2 className="font-semibold text-sky-300 mb-2">{c} <span className="text-slate-500 text-xs">({byCat[c].length})</span></h2>
          <table className="grid">
            <thead><tr><th>conf</th><th>key</th><th>value</th><th>plugin</th><th>mode</th><th></th></tr></thead>
            <tbody>
              {byCat[c].slice(0, 200).map((f, i) => (
                <tr key={i}>
                  <td className="w-24"><div className="confbar"><div style={{ width: `${f.confidence}%` }} /></div></td>
                  <td><code className="text-amber-300 text-xs">{f.key}</code></td>
                  <td className="break-all">{f.value.slice(0, 220)}
                    {f.source_url && <a href={f.source_url} target="_blank" className="ml-2 text-sky-400 text-xs">source</a>}
                    <span className="block text-[10px] text-slate-500">{f.source}</span>
                  </td>
                  <td className="text-xs text-slate-400">{f.plugin}</td>
                  <td><span className={`text-[10px] px-1 rounded ${f.passive ? "pill-info" : "pill-warn"}`}>{f.passive ? "passive" : "ACTIVE"}</span></td>
                  <td><button className="text-xs text-sky-400" onClick={() => copy(f.value)}>copy</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {tab === "subdomains" && <SubdomainsView findings={findings} />}
      {tab === "files" && <FilesView findings={findings} />}
      {tab === "graph" && <GraphView graph={graph} />}
      {tab === "apimap" && <ApiMapView data={apiMap} />}
      {tab === "raw" && (
        <pre className="card p-4 text-xs overflow-auto max-h-[600px]">{JSON.stringify(findings, null, 1).slice(0, 20000)}</pre>
      )}
    </div>
  );
}

function SubdomainsView({ findings }: { findings: Finding[] }) {
  const subs = findings.filter((f) => f.key === "subdomain");
  const notes = findings.filter((f) => f.key === "subdomain_enum_note");
  function copyAll() {
    navigator.clipboard.writeText(subs.map((s) => s.value).join("\n")).catch(() => {});
  }
  return (
    <div className="card p-4">
      <div className="flex items-center gap-3 mb-3">
        <h2 className="font-semibold text-sky-300">Subdomains <span className="text-slate-500 text-xs">({subs.length})</span></h2>
        {subs.length > 0 && (
          <button className="chip px-2 py-1 text-xs text-sky-400 ml-auto" onClick={copyAll}>copy all</button>
        )}
      </div>
      {notes.map((n, i) => (
        <p key={i} className="text-xs text-amber-300/80 mb-2">{n.value} <span className="text-slate-500">({n.source})</span></p>
      ))}
      {subs.length === 0 ? (
        <p className="text-sm text-slate-500">No subdomains found. Sources tried: crt.sh, hackertarget, anubis. The target may have no CT-logged subdomains, or the sources were unreachable.</p>
      ) : (
        <div className="grid md:grid-cols-2 gap-1">
          {subs.map((s, i) => (
            <div key={i} className="flex items-center gap-2 text-sm font-mono px-2 py-1 rounded hover:bg-slate-800/50">
              <span className="text-green-300">{s.value}</span>
              <span className="text-[10px] text-slate-500 ml-auto">{s.confidence}% {s.source}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FilesView({ findings }: { findings: Finding[] }) {
  const files = findings.filter((f) =>
    f.key === "artifact_exposed" || f.key === "artifact_archived" || f.key === "artifact_guarded");
  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-sky-300 mb-3">Exposed Files <span className="text-slate-500 text-xs">({files.length})</span></h2>
      {files.length === 0 ? (
        <p className="text-sm text-slate-500">No exposed files found. The artifacts plugin checks {`/.git/config, /.env, /backup.zip`} and 20+ other sensitive paths via Wayback Machine (passive) or direct probe (active).</p>
      ) : (
        <table className="grid">
          <thead><tr><th>file</th><th>status</th><th>detail</th><th>mode</th><th></th></tr></thead>
          <tbody>
            {files.map((f, i) => (
              <tr key={i}>
                <td><code className="text-amber-300 text-xs">{f.value.split(" ")[0]}</code></td>
                <td className="text-xs">
                  <span className={`px-1 rounded ${f.key === "artifact_exposed" ? "pill-err" : f.key === "artifact_guarded" ? "pill-warn" : "pill-info"}`}>
                    {f.key === "artifact_exposed" ? "EXPOSED" : f.key === "artifact_guarded" ? "GUARDED" : "ARCHIVED"}
                  </span>
                </td>
                <td className="break-all text-xs">{f.value.slice(0, 180)}
                  {f.source_url && <a href={f.source_url} target="_blank" className="ml-2 text-sky-400">open</a>}
                </td>
                <td><span className={`text-[10px] px-1 rounded ${f.passive ? "pill-info" : "pill-warn"}`}>{f.passive ? "passive" : "ACTIVE"}</span></td>
                <td><button className="text-xs text-sky-400" onClick={() => copy(f.value)}>copy</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function GraphView({ graph }: { graph: any }) {
  const [filter, setFilter] = useState("all");
  if (!graph) return <div className="card p-4 text-sm text-slate-500">graph builds when the run finishes...</div>;
  const nodes = (graph.nodes || []).filter((n: any) => filter === "all" || n.kind === filter);
  const ids = new Set(nodes.map((n: any) => n.id));
  const edges = (graph.edges || []).filter((e: any) => ids.has(e.src) && ids.has(e.dst));
  const kinds: string[] = Array.from(new Set((graph.nodes || []).map((n: any) => String(n.kind))));
  // simple radial layout
  const W = 900, H = 520, cx = W / 2, cy = H / 2, R = 200;
  const pos: Record<string, { x: number; y: number }> = {};
  nodes.forEach((n: any, i: number) => {
    const a = (2 * Math.PI * i) / Math.max(nodes.length, 1);
    const rad = n.kind === "target" ? 0 : R;
    pos[n.id] = { x: cx + rad * Math.cos(a), y: cy + rad * Math.sin(a) };
  });
  const color = (k: string) => k === "target" ? "#7dd3fc" : k === "ip" ? "#a5b4fc" : k === "subdomain" ? "#6ee7b7" : k === "endpoint" ? "#fbbf24" : k === "tech" ? "#c4b5fd" : "#f472b6";
  return (
    <div className="card p-4">
      <div className="flex gap-2 mb-2 items-center">
        <span className="text-xs text-slate-500">{nodes.length} nodes, {edges.length} edges</span>
        <select className="input text-xs px-2 py-1 ml-auto" value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">all kinds</option>
          {kinds.map((k: string) => <option key={k} value={k}>{k}</option>)}
        </select>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 560 }}>
        {edges.map((e: any, i: number) => {
          const a = pos[e.src], b = pos[e.dst];
          if (!a || !b) return null;
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#243044" strokeWidth={1}>
            <title>{e.relation} ({e.confidence}%)</title></line>;
        })}
        {nodes.map((n: any) => {
          const p = pos[n.id];
          return (
            <g key={n.id}>
              <circle cx={p.x} cy={p.y} r={n.kind === "target" ? 12 : n.interesting ? 9 : 6}
                fill={n.interesting ? "#ef4444" : color(n.kind)} opacity={0.9}>
                <title>{n.kind}: {n.label}</title>
              </circle>
              {(n.kind === "target" || n.interesting) && (
                <text x={p.x} y={p.y - 14} textAnchor="middle" fill="#e6e6e6" fontSize={10}>
                  {n.label.slice(0, 28)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <p className="text-xs text-slate-500 mt-1">red nodes are flagged interesting (admin, staging, exposed docs, leaked keys...). Hover any node or edge for detail.</p>
    </div>
  );
}

function ApiMapView({ data }: { data: any }) {
  if (!data) return <div className="card p-4 text-sm text-slate-500">API map builds when the run finishes...</div>;
  const entries = Object.entries(data.entries || {});
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-sky-300 mb-2">API map <span className="text-slate-500 text-xs">({entries.length})</span></h2>
      <table className="grid">
        <thead><tr><th>endpoint</th><th>methods</th><th>status</th><th>auth</th></tr></thead>
        <tbody>
          {entries.slice(0, 200).map(([path, v]: any, i: number) => (
            <tr key={i}>
              <td><code className="text-amber-300 text-xs break-all">{path}</code></td>
              <td className="text-xs">{(v.methods || []).join(", ")}</td>
              <td className="text-xs">{String(v.status || "")}</td>
              <td className="text-xs">{String(v.auth || v.note || "")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
