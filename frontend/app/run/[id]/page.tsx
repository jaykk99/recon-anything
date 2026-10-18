"use client";
import { useEffect, useRef, useState } from "react";
import { getCode } from "../../../lib/api";

interface Finding {
  plugin: string; category: string; key: string; value: string;
  source: string; source_url?: string; confidence: number; passive: boolean;
}
interface PluginState { plugin: string; label?: string; status: string; reason: string; findings: number }

const CATS = ["dns", "web", "api", "mobile", "identity", "infra", "leak", "graph"];

function fmtTime(s: number): string {
  if (s < 60) return `${Math.round(s)}s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s % 60);
  return `${m}m ${r}s`;
}

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
  // progress + ETA
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [estimatedS, setEstimatedS] = useState(0);
  const [startTime] = useState(Date.now());
  const [elapsed, setElapsed] = useState(0);
  // file viewer
  const [viewing, setViewing] = useState<{ url: string; body: string; loading: boolean } | null>(null);
  const done = useRef(false);

  // elapsed timer
  useEffect(() => {
    if (status === "done") return;
    const t = setInterval(() => setElapsed((Date.now() - startTime) / 1000), 1000);
    return () => clearInterval(t);
  }, [status, startTime]);

  useEffect(() => {
    const es = new EventSource(`/api/runs/${id}/stream?code=${encodeURIComponent(getCode())}`);
    const on = (ev: string, fn: (e: MessageEvent) => void) => es.addEventListener(ev, fn as EventListener);
    on("run_start", (e) => {
      const d = JSON.parse(e.data);
      if (d.estimated_s) setEstimatedS(d.estimated_s);
      if (d.plugin_count) setProgress({ done: 0, total: d.plugin_count * (d.target_count || 1) });
    });
    on("progress", (e) => {
      const d = JSON.parse(e.data);
      setProgress({ done: d.done || 0, total: d.total || 0 });
    });
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
      setSummary(d); setStatus(d.error ? "failed" : "done"); done.current = true; es.close();
      if (!d.error) {
        const h = { "X-Access-Code": getCode() };
        try {
          const g = await fetch(`/api/runs/${id}/graph`, { headers: h }).then((r) => r.json());
          setGraph(g);
          const m = await fetch(`/api/runs/${id}/apimap`, { headers: h }).then((r) => r.json());
          setApiMap(m);
        } catch {}
      }
    });
    es.onerror = () => { if (!done.current) { /* keep trying briefly */ } };
    const poll = setInterval(async () => {
      try {
        const d = await fetch(`/api/runs/${id}`, { headers: { "X-Access-Code": getCode() } }).then((r) => r.json());
        if (d.run?.status === "done" || d.run?.status === "failed") {
          setStatus(d.run.status); setFindings(d.findings || []); setSummary(d.run.summary);
          clearInterval(poll); es.close();
          if (d.run.status === "done") {
            const h = { "X-Access-Code": getCode() };
            const g = await fetch(`/api/runs/${id}/graph`, { headers: h }).then((r) => r.json());
            setGraph(g);
            const m = await fetch(`/api/runs/${id}/apimap`, { headers: h }).then((r) => r.json());
            setApiMap(m);
          }
        }
      } catch {}
    }, 4000);
    return () => { es.close(); clearInterval(poll); };
  }, [id]);

  async function viewFile(url: string) {
    setViewing({ url, body: "", loading: true });
    try {
      const r = await fetch(
        `/api/runs/${id}/fetch?url=${encodeURIComponent(url)}`,
        { headers: { "X-Access-Code": getCode() } }
      );
      const d = await r.json();
      setViewing({ url, body: d.body || "(empty)", loading: false });
    } catch (e: any) {
      setViewing({ url, body: "Failed to load: " + e.message, loading: false });
    }
  }

  const filtered = findings.filter((f) =>
    (cat === "all" || f.category === cat) &&
    (!q || (f.key + f.value + f.plugin).toLowerCase().includes(q.toLowerCase())));

  const byCat: Record<string, Finding[]> = {};
  filtered.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });

  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }

  const pill = (s: string) =>
    s === "ok" ? "pill-ok" : s === "error" ? "pill-err" : s === "running" ? "pill-info" : s === "failed" ? "pill-err" : "pill-warn";

  const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;
  const remaining = estimatedS > 0 && status === "running" ? Math.max(estimatedS - elapsed, 0) : 0;

  return (
    <div className="space-y-4 max-w-full">
      {/* header */}
      <div className="card p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="font-mono text-sm text-sky-300 break-all">run {id}</h1>
          <span className={`text-xs px-2 py-1 rounded min-h-[28px] flex items-center ${status === "done" ? "pill-ok" : status === "failed" ? "pill-err" : "pill-info"}`}>{status}</span>
          <span className="text-xs text-slate-500">{findings.length} findings</span>
        </div>
        {/* progress bar */}
        {status === "running" && (
          <div className="mt-3">
            <div className="flex justify-between text-xs text-slate-400 mb-1">
              <span>{progress.done}/{progress.total} plugins</span>
              <span>{fmtTime(elapsed)} elapsed{estimatedS > 0 && ` ~${fmtTime(remaining)} left`}</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2.5">
              <div className="bg-sky-500 h-2.5 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
            </div>
            {estimatedS > 0 && progress.total === 0 && (
              <p className="text-xs text-slate-500 mt-1">Estimated: ~{fmtTime(estimatedS)}</p>
            )}
          </div>
        )}
        {summary?.error && (
          <p className="text-red-400 text-sm mt-2">Run failed: {summary.error}</p>
        )}
        <div className="flex gap-2 text-xs mt-3 flex-wrap">
          {(["json", "csv", "md", "html"] as const).map((f) => (
            <a key={f} className="chip px-3 py-2 min-h-[44px] flex items-center hover:bg-slate-800"
              href={`/api/runs/${id}/export?format=${f}`}>{f.toUpperCase()}</a>
          ))}
        </div>
      </div>

      {/* plugins */}
      <div className="card p-4">
        <h2 className="text-xs uppercase text-slate-500 mb-2">Plugins</h2>
        <div className="flex gap-2 flex-wrap">
          {Object.values(plugins).map((p) => (
            <span key={p.plugin} title={p.reason} className={`text-xs px-2 py-1.5 rounded min-h-[32px] inline-flex items-center ${pill(p.status)}`}>
              {p.plugin}: {p.status}{p.findings ? ` (${p.findings})` : ""}
            </span>
          ))}
          {Object.keys(plugins).length === 0 && <span className="text-xs text-slate-500">starting...</span>}
        </div>
      </div>

      {/* tabs - thumb reachable, 44px targets */}
      <div className="flex gap-2 text-sm overflow-x-auto pb-1">
        {(["findings", "subdomains", "files", "graph", "apimap", "raw"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`chip px-4 py-2.5 min-h-[44px] whitespace-nowrap ${tab === t ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}>{t}</button>
        ))}
      </div>
      <div className="flex gap-2 flex-wrap">
        <select className="input text-sm px-3 py-2.5 min-h-[44px]" value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="all">all categories</option>
          {CATS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <input className="input text-sm px-3 py-2.5 min-h-[44px] flex-1 min-w-[140px]" placeholder="filter..." value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {/* findings as cards (mobile friendly) */}
      {tab === "findings" && Object.keys(byCat).sort().map((c) => (
        <div key={c} className="card p-4">
          <h2 className="font-semibold text-sky-300 mb-3">{c} <span className="text-slate-500 text-xs">({byCat[c].length})</span></h2>
          <div className="space-y-3">
            {byCat[c].slice(0, 200).map((f, i) => (
              <div key={i} className="bg-slate-800/50 rounded-lg p-3 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="text-amber-300 text-xs font-mono break-all">{f.key}</code>
                  <span className="text-[10px] text-slate-500 ml-auto">{f.confidence}%</span>
                </div>
                <p className="text-sm break-words">{f.value.slice(0, 300)}</p>
                <div className="flex items-center gap-2 text-xs flex-wrap">
                  <span className="text-slate-500">{f.plugin}</span>
                  <span className={`px-1.5 py-0.5 rounded ${f.passive ? "pill-info" : "pill-warn"}`}>{f.passive ? "passive" : "ACTIVE"}</span>
                  <span className="text-slate-600">{f.source}</span>
                  <div className="ml-auto flex gap-2">
                    {f.source_url && (
                      <a href={f.source_url} target="_blank" rel="noopener"
                        className="text-sky-400 px-2 py-1.5 min-h-[36px] inline-flex items-center">source</a>
                    )}
                    <button className="text-sky-400 px-2 py-1.5 min-h-[36px]" onClick={() => copy(f.value)}>copy</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {tab === "subdomains" && <SubdomainsView findings={findings} />}
      {tab === "files" && <FilesView findings={findings} onView={viewFile} />}
      {tab === "graph" && <GraphView graph={graph} />}
      {tab === "apimap" && <ApiMapView data={apiMap} />}
      {tab === "raw" && (
        <pre className="card p-4 text-xs overflow-auto max-h-[600px]">{JSON.stringify(findings, null, 1).slice(0, 20000)}</pre>
      )}

      {/* file viewer modal */}
      {viewing && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4"
          onClick={() => setViewing(null)}>
          <div className="bg-slate-900 rounded-t-2xl sm:rounded-2xl w-full sm:max-w-2xl max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-2 p-4 border-b border-slate-700">
              <span className="text-xs font-mono text-sky-300 break-all flex-1">{viewing.url}</span>
              <button onClick={() => setViewing(null)}
                className="px-4 py-2.5 min-h-[44px] min-w-[44px] rounded-lg bg-slate-800 text-lg">X</button>
            </div>
            <pre className="p-4 text-xs overflow-auto flex-1 whitespace-pre-wrap break-words">
              {viewing.loading ? "Loading..." : viewing.body}
            </pre>
          </div>
        </div>
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
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <h2 className="font-semibold text-sky-300">Subdomains <span className="text-slate-500 text-xs">({subs.length})</span></h2>
        {subs.length > 0 && (
          <button className="chip px-3 py-2.5 min-h-[44px] text-xs text-sky-400 ml-auto" onClick={copyAll}>copy all</button>
        )}
      </div>
      {notes.map((n, i) => (
        <p key={i} className="text-xs text-amber-300/80 mb-2 break-words">{n.value} <span className="text-slate-500">({n.source})</span></p>
      ))}
      {subs.length === 0 ? (
        <p className="text-sm text-slate-500">No subdomains found yet.</p>
      ) : (
        <div className="space-y-1">
          {subs.map((s, i) => (
            <div key={i} className="flex items-center gap-2 text-sm font-mono px-3 py-2.5 min-h-[44px] rounded-lg bg-slate-800/50">
              <span className="text-green-300 break-all">{s.value}</span>
              <span className="text-[10px] text-slate-500 ml-auto whitespace-nowrap">{s.confidence}%</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FilesView({ findings, onView }: { findings: Finding[]; onView: (url: string) => void }) {
  const files = findings.filter((f) =>
    f.key === "artifact_exposed" || f.key === "artifact_archived" || f.key === "artifact_guarded" ||
    f.key === "open_directory" || f.key === "opendir_archived");
  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-sky-300 mb-3">Files <span className="text-slate-500 text-xs">({files.length})</span></h2>
      <p className="text-xs text-slate-500 mb-3">Tap a file to view its contents.</p>
      {files.length === 0 ? (
        <p className="text-sm text-slate-500">No files found yet.</p>
      ) : (
        <div className="space-y-2">
          {files.map((f, i) => {
            const url = f.source_url || "";
            return (
              <button key={i} onClick={() => url && onView(url)}
                className="w-full text-left bg-slate-800/50 rounded-lg p-3 min-h-[56px] hover:bg-slate-800 transition-colors">
                <div className="flex items-center gap-2">
                  <code className="text-amber-300 text-xs font-mono break-all flex-1">{f.value.split(" ")[0]}</code>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap ${
                    f.key === "artifact_exposed" || f.key === "open_directory" ? "pill-err" :
                    f.key === "artifact_guarded" ? "pill-warn" : "pill-info"}`}>
                    {f.key === "artifact_exposed" ? "EXPOSED" :
                     f.key === "open_directory" ? "OPEN DIR" :
                     f.key === "artifact_guarded" ? "GUARDED" : "ARCHIVED"}
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1 break-words">{f.value.slice(0, 120)}</p>
                <span className="text-xs text-sky-400 mt-1 inline-block">tap to view</span>
              </button>
            );
          })}
        </div>
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
  const W = 900, H = 520, cx = W / 2, cy = H / 2, R = 200;
  const pos: Record<string, { x: number; y: number }> = {};
  nodes.forEach((n: any, i: number) => {
    const a = (2 * Math.PI * i) / Math.max(nodes.length, 1);
    const rad = n.kind === "target" ? 0 : R;
    pos[n.id] = { x: cx + rad * Math.cos(a), y: cy + rad * Math.sin(a) };
  });
  const color = (k: string) => k === "target" ? "#7dd3fc" : k === "ip" ? "#a5b4fc" : k === "subdomain" ? "#6ee7b7" : k === "endpoint" ? "#fbbf24" : k === "tech" ? "#c4b5fd" : "#f472b6";
  return (
    <div className="card p-4 overflow-x-auto">
      <div className="flex gap-2 mb-2 items-center flex-wrap">
        <span className="text-xs text-slate-500">{nodes.length} nodes, {edges.length} edges</span>
        <select className="input text-sm px-3 py-2.5 min-h-[44px] ml-auto" value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">all kinds</option>
          {kinds.map((k: string) => <option key={k} value={k}>{k}</option>)}
        </select>
      </div>
      <div className="min-w-[600px]">
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
      </div>
    </div>
  );
}

function ApiMapView({ data }: { data: any }) {
  if (!data) return <div className="card p-4 text-sm text-slate-500">API map builds when the run finishes...</div>;
  const entries = Object.entries(data.entries || {});
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-sky-300 mb-3">API map <span className="text-slate-500 text-xs">({entries.length})</span></h2>
      <div className="space-y-2">
        {entries.slice(0, 200).map(([path, v]: any, i: number) => (
          <div key={i} className="bg-slate-800/50 rounded-lg p-3">
            <code className="text-amber-300 text-xs font-mono break-all block">{path}</code>
            <div className="flex gap-3 text-xs text-slate-500 mt-1 flex-wrap">
              <span>{(v.methods || []).join(", ")}</span>
              <span>{String(v.status || "")}</span>
              <span>{String(v.auth || v.note || "")}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
