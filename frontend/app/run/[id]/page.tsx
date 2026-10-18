"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { getCode } from "../../../lib/api";

interface Finding {
  plugin: string; category: string; key: string; value: string;
  source: string; source_url?: string; confidence: number; passive: boolean;
  evidence?: Record<string, any>;
}
interface PluginState { plugin: string; label?: string; status: string; reason: string; findings: number }

const CATS = ["dns", "web", "api", "mobile", "identity", "infra", "leak", "graph"];

function sevOf(f: Finding): string {
  return (f.evidence?.severity || "").toLowerCase();
}
function sevColor(s: string): string {
  if (s === "critical") return "text-red-400 border-red-500/40 bg-red-500/10";
  if (s === "high") return "text-orange-400 border-orange-500/40 bg-orange-500/10";
  if (s === "medium") return "text-yellow-300 border-yellow-500/30 bg-yellow-500/10";
  return "text-slate-400 border-slate-700 bg-slate-800/50";
}
function findingMarkdown(f: Finding): string {
  const sev = sevOf(f);
  let md = `## ${f.key}\n\n`;
  md += `- **Severity:** ${sev || "info"}\n`;
  md += `- **Plugin:** ${f.plugin}\n`;
  md += `- **Category:** ${f.category}\n`;
  md += `- **Confidence:** ${f.confidence}%\n`;
  md += `- **Source:** ${f.source}\n`;
  if (f.source_url) md += `- **URL:** ${f.source_url}\n`;
  md += `\n${f.value}\n`;
  if (f.evidence?.remediation) md += `\n**Remediation:** ${f.evidence.remediation}\n`;
  return md;
}
// very small syntax highlighter: comments green, strings amber, keywords sky
function highlight(code: string, lang: string): ReactNode[] {
  if (!/js|json|php|py|html|css|sql|sh|env|config|txt|xml|yaml/i.test(lang)) {
    return [code];
  }
  const parts: ReactNode[] = [];
  const re = /(\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\b(?:function|return|const|let|var|if|else|for|while|import|from|export|class|def|select|insert|update|delete|where)\b)/g;
  let last = 0, i = 0;
  for (const m of code.matchAll(re)) {
    const idx = m.index ?? 0;
    if (idx > last) parts.push(code.slice(last, idx));
    const tok = m[0];
    let cls = "text-slate-200";
    if (/^(\/\*|\/\/|#)/.test(tok)) cls = "text-green-500";
    else if (/^["'`]/.test(tok)) cls = "text-amber-300";
    else cls = "text-sky-300";
    parts.push(<span key={i++} className={cls}>{tok}</span>);
    last = idx + tok.length;
    if (parts.length > 4000) break;
  }
  if (last < code.length) parts.push(code.slice(last, last + 200000));
  return parts;
}
function hexView(text: string): string {
  const bytes = new TextEncoder().encode(text.slice(0, 4096));
  let out = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk).map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    out += `${i.toString(16).padStart(8, "0")}  ${hex.padEnd(48, " ")}  ${ascii}\n`;
  }
  return out;
}

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
  const [sortBy, setSortBy] = useState("severity");
  // progress + ETA
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [estimatedS, setEstimatedS] = useState(0);
  const [startTime] = useState(Date.now());
  const [elapsed, setElapsed] = useState(0);
  // file viewer
  const [viewing, setViewing] = useState<{
    url: string; body: string; loading: boolean;
    status?: number; contentType?: string; size?: number;
    lastModified?: string; headers?: Record<string, string>;
    truncated?: boolean; hex?: boolean;
  } | null>(null);
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
      setViewing({
        url, body: d.body || "(empty)", loading: false,
        status: d.status, contentType: d.content_type, size: d.size,
        lastModified: d.last_modified, headers: d.headers,
        truncated: d.truncated, hex: false,
      });
    } catch (e: any) {
      setViewing({ url, body: "Failed to load: " + e.message, loading: false });
    }
  }
  function downloadViewing() {
    if (!viewing?.body) return;
    const blob = new Blob([viewing.body], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = (viewing.url.split("/").pop() || "file").split("?")[0] || "file";
    a.click();
    URL.revokeObjectURL(a.href);
  }
  function fileLang(url: string, ct?: string): string {
    const u = url.toLowerCase().split("?")[0];
    if (/\.(js|mjs|cjs)$/.test(u)) return "js";
    if (/\.json$/.test(u)) return "json";
    if (/\.php$/.test(u)) return "php";
    if (/\.py$/.test(u)) return "py";
    if (/\.(html?|xml)$/.test(u)) return "html";
    if (/\.css$/.test(u)) return "css";
    if (/\.sql$/.test(u)) return "sql";
    if (/\.(sh|bash)$/.test(u)) return "sh";
    if (/\.(yml|yaml)$/.test(u)) return "yaml";
    if (/\.env/.test(u)) return "env";
    if (ct?.includes("json")) return "json";
    if (ct?.includes("html")) return "html";
    return "txt";
  }

  const filtered = findings.filter((f) =>
    (cat === "all" || f.category === cat) &&
    (!q || (f.key + f.value + f.plugin + (f.evidence?.severity || "")).toLowerCase().includes(q.toLowerCase())));

  const byCat: Record<string, Finding[]> = {};
  filtered.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });

  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }
  function copyMd(f: Finding) { copy(findingMarkdown(f)); }

  // pagination per category: 25 at a time, "show more" for the rest
  const [shownCount, setShownCount] = useState<Record<string, number>>({});
  const PAGE = 25;
  // expanded finding cards: key = category + index
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  function sortFindings(list: Finding[]): Finding[] {
    const rank = (f: Finding) => {
      const s = sevOf(f);
      return s === "critical" ? 0 : s === "high" ? 1 : s === "medium" ? 2 : 3;
    };
    return [...list].sort((a, b) => rank(a) - rank(b) || b.confidence - a.confidence);
  }

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
        {(["findings", "vulns", "connections", "secrets", "creds", "subdomains", "files", "graph", "apimap", "raw"] as const).map((t) => (
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
        <select className="input text-sm px-3 py-2.5 min-h-[44px]" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="severity">sort: severity</option>
                  </select>
      </div>

      {/* findings as expandable cards (mobile friendly, nothing truncated) */}
      {tab === "findings" && Object.keys(byCat).sort().map((c) => {
        const sorted = sortFindings(byCat[c]);
        const shown = shownCount[c] || PAGE;
        const sevCounts: Record<string, number> = {};
        sorted.forEach((f) => { const s = sevOf(f) || "info"; sevCounts[s] = (sevCounts[s] || 0) + 1; });
        return (
        <div key={c} className="card p-4">
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <h2 className="font-semibold text-sky-300">{c} <span className="text-slate-500 text-xs">({sorted.length})</span></h2>
            {Object.entries(sevCounts).map(([s, n]) => (
              <span key={s} className={`text-[10px] px-1.5 py-0.5 rounded border ${sevColor(s)}`}>{s}: {n}</span>
            ))}
          </div>
          <div className="space-y-3">
            {sorted.slice(0, shown).map((f, i) => {
              const ek = `${c}:${i}`;
              const isOpen = !!expanded[ek];
              const sev = sevOf(f);
              const ev = f.evidence || {};
              return (
              <div key={i} className={`rounded-lg p-3 space-y-1.5 border ${sev ? sevColor(sev) : "border-slate-700/50 bg-slate-800/50"}`}>
                <button
                  className="w-full text-left min-h-[44px]"
                  onClick={() => setExpanded((e) => ({ ...e, [ek]: !e[ek] }))}>
                  <div className="flex items-center gap-2 flex-wrap">
                    {sev && <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevColor(sev)}`}>{sev.toUpperCase()}</span>}
                    <code className="text-amber-300 text-xs font-mono break-all">{f.key}</code>
                    <span className="text-[10px] text-slate-500 ml-auto whitespace-nowrap">{f.confidence}%</span>
                    <span className="text-slate-500 text-xs">{isOpen ? "▲" : "▼"}</span>
                  </div>
                  <p className="text-sm break-words whitespace-pre-wrap mt-1">{f.value}</p>
                </button>
                {isOpen && (
                  <div className="pt-2 border-t border-slate-700/50 space-y-2 text-xs">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-slate-500">{f.plugin}</span>
                      <span className={`px-1.5 py-0.5 rounded ${f.passive ? "pill-info" : "pill-warn"}`}>{f.passive ? "passive" : "ACTIVE"}</span>
                      <span className="text-slate-600 break-all">{f.source}</span>
                    </div>
                    {ev.remediation && (
                      <p className="text-green-300/90 break-words"><span className="font-semibold">Fix: </span>{ev.remediation}</p>
                    )}
                    {ev.pattern && <p className="text-slate-400 break-words"><span className="font-semibold">Pattern: </span>{ev.pattern}</p>}
                    {ev.match && (
                      <p className="text-slate-400 break-all"><span className="font-semibold">Match: </span>
                        <code className="font-mono text-red-300/90">{ev.match}</code></p>
                    )}
                    {ev.why && <p className="text-slate-400 break-words"><span className="font-semibold">Why it matters: </span>{ev.why}</p>}
                    {ev.note && <p className="text-slate-500 break-words">{ev.note}</p>}
                    {ev.scope_note && <p className="text-slate-500 italic break-words">{ev.scope_note}</p>}
                    {ev.explorer && (
                      <a href={ev.explorer} target="_blank" rel="noopener" className="text-sky-400 inline-block px-2 py-1.5 min-h-[36px]">open in explorer</a>
                    )}
                    <div className="flex gap-2 flex-wrap pt-1">
                      {f.source_url && (
                        <a href={f.source_url} target="_blank" rel="noopener"
                          className="text-sky-400 px-3 py-2 min-h-[44px] inline-flex items-center rounded-lg bg-slate-800">open source</a>
                      )}
                      <button className="text-sky-400 px-3 py-2 min-h-[44px] rounded-lg bg-slate-800" onClick={() => copy(f.value)}>copy value</button>
                      <button className="text-sky-400 px-3 py-2 min-h-[44px] rounded-lg bg-slate-800" onClick={() => copyMd(f)}>copy as markdown</button>
                    </div>
                  </div>
                )}
              </div>
              );
            })}
          </div>
          {sorted.length > shown && (
            <button
              className="mt-3 w-full chip px-4 py-3 min-h-[48px] text-sm text-sky-300"
              onClick={() => setShownCount((s) => ({ ...s, [c]: (s[c] || PAGE) + PAGE }))}>
              show more ({sorted.length - shown} remaining)
            </button>
          )}
        </div>
        );
      })}

      {tab === "vulns" && <VulnsView runId={id} />}
      {tab === "connections" && <ConnectionsView findings={findings} graph={graph} />}
      {tab === "subdomains" && <SubdomainsView findings={findings} />}
      {tab === "files" && <FilesView findings={findings} onView={viewFile} />}
      {tab === "secrets" && <SecretsView findings={findings} onView={viewFile} />}
      {tab === "creds" && <CredsView findings={findings} />}
      {tab === "graph" && <GraphView graph={graph} />}
      {tab === "apimap" && <ApiMapView data={apiMap} />}
      {tab === "raw" && (
        <div className="card p-4">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className="text-xs text-slate-500">{findings.length} findings, full JSON, scrollable</span>
            <button className="chip px-3 py-2 min-h-[44px] text-xs text-sky-400 ml-auto"
              onClick={() => copy(JSON.stringify(findings, null, 1))}>copy all</button>
          </div>
          <pre className="text-xs overflow-auto max-h-[70vh] whitespace-pre-wrap break-words">{JSON.stringify(findings, null, 1)}</pre>
        </div>
      )}

      {/* file viewer modal: metadata, headers, highlighting, hex, download */}
      {viewing && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4"
          onClick={() => setViewing(null)}>
          <div className="bg-slate-900 rounded-t-2xl sm:rounded-2xl w-full sm:max-w-3xl max-h-[90vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}>
            <div className="p-4 border-b border-slate-700 space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-sky-300 break-all flex-1">{viewing.url}</span>
                <button onClick={() => setViewing(null)}
                  className="px-4 py-2.5 min-h-[44px] min-w-[44px] rounded-lg bg-slate-800 text-lg">X</button>
              </div>
              {!viewing.loading && (
                <div className="flex gap-3 text-xs text-slate-400 flex-wrap">
                  {viewing.status != null && <span>HTTP {viewing.status}</span>}
                  {viewing.size != null && <span>{viewing.size.toLocaleString()} bytes</span>}
                  {viewing.contentType && <span className="break-all">{viewing.contentType}</span>}
                  {viewing.lastModified && <span>modified: {viewing.lastModified}</span>}
                  {viewing.truncated && <span className="text-amber-300">truncated at 200KB</span>}
                </div>
              )}
              {!viewing.loading && (
                <div className="flex gap-2 flex-wrap">
                  <button
                    className={`chip px-3 py-2 min-h-[44px] text-xs ${!viewing.hex ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}
                    onClick={() => setViewing((v) => v && { ...v, hex: false })}>text</button>
                  <button
                    className={`chip px-3 py-2 min-h-[44px] text-xs ${viewing.hex ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}
                    onClick={() => setViewing((v) => v && { ...v, hex: true })}>hex</button>
                  <button className="chip px-3 py-2 min-h-[44px] text-xs text-sky-400"
                    onClick={downloadViewing}>download</button>
                  <button className="chip px-3 py-2 min-h-[44px] text-xs text-sky-400"
                    onClick={() => copy(viewing.body)}>copy</button>
                </div>
              )}
            </div>
            <div className="overflow-auto flex-1 p-4">
              {viewing.loading ? (
                <p className="text-sm text-slate-500">Loading...</p>
              ) : viewing.hex ? (
                <pre className="text-xs font-mono whitespace-pre">{hexView(viewing.body)}</pre>
              ) : (
                <pre className="text-xs overflow-auto whitespace-pre-wrap break-words font-mono">
                  {highlight(viewing.body, fileLang(viewing.url, viewing.contentType))}
                </pre>
              )}
              {viewing.headers && Object.keys(viewing.headers).length > 0 && (
                <details className="mt-4">
                  <summary className="text-xs text-sky-400 cursor-pointer px-2 py-2.5 min-h-[44px]">
                    HTTP headers ({Object.keys(viewing.headers).length})
                  </summary>
                  <pre className="text-xs font-mono break-words whitespace-pre-wrap mt-1 text-slate-400">
                    {Object.entries(viewing.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
                  </pre>
                </details>
              )}
            </div>
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
                <p className="text-xs text-slate-500 mt-1 break-words whitespace-pre-wrap">{f.value}</p>
                <span className="text-xs text-sky-400 mt-1 inline-block">tap to view</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface VulnCandidate {
  id: string; name: string; severity: string; confidence: number;
  why_viable: string; poc_code: string; poc_lang: string;
  dry_run_steps: string[]; remediation: string; evidence_count: number;
}

interface SimResult {
  id: string; name: string; severity: string; confidence: number;
  works: boolean; detail: string;
  poc_code: string; poc_lang: string; why_viable: string; remediation: string;
}
interface SimReport {
  target: string; total_tested: number; working_count: number;
  working: SimResult[]; results: SimResult[];
  disclaimer: string;
}

function VulnsView({ runId }: { runId: string }) {
  const [cands, setCands] = useState<VulnCandidate[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [term, setTerm] = useState<{ cand: VulnCandidate; lines: string[]; busy: boolean } | null>(null);
  // simulation state
  const [sim, setSim] = useState<SimReport | null>(null);
  const [simBusy, setSimBusy] = useState(false);
  const [simExpanded, setSimExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`/api/runs/${runId}/vulns`, { headers: { "X-Access-Code": getCode() } });
        const d = await r.json();
        setCands(d.candidates || []);
      } catch {
        setCands([]);
      } finally {
        setLoading(false);
      }
    })();
  }, [runId]);

  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }

  async function runSimulation() {
    setSimBusy(true);
    setSim(null);
    try {
      const r = await fetch(`/api/runs/${runId}/vulns/test`, {
        method: "POST",
        headers: { "X-Access-Code": getCode(), "Content-Type": "application/json" },
      });
      const d = await r.json();
      setSim(d);
    } catch (e: any) {
      setSim({ target: "", total_tested: 0, working_count: 0, working: [], results: [], disclaimer: "Test failed: " + e.message });
    } finally {
      setSimBusy(false);
    }
  }

  async function openTerminal(cand: VulnCandidate) {
    setTerm({ cand, lines: ["$ initializing safe-test terminal...", "[*] DRY RUN MODE - no requests will be sent"], busy: true });
    try {
      const r = await fetch(`/api/runs/${runId}/vulns/dry-run`, {
        method: "POST",
        headers: { "X-Access-Code": getCode(), "Content-Type": "application/json" },
        body: JSON.stringify({ candidate_id: cand.id }),
      });
      const d = await r.json();
      setTerm({ cand, lines: d.lines || ["(no output)"], busy: false });
    } catch (e: any) {
      setTerm({ cand, lines: ["error: " + e.message], busy: false });
    }
  }

  if (loading) return <div className="card p-4 text-sm text-slate-500">Analyzing findings for viable vulnerabilities...</div>;
  return (
    <div className="space-y-3">
      <div className="card p-4">
        <h2 className="font-semibold text-sky-300">Possible vulnerabilities</h2>
        <p className="text-xs text-slate-500 mt-1">
          <span className="text-amber-300 font-semibold">HYPOTHESES, not confirmed findings.</span>{" "}
          Ranked by viability from YOUR scan results. These are educated guesses about what
          MIGHT be vulnerable. Use the test button below to verify with real (safe) probes.
          Only test targets you are authorized to test.
        </p>
        {/* background testing: real safe probes, only successes shown */}
        <button
          onClick={runSimulation}
          disabled={simBusy}
          className="mt-3 w-full chip px-4 py-3 min-h-[48px] text-sm text-emerald-300 bg-emerald-950/50 border border-emerald-800/50 disabled:opacity-50">
          {simBusy ? "Testing in background..." : "Test for real (safe, non-destructive)"}
        </button>
        <p className="text-[11px] text-slate-600 mt-1">
          Sends real detection probes to the target. GET/HEAD only, rate-limited, nothing modified.
          Only successful detections are shown. Only test targets you are authorized to test.
        </p>
      </div>

      {/* what-works panel: only confirmed real detections */}
      {sim && (
        <div className="card p-4 border border-emerald-800/40">
          <h2 className="font-semibold text-emerald-300">
            Confirmed by live test <span className="text-slate-500 text-xs">({sim.working_count}/{sim.total_tested} tested against {sim.target})</span>
          </h2>
          <p className="text-[11px] text-slate-500 mt-1">
            <span className="text-emerald-300 font-semibold">VERIFIED REAL.</span>{" "}
            These vulnerabilities were confirmed by actual (safe, non-destructive) probes sent to the target. {sim.disclaimer}
          </p>
          {sim.working.length === 0 ? (
            <p className="text-sm text-slate-500 mt-2">
              No vulnerabilities confirmed by live testing. The scan findings did not hold up
              under real probes. Try a deeper scan or a different target.
            </p>
          ) : (
            <div className="space-y-3 mt-3">
              {sim.working.map((w) => {
                const isOpen = !!simExpanded[w.id];
                return (
                  <div key={w.id} className="rounded-lg p-3 border border-emerald-800/40 bg-emerald-950/20">
                    <button className="w-full text-left min-h-[44px]"
                      onClick={() => setSimExpanded((e) => ({ ...e, [w.id]: !e[w.id] }))}>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-emerald-400 text-sm">WORKS</span>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevColor(w.severity)}`}>{w.severity.toUpperCase()}</span>
                        <span className="font-semibold text-sm">{w.name}</span>
                        <span className="text-slate-500 text-xs">{isOpen ? "▲" : "▼"}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 break-words">{w.detail}</p>
                    </button>
                    {isOpen && (
                      <div className="pt-2 mt-2 border-t border-emerald-900/40 space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-500">Working PoC ({w.poc_lang})</span>
                          <button className="chip px-2 py-1.5 min-h-[36px] text-xs text-sky-400 ml-auto"
                            onClick={() => copy(w.poc_code)}>copy code</button>
                        </div>
                        <pre className="text-xs font-mono bg-slate-950 rounded-lg p-3 overflow-auto whitespace-pre-wrap break-words max-h-[300px]">
                          {highlight(w.poc_code, w.poc_lang)}
                        </pre>
                        <p className="text-xs text-green-300/90 break-words"><span className="font-semibold">Fix: </span>{w.remediation}</p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
      {(cands || []).length === 0 && (
        <div className="card p-4 text-sm text-slate-500">
          No strong vulnerability paths found from this scan. Run more plugins or try a different target.
        </div>
      )}
      {(cands || []).map((c, i) => {
        const isOpen = !!expanded[c.id];
        return (
          <div key={c.id} className={`card p-4 border-l-2 ${sevColor(c.severity).split(" ")[1] || "border-slate-700"}`}>
            <button className="w-full text-left min-h-[44px]" onClick={() => setExpanded((e) => ({ ...e, [c.id]: !e[c.id] }))}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold text-slate-400">#{i + 1}</span>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevColor(c.severity)}`}>{c.severity.toUpperCase()}</span>
                <span className="font-semibold text-sm">{c.name}</span>
                <span className="text-[10px] text-slate-500 ml-auto">{c.confidence}% viable</span>
                <span className="text-slate-500 text-xs">{isOpen ? "▲" : "▼"}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1 break-words">{c.why_viable}</p>
            </button>
            {isOpen && (
              <div className="pt-3 mt-2 border-t border-slate-700/50 space-y-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs text-slate-500">Detection PoC ({c.poc_lang})</span>
                    <button className="chip px-2 py-1.5 min-h-[36px] text-xs text-sky-400 ml-auto"
                      onClick={() => copy(c.poc_code)}>copy code</button>
                  </div>
                  <pre className="text-xs font-mono bg-slate-950 rounded-lg p-3 overflow-auto whitespace-pre-wrap break-words max-h-[300px]">
                    {highlight(c.poc_code, c.poc_lang)}
                  </pre>
                </div>
                <div>
                  <span className="text-xs text-slate-500">Safe test plan</span>
                  <ol className="text-xs text-slate-400 mt-1 space-y-1 list-decimal list-inside">
                    {c.dry_run_steps.map((s, j) => <li key={j} className="break-words">{s}</li>)}
                  </ol>
                </div>
                <p className="text-xs text-green-300/90 break-words"><span className="font-semibold">Fix: </span>{c.remediation}</p>
                <button
                  className="w-full chip px-4 py-3 min-h-[48px] text-sm text-emerald-300 bg-emerald-950/50 border border-emerald-800/50"
                  onClick={() => openTerminal(c)}>
                  Test safely (dry-run terminal)
                </button>
              </div>
            )}
          </div>
        );
      })}

      {/* safe test terminal modal */}
      {term && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4"
          onClick={() => setTerm(null)}>
          <div className="bg-slate-950 rounded-t-2xl sm:rounded-2xl w-full sm:max-w-2xl max-h-[90vh] flex flex-col border border-slate-700"
            onClick={(e) => e.stopPropagation()}>
            <div className="p-4 border-b border-slate-800 flex items-center gap-2">
              <span className="text-sm font-mono text-emerald-300">safe-test: {term.cand.name}</span>
              <button onClick={() => setTerm(null)}
                className="px-4 py-2.5 min-h-[44px] min-w-[44px] rounded-lg bg-slate-800 text-lg ml-auto">X</button>
            </div>
            <div className="p-4 bg-amber-950/30 border-b border-amber-900/40">
              <p className="text-xs text-amber-300">
                DRY RUN ONLY. Zero requests are sent. This narrates what a safe,
                non-destructive detection check would do. Only test targets you are authorized to test.
              </p>
            </div>
            <div className="overflow-auto flex-1 p-4 font-mono text-xs space-y-1">
              {term.lines.map((l, i) => (
                <p key={i} className={
                  l.startsWith("$") ? "text-sky-300" :
                  l.startsWith("[ok]") ? "text-emerald-400" :
                  l.startsWith("[!]") ? "text-amber-300" :
                  l.startsWith("[*]") ? "text-slate-400" : "text-slate-300"
                }>{l}</p>
              ))}
              {term.busy && <p className="text-slate-500 animate-pulse">_</p>}
            </div>
            <div className="p-4 border-t border-slate-800">
              <p className="text-[11px] text-slate-500">
                Copy the PoC above into your own authorized test environment to run it for real.
                This terminal never touches the target.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SecretsView({ findings, onView }: { findings: Finding[]; onView: (url: string) => void }) {
  const [typeFilter, setTypeFilter] = useState("all");
  const secrets = findings.filter((f) =>
    f.key.startsWith("exposed_") || f.key.startsWith("wallet_"));
  const types = Array.from(new Set(secrets.map((s) =>
    s.key.replace("exposed_", "").replace("wallet_", "").split("_")[0])));
  const shown = typeFilter === "all" ? secrets :
    secrets.filter((s) => s.key.includes(typeFilter));
  function copy(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-red-300 mb-1">Secrets <span className="text-slate-500 text-xs">({secrets.length})</span></h2>
      <p className="text-xs text-slate-500 mb-3">API keys, tokens, wallet keys found. Tap to view source. Rotate immediately.</p>
      <div className="flex gap-2 flex-wrap mb-3">
        <button onClick={() => setTypeFilter("all")}
          className={`chip px-3 py-2 min-h-[44px] text-xs ${typeFilter === "all" ? "bg-red-900 text-red-200" : "text-slate-400"}`}>all</button>
        {types.map((t) => (
          <button key={t} onClick={() => setTypeFilter(t)}
            className={`chip px-3 py-2 min-h-[44px] text-xs ${typeFilter === t ? "bg-red-900 text-red-200" : "text-slate-400"}`}>{t}</button>
        ))}
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-slate-500">No secrets found yet.</p>
      ) : (
        <div className="space-y-2">
          {shown.map((f, i) => (
            <div key={i} className="bg-slate-800/50 rounded-lg p-3 border-l-2 border-red-500">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 whitespace-nowrap">
                  {f.key.replace("exposed_", "").replace("wallet_", "").replace(/_/g, " ").toUpperCase()}
                </span>
                <span className="text-[10px] text-slate-500 ml-auto">{f.confidence}%</span>
              </div>
              <p className="text-sm text-slate-200 mt-2 break-words whitespace-pre-wrap font-mono text-xs">{f.value}</p>
              {f.source_url && (
                <button onClick={() => onView(f.source_url!)}
                  className="text-xs text-sky-400 mt-2 min-h-[44px]">tap to view source</button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CredsView({ findings }: { findings: Finding[] }) {
  const creds = findings.filter((f) => f.key.startsWith("cred_"));
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-amber-300 mb-1">Credentials <span className="text-slate-500 text-xs">({creds.length})</span></h2>
      <p className="text-xs text-slate-500 mb-3">Hardcoded logins, passwords, DB strings. Rotate immediately.</p>
      {creds.length === 0 ? (
        <p className="text-sm text-slate-500">No credentials found yet.</p>
      ) : (
        <div className="space-y-2">
          {creds.map((f, i) => (
            <div key={i} className="bg-slate-800/50 rounded-lg p-3 border-l-2 border-amber-500">
              <div className="flex items-center gap-2">
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/50 text-amber-300 whitespace-nowrap">
                  {f.key.replace("cred_", "").replace(/_/g, " ").toUpperCase()}
                </span>
                <span className="text-[10px] text-slate-500 ml-auto">{f.confidence}%</span>
              </div>
              <p className="text-sm text-slate-200 mt-2 break-words whitespace-pre-wrap font-mono text-xs">{f.value}</p>
              {f.source_url && (
                <p className="text-xs text-slate-500 mt-1 break-all">{f.source_url}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ConnectionsView({ findings, graph }: { findings: Finding[]; graph: any }) {
  const [filter, setFilter] = useState("all");
  const conns = findings.filter((f) =>
    f.key === "connected_device" || f.key === "connected_service" ||
    f.key === "connected_account" || f.key === "connected_financial" ||
    f.key === "connection_summary" ||
    f.key === "payment_processor" || f.key === "billing_endpoint" ||
    f.key.startsWith("bank_") || f.key.startsWith("crypto_"));

  const byType: Record<string, Finding[]> = { device: [], service: [], account: [], financial: [] };
  conns.forEach((f) => {
    const t = f.evidence?.type as string;
    if (t && byType[t]) byType[t].push(f);
    else if (f.key === "payment_processor" || f.key.startsWith("bank_") || f.key.startsWith("crypto_") || f.key === "billing_endpoint") byType.financial.push(f);
  });

  const typeColor = (t: string) =>
    t === "device" ? "text-sky-300 border-sky-500/40 bg-sky-500/10" :
    t === "service" ? "text-violet-300 border-violet-500/40 bg-violet-500/10" :
    t === "account" ? "text-amber-300 border-amber-500/40 bg-amber-500/10" :
    t === "financial" ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10" :
    "text-slate-400 border-slate-700 bg-slate-800/50";

  const shown = filter === "all" ? conns.filter((f) => f.key !== "connection_summary")
    : filter === "summary" ? conns.filter((f) => f.key === "connection_summary")
    : byType[filter] || [];

  // Mini graph for connections only
  const connKinds = ["device", "service", "account", "financial"];
  const gNodes = (graph?.nodes || []).filter((n: any) =>
    connKinds.includes(n.kind) || n.kind === "target");
  const gIds = new Set(gNodes.map((n: any) => n.id));
  const gEdges = (graph?.edges || []).filter((e: any) => gIds.has(e.src) && gIds.has(e.dst));

  return (
    <div className="space-y-3">
      <div className="card p-4">
        <h2 className="font-semibold text-sky-300">Connections</h2>
        <p className="text-xs text-slate-500 mt-1">
          Everything connected to everything: devices, services, accounts, financial.
          Click a type to filter.
        </p>
        <div className="flex gap-2 flex-wrap mt-3">
          {(["all", "device", "service", "account", "financial"] as const).map((t) => (
            <button key={t} onClick={() => setFilter(t)}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${filter === t ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}>
              {t} ({t === "all" ? shown.length : (byType[t] || []).length})
            </button>
          ))}
        </div>
      </div>

      {/* relationship mini-graph */}
      {gNodes.length > 0 && (
        <div className="card p-4 overflow-x-auto">
          <h3 className="text-xs uppercase text-slate-500 mb-2">Relationship map</h3>
          <div className="min-w-[500px]">
            <svg viewBox="0 0 900 420" className="w-full" style={{ maxHeight: 420 }}>
              {gEdges.map((e: any, i: number) => {
                const a = gNodes.findIndex((n: any) => n.id === e.src);
                const b = gNodes.findIndex((n: any) => n.id === e.dst);
                if (a < 0 || b < 0) return null;
                const pa = { x: 450 + 180 * Math.cos(2 * Math.PI * a / Math.max(gNodes.length, 1)), y: 210 + 150 * Math.sin(2 * Math.PI * a / Math.max(gNodes.length, 1)) };
                const pb = { x: 450 + 180 * Math.cos(2 * Math.PI * b / Math.max(gNodes.length, 1)), y: 210 + 150 * Math.sin(2 * Math.PI * b / Math.max(gNodes.length, 1)) };
                return <line key={i} x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y} stroke="#243044" strokeWidth={1}>
                  <title>{e.relation}</title></line>;
              })}
              {gNodes.slice(0, 40).map((n: any, i: number) => {
                const p = { x: 450 + 180 * Math.cos(2 * Math.PI * i / Math.max(Math.min(gNodes.length, 40), 1)), y: 210 + 150 * Math.sin(2 * Math.PI * i / Math.max(Math.min(gNodes.length, 40), 1)) };
                const col = n.kind === "device" ? "#7dd3fc" : n.kind === "service" ? "#c4b5fd" : n.kind === "account" ? "#fbbf24" : n.kind === "financial" ? "#6ee7b7" : "#e6e6e6";
                return (
                  <g key={n.id}>
                    <circle cx={p.x} cy={p.y} r={n.kind === "target" ? 12 : 7} fill={col} opacity={0.9}>
                      <title>{n.kind}: {n.label}</title>
                    </circle>
                    {(n.kind === "target" || n.interesting) && (
                      <text x={p.x} y={p.y - 12} textAnchor="middle" fill="#e6e6e6" fontSize={10}>{n.label.slice(0, 24)}</text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
          <div className="flex gap-3 text-[11px] text-slate-500 mt-2 flex-wrap">
            <span><span className="text-sky-300">●</span> device</span>
            <span><span className="text-violet-300">●</span> service</span>
            <span><span className="text-amber-300">●</span> account</span>
            <span><span className="text-emerald-300">●</span> financial</span>
          </div>
        </div>
      )}

      {/* connection list */}
      <div className="card p-4">
        <div className="space-y-2">
          {shown.length === 0 && <p className="text-sm text-slate-500">No connections found yet.</p>}
          {shown.map((f, i) => {
            const t = (f.evidence?.type as string) || "info";
            return (
              <div key={i} className="bg-slate-800/50 rounded-lg p-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${typeColor(t)}`}>{t.toUpperCase()}</span>
                  <code className="text-xs font-mono text-slate-200 break-all flex-1">{f.value}</code>
                </div>
                <p className="text-xs text-slate-500 mt-1 break-words">{f.source}</p>
                {f.evidence?.relation && (
                  <p className="text-[11px] text-slate-600">relation: {f.evidence.relation}</p>
                )}
              </div>
            );
          })}
        </div>
      </div>
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
  const [shown, setShown] = useState(50);
  if (!data) return <div className="card p-4 text-sm text-slate-500">API map builds when the run finishes...</div>;
  const entries = Object.entries(data.entries || {});
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-sky-300 mb-3">API map <span className="text-slate-500 text-xs">({entries.length})</span></h2>
      <div className="space-y-2">
        {entries.slice(0, shown).map(([path, v]: any, i: number) => (
          <div key={i} className="bg-slate-800/50 rounded-lg p-3">
            <code className="text-amber-300 text-xs font-mono break-all block">{path}</code>
            <div className="flex gap-3 text-xs text-slate-500 mt-1 flex-wrap">
              <span>{(v.methods || []).join(", ")}</span>
              <span>{String(v.status || "")}</span>
              <span className="break-words">{String(v.auth || v.note || "")}</span>
            </div>
          </div>
        ))}
      </div>
      {entries.length > shown && (
        <button className="mt-3 w-full chip px-4 py-3 min-h-[48px] text-sm text-sky-300"
          onClick={() => setShown((s) => s + 50)}>show more ({entries.length - shown} remaining)</button>
      )}
    </div>
  );
}
