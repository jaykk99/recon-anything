"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { getCode, api } from "../../../lib/api";

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
// normalize to the 3 risk levels (critical maps to high)
function normSev(f: Finding): string {
  const s = sevOf(f);
  if (s === "critical" || s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}
function sevColor(s: string): string {
  // 3 risk levels only: high / medium / low (critical maps to high).
  if (s === "high" || s === "critical") return "text-red-400 border-red-500/40 bg-red-500/10";
  if (s === "medium") return "text-amber-300 border-amber-500/40 bg-amber-500/10";
  return "text-slate-400 border-slate-700 bg-slate-800/50";
}

// ---------- high-value findings: exploitability tiers ----------
type ExploitTier = "weaponized" | "public_poc" | "theoretical" | "unknown";
function exploitOf(f: Finding): ExploitTier {
  const v = String(f.evidence?.exploitability || "unknown").toLowerCase().replace(/-/g, "_").replace(/ /g, "_");
  if (v === "weaponized") return "weaponized";
  if (v === "public_poc") return "public_poc";
  if (v === "theoretical") return "theoretical";
  if (v === "poc" || v === "proof_of_concept" || v === "exploit" || v === "metasploit" || v === "nuclei") return "public_poc";
  return "unknown";
}
function exploitLabel(t: ExploitTier): string {
  return t === "weaponized" ? "WEAPONIZED" : t === "public_poc" ? "PUBLIC PoC" : t === "theoretical" ? "THEORETICAL" : "UNASSESSED";
}
// prominent badge classes; weaponized is loud on purpose
function exploitBadge(t: ExploitTier): string {
  if (t === "weaponized") return "bg-red-600 text-white border-red-400 shadow-[0_0_12px_rgba(239,68,68,0.55)]";
  if (t === "public_poc") return "text-orange-300 border-orange-500/50 bg-orange-500/15";
  if (t === "theoretical") return "text-yellow-200 border-yellow-500/40 bg-yellow-500/10";
  return "text-slate-500 border-slate-700 bg-slate-800/40";
}
// value rank: weaponized high-sev first, then high, then medium.
// low = noise (grouped below). Returns true for the "High value only" view.
function isHighValue(f: Finding): boolean {
  const s = normSev(f);
  const e = exploitOf(f);
  if (e === "weaponized" || e === "public_poc") return true;
  return s === "high" || s === "medium";
}
function valueRank(f: Finding): number {
  const sevRank = normSev(f) === "high" ? 0 : normSev(f) === "medium" ? 1 : 2;
  const expRank = { weaponized: 0, public_poc: 1, theoretical: 2, unknown: 3 }[exploitOf(f)];
  return sevRank * 10 + expRank;
}
function sortByValue(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => valueRank(a) - valueRank(b) || b.confidence - a.confidence);
}
// human label for grouped noise: "520 subdomains"
function groupLabel(key: string, n: number): string {
  const map: Record<string, string> = {
    subdomain: "subdomains", banner: "banners", port_suggestion: "suggested ports",
    connected_device: "connected devices", connected_service: "connected services",
    connected_account: "connected accounts", connected_financial: "financial links",
    tech: "technologies", server_header: "server headers", page_title: "page titles",
    dnssec: "DNSSEC records", whois_note: "WHOIS notes", js_file: "JS files",
    fingerprint_summary: "fingerprints", crawl_summary: "crawl summaries",
    a: "A records", aaaa: "AAAA records", mx: "MX records", txt: "TXT records",
    ns: "NS records", ptr: "PTR records", cname: "CNAME records",
    soa: "SOA records", srv: "SRV records", caa: "CAA records",
  };
  const m = map[key];
  const base = m || key.replace(/_/g, " ");
  return `${n} ${m ? base : base.endsWith("s") ? base : base + "s"}`;
}
function findingMarkdown(f: Finding): string {
  const sev = sevOf(f);
  let md = `## ${f.key}\n\n`;
  md += `- **Risk:** ${sev || "low"}\n`;
  md += `- **Exploitability:** ${exploitOf(f)}\n`;
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

function copyText(t: string) { navigator.clipboard.writeText(t).catch(() => {}); }

// One finding as an expandable card. Used in both the top-findings list
// and inside collapsed noise groups.
function FindingCard({ f, open, onToggle }: { f: Finding; open: boolean; onToggle: () => void }) {
  const sev = normSev(f);
  const tier = exploitOf(f);
  const ev = f.evidence || {};
  return (
    <div className={`rounded-lg p-3 space-y-1.5 border ${sevColor(sev)}`}>
      <button className="w-full text-left min-h-[44px]" onClick={onToggle}>
        <div className="flex items-center gap-2 flex-wrap">
          {tier !== "unknown" && (
            <span className={`text-[11px] font-extrabold px-2 py-0.5 rounded border ${exploitBadge(tier)}`}>
              {tier === "weaponized" ? "⚔ " : ""}{exploitLabel(tier)}
            </span>
          )}
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevColor(sev)}`}>{sev.toUpperCase()}</span>
          <code className="text-amber-300 text-xs font-mono break-all">{f.key}</code>
          <span className="text-[10px] text-slate-500 ml-auto whitespace-nowrap">{f.confidence}%</span>
          <span className="text-slate-500 text-xs">{open ? "▲" : "▼"}</span>
        </div>
        <p className="text-sm break-words whitespace-pre-wrap mt-1">{f.value}</p>
      </button>
      {open && (
        <div className="pt-2 border-t border-slate-700/50 space-y-2 text-xs">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-slate-500">{f.plugin}</span>
            <span className={`px-1.5 py-0.5 rounded ${f.passive ? "pill-info" : "pill-warn"}`}>{f.passive ? "passive" : "ACTIVE"}</span>
            <span className={`px-1.5 py-0.5 rounded border ${exploitBadge(tier)}`}>exploitability: {exploitLabel(tier)}</span>
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
            <button className="text-sky-400 px-3 py-2 min-h-[44px] rounded-lg bg-slate-800" onClick={() => copyText(f.value)}>copy value</button>
            <button className="text-sky-400 px-3 py-2 min-h-[44px] rounded-lg bg-slate-800" onClick={() => copyText(findingMarkdown(f))}>copy as markdown</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function RunPage({ params }: { params: { id: string } }) {
  const id = params.id;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [targets, setTargets] = useState<{ raw: string; normalized: string; type: string }[]>([]);
  const [plugins, setPlugins] = useState<Record<string, PluginState>>({});
  const [status, setStatus] = useState("running");
  const [tab, setTab] = useState("findings");
  const [sourceType, setSourceType] = useState("website");
  const [summary, setSummary] = useState<any>(null);
  const [graph, setGraph] = useState<any>(null);
  const [apiMap, setApiMap] = useState<any>(null);
  const [cat, setCat] = useState("all");
  const [sev, setSev] = useState("all");
  const [sortBy, setSortBy] = useState("value");
  const [q, setQ] = useState("");
  // high-value findings view: weaponized/high first, noise collapsed
  const [highValueOnly, setHighValueOnly] = useState(false);
  const [shownTop, setShownTop] = useState(50);
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const [groupShown, setGroupShown] = useState<Record<string, number>>({});
  const [noiseOpen, setNoiseOpen] = useState(false);
  // reset paging when filters change
  useEffect(() => {
    setShownTop(50); setGroupShown({}); setOpenGroups({}); setExpanded({});
  }, [q, cat, sev, sortBy, highValueOnly]);
  // progress + ETA
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [estimatedS, setEstimatedS] = useState(0);
  const [etaS, setEtaS] = useState<number | null>(null);
  const [wafNotice, setWafNotice] = useState<string | null>(null);
  const [startTime] = useState(Date.now());
  const [elapsed, setElapsed] = useState(0);
  // finding dedupe: SSE replays history on reconnect, so skip repeats.
  const seenFids = useRef<Set<string>>(new Set());
  // connection health: SSE live vs 4s poll fallback vs dead. Never a
  // silent dead page: sseState tracks the event stream, feedState tracks
  // the poll fallback, fatal is a terminal load error (e.g. run wiped).
  const [sseState, setSseState] = useState<"connecting" | "live" | "down">("connecting");
  const [feedState, setFeedState] = useState<"ok" | "degraded" | "dead">("ok");
  const [fatal, setFatal] = useState<string | null>(null);
  const [retryTick, setRetryTick] = useState(0);
  const failCount = useRef(0);
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

  // the atm tab only exists on ATM source-type runs; never leave it selected elsewhere
  useEffect(() => {
    if (tab === "atm" && sourceType !== "atm") setTab("findings");
  }, [tab, sourceType]);

  useEffect(() => {
    // Fresh attempt (mount or Retry button): reset health, allow loops again.
    done.current = false;
    failCount.current = 0;
    setFatal(null);
    setSseState("connecting");
    setFeedState("ok");

    const es = new EventSource(`/api/runs/${id}/stream?code=${encodeURIComponent(getCode())}`);
    // Any SSE event at all means the stream is alive.
    const on = (ev: string, fn: (e: MessageEvent) => void) =>
      es.addEventListener(ev, ((e: MessageEvent) => { setSseState("live"); fn(e); }) as EventListener);
    on("run_start", (e) => {
      const d = JSON.parse(e.data);
      if (d.source_type) setSourceType(d.source_type);
      if (d.estimated_s) setEstimatedS(d.estimated_s);
      if (d.source_type) setSourceType(d.source_type);
      if (d.plugin_count) setProgress({ done: 0, total: d.plugin_count * (d.target_count || 1) });
    });
    on("progress", (e) => {
      const d = JSON.parse(e.data);
      setProgress({ done: d.done || 0, total: d.total || 0 });
      if (typeof d.eta_s === "number") setEtaS(d.eta_s);
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
    on("waf_detected", (e) => {
      const d = JSON.parse(e.data);
      setWafNotice(d.note || `WAF/challenge protection detected on ${d.host || "target"}`);
    });
    on("finding", (e) => {
      const d = JSON.parse(e.data);
      // Dedupe: reconnects replay history, and the 4s poll can overlap.
      const key = d.fid != null ? `fid:${d.fid}` : `c:${d.plugin}|${d.key}|${d.value}`;
      if (seenFids.current.has(key)) return;
      seenFids.current.add(key);
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
    // SSE dropped: EventSource auto-retries in the background; the 4s poll
    // below keeps progress alive meanwhile. Any event flips us back to live.
    es.onerror = () => { if (!done.current) setSseState("down"); };

    // Merge one poll response into state. Returns true when the run is over
    // (stop polling). This is the fallback that keeps progress + ETA +
    // running plugin names alive when the SSE stream is down.
    function applyPoll(d: any): boolean {
      if (d.run?.status === "running" && d.progress) {
        const p = d.progress;
        if (typeof p.total === "number" && p.total > 0)
          setProgress({ done: p.done || 0, total: p.total });
        if (typeof p.eta_s === "number") setEtaS(p.eta_s);
        else if (typeof p.estimated_s === "number" && p.estimated_s > 0) setEstimatedS(p.estimated_s);
        if (Array.isArray(p.running) && p.running.length > 0)
          setPlugins((prev) => {
            const next = { ...prev };
            for (const name of p.running)
              if (!next[name] || next[name].status !== "running")
                next[name] = { plugin: name, status: "running", reason: "", findings: 0 };
            return next;
          });
        // Live findings while running: merge only what is new (deduped, so
        // overlapping SSE + poll can never duplicate a finding).
        if (Array.isArray(d.findings) && d.findings.length > 0) {
          const fresh: Finding[] = [];
          for (const f of d.findings) {
            const key = f.id != null ? `fid:${f.id}` : `c:${f.plugin}|${f.key}|${f.value}`;
            if (!seenFids.current.has(key)) { seenFids.current.add(key); fresh.push(f); }
          }
          if (fresh.length > 0) setFindings((prev) => [...prev, ...fresh]);
        }
        if (d.run?.source_type) setSourceType(d.run.source_type);
        if (Array.isArray(d.targets) && d.targets.length > 0) setTargets(d.targets);
      }
      if (d.run?.status === "done" || d.run?.status === "failed") {
        setStatus(d.run.status); setFindings(d.findings || []); setSummary(d.run.summary);
        setTargets(d.targets || []);
        done.current = true;
        // keep the dedupe set in sync so late SSE events do not duplicate
        (d.findings || []).forEach((f: any) => {
          seenFids.current.add(f.id != null ? `fid:${f.id}` : `c:${f.plugin}|${f.key}|${f.value}`);
        });
        if (d.run?.source_type) setSourceType(d.run.source_type);
        if (d.run.status === "done") {
          const h = { "X-Access-Code": getCode() };
          fetch(`/api/runs/${id}/graph`, { headers: h }).then((r) => r.json()).then(setGraph).catch(() => {});
          fetch(`/api/runs/${id}/apimap`, { headers: h }).then((r) => r.json()).then(setApiMap).catch(() => {});
        }
        return true;
      }
      return false;
    }

    let stopped = false;
    async function pollOnce(): Promise<boolean> {
      const r = await fetch(`/api/runs/${id}`, { headers: { "X-Access-Code": getCode() } });
      if (r.status === 404) {
        setFatal("Run not found. The scan data may have been wiped (the free-tier database resets on redeploys), or this link is wrong or expired.");
        return true;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return applyPoll(await r.json());
    }

    async function tick() {
      if (stopped || done.current) return;
      try {
        const finished = await pollOnce();
        failCount.current = 0;
        setFeedState("ok");
        if (finished) { stopped = true; clearInterval(poll); es.close(); }
      } catch {
        // Transient blip vs dead server: 1-2 misses degrade quietly,
        // 3 in a row means the feed is dead -> loud error + retry button.
        failCount.current += 1;
        setFeedState(failCount.current >= 3 ? "dead" : "degraded");
      }
    }

    const poll = setInterval(tick, 4000);
    tick(); // first paint now, not after 4s; also surfaces 404 immediately
    return () => { stopped = true; es.close(); clearInterval(poll); };
  }, [id, retryTick]);

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
    (sev === "all" || normSev(f) === sev || (sev === "critical" && sevOf(f) === "critical")) &&
    (!q || (f.key + f.value + f.plugin + (f.evidence?.severity || "") + (f.evidence?.exploitability || "")).toLowerCase().includes(q.toLowerCase())));

  // sort: value (default rank), severity, plugin, confidence
  const sortFindings = (list: Finding[]) => {
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const arr = [...list];
    if (sortBy === "severity") arr.sort((a, b) => (sevRank[sevOf(a)] ?? 4) - (sevRank[sevOf(b)] ?? 4));
    else if (sortBy === "plugin") arr.sort((a, b) => (a.plugin || "").localeCompare(b.plugin || ""));
    else if (sortBy === "confidence") arr.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    return arr;
  };

  // ---------- high-value-first layout ----------
  // top: high/medium + anything weaponized or with a public PoC, ranked by value.
  // noise: everything low/informational, grouped by (category, key) and collapsed.
  const top = sortFindings(sortByValue(filtered.filter(isHighValue)));
  const noise = sortFindings(filtered.filter((f) => !isHighValue(f)));
  const sevCounts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  const explCounts: Record<ExploitTier, number> = { weaponized: 0, public_poc: 0, theoretical: 0, unknown: 0 };
  filtered.forEach((f) => { sevCounts[normSev(f)]++; explCounts[exploitOf(f)]++; });
  interface NoiseGroup { gkey: string; category: string; key: string; items: Finding[] }
  const noiseGroups: NoiseGroup[] = [];
  {
    const byKey: Record<string, NoiseGroup> = {};
    noise.forEach((f) => {
      const gk = `${f.category}::${f.key}`;
      if (!byKey[gk]) byKey[gk] = { gkey: gk, category: f.category, key: f.key, items: [] };
      byKey[gk].items.push(f);
    });
    noiseGroups.push(...Object.values(byKey).sort((a, b) => b.items.length - a.items.length));
  }
  // expanded finding cards: key = stable per-list index (e.g. "top:12", "grp:<gkey>:7")
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  function toggleCard(k: string) { setExpanded((e) => ({ ...e, [k]: !e[k] })); }

  const pill = (s: string) =>
    s === "ok" ? "pill-ok" : s === "error" ? "pill-err" : s === "running" ? "pill-info" : s === "failed" ? "pill-err" : "pill-warn";

  const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;
  // Live ETA from the backend (adapts to actual plugin speed); falls back to
  // the pre-run estimate (now also fed by the 4s poll) until observed
  // durations exist. Empty label when there is nothing to base it on.
  const etaLeft = etaS !== null ? Math.max(etaS, 0)
    : estimatedS > 0 && status === "running" ? Math.max(estimatedS - elapsed, 0)
    : null;
  const pluginsLeft = Math.max(progress.total - progress.done, 0);
  // Live batch view: 5 plugins run at a time, show which batch is active.
  const BATCH = 5;
  const runningNow = Object.values(plugins).filter((p) => p.status === "running");
  const batches = Math.ceil(progress.total / BATCH);
  const batch = progress.total > 0 ? Math.min(Math.floor(progress.done / BATCH) + 1, Math.max(batches, 1)) : 0;
  const runningNames = runningNow.slice(0, 8).map((p) => p.plugin).join(", ");

  return (
    <div className="space-y-4 max-w-full">
      {/* header */}
      <div className="card p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="font-mono text-sm text-sky-300 break-all">run {id}</h1>
          <span className={`text-xs px-2 py-1 rounded min-h-[28px] flex items-center ${status === "done" ? "pill-ok" : status === "failed" ? "pill-err" : "pill-info"}`}>{status}</span>
          <span className="text-xs text-slate-500">{findings.length} findings</span>
        </div>
        {/* live batch panel: 5 at a time, visible batches */}
        {status === "running" && progress.total > 0 && (
          <div className="mt-3 rounded-lg border border-emerald-800/50 bg-emerald-950/30 p-3">
            <div className="flex items-center gap-2 text-sm flex-wrap">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400"></span>
              </span>
              <span className="font-bold text-emerald-300">LIVE</span>
              <span className="text-slate-200">Batch {batch} of {batches} · 5 at a time</span>
              <span className="ml-auto text-xs text-slate-400">{findings.length} findings so far</span>
            </div>
            <p className="text-xs text-slate-400 mt-1.5">
              {progress.done} done · {pluginsLeft} left
              {runningNow.length > 0
                ? <> · running now ({runningNow.length}): <span className="text-sky-300 font-mono">{runningNames}{runningNow.length > 8 ? "..." : ""}</span></>
                : " · starting next 5..."}
            </p>
          </div>
        )}
        {/* WAF notice: target is fighting back */}
        {wafNotice && status === "running" && (
          <div className="mt-3 rounded-lg border border-amber-700/50 bg-amber-950/30 p-3 text-xs text-amber-200">
            <span className="font-bold">WAF DETECTED:</span> {wafNotice}
          </div>
        )}
        {/* connection health: never a dead silent page */}
        {fatal ? (
          <div className="mt-3 rounded-lg border border-red-700/50 bg-red-950/30 p-4">
            <p className="text-sm font-bold text-red-300">Run not found</p>
            <p className="text-xs text-slate-400 mt-1">{fatal}</p>
            <div className="flex gap-2 mt-3 flex-wrap">
              <button onClick={() => setRetryTick((t) => t + 1)}
                className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300">Retry</button>
              <a href="/" className="chip px-4 py-2.5 min-h-[44px] text-sm text-slate-300 inline-flex items-center">Back to scans</a>
            </div>
          </div>
        ) : feedState === "dead" ? (
          <div className="mt-3 rounded-lg border border-red-700/50 bg-red-950/30 p-4">
            <p className="text-sm font-bold text-red-300">Connection lost</p>
            <p className="text-xs text-slate-400 mt-1">
              Cannot reach the scan server (3 failed refreshes). Check your connection, then retry.
            </p>
            <button onClick={() => setRetryTick((t) => t + 1)}
              className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300 mt-3">Retry now</button>
          </div>
        ) : sseState === "down" ? (
          <p className="mt-3 text-xs text-amber-300/90">Live stream down, auto-refreshing every 4s.</p>
        ) : null}
        {/* progress bar */}
        {status === "running" && !fatal && (
          <div className="mt-3">
            {progress.total > 0 ? (
              <>
                <p className="text-xl font-bold text-slate-100">
                  {progress.done} <span className="text-slate-400 font-normal text-base">of {progress.total} plugins done</span>
                  {etaLeft !== null && <span className="text-emerald-300"> · ~{fmtTime(etaLeft)} left</span>}
                </p>
                <div className="flex justify-between text-xs text-slate-400 mt-1 mb-1">
                  <span>{pluginsLeft} left · {findings.length} findings so far</span>
                  <span>{fmtTime(elapsed)} elapsed</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2.5">
                  <div className="bg-sky-500 h-2.5 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                </div>
              </>
            ) : (
              <p className="text-sm text-slate-400">
                <span className="animate-pulse">Connecting to the live scan feed…</span>
                {feedState === "degraded" && <span className="text-amber-300/80"> (refresh hit a snag, retrying)</span>}
              </p>
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

      {/* tabs - thumb reachable, 44px targets. The atm tab only exists on
          ATM source-type runs; website scans never show it. */}
      <div className="flex gap-2 text-sm overflow-x-auto pb-1">
        {((() => {
          const tabCount = (t: string): number => {
            if (t === "findings") return findings.length;
            if (t === "secrets") return findings.filter((f) => f.category === "leak").length;
            if (t === "creds") return findings.filter((f) => /cred|password|key|token/i.test(f.key)).length;
            if (t === "subdomains") return findings.filter((f) => /subdomain/i.test(f.key)).length;
            if (t === "ports") return findings.filter((f) => /port|banner/i.test(f.key)).length;
            if (t === "files") return findings.filter((f) => /file|backup|artifact|git_exposed|sourcemap/i.test(f.key)).length;
            if (t === "vulns") return findings.filter((f) => f.category === "vuln").length;
            return 0;
          };
          const tabLabel = (t: string) => {
            const c = tabCount(t);
            const name = t === "assistant" ? "Assistant" : t;
            return c > 0 ? `${name} (${c})` : name;
          };
          return (["findings", "vulns", "assistant", "atm", "connections", "secrets", "creds", "subdomains", "ports", "files", "graph", "apimap", "raw"] as const)
            .filter((t) => t !== "atm" || sourceType === "atm")
            .map((t) => (
              <button key={t} onClick={() => setTab(t)}
                className={`chip px-4 py-2.5 min-h-[44px] whitespace-nowrap ${tab === t ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}>{tabLabel(t)}</button>
            ));
        })())}
      </div>
      <div className="flex gap-2 flex-wrap">
        <select className="input text-sm px-3 py-2.5 min-h-[44px]" value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="all">all categories</option>
          {CATS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="input text-sm px-3 py-2.5 min-h-[44px]" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">all severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select className="input text-sm px-3 py-2.5 min-h-[44px]" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="value">sort: value</option>
          <option value="severity">sort: severity</option>
          <option value="confidence">sort: confidence</option>
          <option value="plugin">sort: plugin</option>
        </select>
        <input className="input text-sm px-3 py-2.5 min-h-[44px] flex-1 min-w-[140px]" placeholder="filter..." value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {tab === "findings" && (
      <div className="space-y-4">
        {/* summary header: counts by severity AND by exploitability */}
        <div className="card p-4">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="font-semibold text-sky-300">Findings <span className="text-slate-500 text-xs">({filtered.length})</span></h2>
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${sevColor("high")}`}>HIGH {sevCounts.high}</span>
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${sevColor("medium")}`}>MEDIUM {sevCounts.medium}</span>
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${sevColor("low")}`}>LOW {sevCounts.low}</span>
          </div>
          <div className="flex items-center gap-2 flex-wrap mt-2">
            <span className="text-[11px] text-slate-500">exploitability:</span>
            <span className={`text-[11px] font-extrabold px-2 py-0.5 rounded border ${exploitBadge("weaponized")}`}>WEAPONIZED {explCounts.weaponized}</span>
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${exploitBadge("public_poc")}`}>PUBLIC PoC {explCounts.public_poc}</span>
            <span className={`text-[11px] px-2 py-0.5 rounded border ${exploitBadge("theoretical")}`}>THEORETICAL {explCounts.theoretical}</span>
            <span className={`text-[11px] px-2 py-0.5 rounded border ${exploitBadge("unknown")}`}>UNASSESSED {explCounts.unknown}</span>
          </div>
          <div className="flex gap-2 mt-3 flex-wrap">
            <button
              onClick={() => setHighValueOnly((v) => !v)}
              className={`chip px-4 py-2.5 min-h-[44px] text-sm ${highValueOnly ? "bg-emerald-900 text-emerald-200 border border-emerald-700" : "text-slate-300"}`}>
              {highValueOnly ? "✓ High value only" : "High value only"}
            </button>
            <button
              onClick={() => { setHighValueOnly(false); setNoiseOpen(true); }}
              className="chip px-4 py-2.5 min-h-[44px] text-sm text-slate-300">
              Show all
            </button>
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(filtered, null, 1)], { type: "application/json" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = `findings-${id}.json`;
                a.click();
              }}
              className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300">
              Export JSON
            </button>
            <button
              onClick={() => {
                const esc = (s: any) => `"${String(s ?? "").replace(/"/g, '""')}"`;
                const rows = [["severity", "category", "key", "value", "plugin", "confidence", "exploitability"]];
                filtered.forEach((f) => rows.push([sevOf(f), f.category, f.key, f.value, f.plugin, f.confidence, exploitOf(f)].map(esc)));
                const blob = new Blob([rows.map((r) => r.join(",")).join("\n")], { type: "text/csv" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = `findings-${id}.csv`;
                a.click();
              }}
              className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300">
              Export CSV
            </button>
          </div>
        </div>

        {/* top findings: ranked by value, not alphabetically */}
        {top.length > 0 && (
          <div className="card p-4">
            <h2 className="font-semibold text-sky-300 mb-3">Top findings <span className="text-slate-500 text-xs">({top.length} ranked by value)</span></h2>
            <div className="space-y-3">
              {top.slice(0, shownTop).map((f, i) => {
                const ek = `top:${i}`;
                return <FindingCard key={ek} f={f} open={!!expanded[ek]} onToggle={() => toggleCard(ek)} />;
              })}
            </div>
            {top.length > shownTop && (
              <button
                className="mt-3 w-full chip px-4 py-3 min-h-[48px] text-sm text-sky-300"
                onClick={() => setShownTop((s) => s + 50)}>
                show more ({top.length - shownTop} remaining)
              </button>
            )}
          </div>
        )}

        {/* noise: low/informational, grouped + collapsed by default */}
        {!highValueOnly && noiseGroups.length > 0 && (
          <div className="card p-4">
            <button
              className="w-full text-left min-h-[44px] flex items-center gap-2 flex-wrap"
              onClick={() => setNoiseOpen((v) => !v)}>
              <h2 className="font-semibold text-slate-300">Noise <span className="text-slate-500 text-xs">({noise.length} low/informational)</span></h2>
              <span className="text-slate-500 text-xs ml-auto">{noiseOpen ? "▲ collapse" : "▼ expand"}</span>
            </button>
            {noiseOpen && (
              <div className="space-y-2 mt-3">
                {noiseGroups.map((g) => {
                  const isOpen = !!openGroups[g.gkey];
                  const shownG = groupShown[g.gkey] || 25;
                  return (
                    <div key={g.gkey} className="rounded-lg border border-slate-700/60 bg-slate-800/40">
                      <button
                        className="w-full text-left min-h-[48px] px-3 py-2.5 flex items-center gap-2 flex-wrap"
                        onClick={() => setOpenGroups((o) => ({ ...o, [g.gkey]: !o[g.gkey] }))}>
                        <span className="text-sm font-medium text-slate-200">{groupLabel(g.key, g.items.length)}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-400">{g.category}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded border text-slate-500 border-slate-700">LOW</span>
                        <span className="text-slate-500 text-xs ml-auto">{isOpen ? "▲" : "▼"}</span>
                      </button>
                      {isOpen && (
                        <div className="px-3 pb-3 space-y-2">
                          {g.items.slice(0, shownG).map((f, j) => {
                            const ek = `grp:${g.gkey}:${j}`;
                            return <FindingCard key={ek} f={f} open={!!expanded[ek]} onToggle={() => toggleCard(ek)} />;
                          })}
                          {g.items.length > shownG && (
                            <button
                              className="w-full chip px-4 py-3 min-h-[44px] text-sm text-sky-300"
                              onClick={() => setGroupShown((s) => ({ ...s, [g.gkey]: (s[g.gkey] || 25) + 25 }))}>
                              show more ({g.items.length - shownG} remaining)
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {filtered.length === 0 && (
          <div className="card p-4 text-sm text-slate-500">No findings match the current filters.</div>
        )}
      </div>
      )}

      {tab === "vulns" && <VulnsView runId={id} />}
      {tab === "assistant" && <AssistantView runId={id} />}
      {tab === "atm" && <AtmView runId={id} findings={findings} />}
      {tab === "connections" && <ConnectionsView findings={findings} graph={graph} />}
      {tab === "subdomains" && <SubdomainsView runId={id} findings={findings} />}
      {tab === "ports" && <PortsView runId={id} findings={findings} targets={targets} />}
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
              onClick={() => copyText(JSON.stringify(findings, null, 1))}>copy all</button>
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
                    onClick={() => copyText(viewing.body)}>copy</button>
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

interface SubStatus { live: boolean; status: number; url: string; server: string; title: string; }

function SubdomainsView({ runId, findings }: { runId: string; findings: Finding[] }) {
  const subs = findings.filter((f) => f.key === "subdomain");
  const notes = findings.filter((f) => f.key === "subdomain_enum_note");
  const [status, setStatus] = useState<Record<string, SubStatus>>({});
  const [verifying, setVerifying] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState("");
  function hostOf(v: string) { return v.split(/\s/)[0].trim().toLowerCase().replace(/\.$/, ""); }
  function copyAll() {
    navigator.clipboard.writeText(subs.map((s) => hostOf(s.value)).join("\n")).catch(() => {});
  }
  async function verify() {
    setVerifying(true); setVerifyMsg("");
    try {
      const d = await api<{ hosts: Record<string, SubStatus>; live: number; count: number }>(
        `/api/runs/${runId}/subdomains/verify`, { method: "POST", body: JSON.stringify({}) });
      setStatus(d.hosts || {});
      setVerifyMsg(`${d.live} of ${d.count} responding`);
    } catch (e: any) { setVerifyMsg("verify failed: " + e.message); }
    setVerifying(false);
  }
  async function scanSub(host: string) {
    try {
      const d = await api<{ run_id: string }>("/api/runs", {
        method: "POST", body: JSON.stringify({ targets: host, mode: "active" }) });
      if (d.run_id) window.location.href = `/run/${d.run_id}`;
    } catch (e: any) { setVerifyMsg("scan failed: " + e.message); }
  }
  const liveCount = Object.values(status).filter((s) => s.live).length;
  return (
    <div className="card p-4">
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <h2 className="font-semibold text-sky-300">Subdomains <span className="text-slate-500 text-xs">({subs.length})</span></h2>
        {liveCount > 0 && <span className="text-xs text-green-400">{liveCount} live</span>}
        {subs.length > 0 && (
          <div className="ml-auto flex gap-2">
            <button className="chip px-3 py-2.5 min-h-[44px] text-xs text-emerald-400" onClick={verify} disabled={verifying}>
              {verifying ? "checking..." : "verify live"}
            </button>
            <button className="chip px-3 py-2.5 min-h-[44px] text-xs text-sky-400" onClick={copyAll}>copy all</button>
          </div>
        )}
      </div>
      {verifyMsg && <p className="text-xs text-slate-400 mb-2">{verifyMsg}</p>}
      {notes.map((n, i) => (
        <p key={i} className="text-xs text-amber-300/80 mb-2 break-words">{n.value} <span className="text-slate-500">({n.source})</span></p>
      ))}
      {subs.length === 0 ? (
        <p className="text-sm text-slate-500">No subdomains found yet.</p>
      ) : (
        <div className="space-y-1">
          {subs.map((s, i) => {
            const host = hostOf(s.value);
            const st = status[host];
            const dot = !st ? "bg-slate-600" : st.live ? "bg-green-400" : "bg-red-400/60";
            const link = st?.live && st.url ? st.url : `https://${host}`;
            return (
              <div key={i} className="flex items-center gap-2 text-sm px-3 py-2.5 min-h-[44px] rounded-lg bg-slate-800/50">
                <span className={`w-2 h-2 rounded-full shrink-0 ${dot}`} title={!st ? "not checked" : st.live ? `live (${st.status})` : "no response"} />
                <a href={link} target="_blank" rel="noreferrer"
                  className="text-green-300 break-all font-mono hover:underline flex-1">{host}</a>
                {st?.live && st.title && <span className="text-[10px] text-slate-500 truncate max-w-[140px] hidden sm:inline">{st.title}</span>}
                <button onClick={() => scanSub(host)}
                  className="chip px-2.5 py-2 min-h-[40px] text-[11px] text-amber-300 whitespace-nowrap">scan</button>
                <span className="text-[10px] text-slate-500 whitespace-nowrap">{s.confidence}%</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface PortProbe { host: string; port: number; open: boolean; banner: string; http: { status?: number; server?: string; title?: string; url?: string; error?: string } | null; error?: string }

function PortsView({ runId, findings, targets }: { runId: string; findings: Finding[]; targets: { raw: string; normalized: string; type: string }[] }) {
  const ports = findings.filter((f) => f.key === "port_open" || f.key === "port_suggestion");
  const [probes, setProbes] = useState<Record<string, PortProbe>>({});
  const [probing, setProbing] = useState<string | null>(null);
  function parsePort(f: Finding) {
    const m = /port (\d+)\s*\(([^)]+)\)/i.exec(f.value);
    return { port: m ? parseInt(m[1]) : 0, service: m ? m[2] : "unknown" };
  }
  function baseHost() {
    const t = targets[0];
    if (!t) return "";
    const n = (t.normalized || t.raw || "").toLowerCase();
    const m = /([a-z0-9]([a-z0-9.\-]*[a-z0-9])?)/.exec(n);
    return m ? m[1] : "";
  }
  function webUrl(host: string, port: number) {
    if (port === 443 || port === 8443) return `https://${host}:${port}/`;
    if ([80, 8000, 8080, 3000, 5000, 9000, 9200, 5601].includes(port)) return `http://${host}:${port}/`;
    return "";
  }
  async function probe(host: string, port: number) {
    const key = `${host}:${port}`;
    setProbing(key);
    try {
      const d = await api<PortProbe>(`/api/runs/${runId}/probe/port?host=${encodeURIComponent(host)}&port=${port}`);
      setProbes((p) => ({ ...p, [key]: d }));
    } catch (e: any) { setProbes((p) => ({ ...p, [key]: { host, port, open: false, banner: "", http: null, error: e.message } })); }
    setProbing(null);
  }
  const host = baseHost();
  const openPorts = ports.filter((f) => f.key === "port_open");
  const sugPorts = ports.filter((f) => f.key === "port_suggestion");
  return (
    <div className="card p-4">
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <h2 className="font-semibold text-sky-300">Ports <span className="text-slate-500 text-xs">({openPorts.length} open, {sugPorts.length} suggested)</span></h2>
      </div>
      <p className="text-xs text-slate-500 mb-3">Tap a port to open it in your browser. Probe grabs the live banner.</p>
      {ports.length === 0 ? (
        <p className="text-sm text-slate-500">No port findings yet. Run an active scan for real results.</p>
      ) : (
        <div className="space-y-1">
          {ports.map((f, i) => {
            const { port, service } = parsePort(f);
            const url = webUrl(host, port);
            const key = `${host}:${port}`;
            const pr = probes[key];
            const banner = (f.evidence as any)?.banner || pr?.banner || "";
            const isOpen = f.key === "port_open";
            return (
              <div key={i} className="px-3 py-2.5 min-h-[44px] rounded-lg bg-slate-800/50">
                <div className="flex items-center gap-2 text-sm flex-wrap">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${isOpen ? "bg-green-400" : "bg-slate-600"}`} />
                  {url ? (
                    <a href={url} target="_blank" rel="noreferrer" className="font-mono text-sky-300 hover:underline">
                      {host}:{port} <span className="text-slate-400">({service})</span>
                    </a>
                  ) : (
                    <span className="font-mono text-slate-300">{port} <span className="text-slate-500">({service})</span></span>
                  )}
                  <span className={`text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap ${isOpen ? "pill-err" : "pill-info"}`}>
                    {isOpen ? "OPEN" : "SUGGESTED"}
                  </span>
                  <div className="ml-auto flex gap-2">
                    {isOpen && host && (
                      <button onClick={() => probe(host, port)} disabled={probing === key}
                        className="chip px-2.5 py-2 min-h-[40px] text-[11px] text-emerald-300 whitespace-nowrap">
                        {probing === key ? "..." : "probe"}
                      </button>
                    )}
                  </div>
                </div>
                {(banner || pr?.http?.title) && (
                  <p className="text-[11px] text-slate-500 font-mono mt-1 break-all">
                    {banner}{pr?.http?.title ? ` | ${pr.http.title}` : ""}
                  </p>
                )}
                {pr?.error && <p className="text-[11px] text-red-400/80 mt-1">{pr.error}</p>}
              </div>
            );
          })}
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

// ---------- Uncensored Assistant tab ----------
// Two modes: Chat (free-form Q&A over the current run) and Agent (gap
// analysis + deep-run follow-ups). Plain pre-wrapped text, no markdown lib.
interface ChatMsg { role: "user" | "assistant"; text: string }

function AssistantView({ runId }: { runId: string }) {
  const [mode, setMode] = useState<"chat" | "agent">("chat");

  // --- chat mode ---
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [chatErr, setChatErr] = useState("");
  const chatEndRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, sending]);

  async function sendChat() {
    const text = draft.trim();
    if (!text || sending) return;
    setDraft("");
    setChatErr("");
    const history = [...msgs, { role: "user" as const, text }];
    setMsgs(history);
    setSending(true);
    try {
      const r = await fetch("/api/assistant/chat", {
        method: "POST",
        headers: { "X-Access-Code": getCode(), "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: history.map((m) => ({ role: m.role, content: m.text })),
          run_id: runId,
        }),
      });
      const d = await r.json();
      const reply = d.reply || d.message || d.error || "No reply.";
      setMsgs((m) => [...m, { role: "assistant" as const, text: String(reply) }]);
      if (d.error && !d.reply && !d.message) setChatErr(d.error);
    } catch (e: any) {
      setChatErr(e.message || "Chat request failed.");
    } finally {
      setSending(false);
    }
  }

  // --- agent mode ---
  const [agentRunId, setAgentRunId] = useState(runId);
  const [instruction, setInstruction] = useState("");
  const [agentRes, setAgentRes] = useState<any>(null);
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentErr, setAgentErr] = useState("");
  const [deepBusy, setDeepBusy] = useState(false);

  async function runAgent() {
    if (!instruction.trim() || agentBusy) return;
    setAgentBusy(true);
    setAgentErr("");
    setAgentRes(null);
    try {
      const r = await fetch("/api/assistant/agent", {
        method: "POST",
        headers: { "X-Access-Code": getCode(), "Content-Type": "application/json" },
        body: JSON.stringify({ run_id: agentRunId, instruction: instruction.trim() }),
      });
      const d = await r.json();
      if (d.error) setAgentErr(d.error);
      else setAgentRes(d);
    } catch (e: any) {
      setAgentErr(e.message || "Agent request failed.");
    } finally {
      setAgentBusy(false);
    }
  }

  async function deepRun() {
    const ids: string[] = agentRes?.suggested_plugins || [];
    if (!ids.length || deepBusy) return;
    setDeepBusy(true);
    try {
      const r = await fetch("/api/assistant/deep-run", {
        method: "POST",
        headers: { "X-Access-Code": getCode(), "Content-Type": "application/json" },
        body: JSON.stringify({ run_id: agentRunId, plugin_ids: ids }),
      });
      const d = await r.json();
      const newId = d.run_id || d.id;
      if (newId) window.location.href = `/run/${newId}`;
      else setAgentErr(d.error || "Deep run started but no new run id was returned.");
    } catch (e: any) {
      setAgentErr(e.message || "Deep run failed.");
    } finally {
      setDeepBusy(false);
    }
  }

  const gaps: any[] = agentRes?.gaps || [];
  const suggested: string[] = agentRes?.suggested_plugins || [];
  const manual: string[] = agentRes?.manual_tests || [];

  return (
    <div className="space-y-3">
      <div className="card p-4">
        <h2 className="font-semibold text-violet-300">Uncensored Assistant</h2>
        <p className="text-xs text-slate-500 mt-1">
          Ask about this scan, or let the agent find coverage gaps and go deeper.
        </p>
        <div className="flex gap-2 mt-3">
          {(["chat", "agent"] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={`chip px-4 py-2.5 min-h-[44px] text-sm capitalize ${mode === m ? "bg-violet-900 text-violet-200" : "text-slate-400"}`}>
              {m}
            </button>
          ))}
        </div>
      </div>

      {mode === "chat" && (
        <div className="card p-4">
          <div className="space-y-2 max-h-[50vh] overflow-y-auto mb-3">
            {msgs.length === 0 && !sending && (
              <p className="text-xs text-slate-500">
                Ask anything about this scan: what the findings mean, what to check next, how to test a vulnerability manually.
              </p>
            )}
            {msgs.map((m, i) => (
              <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded-lg px-3 py-2 text-sm whitespace-pre-wrap break-words ${
                  m.role === "user" ? "bg-violet-900 text-violet-100" : "bg-slate-800 text-slate-200"
                }`}>{m.text}</div>
              </div>
            ))}
            {sending && (
              <div className="flex justify-start">
                <div className="rounded-lg px-3 py-2 text-sm text-violet-300 bg-slate-800 animate-pulse">typing...</div>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>
          {chatErr && <p className="text-xs text-red-400 mb-2">{chatErr}</p>}
          <div className="flex gap-2">
            <input className="input text-sm px-3 py-2.5 min-h-[44px] flex-1 min-w-[140px]"
              placeholder="Ask about this scan..."
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") sendChat(); }} />
            <button onClick={sendChat} disabled={sending || !draft.trim()}
              className="chip px-5 py-2.5 min-h-[44px] text-sm text-violet-300 border border-violet-800/50 disabled:opacity-50">
              {sending ? "..." : "Send"}
            </button>
          </div>
        </div>
      )}

      {mode === "agent" && (
        <div className="space-y-3">
          <div className="card p-4">
            <h3 className="font-semibold text-violet-300 text-sm">Gap analysis</h3>
            <div className="space-y-2 mt-2">
              <input className="input text-sm px-3 py-2.5 min-h-[44px] w-full"
                placeholder="Run ID"
                value={agentRunId}
                onChange={(e) => setAgentRunId(e.target.value)} />
              <textarea className="input text-sm px-3 py-2.5 w-full min-h-[88px]"
                placeholder="What should I look for?"
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)} />
              <button onClick={runAgent} disabled={agentBusy || !instruction.trim()}
                className="chip px-5 py-2.5 min-h-[44px] text-sm text-violet-300 border border-violet-800/50 disabled:opacity-50">
                {agentBusy ? "Analyzing..." : "Analyze"}
              </button>
            </div>
            {agentErr && <p className="text-xs text-red-400 mt-2">{agentErr}</p>}
          </div>

          {agentRes && (
            <>
              {agentRes.summary && (
                <div className="card p-4">
                  <h3 className="font-semibold text-violet-300 text-sm mb-1">Summary</h3>
                  <p className="text-sm text-slate-300 whitespace-pre-wrap break-words">{agentRes.summary}</p>
                </div>
              )}
              {gaps.length > 0 && (
                <div className="card p-4">
                  <h3 className="font-semibold text-violet-300 text-sm mb-2">Coverage gaps <span className="text-slate-500 text-xs">({gaps.length})</span></h3>
                  <div className="space-y-2">
                    {gaps.map((g: any, i: number) => (
                      <div key={i} className="border border-slate-800 rounded p-3">
                        <p className="text-xs font-semibold text-slate-200">
                          {typeof g === "string" ? g : g.title || JSON.stringify(g)}
                        </p>
                        {typeof g !== "string" && g.description && (
                          <p className="text-[11px] text-slate-400 mt-1 whitespace-pre-wrap break-words">{g.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {suggested.length > 0 && (
                <div className="card p-4">
                  <h3 className="font-semibold text-violet-300 text-sm mb-2">Suggested plugins</h3>
                  <div className="flex gap-2 flex-wrap mb-3">
                    {suggested.map((p, i) => (
                      <span key={i} className="text-xs px-2 py-1.5 rounded bg-violet-900/40 text-violet-200 border border-violet-800/50">{p}</span>
                    ))}
                  </div>
                  <button onClick={deepRun} disabled={deepBusy}
                    className="chip px-5 py-2.5 min-h-[44px] text-sm text-violet-300 border border-violet-800/50 disabled:opacity-50">
                    {deepBusy ? "Starting deep run..." : "Run these plugins deeper"}
                  </button>
                </div>
              )}
              {manual.length > 0 && (
                <div className="card p-4">
                  <h3 className="font-semibold text-violet-300 text-sm mb-2">Manual tests</h3>
                  <ol className="list-decimal list-inside text-xs text-slate-400 space-y-1">
                    {manual.map((t: any, i: number) => (
                      <li key={i} className="whitespace-pre-wrap break-words">{typeof t === "string" ? t : t.title || JSON.stringify(t)}</li>
                    ))}
                  </ol>
                </div>
              )}
            </>
          )}
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

function AtmView({ runId, findings }: { runId: string; findings: Finding[] }) {
  const [checked, setChecked] = useState(false);
  const [query, setQuery] = useState("");
  const [atms, setAtms] = useState<any[]>([]);
  const [busy, setBusy] = useState(false);
  const [starting, setStarting] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const atmFindings = findings.filter((f) => f.plugin === "atm" || f.key.startsWith("atm_"));

  async function locate() {
    if (!checked) { setErr("Check the authorization box first."); return; }
    if (!query.trim()) { setErr("Enter a bank name, address, or lat,lon."); return; }
    setBusy(true); setErr(""); setMsg("");
    try {
      const d = await api<{ atms: any[]; radius_m: number }>(`/api/runs/${runId}/atm/locate`, {
        method: "POST",
        body: JSON.stringify({ query: query.trim(), authorized: true }),
      });
      setAtms(d.atms || []);
      setMsg(`found ${d.atms?.length || 0} ATMs within ${d.radius_m}m`);
    } catch (e: any) {
      setErr(e.message || "locate failed");
    } finally {
      setBusy(false);
    }
  }

  async function startRun() {
    if (!checked) { setErr("Check the authorization box first."); return; }
    if (!query.trim()) { setErr("Enter a location in the box above first (address, city, or lat,lon)."); return; }
    setStarting(true); setErr("");
    try {
      const d = await api<{ run_id: string }>("/api/runs", {
        method: "POST",
        // ATM is a source type now: location -> nearby ATMs -> assess each.
        body: JSON.stringify({ targets: query.trim(), mode: "passive", source_type: "atm" }),
      });
      window.location.href = `/run/${d.run_id}`;
    } catch (e: any) {
      setErr(e.message || "could not start run");
    } finally {
      setStarting(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="card p-4 border-l-4 border-red-500 bg-red-500/5">
        <p className="text-sm font-semibold text-red-300">WARNING</p>
        <p className="text-sm text-slate-200 mt-1">Only assess ATMs you own or have WRITTEN authorization to test. Unauthorized ATM testing is a crime.</p>
        <label className="flex items-center gap-2 mt-3 text-sm text-slate-200 min-h-[44px]">
          <input type="checkbox" className="w-5 h-5" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
          I have written authorization to assess these ATMs
        </label>
      </div>

      <div className="card p-4 space-y-3">
        <h2 className="font-semibold text-sky-300 text-sm">Locate ATMs (public map data)</h2>
        <div className="flex gap-2 flex-wrap">
          <input className="input text-sm px-3 py-2.5 min-h-[44px] flex-1 min-w-[180px]" placeholder='bank name, address, or "49.8951,-97.1384" or "lat,lon,radius_m"' value={query} onChange={(e) => setQuery(e.target.value)} />
          <button className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300" onClick={locate} disabled={busy}>{busy ? "locating..." : "Locate ATMs"}</button>
        </div>
        {atms.length > 0 && (
          <div className="space-y-2">
            {atms.map((a, i) => (
              <div key={i} className="rounded-lg p-3 border border-slate-700/50 bg-slate-800/50 text-sm">
                <p className="text-slate-200 font-medium">{a.name || "ATM"}{a.operator ? <span className="text-slate-400"> ({a.operator})</span> : null}</p>
                <p className="text-xs text-slate-500 font-mono">{a.lat}, {a.lon}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card p-4 space-y-3">
        <h2 className="font-semibold text-sky-300 text-sm">Start ATM assessment run</h2>
        <p className="text-xs text-slate-500">Uses the location you entered above. Finds every ATM nearby via OpenStreetMap and assesses each one.</p>
        <div className="flex gap-2 flex-wrap">
          <button className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300" onClick={startRun} disabled={starting}>{starting ? "starting..." : "Assess ATMs at this location"}</button>
        </div>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}
      {msg && <p className="text-sm text-green-400">{msg}</p>}

      <div className="card p-4">
        <h2 className="font-semibold text-sky-300 text-sm mb-2">ATM findings ({atmFindings.length})</h2>
        {atmFindings.length === 0 ? (
          <p className="text-sm text-slate-500">No ATM findings in this run yet. Start an ATM assessment run above.</p>
        ) : (
          <div className="space-y-2">
            {atmFindings.map((f, i) => (
              <div key={i} className="rounded-lg p-3 border border-slate-700/50 bg-slate-800/50">
                <code className="text-amber-300 text-xs font-mono">{f.key}</code>
                <p className="text-sm text-slate-200 mt-1 break-words whitespace-pre-wrap">{f.value}</p>
              </div>
            ))}
          </div>
        )}
      </div>
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
