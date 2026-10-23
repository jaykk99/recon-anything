"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { getCode, api } from "../../../lib/api";
import AuthGate from "../../../components/AuthGate";

interface Finding {
  plugin: string; category: string; key: string; value: string;
  source: string; source_url?: string; confidence: number; passive: boolean;
  attacker_impact?: string;
  evidence?: Record<string, any>;
  // Present on findings served by the run-detail API; id powers the
  // findings playground (re-test endpoint is addressed by run + id).
  id?: number; target_id?: string;
}

interface RetestResult {
  plugin: string; plugin_label?: string; target: string; target_type?: string;
  status: string; reason: string; duration_ms: number; verdict: string;
  checked_at: string; fresh_count: number;
  original: Finding & { id: number };
  fresh_findings: Finding[];
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

// Single source of truth for "what belongs on the Ports tab".
// The tab badge AND the PortsView both use this, so the count
// can never disagree with what is displayed.
function isPortFinding(f: Finding): boolean {
  const k = f.key || "";
  if (k === "port_open" || k === "port_suggestion") return true;
  if (k === "http_banner" || k === "tcp_banner" || k === "banner_note") return true;
  if (k === "tls_nonstandard" || k === "os_guess") return true;
  // danger exposures from port_audit: ftp_open, telnet_open, mongodb_open, ...
  if (/_open$/.test(k) && f.plugin === "port_audit") return true;
  return false;
}
// Same idea for the other tabs: badge count always uses the same
// filter the tab view uses, so counts never disagree with lists.
//
// Secrets/creds classification is built from the keys plugins ACTUALLY
// emit (keyharvest: aws_key; secrets: js_secret; comments:
// comment_credential; artifacts: exposed_env; jwt: jwt_token; ...).
// The old rule (key starts with exposed_/wallet_) matched almost none
// of them, so the tabs showed 0 while leak findings existed.
const SECRET_KEY_RE =
  /(secret|password|passwd|api_?key|access_?key|private_?key|jwt|seed|mnemonic|wallet_?file|exposed_env|laravel_env|hardcoded)/;
const SECRET_POINTER_RE = /^(keyleak_|github_dork|github_manual|github_note)/;
function isSecretFinding(f: Finding): boolean {
  const k = f.key || "";
  if (SECRET_POINTER_RE.test(k)) return false; // dork links point AT secrets; not material
  if (SECRET_KEY_RE.test(k)) return true;
  // exposed_* counts only when the exposed thing is credential material
  // (an exposed admin panel or document is not a secret).
  return k.startsWith("exposed_") &&
    /(key|secret|token|env|credential|aws|github|jwt|password)/.test(k);
}
function isCredFinding(f: Finding): boolean {
  const k = f.key || "";
  return k.startsWith("cred_") || k.includes("credential") ||
    k === "iot_default_creds" || k === "default_creds" ||
    k === "default_credentials" || k === "plaintext_password" ||
    k === "exposed_hardcoded_password" || k === "exposed_card_number";
}
// Connections = relationship findings (the connections mapper's keys,
// plus payment/bank/crypto relationship keys other plugins emit).
function isConnectionFinding(f: Finding): boolean {
  const k = f.key || "";
  return k === "connected_domain" || k === "connected_device" ||
    k === "connected_service" || k === "connected_account" ||
    k === "connected_financial" || k === "connection_summary" ||
    k === "payment_processor" || k === "billing_endpoint" ||
    k.startsWith("bank_") || k.startsWith("crypto_");
}
function isSubdomainFinding(f: Finding): boolean {
  return f.key === "subdomain";
}
function isFileFinding(f: Finding): boolean {
  const k = f.key || "";
  return k === "artifact_exposed" || k === "artifact_archived" ||
    k === "artifact_guarded" || k === "open_directory" ||
    k === "opendir_archived";
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
// bounty-grade impact: backend stamps evidence.impact (1-10).
// "Big stuff only" = impact >= 7. "sort: impact" ranks by impact * confidence.
function impactOf(f: Finding): number {
  const v = Number(f.evidence?.impact ?? 0);
  return isNaN(v) ? 0 : v;
}
// plain-language "what an attacker can do with this" (backend stamps it
// top-level on API rows and inside evidence at creation time).
function attackerImpactOf(f: Finding): string {
  return f.attacker_impact || (f.evidence?.attacker_impact as string) || "";
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
  const ai = attackerImpactOf(f);
  if (ai) md += `\n**What an attacker can do:** ${ai}\n`;
  if (f.evidence?.hash_type) md += `\n**Hash:** ${f.evidence.hash_type}${f.evidence.hash_purpose ? ` — what it is for: ${f.evidence.hash_purpose}` : ""}\n`;
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
function FindingCard({ f, open, onToggle, onPlayground }: {
  f: Finding; open: boolean; onToggle: () => void;
  onPlayground?: (f: Finding) => void;
}) {
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
          {impactOf(f) > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border text-amber-300 border-amber-500/40 bg-amber-500/10"
              title="bounty impact score, 1-10">impact {impactOf(f)}/10</span>
          )}
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
          {attackerImpactOf(f) && (
            <p className="text-red-300/90 break-words"><span className="font-semibold">What an attacker can do: </span>{attackerImpactOf(f)}</p>
          )}
          {ev.hash_type && (
            <p className="text-amber-300/90 break-words"><span className="font-semibold">Hash: </span>{ev.hash_type}{ev.hash_purpose ? ` — what it is for: ${ev.hash_purpose}` : ""}</p>
          )}
          <p className="text-slate-400 break-words"><span className="font-semibold">Source: </span>{f.source}</p>
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
            {onPlayground && f.id != null && (
              <button className="text-emerald-300 px-3 py-2 min-h-[44px] rounded-lg bg-emerald-950/60 border border-emerald-800/50"
                onClick={() => onPlayground(f)}>Test in playground</button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- findings playground ----------
// Re-test ONE finding in place: the endpoint re-runs only the plugin
// that produced the finding, against only that finding's own target
// (both are resolved server-side from the stored finding - there is
// no URL, plugin, or payload to inject), and compares fresh vs stored.
function PlaygroundPanel({ runId, finding, onClose }: {
  runId: string; finding: Finding; onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<RetestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const impact = finding.attacker_impact || finding.evidence?.attacker_impact || "";

  async function runRetest() {
    if (finding.id == null) return;
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`/api/runs/${runId}/findings/${finding.id}/retest`, {
        method: "POST",
        headers: { "X-Access-Code": getCode(), "Content-Type": "application/json" },
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setResult(d as RetestResult);
    } catch (e: any) {
      setError(e.message || "re-test failed");
    } finally {
      setBusy(false);
    }
  }

  const verdictBadge = (v: string) => {
    if (v === "unchanged") return "text-emerald-300 border-emerald-500/40 bg-emerald-500/10";
    if (v === "changed") return "text-amber-300 border-amber-500/40 bg-amber-500/10";
    return "text-rose-300 border-rose-500/40 bg-rose-500/10";
  };
  const verdictText = (v: string) => {
    if (v === "unchanged") return "UNCHANGED - still produced";
    if (v === "changed") return "CHANGED - same check, new value";
    if (v === "gone") return "GONE - no longer produced";
    return "ERROR - re-test failed";
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4"
      onClick={onClose}>
      <div className="bg-slate-950 rounded-t-2xl sm:rounded-2xl w-full sm:max-w-3xl max-h-[92vh] flex flex-col border border-slate-700"
        onClick={(e) => e.stopPropagation()}>
        <div className="p-4 border-b border-slate-800 flex items-center gap-2">
          <span className="text-sm font-semibold text-sky-300">Playground</span>
          <span className="text-xs text-slate-500">re-test this finding live</span>
          <button onClick={onClose}
            className="px-4 py-2.5 min-h-[44px] min-w-[44px] rounded-lg bg-slate-800 text-lg ml-auto">X</button>
        </div>
        <div className="overflow-auto flex-1 p-4 space-y-4">
          <p className="text-[11px] text-slate-500">
            Detection-only re-check: re-runs <span className="text-slate-300">{finding.plugin}</span> against
            this finding&apos;s own target, through the same code path as a scan job.
            The fresh result is shown next to the original; nothing is saved back to the run.
          </p>

          {/* original finding */}
          <div className={`rounded-lg p-3 space-y-1.5 border ${sevColor(normSev(finding))}`}>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevColor(normSev(finding))}`}>{normSev(finding).toUpperCase()}</span>
              <code className="text-amber-300 text-xs font-mono break-all">{finding.key}</code>
              <span className="text-[10px] text-slate-500 ml-auto">{finding.category} · {finding.plugin}</span>
            </div>
            <p className="text-sm break-words whitespace-pre-wrap">{finding.value}</p>
            <div className="flex items-center gap-2 flex-wrap text-xs pt-1">
              <span className="text-slate-500">source:</span>
              <span className="text-slate-400 break-all">{finding.source}</span>
              {finding.source_url && (
                <a href={finding.source_url} target="_blank" rel="noopener"
                  className="text-sky-400 underline">open source</a>
              )}
            </div>
            {impact && (
              <p className="text-xs text-rose-200/90 break-words pt-1">
                <span className="font-semibold">What an attacker can do: </span>{impact}
              </p>
            )}
            {finding.evidence && (
              <details className="pt-1">
                <summary className="text-xs text-slate-500 cursor-pointer py-1">stored evidence (raw)</summary>
                <pre className="text-[11px] font-mono bg-slate-950 rounded-lg p-3 overflow-auto whitespace-pre-wrap break-words max-h-[240px] border border-slate-800">
                  {JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </details>
            )}
          </div>

          <button
            onClick={runRetest}
            disabled={busy || finding.id == null}
            className="w-full chip px-4 py-3 min-h-[48px] text-sm text-emerald-300 bg-emerald-950/50 border border-emerald-800/50 disabled:opacity-50">
            {busy ? "Re-testing..." : `Run ${finding.plugin} again on this target`}
          </button>
          {finding.id == null && (
            <p className="text-xs text-amber-300">This finding has no stored id, so it cannot be re-tested.</p>
          )}
          {error && (
            <div className="rounded-lg p-3 border border-rose-500/40 bg-rose-500/10 text-sm text-rose-200 break-words">
              {error}
            </div>
          )}

          {/* fresh result, side by side with the original */}
          {result && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-[11px] font-extrabold px-2 py-0.5 rounded border ${verdictBadge(result.verdict)}`}>
                  {verdictText(result.verdict)}
                </span>
                <span className="text-[11px] text-slate-500">
                  plugin status: {result.status} · {fmtTime(result.duration_ms / 1000)} ·{" "}
                  {new Date(result.checked_at).toLocaleTimeString()}
                </span>
              </div>
              {result.reason && <p className="text-xs text-slate-400 break-words">{result.reason}</p>}
              <div className="grid sm:grid-cols-2 gap-3">
                <div className="rounded-lg border border-slate-800 p-3 space-y-2">
                  <p className="text-xs font-semibold text-slate-400">Original (stored)</p>
                  <code className="text-amber-300 text-xs font-mono break-all">{result.original.key}</code>
                  <p className="text-xs break-words whitespace-pre-wrap text-slate-300">{result.original.value}</p>
                </div>
                <div className="rounded-lg border border-slate-800 p-3 space-y-2">
                  <p className="text-xs font-semibold text-slate-400">
                    Fresh ({result.fresh_count} finding{result.fresh_count === 1 ? "" : "s"})
                  </p>
                  {result.fresh_findings.length === 0 ? (
                    <p className="text-xs text-slate-500">The plugin produced no findings this time.</p>
                  ) : result.fresh_findings.map((ff, i) => (
                    <div key={i} className="border-t border-slate-800/70 pt-2 first:border-t-0 first:pt-0">
                      <code className="text-amber-300 text-xs font-mono break-all">{ff.key}</code>
                      <p className="text-xs break-words whitespace-pre-wrap text-slate-300">{ff.value}</p>
                      {(ff.attacker_impact || ff.evidence?.attacker_impact) && (
                        <p className="text-[11px] text-rose-200/80 break-words mt-0.5">
                          {ff.attacker_impact || ff.evidence?.attacker_impact}
                        </p>
                      )}
                      <details>
                        <summary className="text-[11px] text-slate-500 cursor-pointer py-1">evidence (raw)</summary>
                        <pre className="text-[11px] font-mono bg-slate-950 rounded-lg p-2 overflow-auto whitespace-pre-wrap break-words max-h-[200px] border border-slate-800">
                          {JSON.stringify(ff.evidence || {}, null, 2)}
                        </pre>
                      </details>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function RunPageInner({ params }: { params: { id: string } }) {
  const id = params.id;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [targets, setTargets] = useState<{ raw: string; normalized: string; type: string }[]>([]);
  const [plugins, setPlugins] = useState<Record<string, PluginState>>({});
  const [status, setStatus] = useState("running");
  const [tab, setTab] = useState("findings");
  const [sourceType, setSourceType] = useState("website");
  const [envMode, setEnvMode] = useState("sandbox");
  const [authInfo, setAuthInfo] = useState<any>(null);
  const [summary, setSummary] = useState<any>(null);
  const [graph, setGraph] = useState<any>(null);
  const [apiMap, setApiMap] = useState<any>(null);
  const [cat, setCat] = useState("all");
  const [sev, setSev] = useState("all");
  const [sortBy, setSortBy] = useState("value");
  const [q, setQ] = useState("");
  // high-value findings view: weaponized/high first, noise collapsed
  const [highValueOnly, setHighValueOnly] = useState(false);
  // big stuff only: findings with evidence.impact >= 7
  const [bigOnly, setBigOnly] = useState(false);
  // bounty mode: run created with bounty=true. Once detected, default sort
  // to "impact" (once only, so a manual sort change is never clobbered).
  const [bounty, setBounty] = useState(false);
  const bountyInit = useRef(false);
  const applyBounty = (b: any) => {
    if (b === true) {
      setBounty(true);
      if (!bountyInit.current) { bountyInit.current = true; setSortBy("impact"); }
    }
  };
  const [agentActions, setAgentActions] = useState(0);
  const [shownTop, setShownTop] = useState(50);
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const [groupShown, setGroupShown] = useState<Record<string, number>>({});
  const [noiseOpen, setNoiseOpen] = useState(false);
  // reset paging when filters change
  useEffect(() => {
    setShownTop(50); setGroupShown({}); setOpenGroups({}); setExpanded({});
  }, [q, cat, sev, sortBy, highValueOnly, bigOnly]);
  // progress + ETA
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [estimatedS, setEstimatedS] = useState(0);
  const [etaS, setEtaS] = useState<number | null>(null);
  const [wafNotice, setWafNotice] = useState<string | null>(null);
  // Vuln candidate count for the tab badge (candidates live behind the
  // advisor endpoint, not in findings - see tabCount).
  const [vulnCount, setVulnCount] = useState(0);
  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const r = await fetch(`/api/runs/${id}/vulns`, { headers: { "X-Access-Code": getCode() } });
        if (!r.ok || !live) return;
        const j = await r.json();
        if (live && Array.isArray(j.candidates)) setVulnCount(j.candidates.length);
      } catch { /* badge just stays 0 until a load succeeds */ }
    })();
    return () => { live = false; };
  }, [id, status]);
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

  // the atm tab only exists on ATM / bank-atm source-type runs; never leave it selected elsewhere
  useEffect(() => {
    if (tab === "atm" && sourceType !== "atm" && sourceType !== "bankatm") setTab("findings");
  }, [tab, sourceType]);

  useEffect(() => {
    // Fresh attempt (mount or Retry button): reset health, allow loops again.
    done.current = false;
    failCount.current = 0;
    setFatal(null);
    setSseState("connecting");
    setFeedState("ok");

    const es = new EventSource(`/live/runs/${id}/stream?code=${encodeURIComponent(getCode())}`);
    // Any SSE event at all means the stream is alive.
    const on = (ev: string, fn: (e: MessageEvent) => void) =>
      es.addEventListener(ev, ((e: MessageEvent) => { setSseState("live"); fn(e); }) as EventListener);
    on("run_start", (e) => {
      const d = JSON.parse(e.data);
      if (d.source_type) setSourceType(d.source_type);
      if (d.estimated_s) setEstimatedS(d.estimated_s);
      if (d.source_type) setSourceType(d.source_type);
      if (d.plugin_count) setProgress({ done: 0, total: d.plugin_count * (d.target_count || 1) });
      applyBounty(d.bounty);
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
        applyBounty(d.run?.bounty);
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
        if (d.auth !== undefined) setAuthInfo(d.auth);
        if (Array.isArray(d.targets) && d.targets.length > 0) setTargets(d.targets);
      }
      if (d.run?.status === "done" || d.run?.status === "failed") {
        setStatus(d.run.status); setFindings(d.findings || []); setSummary(d.run.summary);
        setTargets(d.targets || []);
        applyBounty(d.run?.bounty);
        done.current = true;
        // keep the dedupe set in sync so late SSE events do not duplicate
        (d.findings || []).forEach((f: any) => {
          seenFids.current.add(f.id != null ? `fid:${f.id}` : `c:${f.plugin}|${f.key}|${f.value}`);
        });
        if (d.run?.source_type) setSourceType(d.run.source_type);
        if (d.run?.env_mode) setEnvMode(d.run.env_mode);
        if (d.auth !== undefined) setAuthInfo(d.auth);
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
    (!bigOnly || impactOf(f) >= 7) &&
    (!q || (f.key + f.value + f.plugin + (f.evidence?.severity || "") + (f.evidence?.exploitability || "")).toLowerCase().includes(q.toLowerCase())));

  // sort: value (default rank), severity, plugin, confidence, impact
  const sortFindings = (list: Finding[]) => {
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const arr = [...list];
    if (sortBy === "severity") arr.sort((a, b) => (sevRank[sevOf(a)] ?? 4) - (sevRank[sevOf(b)] ?? 4));
    else if (sortBy === "plugin") arr.sort((a, b) => (a.plugin || "").localeCompare(b.plugin || ""));
    else if (sortBy === "confidence") arr.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    else if (sortBy === "impact") arr.sort((a, b) => (impactOf(b) * (b.confidence || 0)) - (impactOf(a) * (a.confidence || 0)));
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
  // findings playground: the finding currently open in the panel
  const [playground, setPlayground] = useState<Finding | null>(null);

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
          {envMode === "sandbox"
            ? <span title="Sandbox run: own/lab targets only, does not count as production findings" className="text-xs px-2 py-1 rounded min-h-[28px] flex items-center border border-amber-500/40 bg-amber-500/10 text-amber-200">SANDBOX</span>
            : <span title="Live run: production findings" className="text-xs px-2 py-1 rounded min-h-[28px] flex items-center border border-emerald-500/40 bg-emerald-500/10 text-emerald-200">LIVE</span>}
          {bounty && (
            <span className="text-xs font-bold px-2 py-1 rounded min-h-[28px] flex items-center bg-amber-900 text-amber-200 border border-amber-700"
              title="bounty mode: high-impact vuln classes prioritized, findings sorted by impact">
              BOUNTY MODE
            </span>
          )}
          {authInfo && (
            <span className="text-xs font-bold px-2 py-1 rounded min-h-[28px] flex items-center bg-violet-900 text-violet-200 border border-violet-700"
              title={`${authInfo.label || "authenticated"} — attested by ${authInfo.attestation?.attested_by || "owner"} at ${authInfo.attestation?.attested_at || ""}. Authenticated: scans behind the login of your own systems. For authorized testing only.`}>
              AUTHENTICATED
            </span>
          )}
          <span className="text-xs text-slate-500">{findings.length} findings</span>
        </div>
        {authInfo && (
          <p className="text-xs text-violet-300/80 mt-2">
            {authInfo.label} — attested by {authInfo.attestation?.attested_by || "owner"}
            {authInfo.attestation?.attested_at ? ` at ${authInfo.attestation.attested_at}` : ""}.
            Credentials are scoped to the target hosts only and wiped when the run finishes.{" "}
            {authInfo.disclaimer || "Authenticated: scans behind the login of your own systems. For authorized testing only."}
          </p>
        )}
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
        {summary?.bankatm && (
          <div className="mt-3 text-sm space-y-1">
            <p className="text-emerald-300">
              Bank / ATM mode{summary.bankatm.input_kind === "domain"
                ? <> — financial set on <span className="font-mono">{summary.bankatm.domain}</span></>
                : <> — {summary.bankatm.pois ?? summary.bankatm.locations?.length ?? 0} locations near {summary.bankatm.location}
                    {summary.bankatm.resolved_domains?.length
                      ? <>, assessing {(summary.bankatm.resolved_domains as string[]).join(", ")}</>
                      : ", no operator domain resolved"}</>}
            </p>
            {summary.bankatm.input_kind === "location" && (summary.bankatm.locations || []).length > 0 && (
              <ul className="text-xs text-slate-400 space-y-0.5">
                {(summary.bankatm.locations as any[]).map((l, i) => (
                  <li key={i}>
                    {l.poi_type === "atm" ? "ATM" : "Bank"}: {l.name}
                    {l.operator ? ` (${l.operator})` : ""}{l.address ? ` — ${l.address}` : ""}
                    {l.resolved_domain
                      ? <span className="text-slate-500"> → {l.resolved_domain}{l.domain_assessed ? "" : " (over cap, listed only)"}</span>
                      : <span className="text-slate-500"> → no public domain resolved</span>}
                  </li>
                ))}
              </ul>
            )}
          </div>
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
            if (t === "secrets") return findings.filter(isSecretFinding).length;
            if (t === "creds") return findings.filter(isCredFinding).length;
            if (t === "subdomains") return findings.filter(isSubdomainFinding).length;
            if (t === "ports") return findings.filter(isPortFinding).length;
            if (t === "files") return findings.filter(isFileFinding).length;
            if (t === "connections") return findings.filter(isConnectionFinding).length;
            if (t === "atm") return findings.filter((f) => f.plugin === "atm" || f.key.startsWith("atm_")).length;
            // Vuln candidates come from the advisor endpoint, NOT from
            // findings (no plugin emits a "vuln" category) - counting
            // findings here always showed 0.
            if (t === "vulns") return vulnCount;
            if (t === "agents") return agentActions;
            return 0;
          };
          const tabLabel = (t: string) => {
            const c = tabCount(t);
            const name = t;
            return c > 0 ? `${name} (${c})` : name;
          };
          return (["findings", "vulns", "atm", "connections", "secrets", "creds", "subdomains", "ports", "files", "graph", "agents", "apimap", "raw"] as const)
            .filter((t) => t !== "atm" || sourceType === "atm" || sourceType === "bankatm")
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
        <button
          onClick={() => setBigOnly((v) => !v)}
          title="only findings with impact >= 7"
          className={`chip px-4 py-2.5 min-h-[44px] text-sm whitespace-nowrap ${bigOnly ? "bg-amber-900 text-amber-200 border border-amber-700" : "text-slate-300"}`}>
          {bigOnly ? "✓ Big stuff only" : "Big stuff only"}
        </button>
        <select className="input text-sm px-3 py-2.5 min-h-[44px]" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="value">sort: value</option>
          <option value="severity">sort: severity</option>
          <option value="confidence">sort: confidence</option>
          <option value="impact">sort: impact</option>
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
                return <FindingCard key={ek} f={f} open={!!expanded[ek]} onToggle={() => toggleCard(ek)} onPlayground={(ff) => setPlayground(ff)} />;
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
                            return <FindingCard key={ek} f={f} open={!!expanded[ek]} onToggle={() => toggleCard(ek)} onPlayground={(ff) => setPlayground(ff)} />;
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
      {tab === "atm" && <AtmView runId={id} findings={findings} />}
      {tab === "connections" && <ConnectionsView findings={findings} graph={graph} />}
      {tab === "subdomains" && <SubdomainsView runId={id} findings={findings} />}
      {tab === "ports" && <PortsView runId={id} findings={findings} targets={targets} />}
      {tab === "files" && <FilesView findings={findings} onView={viewFile} />}
      {tab === "secrets" && <SecretsView findings={findings} onView={viewFile} />}
      {tab === "creds" && <CredsView findings={findings} />}
      {tab === "graph" && <GraphView graph={graph} />}
      {tab === "agents" && <AgentsView runId={id} live={status !== "done"} onCount={setAgentActions} />}
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

      {/* findings playground panel */}
      {playground && (
        <PlaygroundPanel runId={id} finding={playground} onClose={() => setPlayground(null)} />
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
  const subs = findings.filter(isSubdomainFinding);
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
  // Same filter as the tab badge: the count and the list can never disagree.
  const ports = findings.filter(isPortFinding);
  const [probes, setProbes] = useState<Record<string, PortProbe>>({});
  const [probing, setProbing] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  function parsePort(f: Finding) {
    const evPort = (f.evidence as any)?.port;
    if (typeof evPort === "number" && evPort > 0) {
      return { port: evPort, service: String((f.evidence as any)?.service || "unknown") };
    }
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
  // Structured evidence table: shows what is actually inside the finding,
  // not just the text summary.
  function evidenceRows(f: Finding): [string, string][] {
    const ev: any = f.evidence || {};
    const rows: [string, string][] = [];
    const push = (k: string, v: any) => {
      if (v === undefined || v === null || v === "") return;
      rows.push([k, typeof v === "object" ? JSON.stringify(v, null, 1) : String(v)]);
    };
    push("Port", ev.port);
    push("Service", ev.service);
    push("IP", ev.ip);
    push("Version", ev.version);
    push("OS hint", ev.os_hint || ev.os);
    push("TLS", ev.tls ? (typeof ev.tls === "object" ? JSON.stringify(ev.tls) : ev.tls) : undefined);
    push("Detected via", ev.via);
    push("Default-credential risk", ev.default_cred_risk);
    push("Exploitability", ev.exploitability);
    return rows;
  }
  const host = baseHost();
  const openPorts = ports.filter((f) => f.key === "port_open");
  const sugPorts = ports.filter((f) => f.key === "port_suggestion");
  const danger = ports.filter((f) => /_open$/.test(f.key) && f.key !== "port_open" && f.plugin === "port_audit");
  const banners = ports.filter((f) => f.key === "http_banner" || f.key === "tcp_banner" || f.key === "banner_note");
  const misc = ports.filter((f) => f.key === "tls_nonstandard" || f.key === "os_guess");
  const sev = (f: Finding) => normSev(f);
  function renderRow(f: Finding, i: number, kind: "danger" | "open" | "banner" | "suggested" | "misc") {
    const ek = `ports:${kind}:${i}`;
    const isOpen = !!expanded[ek];
    const { port, service } = parsePort(f);
    const url = port > 0 ? webUrl(host, port) : "";
    const key = `${host}:${port}`;
    const pr = probes[key];
    const banner = (f.evidence as any)?.banner || pr?.banner || "";
    const rows = evidenceRows(f);
    const ev: any = f.evidence || {};
    const dot = kind === "danger" ? "bg-red-500" : kind === "open" ? "bg-green-400" : kind === "banner" ? "bg-sky-400" : "bg-slate-600";
    const tag = kind === "danger" ? "DANGER" : kind === "open" ? "OPEN" : kind === "banner" ? "BANNER" : kind === "suggested" ? "SUGGESTED" : "INFO";
    const tagCls = kind === "danger" ? "pill-err" : kind === "open" ? "bg-green-900/50 text-green-300" : "pill-info";
    return (
      <div key={ek} className={`px-3 py-2.5 rounded-lg bg-slate-800/50 ${kind === "danger" ? "border-l-2 border-red-500" : ""}`}>
        <button className="w-full text-left min-h-[44px]" onClick={() => setExpanded((e) => ({ ...e, [ek]: !e[ek] }))}>
          <div className="flex items-center gap-2 text-sm flex-wrap">
            <span className={`w-2 h-2 rounded-full shrink-0 ${dot}`} />
            {url ? (
              <a href={url} target="_blank" rel="noreferrer" className="font-mono text-sky-300 hover:underline"
                onClick={(e) => e.stopPropagation()}>
                {host}:{port} <span className="text-slate-400">({service})</span>
              </a>
            ) : port > 0 ? (
              <span className="font-mono text-slate-300">{host ? `${host}:` : ""}{port} <span className="text-slate-500">({service})</span></span>
            ) : (
              <code className="text-amber-300 text-xs font-mono break-all">{f.key.replace(/_/g, " ")}</code>
            )}
            <span className={`text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap ${tagCls}`}>{tag}</span>
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevColor(sev(f))}`}>{sev(f).toUpperCase()}</span>
            {kind === "open" && host && port > 0 && (
              <span className="ml-auto" onClick={(e) => e.stopPropagation()}>
                <button onClick={() => probe(host, port)} disabled={probing === key}
                  className="chip px-2.5 py-2 min-h-[40px] text-[11px] text-emerald-300 whitespace-nowrap">
                  {probing === key ? "..." : "probe"}
                </button>
              </span>
            )}
            <span className="text-slate-500 text-xs">{isOpen ? "▲" : "▼"}</span>
          </div>
          <p className="text-xs text-slate-400 mt-1 break-words whitespace-pre-wrap">{f.value}</p>
        </button>
        {isOpen && (
          <div className="pt-2 mt-1 border-t border-slate-700/50 space-y-2">
            {rows.length > 0 && (
              <table className="w-full text-xs">
                <tbody>
                  {rows.map(([k, v], ri) => (
                    <tr key={ri} className="border-b border-slate-800/60">
                      <td className="py-1 pr-3 text-slate-500 whitespace-nowrap align-top w-1/3">{k}</td>
                      <td className="py-1 font-mono text-slate-200 break-all whitespace-pre-wrap">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {(banner || pr?.http?.title) && (
              <p className="text-[11px] text-slate-500 font-mono break-all">
                <span className="text-slate-400 font-sans">banner: </span>
                {banner}{pr?.http?.title ? ` | ${pr.http.title}` : ""}
              </p>
            )}
            {attackerImpactOf(f) && (
              <p className="text-xs text-red-300/90 break-words"><span className="font-semibold">What an attacker can do: </span>{attackerImpactOf(f)}</p>
            )}
            <p className="text-xs text-slate-400 break-words"><span className="font-semibold">Source: </span>{f.source}</p>
            {ev.remediation && (
              <p className="text-xs text-green-300/90 break-words"><span className="font-semibold">Fix: </span>{ev.remediation}</p>
            )}
            {pr?.error && <p className="text-[11px] text-red-400/80">{pr.error}</p>}
            <div className="flex gap-2 flex-wrap text-[11px] text-slate-500">
              <span>plugin: {f.plugin}</span>
              <span>confidence: {f.confidence}%</span>
              {f.source_url && <a href={f.source_url} target="_blank" rel="noreferrer" className="text-sky-400">open source</a>}
            </div>
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="card p-4">
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <h2 className="font-semibold text-sky-300">Ports <span className="text-slate-500 text-xs">({ports.length})</span></h2>
      </div>
      <p className="text-xs text-slate-500 mb-3">Tap a row to expand full details. Tap a port to open it in your browser. Probe grabs the live banner.</p>
      {ports.length === 0 ? (
        <p className="text-sm text-slate-500">No port findings yet. Run an active scan for real results.</p>
      ) : (
        <div className="space-y-4">
          {danger.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs uppercase text-red-400 font-semibold">Dangerous exposures ({danger.length})</h3>
              {danger.map((f, i) => renderRow(f, i, "danger"))}
            </div>
          )}
          {openPorts.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs uppercase text-green-400 font-semibold">Open ports ({openPorts.length})</h3>
              {openPorts.map((f, i) => renderRow(f, i, "open"))}
            </div>
          )}
          {banners.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs uppercase text-sky-400 font-semibold">Banners ({banners.length})</h3>
              {banners.map((f, i) => renderRow(f, i, "banner"))}
            </div>
          )}
          {misc.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs uppercase text-slate-400 font-semibold">TLS / OS ({misc.length})</h3>
              {misc.map((f, i) => renderRow(f, i, "misc"))}
            </div>
          )}
          {sugPorts.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs uppercase text-slate-500 font-semibold">Suggested ({sugPorts.length})</h3>
              {sugPorts.map((f, i) => renderRow(f, i, "suggested"))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FilesView({ findings, onView }: { findings: Finding[]; onView: (url: string) => void }) {
  const files = findings.filter(isFileFinding);
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
  confidence_basis: string; needs_manual_verification: boolean;
  why_viable: string; poc_code: string; poc_lang: string;
  dry_run_steps: string[]; remediation: string; evidence_count: number;
  // Underlying findings (id/plugin/key) - powers "Test in playground".
  evidence_refs?: { id?: number; plugin?: string; key?: string; value?: string }[];
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

interface AgentRollup {
  name: string; specialty: string; actions: number; assets_found: number;
  jobs_enqueued: number; chained_jobs: number; dead_ends: number;
  findings_contributed: number; last_action_at: string | null;
  status: string;
}

interface AgentFeedItem {
  id: number; agent: string; action: string; asset_type: string;
  asset_value: string; description: string; at: string | null;
}

function AgentsView({ runId, live, onCount }: { runId: string; live: boolean; onCount?: (n: number) => void }) {
  const [agents, setAgents] = useState<AgentRollup[] | null>(null);
  const [feed, setFeed] = useState<AgentFeedItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let stop = false;
    const load = async () => {
      try {
        const r = await fetch(`/api/runs/${runId}/agent-activity`, { headers: { "X-Access-Code": getCode() } });
        const d = await r.json();
        if (stop) return;
        setAgents(d.agents || []);
        setFeed(d.actions || []);
        if (onCount) onCount(d.total_actions || 0);
      } catch {
        if (!stop && agents === null) setAgents([]);
      } finally {
        if (!stop) setLoading(false);
      }
    };
    load();
    // Same 4s cadence as the run page's poll fallback while the scan runs.
    const t = live ? setInterval(load, 4000) : undefined;
    return () => { stop = true; if (t) clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, live]);

  const statusPill = (s: string) => {
    if (s === "working") return "bg-emerald-900 text-emerald-200";
    if (s === "abandoned") return "bg-red-900 text-red-200";
    if (s === "idle") return "bg-slate-700 text-slate-300";
    return "bg-sky-900 text-sky-200";
  };
  const fmtTime = (iso: string | null) => {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime()) ? "" : d.toLocaleTimeString();
  };

  if (loading && agents === null) return <div className="card p-4 text-sm text-slate-400">loading agent activity...</div>;
  const list = [...feed].reverse();
  return (
    <div className="space-y-4">
      <div className="card p-4">
        <h2 className="text-xs uppercase text-slate-500 mb-2">Agents on this scan{live ? " (live)" : ""}</h2>
        {(!agents || agents.length === 0) && <p className="text-sm text-slate-500">No agent actions yet. Hunters start expanding once findings land.</p>}
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {(agents || []).map((a) => (
            <div key={a.name} className="rounded bg-slate-800/60 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-slate-200">{a.name}</span>
                <span className={`text-[11px] px-2 py-0.5 rounded ${statusPill(a.status)}`}>{a.status}</span>
              </div>
              {a.specialty && <div className="text-[11px] text-slate-500 mt-0.5">{a.specialty}</div>}
              <div className="text-xs text-slate-400 mt-2 flex flex-wrap gap-x-3 gap-y-1">
                <span>{a.actions} actions</span>
                <span>{a.assets_found} found</span>
                <span>{a.jobs_enqueued} jobs queued</span>
                {a.chained_jobs > 0 && <span>{a.chained_jobs} chained</span>}
                <span>{a.findings_contributed} findings</span>
                {a.dead_ends > 0 && <span>{a.dead_ends} dead ends</span>}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="card p-4">
        <h2 className="text-xs uppercase text-slate-500 mb-2">Activity feed</h2>
        {list.length === 0 && <p className="text-sm text-slate-500">Nothing yet.</p>}
        <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
          {list.map((it) => (
            <div key={it.id} className="text-sm flex gap-2 items-baseline">
              <span className="text-[11px] text-slate-500 whitespace-nowrap">{fmtTime(it.at)}</span>
              <span className="text-slate-200">{it.description}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function VulnsView({ runId }: { runId: string }) {
  const [cands, setCands] = useState<VulnCandidate[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [term, setTerm] = useState<{ cand: VulnCandidate; lines: string[]; busy: boolean } | null>(null);
  // findings playground: resolve a candidate's underlying finding and
  // open it in the shared playground panel
  const [pg, setPg] = useState<Finding | null>(null);
  const [pgBusy, setPgBusy] = useState<string | null>(null);
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

  async function openPlayground(c: VulnCandidate) {
    const ref = (c.evidence_refs || []).find((r) => r.id != null);
    if (!ref) return;
    setPgBusy(c.id);
    try {
      const d = await api<any>(`/api/runs/${runId}`);
      const f = (d.findings || []).find((x: any) => x.id === ref.id);
      if (f) setPg(f as Finding);
    } catch {
      // panel simply does not open; the run detail fetch failing is
      // already surfaced by the rest of this page
    } finally {
      setPgBusy(null);
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
                {c.needs_manual_verification ? (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border border-amber-700/60 text-amber-300" title={c.confidence_basis || "heuristic - verify manually"}>NEEDS MANUAL CHECK</span>
                ) : (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border border-emerald-700/60 text-emerald-300" title={c.confidence_basis || "directly observed by the scan"}>SCAN-CONFIRMED</span>
                )}
                <span className="text-slate-500 text-xs">{isOpen ? "▲" : "▼"}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1 break-words">{c.why_viable}</p>
              {c.confidence_basis && (
                <p className="text-[11px] text-slate-500 mt-1 break-words">
                  <span className="font-semibold text-slate-400">Why this confidence: </span>{c.confidence_basis}
                </p>
              )}
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
                {(c.evidence_refs || []).some((r) => r.id != null) && (
                  <button
                    className="w-full chip px-4 py-3 min-h-[48px] text-sm text-sky-300 bg-sky-950/50 border border-sky-800/50 disabled:opacity-50"
                    disabled={pgBusy === c.id}
                    onClick={() => openPlayground(c)}>
                    {pgBusy === c.id ? "Opening playground..." : "Test in playground (re-run the finding's own check)"}
                  </button>
                )}
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

      {/* findings playground panel (from a candidate's evidence) */}
      {pg && (
        <PlaygroundPanel runId={runId} finding={pg} onClose={() => setPg(null)} />
      )}
    </div>
  );
}

function SecretsView({ findings, onView }: { findings: Finding[]; onView: (url: string) => void }) {
  const [typeFilter, setTypeFilter] = useState("all");
  const secrets = findings.filter(isSecretFinding);
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
              <p className="text-xs text-slate-500 mt-1 break-words"><span className="font-semibold">Source: </span>{f.source}</p>
              {attackerImpactOf(f) && (
                <p className="text-xs text-red-300/80 mt-1 break-words"><span className="font-semibold">What an attacker can do: </span>{attackerImpactOf(f)}</p>
              )}
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
  const creds = findings.filter(isCredFinding);
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
              <p className="text-xs text-slate-500 mt-1 break-words"><span className="font-semibold">Source: </span>{f.source}</p>
              {attackerImpactOf(f) && (
                <p className="text-xs text-red-300/80 mt-1 break-words"><span className="font-semibold">What an attacker can do: </span>{attackerImpactOf(f)}</p>
              )}
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
  const conns = findings.filter(isConnectionFinding);

  const byType: Record<string, Finding[]> = { device: [], service: [], account: [], financial: [], domain: [] };
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
  const connKinds = ["device", "service", "account", "financial", "domain"];
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
          {(["all", "device", "service", "account", "financial", "domain"] as const).map((t) => (
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
                <p className="text-xs text-slate-500 mt-1 break-words"><span className="font-semibold text-slate-400">Source: </span>{f.source}</p>
                {attackerImpactOf(f) && (
                  <p className="text-xs text-red-300/80 mt-1 break-words"><span className="font-semibold">What an attacker can do: </span>{attackerImpactOf(f)}</p>
                )}
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

// ---------- attack surface map: grouped by kind, collapsible, 50-at-a-time ----------
interface ApiMapEntry {
  url: string; method?: string; status?: number | string;
  auth?: string | boolean; params?: string[]; note?: string;
}
// render order + display labels for the backend's grouped shape
const APIMAP_GROUPS: [string, string][] = [
  ["api_routes", "API routes"],
  ["pages", "Pages"],
  ["forms", "Forms"],
  ["js_endpoints", "JS-discovered endpoints"],
  ["websockets", "WebSockets"],
  ["graphql", "GraphQL"],
];
function normalizeApiEntry(e: any): ApiMapEntry {
  const out: ApiMapEntry = { url: String(e?.url ?? "") };
  if (e?.method != null && e.method !== "") out.method = String(e.method);
  if (e?.status != null && e.status !== "") out.status = e.status;
  if (e?.auth != null && e.auth !== "" && e.auth !== false) out.auth = e.auth;
  if (Array.isArray(e?.params) && e.params.length > 0) out.params = e.params.map(String);
  if (e?.note != null && e.note !== "") out.note = String(e.note);
  return out;
}
// Backend may return the new grouped shape {groups:{...},counts:{...}} or the
// old flat shape {entries:{url:{methods,status,auth,note}}} (or an entries array).
function normalizeApiMap(data: any): { key: string; label: string; items: ApiMapEntry[] }[] {
  const g = data?.groups;
  if (g && typeof g === "object" && !Array.isArray(g)) {
    const groups: { key: string; label: string; items: ApiMapEntry[] }[] = [];
    for (const [key, label] of APIMAP_GROUPS) {
      if (Array.isArray(g[key])) groups.push({ key, label, items: g[key].map(normalizeApiEntry) });
    }
    // any extra group keys the backend adds later still render
    for (const k of Object.keys(g)) {
      if (!APIMAP_GROUPS.some(([gk]) => gk === k) && Array.isArray(g[k]))
        groups.push({ key: k, label: k.replace(/_/g, " "), items: g[k].map(normalizeApiEntry) });
    }
    return groups;
  }
  // old flat shape
  const entries = data?.entries;
  let items: ApiMapEntry[] = [];
  if (Array.isArray(entries)) {
    items = entries.map((e: any) =>
      typeof e === "string" ? { url: e } : normalizeApiEntry({ url: e?.url ?? e?.path, method: e?.method, status: e?.status, auth: e?.auth, params: e?.params, note: e?.note }));
  } else if (entries && typeof entries === "object") {
    items = Object.entries(entries).map(([url, v]: any) => normalizeApiEntry({
      url, method: (v?.methods || []).join(" ") || v?.method,
      status: v?.status, auth: v?.auth, params: v?.params, note: v?.note,
    }));
  }
  return items.length > 0 ? [{ key: "endpoints", label: "Endpoints", items }] : [];
}
function statusBadgeClass(s: number | string): string {
  const n = parseInt(String(s), 10);
  if (!isNaN(n)) {
    if (n < 300) return "text-green-300 border-green-700 bg-green-950/60";
    if (n < 400) return "text-sky-300 border-sky-700 bg-sky-950/60";
    if (n < 500) return "text-amber-300 border-amber-700 bg-amber-950/60";
    return "text-red-300 border-red-700 bg-red-950/60";
  }
  return "text-slate-400 border-slate-700 bg-slate-800/60";
}
function ApiMapView({ data }: { data: any }) {
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const [groupShown, setGroupShown] = useState<Record<string, number>>({});
  if (!data) return <div className="card p-4 text-sm text-slate-500">API map builds when the run finishes...</div>;
  const groups = normalizeApiMap(data).filter((g) => g.items.length > 0);
  if (groups.length === 0) return <div className="card p-4 text-sm text-slate-500">No attack-surface entries found.</div>;
  const total = groups.reduce((n, g) => n + g.items.length, 0);
  return (
    <div className="card p-4">
      <h2 className="font-semibold text-sky-300 mb-1">Attack surface <span className="text-slate-500 text-xs">({total} endpoints)</span></h2>
      <p className="text-xs text-slate-500 mb-3">Every reachable surface grouped by kind. Tap a group to expand.</p>
      <div className="space-y-2">
        {groups.map((g) => {
          const isOpen = !!openGroups[g.key];
          const vis = groupShown[g.key] || 50;
          return (
            <div key={g.key} className="rounded-lg border border-slate-700/60 bg-slate-800/40">
              <button
                className="w-full text-left min-h-[48px] px-3 py-2.5 flex items-center gap-2 flex-wrap"
                onClick={() => setOpenGroups((o) => ({ ...o, [g.key]: !o[g.key] }))}>
                <span className="text-sm font-medium text-slate-200">{g.label} <span className="text-slate-400">({g.items.length})</span></span>
                <span className="text-slate-500 text-xs ml-auto">{isOpen ? "▲" : "▼"}</span>
              </button>
              {isOpen && (
                <div className="px-3 pb-3 space-y-1.5">
                  {g.items.slice(0, vis).map((e, i) => (
                    <div key={i} className="bg-slate-900/60 rounded-lg p-2.5">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {e.method && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border text-sky-300 border-sky-700 bg-sky-950/60 font-mono whitespace-nowrap">
                            {e.method}
                          </span>
                        )}
                        {e.status != null && (
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border whitespace-nowrap ${statusBadgeClass(e.status)}`}>
                            {String(e.status)}
                          </span>
                        )}
                        {e.auth != null && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border text-purple-300 border-purple-700 bg-purple-950/60 whitespace-nowrap">
                            {typeof e.auth === "boolean" ? "auth required" : `auth: ${e.auth}`}
                          </span>
                        )}
                        <code className="text-amber-300 text-xs font-mono break-all">{e.url}</code>
                      </div>
                      {e.params && e.params.length > 0 && (
                        <p className="text-[11px] text-slate-500 mt-1">params: <code className="font-mono text-slate-300">{e.params.join(", ")}</code></p>
                      )}
                      {e.note && <p className="text-[11px] text-slate-500 mt-0.5 break-words">{e.note}</p>}
                    </div>
                  ))}
                  {g.items.length > vis && (
                    <button
                      className="w-full chip px-4 py-3 min-h-[48px] text-sm text-sky-300"
                      onClick={() => setGroupShown((s) => ({ ...s, [g.key]: (s[g.key] || 50) + 50 }))}>
                      show more ({g.items.length - vis} remaining)
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function RunPage(props: { params: { id: string } }) {
  return (
    <AuthGate>
      <RunPageInner {...props} />
    </AuthGate>
  );
}
