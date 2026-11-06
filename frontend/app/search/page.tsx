"use client";
import { useEffect, useState } from "react";
import { api } from "../../lib/api";
import AuthGate from "../../components/AuthGate";

interface SearchResult {
  chain: string;
  address: string;
  name: string | null;
  verdict: string | null;
  recipient: string | null;
  value_usd: number | null;
  has_source: boolean;
  plugins: string[];
  finding_kinds: string[];
  functions: string[];
  snippet: string;
  sources: string[];
  first_seen: string | null;
  last_seen: string | null;
}

interface SearchResponse {
  query: string;
  count: number;
  took_ms: number;
  index: { contracts: number; built_at: string | null };
  results: SearchResult[];
}

const CHAINS = ["ethereum", "bsc", "polygon", "arbitrum", "base", "optimism", "solana"];
const VERDICTS = ["VERIFIED_REAL", "UNVERIFIED", "TRIGGER_ONLY", "FALSE_POSITIVE"];

function fmtUsd(v: number | null): string {
  if (v === null || v === undefined) return "-";
  if (v >= 1e9) return `$${(v / 1e9).toFixed(2)}B`;
  if (v >= 1e6) return `$${(v / 1e6).toFixed(2)}M`;
  if (v >= 1e3) return `$${(v / 1e3).toFixed(1)}k`;
  return `$${v.toFixed(2)}`;
}

const VERDICT_STYLE: Record<string, string> = {
  VERIFIED_REAL: "text-red-300",
  UNVERIFIED: "text-amber-300",
  TRIGGER_ONLY: "text-sky-300",
  FALSE_POSITIVE: "text-slate-500",
};

function SearchPageInner() {
  const [q, setQ] = useState("");
  const [chain, setChain] = useState("");
  const [plugin, setPlugin] = useState("");
  const [verdict, setVerdict] = useState("");
  const [recipient, setRecipient] = useState("");
  const [minValue, setMinValue] = useState("");
  const [hasSource, setHasSource] = useState("");
  const [data, setData] = useState<SearchResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function runSearch() {
    setLoading(true);
    setError("");
    const params = new URLSearchParams();
    if (q.trim()) params.set("q", q.trim());
    if (chain) params.set("chain", chain);
    if (plugin.trim()) params.set("plugin", plugin.trim());
    if (verdict) params.set("verdict", verdict);
    if (recipient.trim()) params.set("recipient", recipient.trim());
    if (minValue) params.set("min_value_usd", minValue);
    if (hasSource) params.set("has_source", hasSource);
    params.set("limit", "100");
    try {
      const d = await api<SearchResponse>(`/api/search?${params.toString()}`);
      setData(d);
    } catch (e) {
      setData(null);
      setError(e instanceof Error ? e.message : "search failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    runSearch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Search the collection</h1>
      <p className="text-xs text-slate-500">
        Every contract ReconAnything has collected: verified source, scanner
        results, hunt verdicts and audit adjudications in one index.
        {data?.index ? ` ${data.index.contracts.toLocaleString()} contracts indexed.` : ""}
      </p>
      <div className="card p-4 space-y-3">
        <div className="flex gap-2">
          <input
            className="input px-3 py-2 text-sm flex-1"
            placeholder="keywords: function names, identifiers, plugin ids (ANDed) - or a full address"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
          />
          <button className="btn px-5 py-2 text-sm" onClick={runSearch} disabled={loading}>
            {loading ? "Searching..." : "Search"}
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          <select className="input px-2 py-1 text-sm" value={chain} onChange={(e) => setChain(e.target.value)}>
            <option value="">any chain</option>
            {CHAINS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className="input px-2 py-1 text-sm" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="">any verdict</option>
            {VERDICTS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <input
            className="input px-2 py-1 text-sm w-48"
            placeholder="plugin id contains"
            value={plugin}
            onChange={(e) => setPlugin(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
          />
          <input
            className="input px-2 py-1 text-sm w-40"
            placeholder="recipient class"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
          />
          <input
            className="input px-2 py-1 text-sm w-36"
            placeholder="min value USD"
            type="number"
            min="0"
            value={minValue}
            onChange={(e) => setMinValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
          />
          <select className="input px-2 py-1 text-sm" value={hasSource} onChange={(e) => setHasSource(e.target.value)}>
            <option value="">source: any</option>
            <option value="true">has verified source</option>
            <option value="false">no source</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="card p-4 text-sm text-red-300">
          {error.startsWith("HTTP 401") || error.startsWith("HTTP 403")
            ? "Sign in to search the collection."
            : error}
        </div>
      )}

      {data && (
        <>
          <p className="text-xs text-slate-500">
            {data.count.toLocaleString()} matches, showing {data.results.length},
            in {data.took_ms} ms
            {data.index.built_at ? ` - index built ${data.index.built_at.slice(0, 10)}` : ""}
          </p>
          <div className="card p-4">
            <table className="grid">
              <thead>
                <tr>
                  <th>chain</th><th>contract</th><th>verdict</th>
                  <th>value</th><th>src</th><th>matched</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((r) => (
                  <tr key={`${r.chain}:${r.address}`}>
                    <td className="text-xs">{r.chain}</td>
                    <td>
                      <span className="font-mono text-sky-400 text-xs" title={r.address}>
                        {r.address.length > 22 ? `${r.address.slice(0, 12)}...${r.address.slice(-8)}` : r.address}
                      </span>
                      {r.name && <div className="text-xs text-slate-400">{r.name}</div>}
                      {r.plugins.length > 0 && (
                        <div className="text-[11px] text-slate-500">
                          {r.plugins.slice(0, 3).join(", ")}{r.plugins.length > 3 ? ` +${r.plugins.length - 3}` : ""}
                        </div>
                      )}
                    </td>
                    <td className={`text-xs ${r.verdict ? VERDICT_STYLE[r.verdict] || "" : "text-slate-500"}`}>
                      {r.verdict || "-"}
                      {r.recipient && <div className="text-[11px] text-slate-500">{r.recipient}</div>}
                    </td>
                    <td className="text-xs">{fmtUsd(r.value_usd)}</td>
                    <td className="text-xs">{r.has_source ? "yes" : "-"}</td>
                    <td className="text-xs text-slate-400">{r.snippet || r.functions.slice(0, 3).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.results.length === 0 && (
              <p className="text-sm text-slate-500 py-3">No matches. Loosen the filters or try fewer keywords.</p>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default function SearchPage() {
  return (
    <AuthGate>
      <SearchPageInner />
    </AuthGate>
  );
}
