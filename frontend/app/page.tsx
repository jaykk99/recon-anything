"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, getCode, setCode, clearCode, verifyCode, PluginInfo, ClassifyResult } from "../lib/api";

const GROUPS: Record<string, string> = {
  network: "Network / DNS", web: "Web / Frontend", api: "API / Backend",
  mobile: "Mobile", identity: "Identity / Leaks",
};

export default function Home() {
  const router = useRouter();
  const [text, setText] = useState("");
  const [classified, setClassified] = useState<(ClassifyResult & { raw: string })[]>([]);
  const [override, setOverride] = useState("");
  const [mode, setMode] = useState<"passive" | "active">("passive");
  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [enabled, setEnabled] = useState<Record<string, boolean>>({});
  const [code, setCodeState] = useState("");
  const [codeSaved, setCodeSaved] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const [codeBusy, setCodeBusy] = useState(false);
  const [codeMsg, setCodeMsg] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const saved = getCode();
    setCodeState(saved);
    setCodeSaved(!!saved);
    api<{ plugins: PluginInfo[] }>("/api/plugins")
      .then((d) => {
        setPlugins(d.plugins);
        const e: Record<string, boolean> = {};
        d.plugins.forEach((p) => (e[p.id] = true));
        setEnabled(e);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      const v = text.trim();
      if (!v) { setClassified([]); return; }
      api<any>("/api/classify", { method: "POST", body: JSON.stringify({ text: v }) })
        .then((d) => setClassified(d.results || [{ ...d, raw: v }]))
        .catch(() => {});
    }, 400);
    return () => clearTimeout(t);
  }, [text]);

  async function saveCode() {
    const v = code.trim();
    if (!v || codeBusy) return;
    setCodeBusy(true); setCodeMsg("");
    const ok = await verifyCode(v);
    setCodeBusy(false);
    if (ok) {
      setCode(v);
      setCodeSaved(true);
      setCodeMsg("Code saved, you will not have to enter it again.");
    } else {
      setCodeMsg("Wrong code, not saved.");
    }
  }

  function forgetCode() {
    clearCode();
    setCodeState("");
    setCodeSaved(false);
    setCodeMsg("");
  }

  async function start() {
    setError(""); setRunning(true);
    try {
      const ids = Object.keys(enabled).filter((k) => enabled[k]);
      const d = await api<{ run_id: string }>("/api/runs", {
        method: "POST",
        body: JSON.stringify({ targets: text, mode, plugins: ids }),
      });
      if (!d.run_id) throw new Error("no run id returned");
      if (code.trim()) { setCode(code.trim()); setCodeSaved(true); }
      router.push(`/run/${d.run_id}`);
    } catch (e: any) {
      setError(e.message); setRunning(false);
    }
  }

  const byGroup: Record<string, PluginInfo[]> = {};
  plugins.forEach((p) => { (byGroup[p.group] = byGroup[p.group] || []).push(p); });

  return (
    <div className="space-y-6 max-w-full">
      <div className="card p-4 sm:p-5 space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="text-lg font-semibold">New recon run</h1>
          <div className="w-full sm:w-auto sm:ml-auto flex items-center gap-2 flex-wrap">
            <span className="text-xs text-slate-400">Access code</span>
            <div className="relative flex-1 sm:flex-none">
              <input className="input px-2 py-2.5 min-h-[44px] text-sm w-full sm:w-52 pr-12"
                type={showCode ? "text" : "password"}
                value={code}
                onChange={(e) => { setCodeState(e.target.value); setCodeMsg(""); }}
                onKeyDown={(e) => { if (e.key === "Enter") saveCode(); }}
                placeholder="paste your code"
                autoComplete="off" spellCheck={false} />
              <button type="button" onClick={() => setShowCode(!showCode)}
                className="absolute right-1 top-1/2 -translate-y-1/2 text-xs text-slate-500 hover:text-slate-300 px-3 py-2 min-h-[44px]">
                {showCode ? "hide" : "show"}
              </button>
            </div>
            {!codeSaved ? (
              <button type="button" onClick={saveCode} disabled={!code.trim() || codeBusy}
                className="chip px-4 py-2.5 min-h-[44px] text-sm text-sky-300 hover:bg-slate-800 disabled:opacity-40">
                {codeBusy ? "Checking..." : "Save"}
              </button>
            ) : (
              <>
                <span className="text-xs text-green-400">saved</span>
                <button type="button" onClick={forgetCode}
                  className="chip px-4 py-2.5 min-h-[44px] text-sm text-slate-400 hover:text-red-300 hover:bg-slate-800">
                  Forget
                </button>
              </>
            )}
          </div>
        </div>
        {codeMsg && <p className={`text-xs ${codeMsg.startsWith("Wrong") ? "text-red-400" : "text-green-400"}`}>{codeMsg}</p>}
        <textarea className="input w-full p-3 font-mono text-base min-h-[88px]" rows={3}
          placeholder={"example.com\nhttps://target.com\n8.8.8.8\nuser@example.com"}
          value={text} onChange={(e) => setText(e.target.value)} />
        {classified.length > 0 && (
          <div className="flex gap-2 flex-wrap items-center">
            {classified.slice(0, 5).map((c, i) => (
              <span key={i} className="chip px-3 py-1 text-xs bg-slate-800">
                <span className="text-sky-300 font-semibold">{override || c.type}</span>
                <span className="text-slate-400"> {c.normalized.slice(0, 40)} ({c.confidence}%)</span>
              </span>
            ))}
            <select className="input text-xs px-2 py-1" value={override}
              onChange={(e) => setOverride(e.target.value)}>
              <option value="">auto-detect</option>
              {["domain","url","ip","cidr","asn","email","username","phone","person_or_company",
                "file_hash","crypto_wallet","jwt","github","npm_package","play_store","app_store"]
                .map((t) => <option key={t} value={t}>force: {t}</option>)}
            </select>
          </div>
        )}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-400">Mode:</span>
            <button onClick={() => setMode("passive")}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${mode === "passive" ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}>
              PASSIVE
            </button>
            <button onClick={() => setMode("active")}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${mode === "active" ? "bg-amber-900 text-amber-200" : "text-slate-400"}`}>
              ACTIVE
            </button>
          </div>
          <span className="text-xs text-slate-500 w-full sm:w-auto">
            {mode === "passive" ? "third-party APIs and public datasets only, no packets to the target"
              : "direct DNS, HTTP, probes and scans against the target - be polite, rate-limited"}
          </span>
          <button className="btn px-6 py-3 min-h-[48px] w-full sm:w-auto sm:ml-auto text-base" disabled={!text.trim() || running} onClick={start}>
            {running ? "Starting..." : "Run recon"}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      <div className="card p-5">
        <h2 className="font-semibold mb-3">Plugins ({Object.values(enabled).filter(Boolean).length}/{plugins.length} enabled)</h2>
        {Object.keys(GROUPS).map((g) => (
          <div key={g} className="mb-4">
            <h3 className="text-xs uppercase tracking-wide text-slate-500 mb-2">{GROUPS[g]}</h3>
            <div className="grid md:grid-cols-2 gap-2">
              {(byGroup[g] || []).map((p) => (
                <label key={p.id} className="flex items-start gap-2 text-sm p-2 rounded hover:bg-slate-800/50 cursor-pointer">
                  <input type="checkbox" className="mt-1" checked={!!enabled[p.id]}
                    onChange={() => setEnabled({ ...enabled, [p.id]: !enabled[p.id] })} />
                  <span>
                    <span className="font-medium">{p.label}</span>{" "}
                    <span className="text-xs text-slate-500">[{p.cost}]</span>
                    {p.requires_keys.map((k) => (
                      <span key={k} className={`ml-1 text-[10px] px-1 rounded ${p.key_status[k]?.configured ? "bg-green-900 text-green-300" : "bg-red-900 text-red-300"}`}>
                        {k}{p.key_status[k]?.configured ? "" : " missing"}
                      </span>
                    ))}
                    <span className="block text-xs text-slate-500">{p.description}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
