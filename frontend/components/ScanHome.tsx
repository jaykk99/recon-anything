"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, getCode, setCode, clearCode, verifyCode, fetchMe, PluginInfo, ClassifyResult, type MeInfo } from "../lib/api";
import BreachWatch from "../app/breachwatch";
import SignInCard from "./SignInCard";

const GROUPS: Record<string, string> = {
  network: "Network / DNS", web: "Web / Frontend", api: "API / Backend",
  mobile: "Mobile", identity: "Identity / Leaks", infra: "Infrastructure",
  web3: "Web3 / Crypto", financial: "Financial", graph: "Graph / Relationships",
};

export default function ScanHome() {
  const router = useRouter();
  const [text, setText] = useState("");
  const [classified, setClassified] = useState<(ClassifyResult & { raw: string })[]>([]);
  const [override, setOverride] = useState("");
  const [mode, setMode] = useState<"passive" | "active">("active");
  const [bounty, setBounty] = useState(false);
  const [sourceType, setSourceType] = useState<"website" | "bankatm">("website");
  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [pluginsState, setPluginsState] = useState<"loading" | "ok" | "error">("loading");
  const [enabled, setEnabled] = useState<Record<string, boolean>>({});
  // One-click scan presets (backend app/presets.py): presetId null =
  // Custom (manual plugin selection below). Picking a preset sets
  // mode + plugin selection in one click; touching any advanced
  // option afterwards drops back to Custom.
  const [presets, setPresets] = useState<any[]>([]);
  const [presetId, setPresetId] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [code, setCodeState] = useState("");
  const [codeSaved, setCodeSaved] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const [codeBusy, setCodeBusy] = useState(false);
  const [codeMsg, setCodeMsg] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [me, setMe] = useState<MeInfo | null>(null);
  // Sign-in mode (GitHub OAuth configured server-side): the access
  // code is retired - no code field, GitHub sign-in is the gate.
  const githubMode = me?.auth_mode === "github";

  useEffect(() => {
    fetchMe().then((m) => {
      setMe(m);
      if (m && m.auth_mode === "github") clearCode();
    });
    const saved = getCode();
    setCodeState(saved);
    setCodeSaved(!!saved);
    loadPlugins();
    api<{ presets: any[] }>("/api/presets").then((d) => setPresets(d.presets || [])).catch(() => {});
  }, []);

  function applyPreset(p: any) {
    setPresetId(p.id);
    setMode(p.mode);
    if (Array.isArray(p.plugins)) {
      const e: Record<string, boolean> = {};
      plugins.forEach((pl) => (e[pl.id] = p.plugins.includes(pl.id)));
      setEnabled(e);
    } else {
      const e: Record<string, boolean> = {};
      plugins.forEach((pl) => (e[pl.id] = true));
      setEnabled(e);
    }
  }

  // Loads the plugin catalog. A previous silent failure here (API down,
  // backend cold-starting) left the Plugins card showing "(0/0 enabled)"
  // forever, indistinguishable from "this scan genuinely has zero
  // plugins" - with nothing for the user to do about it. Now it tracks
  // loading/ok/error explicitly so the UI can show a real retry affordance.
  function loadPlugins() {
    setPluginsState("loading");
    api<{ plugins: PluginInfo[] }>("/api/plugins")
      .then((d) => {
        setPlugins(d.plugins);
        const e: Record<string, boolean> = {};
        d.plugins.forEach((p) => (e[p.id] = true));
        setEnabled(e);
        setPluginsState("ok");
      })
      .catch((e) => { setError(e.message); setPluginsState("error"); });
  }

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
        body: JSON.stringify(sourceType === "bankatm"
          // Bank/ATM mode: one input, no options. The server runs the
          // full financial set; no plugin selection is sent at all.
          ? { targets: text, mode: "active", plugins: null, source_type: "bankatm", bounty: false }
          : presetId
            // Preset: the server resolves mode + plugins + depth from
            // the preset name, so the scan matches the button exactly.
            ? { targets: text, preset: presetId, source_type: sourceType, bounty }
            : { targets: text, mode, plugins: ids, source_type: sourceType, bounty }),
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

  const cryptoIds = plugins.filter((p) => p.id.startsWith("cp_")).map((p) => p.id);
  const enabledCount = Object.values(enabled).filter(Boolean).length;
  const cryptoSelected = cryptoIds.filter((id) => enabled[id]).length;
  const packOnly = cryptoIds.length > 0 && cryptoSelected === cryptoIds.length
    && enabledCount === cryptoIds.length;

  function selectOnly(ids: string[]) {
    setPresetId(null);
    const e: Record<string, boolean> = {};
    plugins.forEach((p) => (e[p.id] = ids.includes(p.id)));
    setEnabled(e);
  }

  function addToSelection(ids: string[]) {
    setPresetId(null);
    const e = { ...enabled };
    ids.forEach((id) => (e[id] = true));
    setEnabled(e);
  }

  // Sign-in mode + signed out: GitHub sign-in is the only gate. The
  // scan form (and the retired access-code field) is not shown at
  // all. (The server wrapper in app/page.tsx renders this same card
  // before the client app even loads; this is the client-side path
  // for when the middleware could not stamp the request.)
  if (githubMode && me && !me.signed_in) {
    return <SignInCard />;
  }

  return (
    <div className="space-y-6 max-w-full">
      <div className="card p-4 sm:p-5 space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="text-lg font-semibold">New recon run</h1>
          {githubMode ? (
            <div className="w-full sm:w-auto sm:ml-auto flex items-center gap-2 flex-wrap">
              <span className="text-xs text-slate-400">Signed in as</span>
              <span className="text-sm text-slate-200">{me?.user?.login}</span>
              <span className="text-xs text-slate-500">{me?.plan?.name} plan</span>
            </div>
          ) : (
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
          )}
        </div>
        {!githubMode && codeMsg && <p className={`text-xs ${codeMsg.startsWith("Wrong") ? "text-red-400" : "text-green-400"}`}>{codeMsg}</p>}
        <textarea className="input w-full p-3 font-mono text-base min-h-[88px]" rows={sourceType === "bankatm" ? 1 : 3}
          placeholder={sourceType === "website"
            ? "example.com\nhttps://target.com\n8.8.8.8\nuser@example.com"
            : "rbcroyalbank.com  —  or a location:  Winnipeg, MB · ATMs near Osborne Village · 49.8951,-97.1384"}
          value={text} onChange={(e) => setText(e.target.value)} />
        {sourceType !== "bankatm" && classified.length > 0 && (
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
        {sourceType !== "bankatm" && presets.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm text-slate-400">Preset:</span>
              {presets.map((p) => (
                <button key={p.id} type="button" onClick={() => applyPreset(p)}
                  title={p.description}
                  className={`chip px-4 py-2.5 min-h-[44px] text-xs ${presetId === p.id ? "bg-sky-900 text-sky-200 border border-sky-700" : "text-slate-300 hover:bg-slate-800"}`}>
                  {p.label.toUpperCase()}
                  {p.plugin_count != null && <span className="text-slate-500"> · {p.plugin_count} plugins</span>}
                  {p.max_depth != null && <span className="text-slate-500"> · depth {p.max_depth}</span>}
                </button>
              ))}
              <button type="button" onClick={() => setPresetId(null)}
                className={`chip px-4 py-2.5 min-h-[44px] text-xs ${presetId === null ? "bg-slate-700 text-slate-100" : "text-slate-400 hover:bg-slate-800"}`}>
                CUSTOM
              </button>
            </div>
            <p className="text-xs text-slate-500">
              {presetId
                ? presets.find((p) => p.id === presetId)?.description
                : "One click sets the mode, plugin set, and hunter depth. Pick a preset, or tune everything yourself under Advanced options."}
            </p>
          </div>
        )}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-400">Scan:</span>
            <button onClick={() => setSourceType("website")}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${sourceType === "website" ? "bg-emerald-900 text-emerald-200" : "text-slate-400"}`}>
              WEBSITE
            </button>
            <button onClick={() => setSourceType("bankatm")}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${sourceType === "bankatm" ? "bg-emerald-900 text-emerald-200" : "text-slate-400"}`}>
              BANK / ATM
            </button>
          </div>
          {sourceType === "bankatm" && (
            <span className="text-xs text-amber-300 w-full sm:w-auto">
              One input, no options. A bank URL or domain runs the full financial detection set on it.
              A location finds every bank and ATM nearby via OpenStreetMap, resolves each operator,
              and assesses their sites. It just does it.
            </span>
          )}
          {sourceType !== "bankatm" && (<>
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-400">Mode:</span>
            <button onClick={() => { setPresetId(null); setMode("active"); }}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${mode === "active" ? "bg-amber-900 text-amber-200" : "text-slate-400"}`}>
              ACTIVE (default)
            </button>
            <button onClick={() => { setPresetId(null); setMode("passive"); }}
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${mode === "passive" ? "bg-sky-900 text-sky-200" : "text-slate-400"}`}>
              PASSIVE
            </button>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-400">Bounty:</span>
            <button onClick={() => setBounty(!bounty)} title="prioritizes high-impact vuln classes, sorts by impact"
              className={`chip px-4 py-2.5 min-h-[44px] text-xs ${bounty ? "bg-purple-900 text-purple-200 border border-purple-700" : "text-slate-400"}`}>
              {bounty ? "✓ BOUNTY MODE" : "BOUNTY MODE"}
            </button>
            <span className="text-xs text-slate-500" title="prioritizes high-impact vuln classes, sorts by impact">
              prioritizes high-impact vuln classes, sorts by impact
            </span>
          </div>
          <span className="text-xs text-slate-500 w-full sm:w-auto">
            {mode === "passive" ? "third-party APIs and public datasets only, no packets to the target"
              : "full recon: direct DNS, HTTP requests, port and vuln probes against the target - rate-limited and polite"}
          </span>
          </>)}
          <button className="btn px-6 py-3 min-h-[48px] w-full sm:w-auto sm:ml-auto text-base" disabled={!text.trim() || running} onClick={start}>
            {running ? "Starting..." : "Run recon"}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      <div className="card p-5">
        <h2 className="font-semibold mb-1 text-amber-300">Key Leak Checker</h2>
        <p className="text-xs text-slate-500 mb-3">
          Paste a wallet address or public key to check if it appears in public leaks.
          Cannot crack or derive keys, only finds exposures.
        </p>
        <div className="flex gap-2 flex-wrap">
          <input
            className="input flex-1 min-w-[200px] p-3 font-mono text-sm min-h-[48px]"
            placeholder="bc1q... or 0x..."
            id="keyleak-input"
            aria-label="Wallet address or public key to check for leaks"
            autoComplete="off" spellCheck={false}
            onKeyDown={(e) => { if (e.key === "Enter") (e.currentTarget.nextElementSibling as HTMLButtonElement | null)?.click(); }}
          />
          <button
            className="btn px-6 py-3 min-h-[48px] text-base"
            onClick={() => {
              const el = document.getElementById("keyleak-input") as HTMLInputElement;
              if (el && el.value.trim()) {
                setText(el.value.trim());
                setOverride("crypto_wallet");
                el.value = "";
                window.scrollTo({ top: 0, behavior: "smooth" });
              }
            }}
          >
            Check leaks
          </button>
        </div>
      </div>

      <BreachWatch />

      {sourceType !== "bankatm" && (<>
      <div className="card p-5 border border-amber-800/60">
        <div className="flex items-center gap-3 flex-wrap">
          <h2 className="font-semibold text-amber-300">Crypto pack</h2>
          <span className="text-xs text-slate-400">
            {cryptoIds.length} detectors: checksum-verified wallet addresses (30+ chains),
            cryptojacking &amp; miner kits, seed-phrase &amp; private-key leaks, exchange and
            RPC API keys, wallet drainers &amp; clipboard swappers, Web3 endpoints,
            payment rails, DNS crypto traces.
          </span>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          Selected plugins always run to completion: an explicit selection is exempt from
          the scan time budget that skips unselected plugins on long runs.
          {cryptoIds.length > 0 && (
            <> Currently {cryptoSelected}/{cryptoIds.length} crypto detectors selected
            {packOnly ? " (pack only)" : ""}.</>
          )}
        </p>
        <div className="flex gap-2 flex-wrap mt-3">
          <button type="button" onClick={() => selectOnly(cryptoIds)}
            className={`chip px-4 py-2.5 min-h-[44px] text-xs ${packOnly ? "bg-amber-900 text-amber-200" : "text-amber-300 hover:bg-slate-800"}`}>
            CRYPTO PACK ONLY
          </button>
          <button type="button" onClick={() => addToSelection(cryptoIds)}
            className="chip px-4 py-2.5 min-h-[44px] text-xs text-slate-300 hover:bg-slate-800">
            ADD PACK TO SELECTION
          </button>
          <button type="button" onClick={() => selectOnly(plugins.map((p) => p.id))}
            className="chip px-4 py-2.5 min-h-[44px] text-xs text-slate-400 hover:bg-slate-800">
            ALL PLUGINS
          </button>
          <button type="button" onClick={() => selectOnly([])}
            className="chip px-4 py-2.5 min-h-[44px] text-xs text-slate-400 hover:bg-slate-800">
            NONE
          </button>
        </div>
      </div>

      <div className="card p-5">
        <div className="flex items-center gap-3 flex-wrap mb-3">
          <h2 className="font-semibold">Plugins ({Object.values(enabled).filter(Boolean).length}/{plugins.length} enabled)</h2>
          {pluginsState === "loading" && (
            <span className="text-xs text-slate-500 animate-pulse">loading plugin catalog...</span>
          )}
          {presetId && (
            <span className="text-xs text-sky-300">set by the {presets.find((p) => p.id === presetId)?.label} preset; editing any plugin switches to Custom</span>
          )}
          <button type="button" onClick={() => setShowAdvanced((v) => !v)}
            className="chip px-4 py-2.5 min-h-[44px] text-xs text-slate-300 hover:bg-slate-800 ml-auto">
            {showAdvanced ? "▲ Hide advanced options" : "▼ Advanced options"}
          </button>
        </div>
        {showAdvanced && (<>
        {pluginsState === "error" && (
          <div className="rounded-lg border border-red-700/50 bg-red-950/30 p-3 mb-3 flex items-center gap-3 flex-wrap">
            <p className="text-sm text-red-300">Could not load the plugin list{error ? `: ${error}` : "."}</p>
            <button type="button" onClick={loadPlugins}
              className="chip px-3 py-2 min-h-[40px] text-xs text-sky-300 hover:bg-slate-800">Retry</button>
          </div>
        )}
        {Object.keys(GROUPS).map((g) => (
          <div key={g} className="mb-4">
            <h3 className="text-xs uppercase tracking-wide text-slate-500 mb-2">{GROUPS[g]}</h3>
            <div className="grid md:grid-cols-2 gap-2">
              {(byGroup[g] || []).map((p) => (
                <label key={p.id} className="flex items-start gap-2 text-sm p-2 rounded hover:bg-slate-800/50 cursor-pointer">
                  <input type="checkbox" className="mt-1" checked={!!enabled[p.id]}
                    onChange={() => { setPresetId(null); setEnabled({ ...enabled, [p.id]: !enabled[p.id] }); }} />
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
        </>)}
      </div>
      </>)}
    </div>
  );
}
