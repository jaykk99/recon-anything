"use client";
import { useEffect, useState } from "react";
import { api, fetchMe, getCode, type MeInfo } from "../../lib/api";
import AuthGate from "../../components/AuthGate";

type Settings = {
  mode: string;
  owned_assets: string[];
  audit: { id: number; ts: string | null; action: string; actor: string;
           detail: Record<string, any> }[];
};

function SettingsPageInner() {
  const [s, setS] = useState<Settings | null>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [assetsText, setAssetsText] = useState("");
  const [me, setMe] = useState<MeInfo | null>(null);

  async function load() {
    try {
      const d = await api<Settings>("/api/settings");
      setS(d);
      setAssetsText((d.owned_assets || []).join("\n"));
    } catch (e: any) { setMsg(e.message); }
  }
  useEffect(() => { load(); fetchMe().then(setMe); }, []);

  async function switchMode(mode: string) {
    if (!s || mode === s.mode) return;
    const label = mode === "live" ? "LIVE" : "SANDBOX";
    if (!window.confirm(
      `Switch the whole app to ${label} mode?\n\n` +
      (mode === "live"
        ? "LIVE scans may target any authorized external target and findings count as production data."
        : "SANDBOX restricts scans to your own assets and local/lab targets, and sandbox findings do not count as production data.") +
      "\n\nThis is recorded in the audit log.")) return;
    setBusy(true); setMsg("");
    try {
      await api("/api/settings/mode", {
        method: "PUT", body: JSON.stringify({ mode }),
      });
      setMsg(`mode switched to ${label}`);
      await load();
    } catch (e: any) { setMsg(e.message); }
    setBusy(false);
  }

  async function saveAssets() {
    setBusy(true); setMsg("");
    try {
      const assets = assetsText.split("\n").map((x) => x.trim()).filter(Boolean);
      await api("/api/settings/owned-assets", {
        method: "PUT", body: JSON.stringify({ assets }),
      });
      setMsg("owned assets saved");
      await load();
    } catch (e: any) { setMsg(e.message); }
    setBusy(false);
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <h1 className="text-lg font-semibold">Settings</h1>
      <p className="text-xs text-slate-500">
        {me?.auth_mode === "github"
          ? `Signed in with GitHub${me.user ? ` as ${me.user.login}` : ""}.`
          : `Access code: ${getCode() ? "set" : "not set"} (set it on the home page).`}
      </p>
      {msg && <p className="text-sm text-amber-300">{msg}</p>}

      <div className="card p-4 space-y-3">
        <h2 className="font-semibold text-sky-300">Scan mode</h2>
        {!s ? <p className="text-sm text-slate-500">loading...</p> : (
          <>
            <p className="text-sm">
              Current mode:{" "}
              {s.mode === "sandbox"
                ? <span className="chip border-amber-500/40 bg-amber-500/10 text-amber-200 px-2 py-0.5">SANDBOX</span>
                : <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-200 px-2 py-0.5">LIVE</span>}
            </p>
            <div className="text-sm text-slate-400 space-y-1">
              <p><strong className="text-amber-200">Sandbox</strong>: scans only
                your own assets (list below) and local/lab targets
                (localhost, private IPs, *.local / *.test / *.lab). Runs are
                badged SANDBOX and never count as production findings.</p>
              <p><strong className="text-emerald-200">Live</strong>: authorized
                external targets; findings count as production data.</p>
              <p className="text-xs text-slate-500">
                The mode changes target scope and data handling only. It does
                not change what any plugin is allowed to do: detection and
                gated read-only assessment in both modes, and the bank/ATM
                authorization gates still apply in both modes.</p>
            </div>
            <div className="flex gap-2">
              <button disabled={busy || s.mode === "sandbox"}
                onClick={() => switchMode("sandbox")}
                className="chip px-4 py-2.5 min-h-[44px] bg-amber-900/60 text-amber-100 disabled:opacity-40">
                Switch to SANDBOX
              </button>
              <button disabled={busy || s.mode === "live"}
                onClick={() => switchMode("live")}
                className="chip px-4 py-2.5 min-h-[44px] bg-emerald-900/60 text-emerald-100 disabled:opacity-40">
                Switch to LIVE
              </button>
            </div>
          </>
        )}
      </div>

      <div className="card p-4 space-y-3">
        <h2 className="font-semibold text-sky-300">Owned assets (sandbox allowlist)</h2>
        <p className="text-xs text-slate-500">
          One host per line. Subdomains of a listed host count as owned.
          These are the only public hosts sandbox scans may target.
        </p>
        <textarea value={assetsText} onChange={(e) => setAssetsText(e.target.value)}
          rows={8}
          className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm font-mono" />
        <button disabled={busy} onClick={saveAssets}
          className="chip px-4 py-2.5 min-h-[44px] bg-sky-900 text-sky-100 disabled:opacity-40">
          Save owned assets
        </button>
      </div>

      <div className="card p-4 space-y-2">
        <h2 className="font-semibold text-sky-300">Audit log</h2>
        {!s || s.audit.length === 0
          ? <p className="text-sm text-slate-500">no settings actions recorded yet</p>
          : s.audit.map((a) => (
            <div key={a.id} className="text-sm flex gap-3 flex-wrap">
              <span className="text-slate-500 font-mono text-xs">
                {a.ts ? new Date(a.ts).toLocaleString() : ""}
              </span>
              <span className="text-slate-300">{a.action}</span>
              <span className="text-slate-500">
                {a.detail?.from} → {a.detail?.to || ""}
                {a.actor ? ` by ${a.actor}` : ""}
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <AuthGate>
      <SettingsPageInner />
    </AuthGate>
  );
}
