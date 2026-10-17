"use client";
import { useEffect, useState } from "react";
import { api, getCode } from "../../lib/api";

export default function KeysPage() {
  const [keys, setKeys] = useState<Record<string, { configured: boolean; used_by: string[] }>>({});
  const [encrypted, setEncrypted] = useState(false);
  const [form, setForm] = useState({ name: "", label: "", secret: "" });
  const [msg, setMsg] = useState("");

  async function load() {
    try {
      const d = await api<{ keys: any; encrypted: boolean }>("/api/keys");
      setKeys(d.keys); setEncrypted(d.encrypted);
    } catch (e: any) { setMsg(e.message); }
  }
  useEffect(() => { load(); }, []);

  async function save() {
    setMsg("");
    try {
      await api("/api/keys", { method: "POST", body: JSON.stringify(form) });
      setForm({ name: "", label: "", secret: "" });
      setMsg("saved");
      load();
    } catch (e: any) { setMsg(e.message); }
  }
  async function del(name: string) {
    await api(`/api/keys/${name}`, { method: "DELETE" });
    load();
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <h1 className="text-lg font-semibold">API keys</h1>
      <p className="text-xs text-slate-500">
        Keys are stored server-side and never sent to the browser.{" "}
        {encrypted ? "Encryption at rest is ON." : "Set RECON_MASTER_KEY to encrypt at rest."}
        {" "}Access code: {getCode() ? "set" : "not set"} (set it on the home page).
      </p>
      <div className="card p-4 space-y-2">
        {Object.keys(keys).length === 0 && <p className="text-sm text-slate-500">no keys required by any plugin yet, or none configured</p>}
        {Object.entries(keys).map(([k, v]) => (
          <div key={k} className="flex items-center gap-2 text-sm">
            <code className="text-amber-300">{k}</code>
            <span className={`text-xs px-1 rounded ${v.configured ? "pill-ok" : "pill-warn"}`}>
              {v.configured ? "configured" : "missing"}
            </span>
            <span className="text-xs text-slate-500">used by: {v.used_by.join(", ")}</span>
            {v.configured && <button className="ml-auto text-xs text-red-400" onClick={() => del(k)}>delete</button>}
          </div>
        ))}
      </div>
      <div className="card p-4 space-y-2">
        <h2 className="font-semibold text-sm">Add / update key</h2>
        <input className="input w-full px-2 py-1 text-sm" placeholder="name (e.g. shodan)"
          value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input className="input w-full px-2 py-1 text-sm" placeholder="label (optional)"
          value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} />
        <input className="input w-full px-2 py-1 text-sm" type="password" placeholder="secret"
          value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} />
        <button className="btn px-4 py-1 text-sm" onClick={save} disabled={!form.name || !form.secret}>Save key</button>
        {msg && <p className="text-xs text-slate-400">{msg}</p>}
      </div>
      <div className="card p-4 text-xs text-slate-500 space-y-1">
        <p className="font-semibold text-slate-300">Where to get keys (all optional):</p>
        <p>shodan: shodan.io - HIBP_API_KEY as hibp: haveibeenpwned.com/API/v3</p>
        <p>github_token: github.com/settings/tokens (code search)</p>
      </div>
    </div>
  );
}
