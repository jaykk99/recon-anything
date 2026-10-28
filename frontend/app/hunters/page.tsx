"use client";
import { useEffect, useState } from "react";
import { api } from "../../lib/api";
import AuthGate from "../../components/AuthGate";

// Hunters view: read-only window into the agent data service.
// The 20 hunters do not chat, they hunt: they expand the known set
// through the same endpoints this page reads.

interface HunterDef {
  name: string; specialty: string; consumes: string[]; produces: string[];
  plugins: string[];
  stats: { assets_discovered: number; jobs_enqueued: number;
           dead_ends: number; assets_in_known_set: number };
}

interface PackInfo { name: string; entries: number; size_bytes: number; file: string }

interface ResourceInfo {
  id: string; name: string; url: string; category: string; kind: string;
  used_by: string[]; attribution: string; fetchable: boolean;
  cached: boolean; cached_at: string | null; cached_bytes: number;
}

function HuntersPageInner() {
  const [hunters, setHunters] = useState<HunterDef[]>([]);
  const [packs, setPacks] = useState<PackInfo[]>([]);
  const [resources, setResources] = useState<ResourceInfo[]>([]);
  const [target, setTarget] = useState("");
  const [memory, setMemory] = useState<any>(null);
  const [known, setKnown] = useState<any>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  async function loadBase() {
    try {
      const h = await api<{ hunters: HunterDef[] }>("/api/hunters");
      setHunters(h.hunters);
      const k = await api<{ packs: PackInfo[] }>("/api/hunters/knowledge");
      setPacks(k.packs);
      const r = await api<{ resources: ResourceInfo[] }>("/api/hunters/resources");
      setResources(r.resources);
    } catch (e: any) { setErr(e.message); }
  }
  useEffect(() => { loadBase(); }, []);

  async function loadTarget() {
    if (!target.trim()) return;
    setMsg(""); setErr("");
    try {
      const m = await api<any>(`/api/hunters/memory?target=${encodeURIComponent(target.trim())}`);
      setMemory(m);
      const ks = await api<any>(`/api/hunters/known-set?target=${encodeURIComponent(target.trim())}`);
      setKnown(ks);
      if ((m.runs || []).length === 0) setMsg("No hunt memory yet for this target. Run a scan and the hunters will start building the known set.");
    } catch (e: any) { setErr(e.message); }
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-lg font-semibold">Hunters</h1>
        <p className="text-xs text-slate-500">
          20 hunter agents work the known set: every confirmed asset expands into new
          candidates, the detection plugins verify them, and confirmed results feed the
          next round. Read-only view. The agents do not chat, they hunt.
        </p>
      </div>
      {err && <p className="text-xs text-red-400">{err}</p>}

      <section className="space-y-2">
        <h2 className="font-semibold text-slate-200">Roster</h2>
        <div className="grid gap-2 md:grid-cols-2">
          {hunters.map((h) => (
            <div key={h.name} className="rounded border border-slate-800 p-3 space-y-1">
              <div className="flex justify-between">
                <span className="font-medium text-sky-300">{h.name}</span>
                <span className="text-xs text-slate-500">{h.specialty}</span>
              </div>
              <p className="text-xs text-slate-400">
                consumes: {h.consumes.join(", ") || "none"} | produces: {h.produces.join(", ") || "none"}
              </p>
              <p className="text-xs text-slate-400">plugins: {h.plugins.join(", ")}</p>
              <p className="text-xs text-slate-300">
                {h.stats.assets_discovered} assets found | {h.stats.jobs_enqueued} jobs queued |{" "}
                {h.stats.assets_in_known_set} in known set | {h.stats.dead_ends} dead ends
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold text-slate-200">Target memory and known set</h2>
        <div className="flex gap-2">
          <input className="input text-sm px-3 py-2 flex-1" placeholder="example.com"
            value={target} onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") loadTarget(); }} />
          <button onClick={loadTarget} className="chip px-4 py-2 bg-sky-900 text-sky-200">Load</button>
        </div>
        {msg && <p className="text-xs text-slate-400">{msg}</p>}
        {memory && (
          <div className="space-y-2 text-sm text-slate-300">
            <p>Known set: {known ? known.total : 0} assets
              {memory.known_set_counts && Object.keys(memory.known_set_counts).length > 0 &&
                " (" + Object.entries(memory.known_set_counts).map(([k, v]) => `${k}: ${v}`).join(", ") + ")"}
            </p>
            {(memory.runs || []).length > 0 && (
              <div>
                <p className="text-slate-400">Known-set growth per run:</p>
                <ul className="text-xs space-y-0.5">
                  {memory.runs.map((r: any, i: number) => (
                    <li key={i}>{r.run_id}: {r.known_before} before, {r.known_after} after, {r.findings} findings</li>
                  ))}
                </ul>
              </div>
            )}
            {(memory.dead_ends || []).length > 0 && (
              <p className="text-xs text-slate-400">
                Dead ends recorded: {memory.dead_ends.length} (hunters skip these on repeat hunts)
              </p>
            )}
            {known && (known.assets || []).length > 0 && (
              <ul className="text-xs space-y-0.5 max-h-64 overflow-y-auto">
                {known.assets.map((a: any, i: number) => (
                  <li key={i}>
                    <span className="text-slate-500">{a.type}</span> {a.value}{" "}
                    <span className="text-slate-500">by {a.found_by || "seed"}, first seen in {a.first_run_id || "n/a"}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold text-slate-200">Knowledge packs (bundled)</h2>
        <ul className="text-sm text-slate-300 space-y-1">
          {packs.map((p) => (
            <li key={p.name}>{p.name}: {p.entries} entries, {p.size_bytes} bytes ({p.file})</li>
          ))}
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold text-slate-200">Resource library</h2>
        <p className="text-xs text-slate-500">
          Curated public references the hunters consult through the agent data service.
          Fetched material is cached with its source URL and attribution.
        </p>
        <ul className="text-sm text-slate-300 space-y-2">
          {resources.map((r) => (
            <li key={r.id} className="rounded border border-slate-800 p-2">
              <a href={r.url} target="_blank" rel="noreferrer" className="text-sky-300 hover:underline">{r.name}</a>
              <span className="text-xs text-slate-500"> {r.kind} | {r.category} | used by {r.used_by.join(", ")}</span>
              <p className="text-xs text-slate-500">{r.attribution}</p>
              <p className="text-xs text-slate-400">
                {r.fetchable ? (r.cached ? `cached ${r.cached_bytes} bytes at ${r.cached_at}` : "fetchable, not cached yet") : "reference only"}
              </p>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export default function HuntersPage() {
  return (
    <AuthGate>
      <HuntersPageInner />
    </AuthGate>
  );
}
