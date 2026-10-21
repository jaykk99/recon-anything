"use client";
import { useEffect, useState } from "react";
import { api } from "../../lib/api";

export default function RunsPage() {
  const [runs, setRuns] = useState<any[]>([]);
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [diff, setDiff] = useState<any>(null);

  useEffect(() => {
    api<{ runs: any[] }>("/api/runs").then((d) => setRuns(d.runs)).catch(() => {});
  }, []);

  async function runDiff() {
    if (!a || !b) return;
    const d = await api<any>(`/api/diff?a=${a}&b=${b}`);
    setDiff(d);
  }

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Runs</h1>
      <div className="card p-4">
        <table className="grid">
          <thead><tr><th>id</th><th>mode</th><th>status</th><th>findings</th><th>created</th></tr></thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td><a className="text-sky-400 font-mono" href={`/run/${r.id}`}>{r.id}</a></td>
                <td className="text-xs">{r.mode}</td>
                <td className="text-xs">{r.status}</td>
                <td className="text-xs">{r.findings_count ?? r.summary?.findings ?? "-"}</td>
                <td className="text-xs text-slate-500">{(r.created_at || "").slice(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card p-4 space-y-2">
        <h2 className="font-semibold text-sm">Diff two runs (continuous monitoring)</h2>
        <div className="flex gap-2">
          <input className="input px-2 py-1 text-sm w-40" placeholder="run A id" value={a} onChange={(e) => setA(e.target.value)} />
          <input className="input px-2 py-1 text-sm w-40" placeholder="run B id" value={b} onChange={(e) => setB(e.target.value)} />
          <button className="btn px-4 py-1 text-sm" onClick={runDiff}>Diff</button>
        </div>
        {diff && (
          <div className="text-sm space-y-2">
            <p className="text-xs text-slate-500">
              new: {diff.new_count} | removed: {diff.removed_count} | changed: {diff.changed_count}
            </p>
            {diff.new.slice(0, 30).map((f: any, i: number) => (
              <p key={i} className="text-xs"><span className="text-green-400">+ </span>
                <code className="text-amber-300">{f.key}</code> {f.value.slice(0, 120)}</p>
            ))}
            {diff.changed.slice(0, 30).map((f: any, i: number) => (
              <p key={i} className="text-xs"><span className="text-amber-400">~ </span>
                <code className="text-amber-300">{f.key}</code> {String(f.new).slice(0, 120)}</p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
