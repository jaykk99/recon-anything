"use client";
import { useState } from "react";
import { api } from "../../lib/api";
import AuthGate from "../../components/AuthGate";

function AgentPageInner() {
  const [runId, setRunId] = useState("");
  const [url, setUrl] = useState("");
  const [inv, setInv] = useState<any>(null);
  const [invErr, setInvErr] = useState("");
  const [msg, setMsg] = useState("");
  const [chat, setChat] = useState<any>(null);
  const [chatErr, setChatErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function runInvestigate() {
    setBusy(true); setInvErr(""); setInv(null);
    try {
      const body: any = { verify_limit: 20, target_limit: 3 };
      if (runId) body.run_id = runId;
      else if (url) body.url = url;
      else { setInvErr("Enter a run id or a target URL first."); setBusy(false); return; }
      const d = await api<any>("/api/agent/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      setInv(d);
    } catch (e: any) {
      setInvErr(String(e.message || e));
    }
    setBusy(false);
  }

  async function runChat() {
    if (!msg) return;
    setBusy(true); setChatErr(""); setChat(null);
    try {
      const d = await api<any>("/api/agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg }),
      });
      setChat(d);
    } catch (e: any) {
      setChatErr(String(e.message || e));
    }
    setBusy(false);
  }

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Agent</h1>
      <p className="text-xs text-slate-500">
        The investigation agent lives inside ReconAnything now: it reads a
        completed run&apos;s findings in-process, re-verifies them live, and
        runs its own detectors for what the scanner did not cover. Owner
        only. Detection only, on authorized targets only.
      </p>
      <div className="card p-4 space-y-2">
        <h2 className="font-semibold text-sm">Investigate a run or a target</h2>
        <div className="flex gap-2 flex-wrap">
          <input className="input px-2 py-1 text-sm w-64" placeholder="run id (reads findings in-process)" value={runId} onChange={(e) => setRunId(e.target.value)} />
          <input className="input px-2 py-1 text-sm w-64" placeholder="or target URL (allowlisted hosts only)" value={url} onChange={(e) => setUrl(e.target.value)} />
          <button className="btn px-4 py-1 text-sm" onClick={runInvestigate} disabled={busy}>Investigate</button>
        </div>
        {invErr && <p className="text-xs text-red-400">{invErr}</p>}
        {inv && (
          <div className="text-sm space-y-2">
            <p className="text-xs text-slate-400">
              Run {inv.run_id || "-"}: {inv.findings_count ?? "-"} findings,{" "}
              {inv.verified?.length ?? 0} re-verified,{" "}
              {inv.added_findings?.length ?? 0} added findings.
            </p>
            {(inv.added_findings || []).map((f: any, i: number) => (
              <div key={i} className="border border-slate-800 rounded p-2">
                <p className="text-amber-300 text-xs font-semibold">{f.title}</p>
                <p className="text-xs text-slate-400">{f.evidence}</p>
                <p className="text-xs text-emerald-300">Fix: {f.fix}</p>
              </div>
            ))}
            {(inv.verified || []).slice(0, 20).map((v: any, i: number) => (
              <p key={`v${i}`} className="text-xs text-slate-500">
                Finding {v.finding_id}: {v.status} {v.evidence ? `- ${String(v.evidence).slice(0, 160)}` : ""}
              </p>
            ))}
          </div>
        )}
      </div>
      <div className="card p-4 space-y-2">
        <h2 className="font-semibold text-sm">Ask the agent</h2>
        <div className="flex gap-2">
          <input className="input px-2 py-1 text-sm flex-1" placeholder="Investigate this target, explain these findings..." value={msg} onChange={(e) => setMsg(e.target.value)} />
          <button className="btn px-4 py-1 text-sm" onClick={runChat} disabled={busy}>Ask</button>
        </div>
        {chatErr && <p className="text-xs text-red-400">{chatErr}</p>}
        {chat && (
          <div className="text-sm space-y-2">
            <p className="whitespace-pre-wrap">{chat.reply}</p>
            {(chat.trace || []).map((t: any, i: number) => (
              <p key={i} className="text-xs text-slate-500">{t.tool}: {String(t.result).slice(0, 200)}</p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function AgentPage() {
  return (
    <AuthGate>
      <AgentPageInner />
    </AuthGate>
  );
}
