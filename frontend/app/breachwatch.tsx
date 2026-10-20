"use client";
import { useEffect, useState } from "react";
import { api } from "../lib/api";

type Breach = {
  name: string;
  password_risk: string;
  xposed_data: string;
  xposed_date: string;
  verified: string;
  severity: string;
};

type Cached = {
  email: string;
  status: string;
  breaches: Breach[];
  note?: string;
  checked_at: string;
  guidance?: string;
};

type Entry = { email: string; label: string; cached: Cached | null };

function statusBadge(c: Cached | null) {
  if (!c) return <span className="chip px-3 py-1 text-xs text-slate-500">not checked yet</span>;
  if (c.status === "clean")
    return <span className="chip px-3 py-1 text-xs bg-green-900 text-green-300">clean</span>;
  if (c.status === "breached") {
    const hi = c.breaches.filter((b) => b.severity === "high").length;
    return (
      <span className="chip px-3 py-1 text-xs bg-red-900 text-red-300">
        {c.breaches.length} breach{c.breaches.length === 1 ? "" : "es"}
        {hi > 0 ? ` · ${hi} with passwords` : ""}
      </span>
    );
  }
  if (c.status === "rate_limited")
    return <span className="chip px-3 py-1 text-xs bg-amber-900 text-amber-300">rate limited, try later</span>;
  return <span className="chip px-3 py-1 text-xs bg-slate-700 text-slate-300">{c.note || c.status}</span>;
}

export default function BreachWatch() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [configured, setConfigured] = useState(true);
  const [hint, setHint] = useState("");
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<Record<string, boolean>>({});

  useEffect(() => {
    api<{ emails: Entry[]; configured: boolean; hint: string }>("/api/breachwatch")
      .then((d) => {
        setEntries(d.emails);
        setConfigured(d.configured);
        setHint(d.hint || "");
      })
      .catch((e) => setErr(e.message));
  }, []);

  async function check(email: string) {
    setBusy((b) => ({ ...b, [email]: true }));
    setErr("");
    try {
      const r = await api<Cached>("/api/breachwatch/check", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      setEntries((es) => es.map((e) => (e.email === email ? { ...e, cached: r } : e)));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy((b) => ({ ...b, [email]: false }));
    }
  }

  return (
    <div className="card p-5">
      <h2 className="font-semibold mb-1 text-red-300">Breach Watch</h2>
      <p className="text-xs text-slate-500 mb-3">
        Checks your own addresses against public breach dumps (XposedOrNot, no key needed).
        Defensive only: tells you what to rotate. Never attempts logins.
      </p>
      {!configured && (
        <p className="text-xs text-amber-300 mb-3">
          No addresses configured. {hint}
        </p>
      )}
      {err && <p className="text-red-400 text-sm mb-3">{err}</p>}
      <div className="space-y-3">
        {entries.map((e) => (
          <div key={e.email} className="rounded border border-slate-800 p-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm">{e.email}</span>
              {e.label && <span className="text-xs text-slate-500">({e.label})</span>}
              <span className="ml-auto flex items-center gap-2">
                {statusBadge(e.cached)}
                <button
                  className="btn px-4 py-2 min-h-[40px] text-sm"
                  disabled={!!busy[e.email]}
                  onClick={() => check(e.email)}
                >
                  {busy[e.email] ? "Checking..." : e.cached ? "Re-check" : "Check now"}
                </button>
              </span>
            </div>
            {e.cached?.checked_at && (
              <p className="text-[11px] text-slate-500 mt-1">
                Last checked: {new Date(e.cached.checked_at).toLocaleString()}
              </p>
            )}
            {e.cached?.status === "breached" && (
              <div className="mt-2">
                <button
                  className="text-xs text-sky-300 hover:underline"
                  onClick={() => setOpen((o) => ({ ...o, [e.email]: !o[e.email] }))}
                >
                  {open[e.email] ? "Hide breach details" : `Show ${e.cached.breaches.length} breaches`}
                </button>
                {open[e.email] && (
                  <ul className="mt-2 space-y-1 text-sm">
                    {e.cached.breaches.map((b) => (
                      <li key={b.name} className="flex items-start gap-2">
                        <span
                          className={`mt-1 inline-block w-2 h-2 rounded-full shrink-0 ${
                            b.severity === "high" ? "bg-red-400" : "bg-amber-400"
                          }`}
                        />
                        <span>
                          <span className="font-medium">{b.name}</span>
                          {b.xposed_date && (
                            <span className="text-slate-500"> · {b.xposed_date}</span>
                          )}
                          <span className="block text-xs text-slate-500">
                            Exposed: {b.xposed_data ? b.xposed_data.replace(/;/g, ", ") : "details unavailable"}
                            {b.password_risk && b.password_risk !== "unknown" && (
                              <> · password risk: {b.password_risk}</>
                            )}
                          </span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="text-xs text-amber-300 mt-2">
                  If breached: change that password everywhere you reused it, starting with
                  email and banking. Enable 2FA.
                </p>
              </div>
            )}
            {e.cached?.status === "clean" && (
              <p className="text-xs text-green-400/80 mt-1">
                Not found in any public breach dump.
              </p>
            )}
          </div>
        ))}
        {configured && entries.length === 0 && (
          <p className="text-xs text-slate-500">Loading...</p>
        )}
      </div>
    </div>
  );
}
