"use client";
// Always-visible app mode banner. SANDBOX restricts scans to Jay's own
// assets + local/lab targets and marks runs as non-production; LIVE is
// the regular authorized-scanning behavior. The mode is a settings-level
// switch (Settings page), never a per-scan choice.
import { useEffect, useState } from "react";
import { getCode } from "../lib/api";

export default function ModeBanner() {
  const [mode, setMode] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = async () => {
      try {
        const r = await fetch("/api/settings", {
          headers: { "X-Access-Code": getCode() },
        });
        if (!r.ok || !live) return;
        const j = await r.json();
        if (live && (j.mode === "sandbox" || j.mode === "live")) {
          setMode(j.mode);
        }
      } catch { /* no code set yet - banner stays hidden */ }
    };
    load();
    const t = setInterval(load, 30000);
    return () => { live = false; clearInterval(t); };
  }, []);

  if (!mode) return null;
  if (mode === "sandbox") {
    return (
      <div className="bg-amber-500/15 border-b border-amber-500/40 px-6 py-2 text-center text-sm text-amber-200">
        <strong>SANDBOX MODE</strong> — scans are limited to your own assets
        and local/lab targets. Results are test data and do not count as
        production findings.{" "}
        <a href="/settings" className="underline">Settings</a>
      </div>
    );
  }
  return (
    <div className="bg-emerald-500/10 border-b border-emerald-500/30 px-6 py-2 text-center text-sm text-emerald-200">
      <strong>LIVE MODE</strong> — authorized targets, production findings.{" "}
      <a href="/settings" className="underline">Settings</a>
    </div>
  );
}
