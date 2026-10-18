"use client";
import { useEffect, useState } from "react";
import { isPinUnlocked, pinRequired, setPinUnlocked, verifyPin } from "../lib/api";

const MAX_LEN = 8;

export default function Gate({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<"loading" | "locked" | "open">("loading");
  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (isPinUnlocked()) { setState("open"); return; }
    pinRequired()
      .then((req) => setState(req ? "locked" : "open"))
      .catch(() => setState("open"));
  }, []);

  function press(d: string) {
    setError("");
    if (pin.length < MAX_LEN) setPin(pin + d);
  }

  function backspace() {
    setError("");
    setPin(pin.slice(0, -1));
  }

  function clear() {
    setError("");
    setPin("");
  }

  async function submit() {
    if (pin.length < 4 || busy) return;
    setBusy(true); setError("");
    try {
      const ok = await verifyPin(pin);
      if (ok) { setPinUnlocked(); setState("open"); }
      else { setError("Wrong PIN, try again."); setPin(""); }
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  if (state === "open") return <>{children}</>;

  if (state === "loading") {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <p className="text-slate-500 text-sm">Loading...</p>
      </div>
    );
  }

  const dots = Array.from({ length: MAX_LEN }, (_, i) => (
    <span key={i}
      className={`w-3.5 h-3.5 rounded-full border ${i < pin.length ? "bg-sky-300 border-sky-300" : "border-slate-600"}`} />
  ));

  const keys = ["1","2","3","4","5","6","7","8","9"];

  return (
    <div className="min-h-[70vh] flex items-center justify-center px-4">
      <div className="card p-8 w-full max-w-xs text-center space-y-5">
        <div>
          <h1 className="text-lg font-bold text-sky-300">ReconAnything</h1>
          <p className="text-xs text-slate-500 mt-1">Enter your PIN to continue</p>
        </div>
        <div className="flex justify-center gap-2">{dots}</div>
        <div className="grid grid-cols-3 gap-2">
          {keys.map((k) => (
            <button key={k} onClick={() => press(k)}
              className="chip py-3 text-xl font-semibold text-slate-200 hover:bg-slate-800 active:bg-slate-700">
              {k}
            </button>
          ))}
          <button onClick={clear}
            className="chip py-3 text-sm text-slate-400 hover:bg-slate-800 active:bg-slate-700">
            Clear
          </button>
          <button onClick={() => press("0")}
            className="chip py-3 text-xl font-semibold text-slate-200 hover:bg-slate-800 active:bg-slate-700">
            0
          </button>
          <button onClick={backspace}
            className="chip py-3 text-sm text-slate-400 hover:bg-slate-800 active:bg-slate-700">
            Back
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <button onClick={submit} disabled={pin.length < 4 || busy}
          className="btn w-full py-3 text-base">
          {busy ? "Checking..." : "Unlock"}
        </button>
        <p className="text-[11px] text-slate-600">4 to 8 digits</p>
      </div>
    </div>
  );
}
