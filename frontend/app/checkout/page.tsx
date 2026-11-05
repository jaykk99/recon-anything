"use client";
import { useEffect, useState } from "react";
import { api } from "../../lib/api";
import AuthGate from "../../components/AuthGate";

// BTC checkout for one order. The amount and address come from the
// server (pinned at order creation); this page never invents either.
// The buyer enters the wallet address they will send FROM, then the
// watcher unlocks the plan automatically at 2 confirmations.
function CheckoutPageInner() {
  const [order, setOrder] = useState<any>(null);
  const [err, setErr] = useState("");
  const [payer, setPayer] = useState("");
  const [note, setNote] = useState("");

  const load = () => {
    const id = new URLSearchParams(window.location.search).get("order");
    if (!id) { setErr("No order specified."); return; }
    api<any>(`/api/orders/${id}`).then((d) => {
      setOrder(d.order);
      if (d.order?.watch?.payer_address) setPayer(d.order.watch.payer_address);
    }).catch((e) => setErr(String(e?.message || e).slice(0, 200)));
  };

  useEffect(load, []);

  const savePayer = async () => {
    if (!order) return;
    setNote("");
    try {
      const d = await api<any>(`/api/orders/${order.id}/payer-address`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payer_address: payer.trim() }),
      });
      setOrder(d.order);
      setNote("Sending address saved. The watcher will match payments from it.");
    } catch (e: any) {
      setNote(String(e?.message || e).slice(0, 200));
    }
  };

  const checkNow = async () => {
    if (!order) return;
    setNote("");
    try {
      const d = await api<any>(`/api/orders/${order.id}/check-payment`, {
        method: "POST",
      });
      setOrder(d.order);
      setNote(`Watcher check: ${d.action}.`);
    } catch (e: any) {
      setNote(String(e?.message || e).slice(0, 200));
    }
  };

  if (err) return <div className="card p-4 text-sm text-amber-300">{err}</div>;
  if (!order) return <div className="text-sm text-slate-400">Loading order…</div>;

  const w = order.watch || {};
  return (
    <div className="space-y-4 max-w-xl">
      <h1 className="text-lg font-semibold">Checkout: {order.plan} plan</h1>
      <div className="card p-4 space-y-3 text-sm">
        <div>Status: <b>{order.status}</b></div>
        <div>Price: <b>${order.amount_usd}</b> (one month)</div>
        <div>
          Send exactly:{" "}
          <span className="font-mono text-sky-300">{order.amount_btc} BTC</span>
        </div>
        <div>
          To address:{" "}
          <span className="font-mono break-all">{order.btc_address}</span>
        </div>
        <p className="text-slate-400">{order.activation}</p>
        {order.status === "paid" && (
          <p className="text-emerald-300">Payment approved. Your plan is active.</p>
        )}
      </div>
      {order.status === "pending" && (
        <div className="card p-4 space-y-3 text-sm">
          <div>
            <label className="block text-slate-400 mb-1">
              Wallet address you will send FROM
            </label>
            <input
              className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 font-mono text-xs"
              value={payer}
              onChange={(e) => setPayer(e.target.value)}
              placeholder="bc1q…"
            />
            <button
              className="mt-2 px-3 py-1 rounded bg-sky-700 text-white text-xs"
              onClick={savePayer}
            >Save sending address</button>
            <p className="text-slate-400 mt-1">
              The watcher can only match a payment sent from this
              address. Payments from an exchange account will not
              match, send from a wallet you control.
            </p>
          </div>
          <div className="border-t border-slate-800 pt-3 space-y-1">
            <div>Payment watch: <b>{w.status || "none"}</b></div>
            {w.status === "underpaid" && (
              <div className="text-amber-300">
                Seen {w.seen_sats} sats, short {w.shortfall_sats} sats
                of the {w.threshold_sats} needed. Send the rest from
                the same address before the invoice expires.
              </div>
            )}
            {w.confirmations > 0 && (
              <div>Confirmations: {w.confirmations} / {w.required_confirmations}</div>
            )}
            {w.txid && (
              <div className="break-all text-slate-400">Tx: {w.txid}</div>
            )}
            {w.expires_at && <div>Invoice expires: {w.expires_at}</div>}
            {w.late_payment_note && (
              <div className="text-amber-300">{w.late_payment_note}</div>
            )}
            <button
              className="px-3 py-1 rounded bg-slate-700 text-white text-xs"
              onClick={checkNow}
            >Check payment now</button>
            <p className="text-slate-400">
              The plan unlocks automatically at 2 confirmations. An
              invoice unpaid after 60 minutes expires and a late
              payment will not auto-unlock. Overpaying unlocks the
              picked tier only, the excess is not refunded
              automatically.
            </p>
          </div>
          {note && <p className="text-sky-300">{note}</p>}
        </div>
      )}
      <a className="text-sky-300 text-sm underline" href="/pricing">Back to pricing</a>
    </div>
  );
}

export default function CheckoutPage() {
  return (
    <AuthGate>
      <CheckoutPageInner />
    </AuthGate>
  );
}
