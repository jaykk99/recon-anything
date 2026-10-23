"use client";
import { useEffect, useState } from "react";
import { api } from "../../lib/api";

// BTC checkout for one order. The amount and address come from the
// server (pinned at order creation); this page never invents either.
export default function CheckoutPage() {
  const [order, setOrder] = useState<any>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get("order");
    if (!id) { setErr("No order specified."); return; }
    api<any>(`/api/orders/${id}`).then((d) => setOrder(d.order))
      .catch((e) => setErr(String(e?.message || e).slice(0, 200)));
  }, []);

  if (err) return <div className="card p-4 text-sm text-amber-300">{err}</div>;
  if (!order) return <div className="text-sm text-slate-400">Loading order…</div>;

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
      <a className="text-sky-300 text-sm underline" href="/pricing">Back to pricing</a>
    </div>
  );
}
