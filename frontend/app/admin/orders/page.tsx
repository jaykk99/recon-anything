"use client";
import { useEffect, useState } from "react";
import { api } from "../../../lib/api";

// Owner-only: BTC orders awaiting payment confirmation. Approving an
// order activates the buyer's plan for 30 days. The API enforces the
// owner gate server-side; this page just renders what it is given.
export default function AdminOrdersPage() {
  const [orders, setOrders] = useState<any[]>([]);
  const [err, setErr] = useState("");

  async function load() {
    try {
      const d = await api<any>("/api/admin/orders");
      setOrders(d.orders || []);
      setErr("");
    } catch (e: any) {
      setErr(String(e?.message || e).slice(0, 200));
    }
  }

  useEffect(() => { load(); }, []);

  async function approve(id: string) {
    try {
      await api<any>(`/api/admin/orders/${id}/approve`, { method: "POST" });
      await load();
    } catch (e: any) {
      setErr(String(e?.message || e).slice(0, 200));
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Orders (owner)</h1>
      {err && <div className="card p-4 text-sm text-amber-300">{err}</div>}
      <div className="card p-4">
        <table className="grid">
          <thead><tr><th>id</th><th>user</th><th>plan</th><th>usd</th><th>btc</th><th>status</th><th>created</th><th></th></tr></thead>
          <tbody>
            {orders.map((o) => (
              <tr key={o.id}>
                <td className="font-mono text-xs">{o.id}</td>
                <td className="text-xs">{o.user_login || ""}</td>
                <td className="text-xs">{o.plan}</td>
                <td className="text-xs">${o.amount_usd}</td>
                <td className="font-mono text-xs">{o.amount_btc}</td>
                <td className="text-xs">{o.status}</td>
                <td className="text-xs text-slate-500">{(o.created_at || "").slice(0, 19)}</td>
                <td>
                  {o.status === "pending" && (
                    <button
                      className="bg-emerald-600 hover:bg-emerald-500 text-white rounded px-2 py-1 text-xs"
                      onClick={() => approve(o.id)}
                    >
                      Payment received: approve
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {orders.length === 0 && !err && (
              <tr><td className="text-sm text-slate-500">No orders yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
