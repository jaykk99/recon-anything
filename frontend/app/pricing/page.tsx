"use client";
import { useEffect, useState } from "react";
import { api } from "../../lib/api";

// Pricing is driven by the server (/api/plans + /api/me), never by
// hardcoded client data: plan limits and the free-tier rule are
// enforced server-side, and the owner account (show_payment_ui=false)
// never sees a buy button, an upgrade banner, or checkout data here.
export default function PricingPage() {
  const [plans, setPlans] = useState<any[]>([]);
  const [me, setMe] = useState<any>(null);
  const [freeRule, setFreeRule] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    api<any>("/api/plans").then((d) => {
      setPlans(d.plans || []);
      setFreeRule(d.free_rule || "");
    }).catch(() => {});
    // /api/me is a plain fetch (not the access-code api helper): it
    // answers for anonymous, owner, and signed-in customers alike.
    fetch("/api/me").then((r) => r.json()).then(setMe).catch(() => {});
  }, []);

  async function buy(planId: string) {
    setMsg("");
    try {
      const d = await api<any>("/api/orders", {
        method: "POST",
        body: JSON.stringify({ plan: planId }),
      });
      if (d.checkout_open === false) {
        setMsg("Checkout opens soon.");
        return;
      }
      window.location.href = d.checkout_path || `/checkout?order=${d.order.id}`;
    } catch (e: any) {
      setMsg(String(e?.message || e).slice(0, 200));
    }
  }

  const owner = me?.is_owner;
  const showPay = me ? me.show_payment_ui : true;

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold">Pricing</h1>
      <p className="text-sm text-slate-400 max-w-2xl">
        ReconAnything finds exposed attack surface before attackers do.
        Paid plans are paid in BTC only. {freeRule}
      </p>

      {owner && (
        <div className="card p-4 text-sm text-emerald-300 border border-emerald-500/40">
          Owner account: full access to everything. No payment is needed
          and no checkout applies to this account.
        </div>
      )}

      {me && !me.signed_in && !owner && (
        <div className="card p-4 text-sm">
          {me.github_enabled ? (
            <a className="text-sky-300 underline" href="/api/auth/github">
              Sign in with GitHub
            </a>
          ) : (
            <span className="text-slate-400">GitHub sign-in opens soon.</span>
          )}
          <span className="text-slate-500">{" "}Buying a plan needs a GitHub sign-in so the plan sticks to your account.</span>
        </div>
      )}
      {me?.signed_in && !owner && (
        <div className="card p-4 text-sm text-slate-300">
          Signed in as <span className="font-mono">{me.user?.login}</span> on
          the <b>{me.plan?.name}</b> plan.
          {me.plan?.id === "free" && (
            <span className="text-slate-500"> Reveals used today: {me.reveals_used_today ?? 0} of {me.free_reveals_per_day ?? 1} (resets at UTC midnight).</span>
          )}
        </div>
      )}

      {msg && <div className="card p-4 text-sm text-amber-300">{msg}</div>}

      <div className="grid md:grid-cols-4 gap-4">
        {plans.map((p) => (
          <div key={p.id} className="card p-4 space-y-3 flex flex-col">
            <div>
              <div className="font-semibold">{p.name}</div>
              <div className="text-2xl text-sky-300">
                {p.price_usd === 0 ? "Free" : `$${p.price_usd}/mo`}
              </div>
            </div>
            <ul className="text-sm text-slate-400 space-y-1 flex-1">
              {(p.features || []).map((f: string) => (
                <li key={f}>• {f}</li>
              ))}
            </ul>
            {showPay && p.price_usd > 0 && (
              <button
                className="bg-sky-600 hover:bg-sky-500 text-white rounded px-3 py-2 text-sm"
                onClick={() => buy(p.id)}
              >
                Buy {p.name} with BTC
              </button>
            )}
            {showPay && p.price_usd === 0 && (
              <div className="text-xs text-slate-500">
                No card, no sign-up wall: sign in with GitHub and scan.
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
