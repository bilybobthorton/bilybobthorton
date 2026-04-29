"use client";

import { useState } from "react";

const PLANS = [
  {
    id: "free",
    name: "Free",
    price: "$0",
    period: "forever",
    features: [
      "5 file scans per day",
      "Basic static analysis",
      "Hash reputation lookup",
      "Community YARA rules",
    ],
    cta: "Current plan",
    disabled: true,
    highlight: false,
  },
  {
    id: "pro",
    name: "Pro",
    price: "$9.99",
    period: "per month",
    features: [
      "Unlimited file scans",
      "Full ML threat scoring",
      "VirusTotal enrichment",
      "Custom YARA rules",
      "Endpoint agent access",
      "Priority support",
    ],
    cta: "Upgrade to Pro",
    disabled: false,
    highlight: true,
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "$99",
    period: "per month",
    features: [
      "Everything in Pro",
      "Behavioral sandbox",
      "Threat intel feeds (OTX, MISP)",
      "API access + webhooks",
      "SIEM integration",
      "SLA + dedicated support",
    ],
    cta: "Upgrade to Enterprise",
    disabled: false,
    highlight: false,
  },
];

export default function BillingPage() {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleUpgrade = async (plan: string) => {
    setLoading(plan);
    setError(null);
    try {
      const res = await fetch("/api/v1/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plan,
          success_url: `${window.location.origin}/billing?success=true`,
          cancel_url: `${window.location.origin}/billing`,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? "Checkout failed");
      }

      const { checkout_url } = await res.json();
      window.location.href = checkout_url;
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Something went wrong");
    } finally {
      setLoading(null);
    }
  };

  const handleManage = async () => {
    setLoading("portal");
    try {
      const res = await fetch("/api/v1/billing/portal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ return_url: window.location.href }),
      });
      if (!res.ok) throw new Error("Could not open billing portal");
      const { portal_url } = await res.json();
      window.location.href = portal_url;
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Something went wrong");
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Plans &amp; Billing</h1>
        <p className="text-slate-500 text-sm mt-1">
          Upgrade your plan to unlock more scans, custom rules, and the endpoint agent.
        </p>
      </div>

      {error && (
        <div className="rounded-lg bg-red-900/20 border border-red-800 px-4 py-3 text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {PLANS.map((plan) => (
          <div
            key={plan.id}
            className={`rounded-xl border p-6 flex flex-col gap-5 transition-all ${
              plan.highlight
                ? "border-red-600 bg-red-950/20"
                : "border-slate-800 bg-slate-900/50"
            }`}
          >
            {plan.highlight && (
              <div className="text-xs font-semibold text-red-400 uppercase tracking-widest">
                Most popular
              </div>
            )}
            <div>
              <h2 className="text-lg font-bold text-white">{plan.name}</h2>
              <div className="flex items-baseline gap-1 mt-1">
                <span className="text-3xl font-bold text-white">{plan.price}</span>
                <span className="text-slate-500 text-sm">/{plan.period}</span>
              </div>
            </div>

            <ul className="space-y-2 flex-1">
              {plan.features.map((f) => (
                <li key={f} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="text-green-500 mt-0.5 shrink-0">✓</span>
                  {f}
                </li>
              ))}
            </ul>

            {plan.disabled ? (
              <div className="text-center text-sm text-slate-500 border border-slate-800 rounded-lg py-2">
                {plan.cta}
              </div>
            ) : (
              <button
                onClick={() => handleUpgrade(plan.id)}
                disabled={loading === plan.id}
                className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all ${
                  plan.highlight
                    ? "bg-red-600 hover:bg-red-500 text-white disabled:opacity-50"
                    : "bg-slate-700 hover:bg-slate-600 text-white disabled:opacity-50"
                }`}
              >
                {loading === plan.id ? "Redirecting..." : plan.cta}
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="border-t border-slate-800 pt-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-300 font-medium">Manage subscription</p>
            <p className="text-xs text-slate-500 mt-0.5">
              Update payment method, view invoices, or cancel your plan.
            </p>
          </div>
          <button
            onClick={handleManage}
            disabled={loading === "portal"}
            className="text-sm px-4 py-2 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition-colors disabled:opacity-50"
          >
            {loading === "portal" ? "Opening..." : "Billing portal →"}
          </button>
        </div>
      </div>
    </div>
  );
}
