"use client";

import { useEffect, useState } from "react";

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
    urlKey: null,
    cta: "Current plan",
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
    urlKey: "pro_url" as const,
    cta: "Upgrade to Pro",
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
    urlKey: "enterprise_url" as const,
    cta: "Upgrade to Enterprise",
    highlight: false,
  },
];

interface ShopifyConfig {
  store_url: string | null;
  pro_url: string | null;
  enterprise_url: string | null;
  bundle_url: string | null;
  manage_url: string | null;
}

export default function BillingPage() {
  const [config, setConfig] = useState<ShopifyConfig | null>(null);

  useEffect(() => {
    fetch("/api/v1/shopify/config")
      .then((r) => r.json())
      .then(setConfig)
      .catch(() => null);
  }, []);

  const handleUpgrade = (plan: typeof PLANS[number]) => {
    if (!plan.urlKey) return;
    const url = config?.[plan.urlKey];
    if (url) {
      window.open(url, "_blank", "noopener noreferrer");
    } else if (config?.store_url) {
      window.open(config.store_url, "_blank", "noopener noreferrer");
    }
  };

  const handleManage = () => {
    const url = config?.manage_url ?? config?.store_url;
    if (url) window.open(url, "_blank", "noopener noreferrer");
  };

  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Plans &amp; Billing</h1>
        <p className="text-slate-500 text-sm mt-1">
          Upgrade your plan to unlock more scans, custom rules, and the endpoint agent.
          Purchases are handled securely through our Shopify store.
        </p>
      </div>

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

            {!plan.urlKey ? (
              <div className="text-center text-sm text-slate-500 border border-slate-800 rounded-lg py-2">
                {plan.cta}
              </div>
            ) : (
              <button
                onClick={() => handleUpgrade(plan)}
                className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all ${
                  plan.highlight
                    ? "bg-red-600 hover:bg-red-500 text-white"
                    : "bg-slate-700 hover:bg-slate-600 text-white"
                }`}
              >
                {plan.cta}
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
              Update payment method, view invoices, or cancel — handled through your Shopify account.
            </p>
          </div>
          <button
            onClick={handleManage}
            className="text-sm px-4 py-2 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            Manage on Shopify →
          </button>
        </div>
      </div>
    </div>
  );
}
