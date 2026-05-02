"use client";
import { Shield, Zap, Globe, Lock, Server, Eye, CheckCircle, Wifi } from "lucide-react";
import { getToken } from "@/lib/auth";

const FEATURES = [
  {
    icon: Lock,
    title: "WireGuard Protocol",
    body: "Modern cryptography (ChaCha20, Poly1305, Curve25519). 3–4× faster than OpenVPN with a fraction of the attack surface.",
  },
  {
    icon: Eye,
    title: "Zero-Log Policy",
    body: "We never log connection times, IP addresses, DNS queries, or browsing activity. Verified by third-party audit.",
  },
  {
    icon: Zap,
    title: "Threat-Aware Routing",
    body: "Pairs with SentinelCore: known-malicious domains and C2 IPs are blocked at the VPN gateway before they reach your device.",
  },
  {
    icon: Globe,
    title: "Global Servers",
    body: "Nodes across North America, Europe, and Asia-Pacific. Automatic failover to the lowest-latency server.",
  },
  {
    icon: Server,
    title: "Kill Switch",
    body: "Drop all traffic the moment the VPN tunnel drops. No accidental IP leaks, ever.",
  },
  {
    icon: Shield,
    title: "DNS Leak Protection",
    body: "All DNS queries route through our encrypted resolver. WebRTC leak prevention built in for every platform.",
  },
];

const PLANS = [
  {
    name: "VPN Free",
    price: "$0",
    period: "",
    description: "One location · 10 GB/mo · 1 device",
    features: [
      "1 VPN server (US East)",
      "10 GB bandwidth per month",
      "1 simultaneous device",
      "WireGuard protocol",
    ],
    cta: "Start free",
    href: "/register",
    highlight: false,
  },
  {
    name: "VPN Pro",
    price: "$4.99",
    period: "/mo",
    description: "All locations · Unlimited · 5 devices",
    features: [
      "All global server locations",
      "Unlimited bandwidth",
      "5 simultaneous devices",
      "Kill switch + DNS leak protection",
      "Zero-log policy",
    ],
    cta: "Get VPN Pro",
    href: "/billing",
    highlight: false,
  },
  {
    name: "Security Bundle",
    price: "$12.99",
    period: "/mo",
    description: "VPN Pro + SentinelCore Pro · Best value",
    badge: "Best value",
    features: [
      "Everything in VPN Pro",
      "SentinelCore Pro (unlimited scans)",
      "Threat-aware VPN routing",
      "ML malware scoring",
      "Custom YARA rules",
      "PDF threat reports",
      "Priority support",
    ],
    cta: "Get the Bundle",
    href: "/billing",
    highlight: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    description: "Dedicated infrastructure · SLA · API",
    features: [
      "Dedicated VPN nodes",
      "MISP + SIEM integration",
      "Centralized policy management",
      "Endpoint agent + VPN combo",
      "99.9% uptime SLA",
      "24/7 support",
    ],
    cta: "Contact sales",
    href: "mailto:sales@sentinelcore.io",
    highlight: false,
  },
];

const PLATFORMS = ["Windows", "macOS", "Linux", "iOS", "Android"];

export default function VPNPage() {
  return (
    <div className="bg-[#0a0a0f] text-slate-200">
      {/* Hero */}
      <section className="relative px-6 pt-24 pb-20 text-center overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute left-1/2 top-0 -translate-x-1/2 h-96 w-96 rounded-full bg-indigo-700/10 blur-3xl" />
        </div>
        <div className="relative mx-auto max-w-3xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-indigo-700/50 bg-indigo-900/20 px-4 py-1.5 text-xs text-indigo-300 mb-6">
            <span className="h-1.5 w-1.5 rounded-full bg-indigo-400 animate-pulse" />
            Now in beta · Free during launch
          </div>
          <h1 className="text-5xl sm:text-6xl font-bold text-white leading-tight tracking-tight mb-4">
            SentinelVPN
          </h1>
          <p className="text-lg text-slate-400 leading-relaxed mb-3">
            Privacy protection built by a cybersecurity operator — not a marketing team.
          </p>
          <p className="text-base text-slate-500 mb-10 max-w-xl mx-auto">
            WireGuard-powered. Zero logs. Threat-aware routing that blocks C2 domains and malicious IPs
            at the VPN gateway level, before they ever reach your device.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            {getToken() ? (
              <a
                href="/vpn/keys"
                className="flex items-center gap-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 transition-colors px-8 py-3 text-sm font-bold text-white"
              >
                <Wifi size={16} /> Manage my devices
              </a>
            ) : (
              <a
                href="/register"
                className="rounded-xl bg-indigo-600 hover:bg-indigo-500 transition-colors px-8 py-3 text-sm font-bold text-white"
              >
                Start free — no card required
              </a>
            )}
            <a
              href="#pricing"
              className="rounded-xl border border-slate-700 hover:border-slate-500 transition-colors px-8 py-3 text-sm font-semibold text-slate-300"
            >
              See pricing
            </a>
          </div>
          <div className="mt-8 flex items-center justify-center flex-wrap gap-3">
            {PLATFORMS.map((p) => (
              <span key={p} className="text-xs text-slate-500 border border-slate-800 rounded px-2.5 py-1">
                {p}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Why bundle with antivirus */}
      <section className="px-6 py-16 border-y border-slate-800 bg-[#0d0d14]">
        <div className="mx-auto max-w-4xl text-center">
          <h2 className="text-2xl font-bold text-white mb-3">
            Your antivirus stops malware.<br />Your VPN stops surveillance.
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto mb-10 text-sm leading-relaxed">
            Most threats in 2025 don&apos;t require a malicious file — they use your IP, your ISP&apos;s DNS,
            and your unencrypted traffic. SentinelVPN closes the gap that antivirus can&apos;t reach.
            Together, they form a full-stack defense layer.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-left">
            {[
              { label: "Malware & suspicious files", av: true, vpn: false },
              { label: "ISP tracking & DNS logging", av: false, vpn: true },
              { label: "Public Wi-Fi interception", av: false, vpn: true },
              { label: "Known C2 IP blocking", av: true, vpn: true },
              { label: "Phishing domains", av: true, vpn: true },
              { label: "Data exfiltration over network", av: true, vpn: true },
            ].map((row) => (
              <div key={row.label} className="rounded-lg border border-slate-800 bg-slate-900/30 p-3 flex items-center gap-3">
                <div className="shrink-0 flex gap-1">
                  <span className={`text-xs px-1.5 rounded ${row.av ? "bg-red-900/40 text-red-400 border border-red-800" : "bg-slate-800 text-slate-600 border border-slate-700"}`}>AV</span>
                  <span className={`text-xs px-1.5 rounded ${row.vpn ? "bg-indigo-900/40 text-indigo-400 border border-indigo-800" : "bg-slate-800 text-slate-600 border border-slate-700"}`}>VPN</span>
                </div>
                <p className="text-xs text-slate-300">{row.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="px-6 py-20">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-3xl font-bold text-white text-center mb-12">
            Built different
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURES.map((f) => (
              <div key={f.title} className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5">
                <f.icon className="h-6 w-6 text-indigo-400 mb-3" />
                <h3 className="font-semibold text-white mb-1.5">{f.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{f.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="px-6 py-20 border-t border-slate-800 bg-[#0d0d14]">
        <div className="mx-auto max-w-6xl">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-white mb-3">Simple pricing</h2>
            <p className="text-slate-400">Bundle SentinelVPN + SentinelCore and save 30% vs buying separately.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {PLANS.map((plan) => (
              <div
                key={plan.name}
                className={`relative rounded-xl border p-6 flex flex-col ${
                  plan.highlight
                    ? "border-indigo-600 bg-indigo-950/30"
                    : "border-slate-800 bg-[#0a0a0f]"
                }`}
              >
                {plan.badge && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <span className="rounded-full bg-indigo-600 px-3 py-0.5 text-xs font-bold text-white">
                      {plan.badge}
                    </span>
                  </div>
                )}
                <h3 className="font-bold text-white mb-1">{plan.name}</h3>
                <div className="flex items-end gap-0.5 mb-1">
                  <span className="text-3xl font-bold text-white">{plan.price}</span>
                  {plan.period && <span className="text-slate-400 text-sm mb-0.5">{plan.period}</span>}
                </div>
                <p className="text-xs text-slate-500 mb-5">{plan.description}</p>
                <ul className="space-y-2 flex-1 mb-6">
                  {plan.features.map((feat) => (
                    <li key={feat} className="flex items-start gap-2 text-xs text-slate-300">
                      <CheckCircle size={13} className={`mt-0.5 shrink-0 ${plan.highlight ? "text-indigo-400" : "text-green-500"}`} />
                      {feat}
                    </li>
                  ))}
                </ul>
                <a
                  href={plan.href}
                  className={`block text-center rounded-lg py-2.5 text-sm font-semibold transition-colors ${
                    plan.highlight
                      ? "bg-indigo-600 hover:bg-indigo-500 text-white"
                      : "border border-slate-700 hover:border-slate-500 text-slate-300"
                  }`}
                >
                  {plan.cta}
                </a>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="px-6 py-20 text-center">
        <div className="mx-auto max-w-xl">
          <Shield className="mx-auto h-10 w-10 text-indigo-400 mb-4" />
          <h2 className="text-3xl font-bold text-white mb-3">
            Full-stack protection starts free.
          </h2>
          <p className="text-slate-400 mb-8 text-sm leading-relaxed">
            SentinelCore catches what&apos;s already on your device. SentinelVPN secures what&apos;s going in and out.
            Together, they&apos;re a complete threat response platform.
          </p>
          <a
            href="/register"
            className="inline-block rounded-xl bg-indigo-600 hover:bg-indigo-500 transition-colors px-8 py-3 text-sm font-bold text-white"
          >
            Create free account
          </a>
        </div>
      </section>
    </div>
  );
}
