import {
  Shield,
  Zap,
  Search,
  Brain,
  Globe,
  Terminal,
  CheckCircle,
  ArrowRight,
  Lock,
  Eye,
  AlertTriangle,
  Server,
} from "lucide-react";

// ── Data ─────────────────────────────────────────────────────────────────────

const LAYERS = [
  {
    step: "01",
    icon: Shield,
    title: "Static Analysis",
    desc: "PE structure, section entropy, import tables, YARA rules, and string extraction — all without executing the file.",
  },
  {
    step: "02",
    icon: Brain,
    title: "ML Scoring",
    desc: "A 31-feature RandomForest model trained on real malware samples scores every file and boosts confidence when it agrees with static analysis.",
  },
  {
    step: "03",
    icon: Globe,
    title: "VirusTotal",
    desc: "Hash lookup across 70+ antivirus engines. Confirmed malicious hashes are automatically added to your local blocklist.",
  },
  {
    step: "04",
    icon: Eye,
    title: "OTX Threat Intel",
    desc: "AlienVault OTX pulse count enrichment — see how many threat researchers have flagged this file in the wild.",
  },
];

const FEATURES = [
  {
    icon: Terminal,
    title: "Endpoint Agent",
    desc: "Rust-based agent monitors filesystem, processes, and critical system files in real time. Quarantine threats with one command.",
  },
  {
    icon: Zap,
    title: "Custom YARA Rules",
    desc: "Write and deploy your own YARA signatures. Live syntax validation, per-rule hit counters, and instant deployment.",
  },
  {
    icon: Search,
    title: "IOC Extraction",
    desc: "Automatically pulls URLs, IPs, registry keys, mutex names, and suspicious API calls from every scanned file.",
  },
  {
    icon: Lock,
    title: "Hash Reputation DB",
    desc: "Local SHA-256 blocklist seeded with WannaCry, NotPetya, Emotet, Cobalt Strike, and more. Instant offline lookups.",
  },
  {
    icon: AlertTriangle,
    title: "Real-time Alerts",
    desc: "Agent alerts stream to your dashboard the moment suspicious activity is detected — filesystem drops, LOLBin abuse, FIM drift.",
  },
  {
    icon: Server,
    title: "API Access",
    desc: "Enterprise-grade REST API with JWT + API key auth. Integrate detection into your existing security pipeline or SIEM.",
  },
];

const PLANS = [
  {
    name: "Free",
    price: "$0",
    period: "forever",
    highlight: false,
    cta: "Get started",
    href: "/register",
    features: [
      "5 file scans per day",
      "Static PE / ELF analysis",
      "YARA rule matching",
      "IOC string extraction",
      "Hash reputation lookup",
    ],
  },
  {
    name: "Pro",
    price: "$9.99",
    period: "/ month",
    highlight: true,
    cta: "Start Pro",
    href: "/billing",
    features: [
      "Unlimited scans",
      "ML malice scoring",
      "VirusTotal enrichment",
      "OTX threat intel",
      "Custom YARA rules",
      "Endpoint agent",
      "Downloadable reports",
    ],
  },
  {
    name: "Enterprise",
    price: "$99",
    period: "/ month",
    highlight: false,
    cta: "Contact us",
    href: "mailto:kingtrevor981@gmail.com",
    features: [
      "Everything in Pro",
      "Dedicated API access",
      "Sandbox detonation",
      "MISP integration",
      "SLA & priority support",
      "Custom threat intel feeds",
      "Team management",
    ],
  },
];

const STATS = [
  { value: "4-layer", label: "detection pipeline" },
  { value: "31", label: "ML features extracted" },
  { value: "70+", label: "AV engines via VirusTotal" },
  { value: "< 30s", label: "average scan time" },
];

// ── Components ────────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-block rounded-full border border-red-900/60 bg-red-950/40 px-3 py-1 text-xs font-medium text-red-400 tracking-wide uppercase">
      {children}
    </span>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <div className="overflow-x-hidden">

      {/* ── Hero ───────────────────────────────────────────────────────────── */}
      <section className="relative px-6 pt-24 pb-32 text-center">
        {/* Glow */}
        <div className="pointer-events-none absolute inset-0 flex items-start justify-center overflow-hidden">
          <div className="mt-10 h-96 w-[600px] rounded-full bg-red-700/10 blur-[120px]" />
        </div>

        <div className="relative mx-auto max-w-4xl space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/60 px-4 py-1.5 text-xs text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" />
            Early Access — free tier available now
          </div>

          <h1 className="text-5xl sm:text-6xl font-extrabold text-white leading-tight tracking-tight">
            Enterprise malware detection
            <br />
            <span className="text-red-500">for everyone.</span>
          </h1>

          <p className="mx-auto max-w-2xl text-lg text-slate-400 leading-relaxed">
            SentinelCore combines static analysis, machine learning, VirusTotal,
            and AlienVault OTX into a single 4-layer pipeline. Scan any file in
            seconds — no installation required.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
            <a
              href="/scan"
              className="flex items-center gap-2 rounded-xl bg-red-600 hover:bg-red-500 transition-colors px-8 py-3.5 text-base font-semibold text-white shadow-lg shadow-red-900/30"
            >
              Scan a file now
              <ArrowRight size={16} />
            </a>
            <a
              href="/#pricing"
              className="rounded-xl border border-slate-700 bg-slate-900 hover:bg-slate-800 transition-colors px-8 py-3.5 text-base font-semibold text-slate-300"
            >
              View pricing
            </a>
          </div>
        </div>
      </section>

      {/* ── Stats bar ──────────────────────────────────────────────────────── */}
      <section className="border-y border-slate-800 bg-[#0d0d14] px-6 py-10">
        <div className="mx-auto max-w-6xl grid grid-cols-2 sm:grid-cols-4 gap-8 text-center">
          {STATS.map(({ value, label }) => (
            <div key={label}>
              <p className="text-3xl font-extrabold text-white">{value}</p>
              <p className="mt-1 text-sm text-slate-500">{label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Detection pipeline ─────────────────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="mx-auto max-w-6xl space-y-14">
          <div className="text-center space-y-3">
            <SectionLabel>Detection pipeline</SectionLabel>
            <h2 className="text-3xl sm:text-4xl font-bold text-white">
              Four layers. Zero guesswork.
            </h2>
            <p className="mx-auto max-w-xl text-slate-400">
              Each layer enriches the previous result — a file clean to one
              layer can still be caught by the next.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {LAYERS.map(({ step, icon: Icon, title, desc }) => (
              <div
                key={step}
                className="relative rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4 hover:border-slate-700 transition-colors"
              >
                <span className="absolute top-5 right-5 text-[11px] font-mono text-slate-700">
                  {step}
                </span>
                <div className="h-9 w-9 rounded-lg bg-red-950/50 border border-red-900/40 flex items-center justify-center">
                  <Icon size={18} className="text-red-400" />
                </div>
                <h3 className="font-semibold text-white">{title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features grid ──────────────────────────────────────────────────── */}
      <section className="border-t border-slate-800 bg-[#0d0d14] px-6 py-24">
        <div className="mx-auto max-w-6xl space-y-14">
          <div className="text-center space-y-3">
            <SectionLabel>Platform features</SectionLabel>
            <h2 className="text-3xl sm:text-4xl font-bold text-white">
              Everything you need to detect, analyze, and respond.
            </h2>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <div
                key={title}
                className="rounded-xl border border-slate-800 bg-[#0a0a0f] p-6 space-y-3 hover:border-slate-700 transition-colors"
              >
                <div className="h-8 w-8 rounded-lg bg-slate-900 border border-slate-700 flex items-center justify-center">
                  <Icon size={15} className="text-slate-300" />
                </div>
                <h3 className="font-semibold text-white">{title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ───────────────────────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="mx-auto max-w-4xl space-y-14">
          <div className="text-center space-y-3">
            <SectionLabel>How it works</SectionLabel>
            <h2 className="text-3xl sm:text-4xl font-bold text-white">
              From upload to verdict in under 30 seconds.
            </h2>
          </div>

          <div className="space-y-6">
            {[
              {
                n: "1",
                title: "Upload any file",
                desc: "Drag and drop an executable, document, script, or archive. Up to 100 MB. No account required on the free tier.",
              },
              {
                n: "2",
                title: "Four-layer analysis runs automatically",
                desc: "Static analysis fires first, followed by ML scoring, VirusTotal hash lookup, and OTX pulse enrichment — all in parallel where possible.",
              },
              {
                n: "3",
                title: "Get a full threat report",
                desc: "Threat level, confidence score, all indicators of compromise, ML probability, and raw engine results. Download as PDF on Pro.",
              },
            ].map(({ n, title, desc }) => (
              <div key={n} className="flex gap-6 items-start">
                <div className="shrink-0 h-10 w-10 rounded-full border border-red-900/60 bg-red-950/30 flex items-center justify-center text-red-400 font-bold text-sm">
                  {n}
                </div>
                <div className="space-y-1 pt-1.5">
                  <h3 className="font-semibold text-white">{title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pricing ────────────────────────────────────────────────────────── */}
      <section id="pricing" className="border-t border-slate-800 bg-[#0d0d14] px-6 py-24">
        <div className="mx-auto max-w-6xl space-y-14">
          <div className="text-center space-y-3">
            <SectionLabel>Pricing</SectionLabel>
            <h2 className="text-3xl sm:text-4xl font-bold text-white">
              Start free. Scale when you need to.
            </h2>
            <p className="text-slate-400">No credit card required for the free tier.</p>
          </div>

          <div className="grid sm:grid-cols-3 gap-6 items-start">
            {PLANS.map(({ name, price, period, highlight, cta, href, features }) => (
              <div
                key={name}
                className={`rounded-xl border p-8 space-y-6 ${
                  highlight
                    ? "border-red-600/60 bg-red-950/10 ring-1 ring-red-600/30"
                    : "border-slate-800 bg-[#0a0a0f]"
                }`}
              >
                {highlight && (
                  <span className="inline-block rounded-full bg-red-600 px-3 py-0.5 text-[11px] font-semibold text-white uppercase tracking-wide">
                    Most popular
                  </span>
                )}
                <div>
                  <p className="text-sm font-medium text-slate-400">{name}</p>
                  <p className="mt-1 flex items-baseline gap-1">
                    <span className="text-4xl font-extrabold text-white">{price}</span>
                    <span className="text-slate-500 text-sm">{period}</span>
                  </p>
                </div>
                <a
                  href={href}
                  className={`block w-full rounded-lg py-2.5 text-center text-sm font-semibold transition-colors ${
                    highlight
                      ? "bg-red-600 hover:bg-red-500 text-white"
                      : "border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-300"
                  }`}
                >
                  {cta}
                </a>
                <ul className="space-y-2.5">
                  {features.map((f) => (
                    <li key={f} className="flex items-start gap-2.5 text-sm text-slate-300">
                      <CheckCircle size={14} className="mt-0.5 shrink-0 text-green-500" />
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ──────────────────────────────────────────────────────── */}
      <section className="px-6 py-24">
        <div className="mx-auto max-w-2xl text-center space-y-6">
          <h2 className="text-3xl sm:text-4xl font-bold text-white">
            Ready to see what's really in that file?
          </h2>
          <p className="text-slate-400">
            Free tier. No credit card. No installation. Scan your first file in
            seconds.
          </p>
          <a
            href="/scan"
            className="inline-flex items-center gap-2 rounded-xl bg-red-600 hover:bg-red-500 transition-colors px-10 py-4 text-base font-semibold text-white shadow-lg shadow-red-900/30"
          >
            Scan a file — it&apos;s free
            <ArrowRight size={16} />
          </a>
        </div>
      </section>
    </div>
  );
}
