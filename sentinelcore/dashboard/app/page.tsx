import { ScanUpload } from "@/components/ScanUpload";
import { Shield, Zap, Search } from "lucide-react";

export default function Home() {
  return (
    <div className="space-y-10">
      {/* Hero */}
      <div className="text-center space-y-3">
        <h1 className="text-4xl font-bold text-white tracking-tight">
          Malware Detection &amp; Analysis
        </h1>
        <p className="text-slate-400 max-w-xl mx-auto">
          Upload any file for instant static analysis — PE structure, entropy, YARA rules,
          string extraction, and threat scoring.
        </p>
      </div>

      {/* Feature pills */}
      <div className="flex flex-wrap justify-center gap-3">
        {[
          { icon: Shield, label: "PE / ELF Analysis" },
          { icon: Zap,    label: "YARA Rule Matching" },
          { icon: Search, label: "IOC Extraction" },
        ].map(({ icon: Icon, label }) => (
          <span key={label} className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-400">
            <Icon size={12} className="text-red-500" />
            {label}
          </span>
        ))}
      </div>

      {/* Upload */}
      <ScanUpload />

      {/* Tier callout */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 flex items-center justify-between gap-4">
        <div>
          <p className="font-semibold text-white">Upgrade to Pro</p>
          <p className="text-sm text-slate-400 mt-0.5">
            Unlimited scans · ML scoring · Custom YARA rules · Full reports
          </p>
        </div>
        <button className="shrink-0 rounded-lg bg-red-600 hover:bg-red-500 transition-colors px-4 py-2 text-sm font-semibold text-white">
          Get Pro — $9.99/mo
        </button>
      </div>
    </div>
  );
}
