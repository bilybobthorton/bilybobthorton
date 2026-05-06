"use client";
import { Download, Shield, Monitor, Zap, Lock } from "lucide-react";

const DOWNLOAD_URL = "http://dashboard.redgaurd.com/files/RedGuard_Setup.exe";

const FEATURES = [
  { icon: Shield, text: "Real-time malware protection" },
  { icon: Zap,    text: "Instant threat detection" },
  { icon: Lock,   text: "Built-in WireGuard VPN" },
  { icon: Monitor, text: "Silent background protection" },
];

export default function DownloadPage() {
  return (
    <div className="min-h-screen bg-[#0a0a0f] flex flex-col items-center justify-center px-6 py-20">
      <div className="mx-auto max-w-2xl text-center">

        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="h-14 w-14 rounded-xl bg-red-600 flex items-center justify-center shadow-lg shadow-red-900/40">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <div className="text-left">
            <p className="text-2xl font-bold text-white leading-none">RedGuard</p>
            <p className="text-sm text-slate-400">Security Suite</p>
          </div>
        </div>

        <h1 className="text-4xl sm:text-5xl font-bold text-white leading-tight tracking-tight mb-4">
          Download RedGuard
        </h1>
        <p className="text-lg text-slate-400 mb-10">
          Full antivirus + VPN protection in one silent app. Installs in under a minute.
        </p>

        {/* Download button */}
        <a
          href={DOWNLOAD_URL}
          className="inline-flex items-center gap-3 bg-red-600 hover:bg-red-500 transition-colors text-white font-bold text-lg px-10 py-4 rounded-xl shadow-lg shadow-red-900/30"
        >
          <Download className="h-5 w-5" />
          Download for Windows
        </a>

        <p className="text-xs text-slate-600 mt-3">
          Windows 10 / 11 · 64-bit · ~15 MB
        </p>

        {/* Features */}
        <div className="grid grid-cols-2 gap-3 mt-12">
          {FEATURES.map(({ icon: Icon, text }) => (
            <div key={text} className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3 text-left">
              <Icon className="h-4 w-4 text-red-500 shrink-0" />
              <span className="text-sm text-slate-300">{text}</span>
            </div>
          ))}
        </div>

        {/* Install steps */}
        <div className="mt-12 text-left rounded-xl border border-slate-800 bg-[#0d0d14] p-6">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Installation</h2>
          <ol className="space-y-3">
            {[
              "Run RedGuard_Setup.exe — click Yes on the Windows prompt",
              "RedGuard installs and starts silently in the background",
              "Click the red shield icon in your system tray to open the app",
              "Sign in with your RedGuard account to activate protection",
            ].map((step, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-slate-400">
                <span className="shrink-0 h-5 w-5 rounded-full bg-red-900/50 border border-red-800 text-red-400 text-xs flex items-center justify-center font-bold">
                  {i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
        </div>

        {/* Other links */}
        <div className="mt-8 flex items-center justify-center gap-6 text-sm text-slate-500">
          <a href="/register" className="hover:text-slate-300 transition-colors">Create account</a>
          <span>·</span>
          <a href="https://dashboard.redgaurd.com" className="hover:text-slate-300 transition-colors">Dashboard</a>
        </div>
      </div>
    </div>
  );
}
