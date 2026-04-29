import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelCore",
  description: "Malware detection and analysis platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#0a0a0f] text-slate-200 antialiased">
        <nav className="border-b border-slate-800 bg-[#0d0d14] px-6 py-4">
          <div className="mx-auto max-w-5xl flex items-center gap-6">
            <div className="flex items-center gap-3">
              <div className="h-7 w-7 rounded bg-red-600 flex items-center justify-center">
                <span className="text-white font-bold text-xs">SC</span>
              </div>
              <span className="font-semibold text-white tracking-tight">SentinelCore</span>
            </div>
            <a href="/" className="text-sm text-slate-400 hover:text-white transition-colors">Scan</a>
            <a href="/alerts" className="text-sm text-slate-400 hover:text-white transition-colors">Alerts</a>
            <a href="/yara" className="text-sm text-slate-400 hover:text-white transition-colors">YARA</a>
            <a href="/billing" className="text-sm text-slate-400 hover:text-white transition-colors">Billing</a>
            <span className="ml-auto text-xs text-slate-500">v0.1.0 — Early Access</span>
          </div>
        </nav>
        <main className="mx-auto max-w-5xl px-6 py-10">{children}</main>
      </body>
    </html>
  );
}
