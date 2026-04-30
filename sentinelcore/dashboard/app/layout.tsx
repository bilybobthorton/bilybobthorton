import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelCore — Enterprise Malware Detection",
  description:
    "Four-layer malware detection: static analysis, ML scoring, VirusTotal, and OTX threat intel. Built for consumers, SMBs, and enterprise.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#0a0a0f] text-slate-200 antialiased">
        <nav className="border-b border-slate-800 bg-[#0d0d14]/95 backdrop-blur sticky top-0 z-50 px-6 py-4">
          <div className="mx-auto max-w-6xl flex items-center gap-6">
            <a href="/" className="flex items-center gap-3 mr-2">
              <div className="h-7 w-7 rounded bg-red-600 flex items-center justify-center">
                <span className="text-white font-bold text-xs">SC</span>
              </div>
              <span className="font-semibold text-white tracking-tight">SentinelCore</span>
            </a>
            <a href="/scan"     className="text-sm text-slate-400 hover:text-white transition-colors">Scan</a>
            <a href="/alerts"   className="text-sm text-slate-400 hover:text-white transition-colors">Alerts</a>
            <a href="/yara"     className="text-sm text-slate-400 hover:text-white transition-colors">YARA</a>
            <a href="/#pricing" className="text-sm text-slate-400 hover:text-white transition-colors">Pricing</a>
            <div className="ml-auto flex items-center gap-3">
              <a href="/login"
                className="text-sm text-slate-400 hover:text-white transition-colors">
                Log in
              </a>
              <a href="/register"
                className="rounded-lg bg-red-600 hover:bg-red-500 transition-colors px-4 py-1.5 text-sm font-semibold text-white">
                Get started free
              </a>
            </div>
          </div>
        </nav>
        <main>{children}</main>
        <footer className="border-t border-slate-800 bg-[#0d0d14] mt-24 px-6 py-10">
          <div className="mx-auto max-w-6xl flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-500">
            <div className="flex items-center gap-2">
              <div className="h-5 w-5 rounded bg-red-600 flex items-center justify-center">
                <span className="text-white font-bold text-[9px]">SC</span>
              </div>
              <span>SentinelCore</span>
            </div>
            <p>© {new Date().getFullYear()} SentinelCore. Built by a cybersecurity operator, for everyone.</p>
            <div className="flex gap-4">
              <a href="/scan"     className="hover:text-slate-300 transition-colors">Scan</a>
              <a href="/#pricing" className="hover:text-slate-300 transition-colors">Pricing</a>
              <a href="/billing"  className="hover:text-slate-300 transition-colors">Billing</a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
