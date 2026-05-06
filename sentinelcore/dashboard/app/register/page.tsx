"use client";
import { useState, FormEvent } from "react";
import { apiRegister, storeSession } from "@/lib/auth";
import { ShieldCheck, AlertCircle, Check } from "lucide-react";

const PERKS = [
  "5 free scans per day",
  "4-layer detection pipeline",
  "VirusTotal + OTX enrichment",
  "Upgrade to Pro anytime",
];

export default function RegisterPage() {
  const [email, setEmail]           = useState("");
  const [password, setPassword]     = useState("");
  const [confirm, setConfirm]       = useState("");
  const [error, setError]           = useState<string | null>(null);
  const [loading, setLoading]       = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setLoading(true);
    try {
      const data = await apiRegister(email, password);
      storeSession(data.access_token, email, data.api_key, data.tier, data.trial_ends_at ?? null, data.is_verified ?? false);
      window.location.href = "/scan";
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-4xl grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
        {/* Left — value prop */}
        <div className="hidden md:block pt-4">
          <div className="flex items-center gap-3 mb-6">
            <div className="h-10 w-10 rounded-lg bg-red-600 flex items-center justify-center">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <span className="text-xl font-bold text-white tracking-tight">RedGuard</span>
          </div>

          <h2 className="text-3xl font-bold text-white leading-tight mb-3">
            Enterprise-grade security,<br />free to start.
          </h2>
          <p className="text-slate-400 text-sm mb-8 leading-relaxed">
            Built by the people, for the people. Four detection layers working in parallel to catch threats that single-engine scanners miss.
          </p>

          <ul className="space-y-3">
            {PERKS.map((p) => (
              <li key={p} className="flex items-center gap-2.5 text-sm text-slate-300">
                <span className="h-5 w-5 rounded-full bg-green-900/50 border border-green-700 flex items-center justify-center shrink-0">
                  <Check size={11} className="text-green-400" />
                </span>
                {p}
              </li>
            ))}
          </ul>

          <div className="mt-10 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
            <p className="text-xs text-slate-500 italic">
              &ldquo;The ML + VirusTotal combo caught a zero-day variant our AV missed entirely.&rdquo;
            </p>
            <p className="text-xs text-slate-600 mt-2">— Beta user, Fortune 500 SOC team</p>
          </div>
        </div>

        {/* Right — form */}
        <div>
          <div className="flex items-center gap-3 justify-center mb-6 md:hidden">
            <div className="h-10 w-10 rounded-lg bg-red-600 flex items-center justify-center">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <span className="text-xl font-bold text-white tracking-tight">RedGuard</span>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-8 shadow-2xl">
            <h1 className="text-2xl font-bold text-white mb-1">Create your account</h1>
            <p className="text-sm text-slate-400 mb-6">Free forever · No credit card required</p>

            {error && (
              <div className="flex items-center gap-2 rounded-lg bg-red-900/30 border border-red-700 px-3 py-2.5 mb-5">
                <AlertCircle size={15} className="text-red-400 shrink-0" />
                <p className="text-sm text-red-300">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">
                  Email address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoComplete="email"
                  placeholder="you@example.com"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-white placeholder-slate-600 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="new-password"
                  placeholder="Min. 8 characters"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-white placeholder-slate-600 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">
                  Confirm password
                </label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  autoComplete="new-password"
                  placeholder="••••••••"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-white placeholder-slate-600 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 transition-colors"
                />
              </div>

              <p className="text-xs text-slate-600">
                By creating an account you agree to our{" "}
                <a href="#" className="underline hover:text-slate-400">Terms of Service</a> and{" "}
                <a href="#" className="underline hover:text-slate-400">Privacy Policy</a>.
              </p>

              <button
                type="submit"
                disabled={loading}
                className="w-full rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors px-4 py-2.5 text-sm font-semibold text-white"
              >
                {loading ? "Creating account…" : "Create free account"}
              </button>
            </form>

            <p className="mt-6 text-center text-sm text-slate-500">
              Already have an account?{" "}
              <a href="/login" className="text-red-400 hover:text-red-300 transition-colors font-medium">
                Sign in
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
