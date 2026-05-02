"use client";
import { useEffect, useState } from "react";
import { getStoredEmail, getApiKey, getStoredTier, trialDaysLeft, isTrialActive, clearSession, isVerified, getToken, authHeaders } from "@/lib/auth";
import { Copy, Check, ShieldAlert, Zap, CheckCircle, AlertCircle, Lock } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function SettingsPage() {
  const [email, setEmail]       = useState<string | null>(null);
  const [apiKey, setApiKey]     = useState<string | null>(null);
  const [tier, setTier]         = useState<string>("free");
  const [daysLeft, setDaysLeft] = useState<number | null>(null);
  const [onTrial, setOnTrial]   = useState(false);
  const [copied, setCopied]     = useState(false);
  const [verified, setVerified] = useState(false);
  const [resending, setResending] = useState(false);
  const [resent, setResent]     = useState(false);

  const [currentPw, setCurrentPw]   = useState("");
  const [newPw, setNewPw]           = useState("");
  const [confirmPw, setConfirmPw]   = useState("");
  const [pwSaving, setPwSaving]     = useState(false);
  const [pwSuccess, setPwSuccess]   = useState(false);
  const [pwError, setPwError]       = useState("");

  useEffect(() => {
    setEmail(getStoredEmail());
    setApiKey(getApiKey());
    setTier(getStoredTier());
    setDaysLeft(trialDaysLeft());
    setOnTrial(isTrialActive());
    setVerified(isVerified());
  }, []);

  async function resendVerification() {
    setResending(true);
    const token = getToken();
    await fetch(`${API}/api/v1/auth/resend-verification`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    setResending(false);
    setResent(true);
  }

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    setPwError("");
    setPwSuccess(false);
    if (newPw !== confirmPw) { setPwError("New passwords don't match"); return; }
    if (newPw.length < 8)    { setPwError("Password must be at least 8 characters"); return; }
    setPwSaving(true);
    try {
      const r = await fetch(`${API}/api/v1/auth/change-password`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
      });
      const d = await r.json();
      if (r.ok) {
        setPwSuccess(true);
        setCurrentPw(""); setNewPw(""); setConfirmPw("");
        setTimeout(() => setPwSuccess(false), 4000);
      } else {
        setPwError(d.detail ?? "Failed to update password");
      }
    } finally {
      setPwSaving(false);
    }
  }

  function copyKey() {
    if (!apiKey) return;
    navigator.clipboard.writeText(apiKey).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!email) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center">
        <ShieldAlert className="mx-auto mb-4 h-10 w-10 text-slate-600" />
        <p className="text-slate-400 mb-4">You are not signed in.</p>
        <a
          href="/login"
          className="inline-block rounded-lg bg-red-600 hover:bg-red-500 transition-colors px-5 py-2 text-sm font-semibold text-white"
        >
          Sign in
        </a>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl px-6 py-10 space-y-6">
      <h1 className="text-2xl font-bold text-white">Account Settings</h1>

      {/* Trial banner */}
      {onTrial && (
        <div className="rounded-xl border border-amber-700/50 bg-amber-900/20 px-5 py-4 flex items-center gap-3">
          <Zap size={18} className="text-amber-400 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-amber-300">
              Pro Trial Active — {daysLeft} day{daysLeft !== 1 ? "s" : ""} remaining
            </p>
            <p className="text-xs text-amber-500 mt-0.5">
              You have full Pro access. Upgrade before your trial ends to keep it.
            </p>
          </div>
          <a
            href="/billing"
            className="ml-auto shrink-0 rounded-lg bg-amber-600 hover:bg-amber-500 transition-colors px-4 py-1.5 text-xs font-semibold text-white"
          >
            Upgrade now
          </a>
        </div>
      )}

      {/* Account info */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Profile</h2>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-slate-500 mb-1">Email</p>
            <p className="text-sm text-white">{email}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Plan</p>
            <p className="text-sm text-white capitalize">
              {tier}{onTrial ? <span className="ml-1.5 text-xs text-amber-400">(trial)</span> : null}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Email status</p>
            {verified ? (
              <p className="flex items-center gap-1.5 text-sm text-green-400">
                <CheckCircle size={13} /> Verified
              </p>
            ) : (
              <div className="flex items-center gap-2 flex-wrap">
                <p className="flex items-center gap-1.5 text-sm text-amber-400">
                  <AlertCircle size={13} /> Not verified
                </p>
                {resent ? (
                  <span className="text-xs text-green-400">Email sent!</span>
                ) : (
                  <button
                    onClick={resendVerification}
                    disabled={resending}
                    className="text-xs text-slate-400 hover:text-white underline transition-colors"
                  >
                    {resending ? "Sending…" : "Resend verification"}
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
        <div className="flex gap-4 text-xs">
          <a href="/history"   className="text-slate-400 hover:text-white transition-colors underline">Scan history →</a>
          <a href="/dashboard" className="text-slate-400 hover:text-white transition-colors underline">Dashboard →</a>
          <a href="/webhooks"  className="text-slate-400 hover:text-white transition-colors underline">Webhooks →</a>
        </div>
      </div>

      {/* Change password */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Lock size={15} className="text-slate-500" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Change Password</h2>
        </div>
        <form onSubmit={changePassword} className="space-y-3">
          <div>
            <label className="text-xs text-slate-500 block mb-1">Current password</label>
            <input
              type="password"
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-slate-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-500 block mb-1">New password</label>
              <input
                type="password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                required
                minLength={8}
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-slate-500"
              />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Confirm new password</label>
              <input
                type="password"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-slate-500"
              />
            </div>
          </div>
          {pwError   && <p className="text-xs text-red-400">{pwError}</p>}
          {pwSuccess && <p className="text-xs text-green-400">Password updated successfully.</p>}
          <button
            type="submit"
            disabled={pwSaving}
            className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 transition-colors px-4 py-2 text-sm font-semibold text-white"
          >
            {pwSaving ? "Saving…" : "Update password"}
          </button>
        </form>
      </div>

      {/* API Key */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">API Key</h2>
          <p className="text-xs text-slate-500 mt-1">
            Use this key with the <code className="text-slate-400">X-API-Key</code> header to authenticate
            direct API requests.
          </p>
        </div>

        {apiKey ? (
          <div className="flex items-center gap-2 rounded-lg bg-slate-900 border border-slate-700 px-3 py-2">
            <code className="text-xs text-slate-300 flex-1 break-all font-mono">{apiKey}</code>
            <button
              onClick={copyKey}
              className="shrink-0 text-slate-500 hover:text-white transition-colors"
              title="Copy API key"
            >
              {copied ? <Check size={15} className="text-green-400" /> : <Copy size={15} />}
            </button>
          </div>
        ) : (
          <p className="text-sm text-slate-500">No API key stored in this session.</p>
        )}
      </div>

      {/* Danger zone */}
      <div className="rounded-xl border border-red-900/50 bg-[#0d0d14] p-6 space-y-3">
        <h2 className="text-sm font-semibold text-red-400 uppercase tracking-wider">Sign out</h2>
        <p className="text-xs text-slate-500">
          Signs you out of this browser session. Your data is preserved.
        </p>
        <button
          onClick={() => {
            clearSession();
            window.location.href = "/";
          }}
          className="rounded-lg border border-red-700 px-4 py-1.5 text-sm text-red-400 hover:bg-red-900/30 transition-colors"
        >
          Sign out
        </button>
      </div>
    </div>
  );
}
