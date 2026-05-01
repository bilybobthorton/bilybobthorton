"use client";
import { useEffect, useState } from "react";
import { getStoredEmail, clearSession } from "@/lib/auth";

export function AuthNav() {
  const [email, setEmail] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    setEmail(getStoredEmail());
  }, []);

  function logout() {
    clearSession();
    setEmail(null);
    setMenuOpen(false);
    window.location.href = "/";
  }

  if (!email) {
    return (
      <div className="ml-auto flex items-center gap-3">
        <a href="/login" className="text-sm text-slate-400 hover:text-white transition-colors">
          Log in
        </a>
        <a
          href="/register"
          className="rounded-lg bg-red-600 hover:bg-red-500 transition-colors px-4 py-1.5 text-sm font-semibold text-white"
        >
          Get started free
        </a>
      </div>
    );
  }

  return (
    <div className="ml-auto relative">
      <button
        onClick={() => setMenuOpen((o) => !o)}
        className="flex items-center gap-2 text-sm text-slate-300 hover:text-white transition-colors"
      >
        <span className="h-7 w-7 rounded-full bg-red-600 flex items-center justify-center text-xs font-bold text-white">
          {email[0].toUpperCase()}
        </span>
        <span className="hidden sm:block max-w-[160px] truncate">{email}</span>
        <svg className="h-4 w-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {menuOpen && (
        <div className="absolute right-0 mt-2 w-48 rounded-lg border border-slate-700 bg-[#0d0d14] shadow-xl z-50">
          <div className="px-3 py-2 border-b border-slate-700">
            <p className="text-xs text-slate-500 truncate">{email}</p>
          </div>
          <a
            href="/scan"
            onClick={() => setMenuOpen(false)}
            className="block px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
          >
            Dashboard
          </a>
          <a
            href="/billing"
            onClick={() => setMenuOpen(false)}
            className="block px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
          >
            Billing
          </a>
          <a
            href="/settings"
            onClick={() => setMenuOpen(false)}
            className="block px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
          >
            Settings
          </a>
          <div className="border-t border-slate-700">
            <button
              onClick={logout}
              className="w-full text-left px-3 py-2 text-sm text-red-400 hover:bg-slate-800 transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
