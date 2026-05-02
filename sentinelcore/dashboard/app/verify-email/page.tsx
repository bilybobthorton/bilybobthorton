"use client";
import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { CheckCircle, XCircle, Loader2 } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function VerifyEmailPage() {
  const params = useSearchParams();
  const token = params.get("token");
  const [state, setState] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setState("error");
      setMessage("No verification token provided.");
      return;
    }
    fetch(`${API}/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`)
      .then(async (r) => {
        const data = await r.json();
        if (r.ok) {
          setState("success");
          setMessage(data.message ?? "Email verified!");
        } else {
          setState("error");
          setMessage(data.detail ?? "Verification failed.");
        }
      })
      .catch(() => {
        setState("error");
        setMessage("Network error — please try again.");
      });
  }, [token]);

  return (
    <div className="mx-auto max-w-md px-6 py-24 text-center">
      {state === "loading" && (
        <>
          <Loader2 className="mx-auto mb-4 h-10 w-10 text-slate-400 animate-spin" />
          <p className="text-slate-400">Verifying your email…</p>
        </>
      )}
      {state === "success" && (
        <>
          <CheckCircle className="mx-auto mb-4 h-12 w-12 text-green-500" />
          <h1 className="text-2xl font-bold text-white mb-2">Email verified!</h1>
          <p className="text-slate-400 mb-8">{message}</p>
          <a
            href="/scan"
            className="inline-block rounded-lg bg-red-600 hover:bg-red-500 transition-colors px-6 py-2.5 text-sm font-semibold text-white"
          >
            Start scanning →
          </a>
        </>
      )}
      {state === "error" && (
        <>
          <XCircle className="mx-auto mb-4 h-12 w-12 text-red-500" />
          <h1 className="text-2xl font-bold text-white mb-2">Verification failed</h1>
          <p className="text-slate-400 mb-8">{message}</p>
          <a
            href="/settings"
            className="inline-block rounded-lg border border-slate-700 hover:border-slate-500 transition-colors px-6 py-2.5 text-sm font-semibold text-slate-300"
          >
            Resend verification
          </a>
        </>
      )}
    </div>
  );
}
