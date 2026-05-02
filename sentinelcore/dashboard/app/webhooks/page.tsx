"use client";
import { useEffect, useState } from "react";
import { Plus, Trash2, Zap, ShieldAlert, CheckCircle, XCircle, Copy, Check } from "lucide-react";
import { getToken, getStoredTier } from "@/lib/auth";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

interface Webhook {
  id: string;
  url: string;
  events: string[];
  is_active: boolean;
  secret: string;
  created_at: string;
}

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [tier, setTier] = useState("free");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>(["scan.malicious", "scan.suspicious"]);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean } | null>(null);
  const [copiedSecret, setCopiedSecret] = useState<string | null>(null);

  useEffect(() => {
    setTier(getStoredTier());
    fetch(`${API}/api/v1/webhooks`, { headers: authHeaders() })
      .then((r) => r.json())
      .then((d) => { if (Array.isArray(d)) setWebhooks(d); })
      .finally(() => setLoading(false));
  }, []);

  async function createWebhook() {
    if (!url) return;
    setCreating(true);
    setError("");
    try {
      const r = await fetch(`${API}/api/v1/webhooks`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ url, events }),
      });
      const d = await r.json();
      if (r.ok) {
        setWebhooks((prev) => [...prev, d]);
        setUrl("");
      } else {
        setError(d.detail ?? "Failed to create webhook");
      }
    } finally {
      setCreating(false);
    }
  }

  async function deleteWebhook(id: string) {
    await fetch(`${API}/api/v1/webhooks/${id}`, { method: "DELETE", headers: authHeaders() });
    setWebhooks((prev) => prev.filter((w) => w.id !== id));
  }

  async function testWebhook(id: string) {
    setTesting(id);
    setTestResult(null);
    const r = await fetch(`${API}/api/v1/webhooks/${id}/test`, { method: "POST", headers: authHeaders() });
    const d = await r.json();
    setTestResult({ id, ok: d.success });
    setTesting(null);
  }

  function copySecret(secret: string, id: string) {
    navigator.clipboard.writeText(secret).then(() => {
      setCopiedSecret(id);
      setTimeout(() => setCopiedSecret(null), 2000);
    });
  }

  function toggleEvent(ev: string) {
    setEvents((prev) =>
      prev.includes(ev) ? prev.filter((e) => e !== ev) : [...prev, ev]
    );
  }

  const canCreate = tier === "pro" || tier === "enterprise";

  if (!getToken()) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center">
        <ShieldAlert className="mx-auto mb-4 h-10 w-10 text-slate-600" />
        <p className="text-slate-400 mb-4">Sign in to manage webhooks.</p>
        <a href="/login" className="inline-block rounded-lg bg-red-600 px-5 py-2 text-sm font-semibold text-white">Sign in</a>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-10 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Webhook Endpoints</h1>
        <p className="text-sm text-slate-400 mt-1">
          Receive real-time HTTP POST notifications when scans complete. Verified with <code className="text-slate-300">X-Sentinel-Signature</code>.
        </p>
      </div>

      {!canCreate && (
        <div className="rounded-xl border border-amber-700/40 bg-amber-900/15 px-5 py-4 flex items-center gap-3">
          <Zap size={17} className="text-amber-400 shrink-0" />
          <p className="text-sm text-amber-300">
            Webhooks are available on Pro and Enterprise plans.{" "}
            <a href="/billing" className="underline">Upgrade →</a>
          </p>
        </div>
      )}

      {/* Add webhook form */}
      {canCreate && (
        <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Add endpoint</h2>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://your-server.com/webhook"
            className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-slate-500"
          />
          <div className="flex gap-3 flex-wrap">
            {["scan.complete", "scan.malicious", "scan.suspicious"].map((ev) => (
              <label key={ev} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={events.includes(ev)}
                  onChange={() => toggleEvent(ev)}
                  className="rounded border-slate-600 bg-slate-800 text-red-600"
                />
                <span className="text-xs text-slate-300 font-mono">{ev}</span>
              </label>
            ))}
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            onClick={createWebhook}
            disabled={creating || !url}
            className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 transition-colors px-4 py-2 text-sm font-semibold text-white"
          >
            <Plus size={15} />
            {creating ? "Adding…" : "Add webhook"}
          </button>
        </div>
      )}

      {/* Webhook list */}
      <div className="space-y-4">
        {loading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : webhooks.length === 0 ? (
          <div className="rounded-xl border border-slate-800 p-8 text-center">
            <p className="text-sm text-slate-500">No webhook endpoints configured.</p>
          </div>
        ) : (
          webhooks.map((wh) => (
            <div key={wh.id} className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5 space-y-3">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-mono text-white truncate">{wh.url}</p>
                  <div className="flex gap-2 mt-1.5 flex-wrap">
                    {wh.events.map((ev) => (
                      <span key={ev} className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                        {ev}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => testWebhook(wh.id)}
                    disabled={testing === wh.id}
                    className="text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 rounded px-2.5 py-1 transition-colors"
                  >
                    {testing === wh.id ? "Testing…" : "Test"}
                  </button>
                  <button
                    onClick={() => deleteWebhook(wh.id)}
                    className="text-red-500 hover:text-red-400 transition-colors"
                    title="Delete webhook"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>

              {testResult?.id === wh.id && (
                <div className={`flex items-center gap-2 text-xs ${testResult.ok ? "text-green-400" : "text-red-400"}`}>
                  {testResult.ok ? <CheckCircle size={13} /> : <XCircle size={13} />}
                  {testResult.ok ? "Test delivery succeeded" : "Test delivery failed — check your endpoint"}
                </div>
              )}

              <div className="flex items-center gap-2 pt-1 border-t border-slate-800">
                <span className="text-xs text-slate-500">Secret:</span>
                <code className="text-xs font-mono text-slate-400 flex-1 truncate">{wh.secret.slice(0, 20)}…</code>
                <button
                  onClick={() => copySecret(wh.secret, wh.id)}
                  className="text-slate-500 hover:text-white transition-colors"
                  title="Copy signing secret"
                >
                  {copiedSecret === wh.id ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Docs */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-3">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Verifying signatures</h2>
        <pre className="text-xs text-slate-400 bg-slate-900 rounded-lg p-4 overflow-x-auto">{`import hmac, hashlib

secret = "your_signing_secret"
body   = request.body        # raw bytes

sig = "sha256=" + hmac.new(
    secret.encode(), body, hashlib.sha256
).hexdigest()

assert sig == request.headers["X-Sentinel-Signature"]`}</pre>
      </div>
    </div>
  );
}
