"use client";
import { useEffect, useState } from "react";
import { Plus, Trash2, Download, Copy, Check, ShieldAlert, Zap, Wifi } from "lucide-react";
import { getToken, getStoredTier, authHeaders } from "@/lib/auth";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

interface VpnKey {
  id: string;
  name: string;
  public_key: string;
  client_ip: string;
  created_at: string;
}

interface VpnKeyCreated extends VpnKey {
  private_key: string;
  preshared_key: string;
  config: string;
}

const DEVICE_LIMITS: Record<string, number> = { free: 1, pro: 5, enterprise: 25 };

export default function VpnKeysPage() {
  const [keys, setKeys] = useState<VpnKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [tier, setTier] = useState("free");
  const [name, setName] = useState("My Device");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<VpnKeyCreated | null>(null);
  const [error, setError] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  useEffect(() => {
    setTier(getStoredTier());
    if (!getToken()) { setLoading(false); return; }
    fetch(`${API}/api/v1/vpn/keys`, { headers: authHeaders() })
      .then((r) => r.ok ? r.json() : [])
      .then((d) => { if (Array.isArray(d)) setKeys(d); })
      .finally(() => setLoading(false));
  }, []);

  async function generateKey() {
    setCreating(true);
    setError("");
    setNewKey(null);
    try {
      const r = await fetch(`${API}/api/v1/vpn/keys`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const d = await r.json();
      if (r.ok) {
        setNewKey(d);
        setKeys((prev) => [...prev, { id: d.id, name: d.name, public_key: d.public_key, client_ip: d.client_ip, created_at: d.created_at }]);
        setName("My Device");
      } else {
        setError(d.detail ?? "Failed to generate key");
      }
    } finally {
      setCreating(false);
    }
  }

  async function revokeKey(id: string) {
    setDeleting(id);
    await fetch(`${API}/api/v1/vpn/keys/${id}`, { method: "DELETE", headers: authHeaders() });
    setKeys((prev) => prev.filter((k) => k.id !== id));
    if (newKey?.id === id) setNewKey(null);
    setDeleting(null);
  }

  function downloadConfig(key: VpnKeyCreated) {
    const blob = new Blob([key.config], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${key.name.replace(/\s+/g, "_")}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copyPubKey(pub: string, id: string) {
    navigator.clipboard.writeText(pub).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    });
  }

  const limit = DEVICE_LIMITS[tier] ?? 1;
  const atLimit = keys.length >= limit;

  if (!getToken()) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center">
        <ShieldAlert className="mx-auto mb-4 h-10 w-10 text-slate-600" />
        <p className="text-slate-400 mb-4">Sign in to manage VPN devices.</p>
        <a href="/login" className="inline-block rounded-lg bg-red-600 px-5 py-2 text-sm font-semibold text-white">Sign in</a>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-10 space-y-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Wifi size={22} className="text-indigo-400" /> VPN Devices
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Generate WireGuard configs for your devices. Download and import into any WireGuard client.
          </p>
        </div>
        <span className="text-xs text-slate-500 border border-slate-800 rounded px-2 py-1 mt-1 shrink-0">
          {keys.length} / {limit} devices
        </span>
      </div>

      {tier === "free" && (
        <div className="rounded-xl border border-indigo-700/40 bg-indigo-900/15 px-5 py-4 flex items-center gap-3">
          <Zap size={17} className="text-indigo-400 shrink-0" />
          <p className="text-sm text-indigo-300">
            Free plan includes 1 device. Upgrade to Pro for 5 devices and all server locations.{" "}
            <a href="/billing" className="underline">Upgrade →</a>
          </p>
        </div>
      )}

      {/* New key created — show once */}
      {newKey && (
        <div className="rounded-xl border border-green-700/50 bg-green-900/15 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-green-300">
              ✓ Key generated — download your config now. Private key won't be shown again.
            </p>
            <button
              onClick={() => setNewKey(null)}
              className="text-slate-500 hover:text-white text-xs transition-colors"
            >
              Dismiss
            </button>
          </div>
          <div className="space-y-2">
            <p className="text-xs text-slate-400">Config file for <strong className="text-white">{newKey.name}</strong></p>
            <pre className="text-xs text-slate-300 bg-slate-900 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all font-mono leading-relaxed">
              {newKey.config}
            </pre>
          </div>
          <button
            onClick={() => downloadConfig(newKey)}
            className="flex items-center gap-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 transition-colors px-4 py-2 text-sm font-semibold text-white"
          >
            <Download size={15} /> Download {newKey.name.replace(/\s+/g, "_")}.conf
          </button>
        </div>
      )}

      {/* Add device form */}
      {!atLimit && (
        <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Add device</h2>
          <div className="flex gap-3">
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Device name (e.g. MacBook, iPhone)"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-slate-500"
            />
            <button
              onClick={generateKey}
              disabled={creating || !name.trim()}
              className="flex items-center gap-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 transition-colors px-4 py-2 text-sm font-semibold text-white shrink-0"
            >
              <Plus size={15} />
              {creating ? "Generating…" : "Generate"}
            </button>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
      )}

      {atLimit && !newKey && (
        <div className="rounded-xl border border-slate-800 bg-[#0d0d14] px-5 py-4 text-sm text-slate-400">
          Device limit reached ({limit} for {tier} plan).{" "}
          {tier !== "enterprise" && <a href="/billing" className="text-indigo-400 hover:text-indigo-300 underline">Upgrade →</a>}
        </div>
      )}

      {/* Device list */}
      <div className="space-y-3">
        <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Your devices</h2>
        {loading ? (
          <div className="space-y-3">
            {[...Array(2)].map((_, i) => (
              <div key={i} className="h-20 rounded-xl border border-slate-800 bg-[#0d0d14] animate-pulse" />
            ))}
          </div>
        ) : keys.length === 0 ? (
          <div className="rounded-xl border border-slate-800 p-8 text-center">
            <Wifi size={28} className="mx-auto mb-3 text-slate-700" />
            <p className="text-sm text-slate-500">No devices yet. Generate your first WireGuard config above.</p>
          </div>
        ) : (
          keys.map((k) => (
            <div key={k.id} className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-white">{k.name}</p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {k.client_ip} · Added {new Date(k.created_at).toLocaleDateString()}
                  </p>
                  <div className="flex items-center gap-2 mt-2">
                    <code className="text-xs font-mono text-slate-500 truncate max-w-[260px]">{k.public_key}</code>
                    <button
                      onClick={() => copyPubKey(k.public_key, k.id)}
                      className="text-slate-600 hover:text-slate-400 transition-colors shrink-0"
                      title="Copy public key"
                    >
                      {copiedId === k.id ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <a
                    href={`${API}/api/v1/vpn/keys/${k.id}/config`}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-800/60 hover:border-indigo-600 rounded px-2.5 py-1 transition-colors"
                  >
                    <Download size={12} /> Config
                  </a>
                  <button
                    onClick={() => revokeKey(k.id)}
                    disabled={deleting === k.id}
                    className="text-red-600 hover:text-red-400 transition-colors disabled:opacity-50"
                    title="Revoke device"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Setup guide */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-3">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Setup guide</h2>
        <div className="space-y-3 text-sm text-slate-400">
          <div className="flex gap-3">
            <span className="text-slate-600 font-mono w-4 shrink-0">1.</span>
            <span>Generate a config for your device above and download the <code className="text-slate-300">.conf</code> file.</span>
          </div>
          <div className="flex gap-3">
            <span className="text-slate-600 font-mono w-4 shrink-0">2.</span>
            <span>Install the WireGuard app: <a href="https://www.wireguard.com/install/" target="_blank" rel="noreferrer" className="text-indigo-400 hover:text-indigo-300">wireguard.com/install</a> (Windows / macOS / iOS / Android / Linux).</span>
          </div>
          <div className="flex gap-3">
            <span className="text-slate-600 font-mono w-4 shrink-0">3.</span>
            <span>Import the <code className="text-slate-300">.conf</code> file into WireGuard and toggle the tunnel on.</span>
          </div>
          <div className="flex gap-3">
            <span className="text-slate-600 font-mono w-4 shrink-0">4.</span>
            <span>All traffic is encrypted and routed through SentinelVPN. DNS is protected against C2 domain leakage.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
