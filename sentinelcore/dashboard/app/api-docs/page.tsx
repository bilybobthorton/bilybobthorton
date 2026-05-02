import { Shield, Key, FileSearch, Cpu, Bell, Radio, Zap } from "lucide-react";

const BASE = "https://api.sentinelguard.com"; // update when domain is live

const endpoints = [
  {
    section: "Authentication",
    icon: <Key size={16} />,
    items: [
      { method: "POST", path: "/api/v1/auth/register", desc: "Create account. Returns JWT + API key. Starts 14-day Pro trial.", auth: false },
      { method: "POST", path: "/api/v1/auth/login",    desc: "Log in. Returns JWT + API key.", auth: false },
      { method: "GET",  path: "/api/v1/auth/verify-email?token=TOKEN", desc: "Verify email address via token from verification email.", auth: false },
      { method: "POST", path: "/api/v1/auth/resend-verification", desc: "Re-send verification email.", auth: true },
      { method: "POST", path: "/api/v1/auth/change-password", desc: "Change account password. Body: { current_password, new_password }.", auth: true },
    ],
  },
  {
    section: "File Scanning",
    icon: <FileSearch size={16} />,
    items: [
      { method: "POST", path: "/api/v1/scan/file", desc: "Upload a file for analysis. Runs static analysis → ML → VirusTotal → OTX in a background task. Returns scan_id immediately.", auth: true },
      { method: "GET",  path: "/api/v1/scan/{id}", desc: "Poll scan status and get full results including heuristics, ML score, VT/OTX intel.", auth: true },
      { method: "POST", path: "/api/v1/scan/hash", desc: "Look up a file by SHA256 hash only. Skips upload if already in DB.", auth: true },
      { method: "GET",  path: "/api/v1/scan/history", desc: "Paginated scan history. Params: limit (≤200), offset.", auth: true },
      { method: "GET",  path: "/api/v1/scan/quota/me", desc: "Returns daily quota used vs. limit for current user.", auth: true },
    ],
  },
  {
    section: "Reports",
    icon: <Shield size={16} />,
    items: [
      { method: "GET", path: "/api/v1/report/{id}",      desc: "Render full HTML scan report.", auth: true },
      { method: "GET", path: "/api/v1/report/{id}/pdf",  desc: "Download PDF scan report (Pro+). WeasyPrint-rendered A4.", auth: true },
      { method: "GET", path: "/api/v1/report/{id}/json", desc: "Raw JSON result of a scan.", auth: true },
    ],
  },
  {
    section: "ML Engine",
    icon: <Cpu size={16} />,
    items: [
      { method: "GET",  path: "/api/v1/ml/status",          desc: "ML model status: trained, threshold, feature count.", auth: true },
      { method: "POST", path: "/api/v1/ml/reload",          desc: "Hot-reload the ML model from disk (no restart needed).", auth: true },
      { method: "POST", path: "/api/v1/ml/train/synthetic", desc: "Train a new model on synthetic data (dev use). Enterprise only.", auth: true },
    ],
  },
  {
    section: "YARA Rules",
    icon: <FileSearch size={16} />,
    items: [
      { method: "GET",    path: "/api/v1/yara/rules",        desc: "List all YARA rules (built-in + custom). Pro+ for custom rules.", auth: true },
      { method: "POST",   path: "/api/v1/yara/rules",        desc: "Create a new custom YARA rule.", auth: true },
      { method: "GET",    path: "/api/v1/yara/rules/{id}",   desc: "Get a single rule.", auth: true },
      { method: "PUT",    path: "/api/v1/yara/rules/{id}",   desc: "Update a rule.", auth: true },
      { method: "DELETE", path: "/api/v1/yara/rules/{id}",   desc: "Delete a rule.", auth: true },
      { method: "POST",   path: "/api/v1/yara/validate",     desc: "Validate YARA rule syntax without saving.", auth: true },
    ],
  },
  {
    section: "Webhooks",
    icon: <Bell size={16} />,
    items: [
      { method: "GET",    path: "/api/v1/webhooks",           desc: "List webhook endpoints. Pro+ only.", auth: true },
      { method: "POST",   path: "/api/v1/webhooks",           desc: "Create endpoint. Events: scan.complete, scan.malicious, scan.suspicious.", auth: true },
      { method: "DELETE", path: "/api/v1/webhooks/{id}",      desc: "Delete endpoint.", auth: true },
      { method: "POST",   path: "/api/v1/webhooks/{id}/test", desc: "Send test payload to verify endpoint is reachable.", auth: true },
    ],
  },
  {
    section: "Agent Alerts",
    icon: <Radio size={16} />,
    items: [
      { method: "POST", path: "/api/v1/agent/alert",   desc: "Ingest alert from Rust endpoint agent. Authenticated with X-API-Key.", auth: true },
      { method: "GET",  path: "/api/v1/agent/alerts",  desc: "List recent agent alerts. Params: limit, offset.", auth: true },
      { method: "GET",  path: "/api/v1/agent/stats",   desc: "Agent alert counts by severity and kind.", auth: true },
    ],
  },
  {
    section: "SentinelVPN",
    icon: <Zap size={16} />,
    items: [
      { method: "GET",    path: "/api/v1/vpn/keys",              desc: "List your WireGuard device keys.", auth: true },
      { method: "POST",   path: "/api/v1/vpn/keys",              desc: "Generate a new WireGuard keypair. Returns private key + full .conf — save it, it won't be shown again.", auth: true },
      { method: "GET",    path: "/api/v1/vpn/keys/{id}/config",  desc: "Download WireGuard .conf file for this device.", auth: true },
      { method: "DELETE", path: "/api/v1/vpn/keys/{id}",         desc: "Revoke a device key.", auth: true },
    ],
  },
  {
    section: "Stats",
    icon: <Cpu size={16} />,
    items: [
      { method: "GET", path: "/api/v1/stats/me", desc: "Your usage stats: scans today/week/month, daily counts (14 days), threat breakdown, quota.", auth: true },
    ],
  },
];

const METHOD_COLORS: Record<string, string> = {
  GET: "bg-blue-900/40 text-blue-300 border-blue-800",
  POST: "bg-green-900/40 text-green-300 border-green-800",
  PUT: "bg-amber-900/40 text-amber-300 border-amber-800",
  DELETE: "bg-red-900/40 text-red-300 border-red-800",
  PATCH: "bg-purple-900/40 text-purple-300 border-purple-800",
};

export default function ApiDocsPage() {
  return (
    <div className="mx-auto max-w-4xl px-6 py-10 space-y-10">
      {/* Header */}
      <div className="space-y-3">
        <h1 className="text-3xl font-bold text-white">API Reference</h1>
        <p className="text-slate-400 max-w-2xl">
          REST API for SentinelCore malware scanning, threat intel, YARA rules, endpoint agent
          ingestion, webhooks, and SentinelVPN key management.
        </p>
        <div className="flex flex-wrap gap-3 pt-2">
          <div className="rounded-lg border border-slate-700 bg-[#0d0d14] px-4 py-2.5 text-sm">
            <span className="text-slate-500">Base URL: </span>
            <code className="text-slate-300 font-mono">{BASE}</code>
          </div>
        </div>
      </div>

      {/* Auth box */}
      <div className="rounded-xl border border-slate-700 bg-[#0d0d14] p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Key size={14} /> Authentication
        </h2>
        <p className="text-sm text-slate-400">
          All authenticated endpoints accept either a <strong className="text-slate-300">JWT Bearer token</strong> or
          an <strong className="text-slate-300">X-API-Key</strong> header.
        </p>
        <pre className="text-xs text-slate-300 bg-slate-900 rounded-lg p-4 overflow-x-auto">{`# JWT (after login/register)
Authorization: Bearer eyJhbGci...

# API Key (from /settings)
X-API-Key: sc_live_...`}</pre>
      </div>

      {/* Tier table */}
      <div className="rounded-xl border border-slate-700 bg-[#0d0d14] p-6 space-y-4 overflow-x-auto">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Rate limits</h2>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-slate-800">
              <th className="text-left py-2 pr-6 text-xs text-slate-500 font-medium">Tier</th>
              <th className="text-left py-2 pr-6 text-xs text-slate-500 font-medium">Scans / day</th>
              <th className="text-left py-2 pr-6 text-xs text-slate-500 font-medium">YARA rules</th>
              <th className="text-left py-2 pr-6 text-xs text-slate-500 font-medium">Webhooks</th>
              <th className="text-left py-2 text-xs text-slate-500 font-medium">VPN devices</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {[
              ["Free",       "5",   "—",   "—", "1"],
              ["Pro",        "∞",   "25",  "3", "5"],
              ["Enterprise", "∞",   "∞",   "20","25"],
            ].map(([tier, scans, yara, hooks, vpn]) => (
              <tr key={tier}>
                <td className="py-2 pr-6 text-white font-medium">{tier}</td>
                <td className="py-2 pr-6 text-slate-300">{scans}</td>
                <td className="py-2 pr-6 text-slate-300">{yara}</td>
                <td className="py-2 pr-6 text-slate-300">{hooks}</td>
                <td className="py-2 text-slate-300">{vpn}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Endpoints */}
      {endpoints.map((section) => (
        <div key={section.section} className="space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
            <span className="text-slate-500">{section.icon}</span>
            {section.section}
          </h2>
          <div className="rounded-xl border border-slate-800 bg-[#0d0d14] divide-y divide-slate-800 overflow-hidden">
            {section.items.map((item) => (
              <div key={item.path} className="px-5 py-4 flex flex-col sm:flex-row sm:items-start gap-3">
                <span className={`shrink-0 self-start text-xs font-mono font-bold px-2 py-0.5 rounded border ${METHOD_COLORS[item.method] ?? ""}`}>
                  {item.method}
                </span>
                <div className="min-w-0 flex-1">
                  <code className="text-sm text-slate-200 font-mono break-all">{item.path}</code>
                  <p className="text-xs text-slate-500 mt-0.5">{item.desc}</p>
                </div>
                {item.auth && (
                  <span className="shrink-0 self-start text-[10px] text-slate-600 border border-slate-800 rounded px-1.5 py-0.5">
                    auth
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Webhook payload */}
      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Webhook payload</h2>
        <pre className="text-xs text-slate-300 bg-slate-900 rounded-lg p-4 overflow-x-auto">{`{
  "event":       "scan.malicious",
  "scan_id":     "uuid",
  "filename":    "malware.exe",
  "sha256":      "abc123...",
  "threat_level":"malicious",
  "confidence":  0.9823,
  "timestamp":   "2026-05-02T12:00:00Z"
}`}</pre>
        <p className="text-xs text-slate-500">
          Every delivery includes an <code className="text-slate-400">X-Sentinel-Signature: sha256=...</code> header
          for verification.
        </p>
      </div>
    </div>
  );
}
