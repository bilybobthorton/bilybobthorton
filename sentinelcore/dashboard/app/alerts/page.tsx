"use client";

import { useEffect, useState, useCallback } from "react";

interface AgentAlert {
  id: string;
  remote_id: string;
  agent_id: string;
  hostname: string;
  kind: string;
  severity: string;
  title: string;
  description: string;
  path: string | null;
  mitre_technique: string | null;
  process: Record<string, unknown> | null;
  hashes: { md5: string; sha256: string } | null;
  received_at: string;
  agent_timestamp: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-300 border border-red-700",
  high:     "bg-orange-900/50 text-orange-300 border border-orange-700",
  medium:   "bg-yellow-900/50 text-yellow-300 border border-yellow-700",
  low:      "bg-blue-900/50 text-blue-300 border border-blue-700",
  info:     "bg-slate-800 text-slate-300 border border-slate-600",
};

const KIND_LABELS: Record<string, string> = {
  malicious_file_detected:  "Malicious File",
  suspicious_file_created:  "Suspicious File",
  lolbas_abuse:             "LOLBAS Abuse",
  suspicious_process_chain: "Process Chain",
  critical_file_modified:   "FIM Modified",
  critical_file_deleted:    "FIM Deleted",
  known_malicious_hash:     "Known Hash",
  system_file_modified:     "System File",
  high_entropy_file:        "High Entropy",
  suspicious_child_process: "Child Process",
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}

function AlertRow({ alert, onClick }: { alert: AgentAlert; onClick: () => void }) {
  const ts = new Date(alert.received_at).toLocaleString();
  const kind = KIND_LABELS[alert.kind] ?? alert.kind;

  return (
    <tr
      className="border-b border-slate-800 hover:bg-slate-800/50 cursor-pointer transition-colors"
      onClick={onClick}
    >
      <td className="py-3 px-4">
        <SeverityBadge severity={alert.severity} />
      </td>
      <td className="py-3 px-4 font-medium text-white text-sm">{alert.title}</td>
      <td className="py-3 px-4 text-slate-400 text-xs">{kind}</td>
      <td className="py-3 px-4 text-slate-400 text-xs font-mono">{alert.hostname}</td>
      <td className="py-3 px-4 text-slate-500 text-xs">{ts}</td>
      {alert.mitre_technique && (
        <td className="py-3 px-4">
          <span className="text-xs font-mono bg-slate-800 border border-slate-700 px-2 py-0.5 rounded text-slate-300">
            {alert.mitre_technique}
          </span>
        </td>
      )}
    </tr>
  );
}

function AlertDetail({ alert, onClose }: { alert: AgentAlert; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/70">
      <div className="bg-[#0d0d14] border border-slate-700 rounded-lg w-full max-w-2xl max-h-[80vh] overflow-y-auto">
        <div className="flex items-start justify-between p-6 border-b border-slate-800">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={alert.severity} />
              {alert.mitre_technique && (
                <span className="text-xs font-mono bg-slate-800 border border-slate-700 px-2 py-0.5 rounded text-slate-300">
                  {alert.mitre_technique}
                </span>
              )}
            </div>
            <h2 className="text-white font-semibold text-lg">{alert.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-white text-xl leading-none ml-4"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-5">
          <div>
            <p className="text-slate-400 text-sm leading-relaxed">{alert.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <Field label="Hostname" value={alert.hostname} mono />
            <Field label="Agent ID" value={alert.agent_id} mono />
            <Field label="Kind" value={KIND_LABELS[alert.kind] ?? alert.kind} />
            <Field label="Received" value={new Date(alert.received_at).toLocaleString()} />
          </div>

          {alert.path && (
            <div>
              <p className="text-xs text-slate-500 mb-1 uppercase tracking-wide">Path</p>
              <p className="font-mono text-sm text-slate-300 bg-slate-900 rounded px-3 py-2 break-all">
                {alert.path}
              </p>
            </div>
          )}

          {alert.hashes && (
            <div>
              <p className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Hashes</p>
              <div className="space-y-1">
                <div className="flex gap-3 font-mono text-xs">
                  <span className="text-slate-500 w-12">MD5</span>
                  <span className="text-slate-300">{alert.hashes.md5}</span>
                </div>
                <div className="flex gap-3 font-mono text-xs">
                  <span className="text-slate-500 w-12">SHA256</span>
                  <span className="text-slate-300 break-all">{alert.hashes.sha256}</span>
                </div>
              </div>
            </div>
          )}

          {alert.process && (
            <div>
              <p className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Process</p>
              <pre className="text-xs text-slate-300 bg-slate-900 rounded px-3 py-2 overflow-x-auto">
                {JSON.stringify(alert.process, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs text-slate-500 uppercase tracking-wide mb-0.5">{label}</p>
      <p className={`text-sm text-slate-200 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AgentAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AgentAlert | null>(null);
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterKind, setFilterKind] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchAlerts = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "200" });
      if (filterSeverity) params.set("severity", filterSeverity);
      if (filterKind) params.set("kind", filterKind);

      const res = await fetch(`/api/v1/agent/alerts?${params}`);
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const data = await res.json();
      setAlerts(data);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [filterSeverity, filterKind]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(fetchAlerts, 5000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchAlerts]);

  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = alerts.filter((a) => a.severity === s).length;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Endpoint Alerts</h1>
          <p className="text-slate-500 text-sm mt-1">
            Real-time detections from the SentinelCore agent
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${
              autoRefresh
                ? "bg-green-900/40 border-green-700 text-green-400"
                : "bg-slate-800 border-slate-700 text-slate-400"
            }`}
          >
            {autoRefresh ? "Live" : "Paused"}
          </button>
          <button
            onClick={fetchAlerts}
            className="text-xs px-3 py-1.5 rounded border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-5 gap-3">
        {SEVERITY_ORDER.map((s) => (
          <button
            key={s}
            onClick={() => setFilterSeverity(filterSeverity === s ? "" : s)}
            className={`rounded-lg border p-3 text-left transition-all ${
              filterSeverity === s
                ? (SEVERITY_STYLES[s] ?? "bg-slate-800 border-slate-600")
                : "bg-slate-900 border-slate-800 hover:border-slate-600"
            }`}
          >
            <p className="text-2xl font-bold text-white">{counts[s] ?? 0}</p>
            <p className="text-xs text-slate-400 capitalize mt-0.5">{s}</p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-slate-900 border border-slate-700 text-slate-300 text-sm rounded px-3 py-1.5"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={filterKind}
          onChange={(e) => setFilterKind(e.target.value)}
          className="bg-slate-900 border border-slate-700 text-slate-300 text-sm rounded px-3 py-1.5"
        >
          <option value="">All types</option>
          {Object.entries(KIND_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        {(filterSeverity || filterKind) && (
          <button
            onClick={() => { setFilterSeverity(""); setFilterKind(""); }}
            className="text-xs text-slate-500 hover:text-slate-300 px-2"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      {loading ? (
        <div className="text-slate-500 text-sm">Loading alerts...</div>
      ) : error ? (
        <div className="rounded-lg bg-red-900/20 border border-red-800 p-4 text-red-400 text-sm">
          {error}
        </div>
      ) : alerts.length === 0 ? (
        <div className="rounded-lg border border-slate-800 p-12 text-center">
          <p className="text-slate-500 text-sm">No alerts yet.</p>
          <p className="text-slate-600 text-xs mt-1">
            Start the endpoint agent to begin receiving real-time detections.
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-slate-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="text-left py-2.5 px-4 text-xs text-slate-500 font-medium uppercase tracking-wide">Severity</th>
                <th className="text-left py-2.5 px-4 text-xs text-slate-500 font-medium uppercase tracking-wide">Title</th>
                <th className="text-left py-2.5 px-4 text-xs text-slate-500 font-medium uppercase tracking-wide">Type</th>
                <th className="text-left py-2.5 px-4 text-xs text-slate-500 font-medium uppercase tracking-wide">Host</th>
                <th className="text-left py-2.5 px-4 text-xs text-slate-500 font-medium uppercase tracking-wide">Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <AlertRow key={a.id} alert={a} onClick={() => setSelected(a)} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <AlertDetail alert={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
