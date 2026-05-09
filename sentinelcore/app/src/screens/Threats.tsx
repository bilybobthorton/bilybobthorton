import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, CheckCircle, Clock, RefreshCw } from "lucide-react";
import StatusBadge from "../components/StatusBadge";

interface Alert {
  id: number;
  severity: string;
  message: string;
  file_path: string | null;
  created_at: string;
}

type Filter = "all" | "critical" | "high" | "medium";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all",      label: "All" },
  { id: "critical", label: "Critical" },
  { id: "high",     label: "High" },
  { id: "medium",   label: "Medium" },
];

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function severityColor(severity: string): string {
  switch (severity) {
    case "critical": return "#e0343a";
    case "high":     return "#f97316";
    default:         return "#eab308";
  }
}

export default function Threats() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await invoke<Alert[]>("get_alerts", { limit: 50 });
      setAlerts(data);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const filtered = filter === "all" ? alerts : alerts.filter((a) => a.severity === filter);

  return (
    <div className="screen">
      <div className="screen-header">
        <h2 className="screen-title">Threats</h2>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 12, color: "var(--text-3)" }}>{alerts.length} total</span>
          <button
            onClick={load}
            disabled={loading}
            className="btn btn-secondary"
            style={{ padding: "6px 10px", gap: 6, fontSize: 12 }}
          >
            <RefreshCw size={12} className={loading ? "spin" : ""} />
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            onClick={() => setFilter(f.id)}
            className={`filter-pill${filter === f.id ? " active" : ""}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="error-banner" style={{ marginBottom: 16 }}>
          <span>{error}</span>
          <button className="error-dismiss" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {!loading && filtered.length === 0 && (
        <div className="empty-state">
          <CheckCircle size={40} color="var(--green)" />
          <div className="empty-state-title">No threats detected</div>
          <div>
            {filter === "all" ? "Your system is clean." : `No ${filter} severity threats.`}
          </div>
        </div>
      )}

      {!loading && filtered.length > 0 && (
        <div className="card-list">
          {filtered.map((alert, i) => (
            <div
              key={alert.id}
              className="card-list-row"
              style={{
                gap: 14,
                alignItems: "flex-start",
                borderLeft: `3px solid ${severityColor(alert.severity)}`,
              }}
            >
              <AlertTriangle
                size={15}
                color={severityColor(alert.severity)}
                style={{ flexShrink: 0, marginTop: 1 }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, color: "var(--text-2)", marginBottom: 4, lineHeight: 1.4 }}>
                  {alert.message}
                </div>
                {alert.file_path && (
                  <div
                    style={{
                      fontSize: 10.5,
                      color: "var(--text-3)",
                      fontFamily: "monospace",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      marginBottom: 5,
                    }}
                    title={alert.file_path}
                  >
                    {alert.file_path}
                  </div>
                )}
                <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10.5, color: "var(--text-3)" }}>
                  <Clock size={10} />
                  {timeAgo(alert.created_at)}
                </div>
              </div>
              <div style={{ flexShrink: 0 }}>
                <StatusBadge label={alert.severity} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
