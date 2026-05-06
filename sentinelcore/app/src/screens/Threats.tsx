import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, CheckCircle, Clock } from "lucide-react";
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
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "high", label: "High" },
  { id: "medium", label: "Medium" },
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

function severityIcon(severity: string) {
  const color =
    severity === "critical"
      ? "#ef4444"
      : severity === "high"
      ? "#f97316"
      : "#eab308";
  return <AlertTriangle size={16} color={color} />;
}

export default function Threats() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await invoke<Alert[]>("get_alerts", { limit: 50 });
        setAlerts(data);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered =
    filter === "all" ? alerts : alerts.filter((a) => a.severity === filter);

  return (
    <div style={{ padding: "28px 32px", height: "100%", overflowY: "auto" }}>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 24,
        }}
      >
        <h2
          style={{
            fontSize: 18,
            fontWeight: 700,
            color: "#f1f5f9",
            letterSpacing: "-0.02em",
          }}
        >
          Threats
        </h2>
        <span style={{ fontSize: 12, color: "#475569" }}>
          {alerts.length} total
        </span>
      </div>

      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          gap: 6,
          marginBottom: 20,
        }}
      >
        {FILTERS.map((f) => {
          const active = filter === f.id;
          return (
            <button
              key={f.id}
              onClick={() => setFilter(f.id)}
              style={{
                padding: "6px 14px",
                borderRadius: 20,
                border: active ? "none" : "1px solid #1e1e2e",
                background: active ? "#dc2626" : "transparent",
                color: active ? "#fff" : "#64748b",
                fontSize: 12,
                fontWeight: active ? 600 : 400,
                cursor: "pointer",
                transition: "all 0.15s",
              }}
            >
              {f.label}
            </button>
          );
        })}
      </div>

      {loading && (
        <div style={{ textAlign: "center", color: "#475569", padding: "40px 0" }}>
          Loading…
        </div>
      )}

      {error && (
        <div
          style={{
            padding: "10px 14px",
            background: "#ef444418",
            border: "1px solid #ef444430",
            borderRadius: 8,
            color: "#ef4444",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {error}
        </div>
      )}

      {!loading && filtered.length === 0 && (
        <div
          style={{
            textAlign: "center",
            padding: "60px 0",
            color: "#475569",
          }}
        >
          <CheckCircle
            size={40}
            color="#22c55e"
            style={{ margin: "0 auto 12px" }}
          />
          <div style={{ fontSize: 15, color: "#94a3b8", marginBottom: 4 }}>
            No threats detected
          </div>
          <div style={{ fontSize: 13 }}>
            {filter === "all"
              ? "Your system is clean."
              : `No ${filter} severity threats found.`}
          </div>
        </div>
      )}

      {!loading && filtered.length > 0 && (
        <div
          style={{
            background: "#0d0d14",
            border: "1px solid #1e1e2e",
            borderRadius: 10,
            overflow: "hidden",
          }}
        >
          {filtered.map((alert, i) => (
            <div
              key={alert.id}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 14,
                padding: "14px 16px",
                borderBottom:
                  i < filtered.length - 1 ? "1px solid #1e1e2e" : "none",
                transition: "background 0.1s",
              }}
              onMouseEnter={(e) =>
                ((e.currentTarget as HTMLDivElement).style.background =
                  "#0a0a0f")
              }
              onMouseLeave={(e) =>
                ((e.currentTarget as HTMLDivElement).style.background =
                  "transparent")
              }
            >
              <div style={{ marginTop: 1 }}>{severityIcon(alert.severity)}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    fontSize: 13,
                    color: "#cbd5e1",
                    marginBottom: 3,
                    lineHeight: 1.4,
                  }}
                >
                  {alert.message}
                </div>
                {alert.file_path && (
                  <div
                    style={{
                      fontSize: 11,
                      color: "#475569",
                      fontFamily: "monospace",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      marginBottom: 4,
                    }}
                    title={alert.file_path}
                  >
                    {alert.file_path}
                  </div>
                )}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: 11,
                    color: "#475569",
                  }}
                >
                  <Clock size={11} />
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
