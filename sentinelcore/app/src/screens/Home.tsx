import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Globe,
  FileSearch,
  AlertTriangle,
} from "lucide-react";
import type { AuthState, Screen } from "../App";
import StatusBadge from "../components/StatusBadge";

interface ThreatStats {
  total_alerts: number;
  critical: number;
  high: number;
}

interface Alert {
  id: number;
  severity: string;
  message: string;
  file_path: string | null;
  created_at: string;
}

interface ScanResult {
  threat_level: string;
  score: number;
  status: string;
}

interface HomeProps {
  auth: AuthState;
  onNavigate: (s: Screen) => void;
}

function Toggle({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      style={{
        width: 44,
        height: 24,
        borderRadius: 12,
        border: "none",
        background: checked ? "#dc2626" : "#1e1e2e",
        position: "relative",
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "background 0.2s",
        flexShrink: 0,
      }}
    >
      <span
        style={{
          position: "absolute",
          top: 3,
          left: checked ? 23 : 3,
          width: 18,
          height: 18,
          borderRadius: "50%",
          background: "#fff",
          transition: "left 0.2s",
        }}
      />
    </button>
  );
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function Home({ onNavigate }: HomeProps) {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [vpnConnected, setVpnConnected] = useState(false);
  const [protectionOn, setProtectionOn] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [s, a, v] = await Promise.all([
        invoke<ThreatStats>("get_threat_stats"),
        invoke<Alert[]>("get_alerts", { limit: 5 }),
        invoke<{ connected: boolean }>("get_vpn_status"),
      ]);
      setStats(s);
      setAlerts(a);
      setVpnConnected(v.connected);
    } catch (e) {
      console.warn("Failed to load home data:", e);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleVpnToggle = async (on: boolean) => {
    try {
      if (on) {
        // Use first available device.
        const keys = await invoke<{ id: number; name: string }[]>("get_vpn_keys");
        if (keys.length === 0) {
          setError("No VPN devices configured. Add one at dashboard.redgaurd.com");
          return;
        }
        await invoke("connect_vpn", { deviceId: keys[0].id });
        setVpnConnected(true);
      } else {
        await invoke("disconnect_vpn");
        setVpnConnected(false);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handleScanFile = async () => {
    try {
      // Use Tauri's dialog via shell open — but for file picking we use
      // the native file dialog via tauri-plugin-dialog if available.
      // Fallback: prompt the user for a path via JS input.
      const path = window.prompt("Enter the full path of the file to scan:");
      if (!path) return;
      setScanning(true);
      setScanResult(null);
      setError(null);
      const result = await invoke<ScanResult>("scan_file", { path });
      setScanResult(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  };

  const isProtected = protectionOn && !stats?.critical;

  return (
    <div
      style={{
        padding: "28px 32px",
        height: "100%",
        overflowY: "auto",
      }}
    >
      <h2
        style={{
          fontSize: 18,
          fontWeight: 700,
          color: "#f1f5f9",
          marginBottom: 24,
          letterSpacing: "-0.02em",
        }}
      >
        Dashboard
      </h2>

      {/* Protection status card */}
      <div
        style={{
          background: "#0d0d14",
          border: `1px solid ${isProtected ? "#166534" : "#7f1d1d"}`,
          borderRadius: 12,
          padding: "28px 24px",
          display: "flex",
          alignItems: "center",
          gap: 24,
          marginBottom: 20,
        }}
      >
        <div
          style={{
            width: 64,
            height: 64,
            borderRadius: "50%",
            background: isProtected ? "#14532d" : "#450a0a",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            boxShadow: isProtected
              ? "0 0 24px #22c55e30"
              : "0 0 24px #ef444430",
          }}
        >
          {isProtected ? (
            <ShieldCheck size={32} color="#22c55e" />
          ) : (
            <ShieldAlert size={32} color="#ef4444" />
          )}
        </div>
        <div>
          <div
            style={{
              fontSize: 20,
              fontWeight: 700,
              color: isProtected ? "#22c55e" : "#ef4444",
              marginBottom: 4,
            }}
          >
            {isProtected ? "You're Protected" : "At Risk"}
          </div>
          <div style={{ color: "#64748b", fontSize: 13 }}>
            {isProtected
              ? "Real-time protection is active. Your system is secure."
              : "Action required. Review threats below."}
          </div>
        </div>
      </div>

      {/* Toggle cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 12,
          marginBottom: 20,
        }}
      >
        <ToggleCard
          title="Malware Protection"
          subtitle="Real-time file scanning"
          icon={<Shield size={18} color={protectionOn ? "#dc2626" : "#64748b"} />}
          checked={protectionOn}
          onChange={setProtectionOn}
        />
        <ToggleCard
          title="VPN Protection"
          subtitle={vpnConnected ? "US East — New York" : "Not connected"}
          icon={<Globe size={18} color={vpnConnected ? "#22c55e" : "#64748b"} />}
          checked={vpnConnected}
          onChange={handleVpnToggle}
        />
      </div>

      {/* Stats row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 12,
          marginBottom: 20,
        }}
      >
        <StatCard label="Threats Blocked" value={stats?.total_alerts ?? "—"} />
        <StatCard label="Critical" value={stats?.critical ?? "—"} accent="#ef4444" />
        <StatCard
          label="VPN Status"
          value={vpnConnected ? "Connected" : "Off"}
          accent={vpnConnected ? "#22c55e" : "#64748b"}
        />
      </div>

      {/* Scan file button */}
      <div style={{ marginBottom: 20 }}>
        <button
          onClick={handleScanFile}
          disabled={scanning}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "10px 18px",
            background: scanning ? "#1e1e2e" : "#dc2626",
            color: "#fff",
            border: "none",
            borderRadius: 8,
            fontWeight: 600,
            fontSize: 13,
            cursor: scanning ? "not-allowed" : "pointer",
            transition: "background 0.15s",
          }}
        >
          <FileSearch size={16} />
          {scanning ? "Scanning…" : "Scan a file"}
        </button>

        {scanResult && (
          <div
            style={{
              marginTop: 12,
              padding: "12px 16px",
              background: "#0d0d14",
              border: "1px solid #1e1e2e",
              borderRadius: 8,
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <span style={{ color: "#94a3b8", fontSize: 13 }}>Scan result:</span>
            <StatusBadge label={scanResult.threat_level} />
            <span style={{ color: "#64748b", fontSize: 12 }}>
              Score: {(scanResult.score * 100).toFixed(1)}%
            </span>
          </div>
        )}

        {error && (
          <div
            style={{
              marginTop: 10,
              padding: "8px 12px",
              background: "#ef444418",
              border: "1px solid #ef444430",
              borderRadius: 7,
              color: "#ef4444",
              fontSize: 12,
            }}
          >
            {error}
          </div>
        )}
      </div>

      {/* Recent threats */}
      <div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 12,
          }}
        >
          <h3 style={{ fontSize: 14, fontWeight: 600, color: "#94a3b8" }}>
            Recent Threats
          </h3>
          <button
            onClick={() => onNavigate("threats")}
            style={{
              background: "none",
              border: "none",
              color: "#dc2626",
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            View all
          </button>
        </div>

        {alerts.length === 0 ? (
          <div
            style={{
              padding: "20px",
              textAlign: "center",
              color: "#475569",
              fontSize: 13,
              background: "#0d0d14",
              border: "1px solid #1e1e2e",
              borderRadius: 8,
            }}
          >
            No recent threats detected
          </div>
        ) : (
          <div
            style={{
              background: "#0d0d14",
              border: "1px solid #1e1e2e",
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            {alerts.map((alert, i) => (
              <div
                key={alert.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "12px 16px",
                  borderBottom:
                    i < alerts.length - 1 ? "1px solid #1e1e2e" : "none",
                }}
              >
                <AlertTriangle
                  size={15}
                  color={
                    alert.severity === "critical"
                      ? "#ef4444"
                      : alert.severity === "high"
                      ? "#f97316"
                      : "#eab308"
                  }
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      color: "#cbd5e1",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {alert.message}
                  </div>
                  {alert.file_path && (
                    <div
                      style={{
                        fontSize: 11,
                        color: "#475569",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {alert.file_path}
                    </div>
                  )}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <StatusBadge label={alert.severity} />
                  <span style={{ fontSize: 11, color: "#475569", whiteSpace: "nowrap" }}>
                    {timeAgo(alert.created_at)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ToggleCard({
  title,
  subtitle,
  icon,
  checked,
  onChange,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div
      style={{
        background: "#0d0d14",
        border: "1px solid #1e1e2e",
        borderRadius: 10,
        padding: "16px",
        display: "flex",
        alignItems: "center",
        gap: 12,
      }}
    >
      <div
        style={{
          width: 36,
          height: 36,
          background: "#1e1e2e",
          borderRadius: 8,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        {icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#f1f5f9" }}>
          {title}
        </div>
        <div
          style={{
            fontSize: 11,
            color: "#64748b",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {subtitle}
        </div>
      </div>
      <Toggle checked={checked} onChange={onChange} />
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div
      style={{
        background: "#0d0d14",
        border: "1px solid #1e1e2e",
        borderRadius: 10,
        padding: "16px",
      }}
    >
      <div
        style={{
          fontSize: 22,
          fontWeight: 700,
          color: accent ?? "#f1f5f9",
          marginBottom: 4,
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {label}
      </div>
    </div>
  );
}
