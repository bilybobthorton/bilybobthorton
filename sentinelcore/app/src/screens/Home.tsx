import { useEffect, useState, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Globe,
  FileSearch,
  AlertTriangle,
  Lock,
  Trash2,
  RotateCcw,
} from "lucide-react";
import type { AuthState, Screen } from "../App";
import StatusBadge from "../components/StatusBadge";

interface ProtectionStatus {
  enabled: boolean;
  files_analyzed: number;
  threats_blocked: number;
  threats_flagged: number;
}

interface RealtimeAlert {
  filename: string;
  path: string;
  threat_level: string;
  score: number;
  action: string;
  detail: string;
  timestamp: string;
}

interface QuarantineEntry {
  id: string;
  original_path: string;
  quarantine_path: string;
  filename: string;
  sha256: string;
  threat_level: string;
  score: number;
  timestamp: string;
  restored: boolean;
}

interface CloudStats {
  total_alerts: number;
  critical: number;
  high: number;
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

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function severityColor(level: string): string {
  switch (level.toUpperCase()) {
    case "MALICIOUS":  return "#e0343a";
    case "SUSPICIOUS": return "#f59e0b";
    default:           return "#eab308";
  }
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
      className={`toggle${checked ? " on" : ""}${disabled ? " disabled" : ""}`}
    />
  );
}

function ToggleCard({
  title,
  subtitle,
  icon,
  checked,
  onChange,
  loading,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
  loading?: boolean;
}) {
  return (
    <div className={`toggle-card${checked ? " active-border" : ""}`}>
      <div className="toggle-icon">{icon}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-1)", marginBottom: 2 }}>
          {title}
        </div>
        <div
          style={{
            fontSize: 11,
            color: "var(--text-3)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {loading ? "…" : subtitle}
        </div>
      </div>
      <Toggle checked={checked} onChange={onChange} disabled={loading} />
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
    <div className="stat-card">
      <div className="stat-value" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export default function Home({ onNavigate }: HomeProps) {
  const [protection, setProtection] = useState<ProtectionStatus>({
    enabled: true,
    files_analyzed: 0,
    threats_blocked: 0,
    threats_flagged: 0,
  });
  const [cloudStats, setCloudStats]   = useState<CloudStats | null>(null);
  const [liveAlerts, setLiveAlerts]   = useState<RealtimeAlert[]>([]);
  const [quarantine, setQuarantine]   = useState<QuarantineEntry[]>([]);
  const [vpnConnected, setVpnConnected] = useState(false);
  const [scanning, setScanning]       = useState(false);
  const [scanResult, setScanResult]   = useState<ScanResult | null>(null);
  const [error, setError]             = useState<string | null>(null);
  const [togglingProtection, setTogglingProtection] = useState(false);
  const [showQuarantine, setShowQuarantine] = useState(false);

  const addLiveAlert = useCallback((alert: RealtimeAlert) => {
    setLiveAlerts((prev) => [alert, ...prev].slice(0, 20));
  }, []);

  const loadData = useCallback(async () => {
    try {
      const [ps, vpn] = await Promise.all([
        invoke<ProtectionStatus>("get_protection_status"),
        invoke<{ connected: boolean }>("get_vpn_status"),
      ]);
      setProtection(ps);
      setVpnConnected(vpn.connected);
    } catch (e) {
      console.warn("loadData:", e);
    }
    try {
      const cs = await invoke<CloudStats>("get_threat_stats");
      setCloudStats(cs);
    } catch { /* optional */ }
    try {
      const q = await invoke<QuarantineEntry[]>("get_quarantine");
      setQuarantine(q);
    } catch { /* optional */ }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  const unlistenRef = useRef<(() => void) | null>(null);
  useEffect(() => {
    let cancelled = false;
    listen<RealtimeAlert>("protection-alert", (event) => {
      if (!cancelled) {
        addLiveAlert(event.payload);
        if (event.payload.action === "quarantined") {
          invoke<QuarantineEntry[]>("get_quarantine").then(setQuarantine).catch(() => {});
        }
      }
    }).then((unlisten) => { unlistenRef.current = unlisten; });
    return () => {
      cancelled = true;
      unlistenRef.current?.();
    };
  }, [addLiveAlert]);

  const handleProtectionToggle = async (on: boolean) => {
    setTogglingProtection(true);
    try {
      const status = await invoke<ProtectionStatus>(
        on ? "enable_realtime_protection" : "disable_realtime_protection"
      );
      setProtection(status);
    } catch (e) {
      setError(String(e));
    } finally {
      setTogglingProtection(false);
    }
  };

  const handleVpnToggle = async (on: boolean) => {
    try {
      if (on) {
        await invoke("connect_vpn");
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
    const path = window.prompt("Enter the full path of the file to scan:");
    if (!path) return;
    setScanning(true);
    setScanResult(null);
    setError(null);
    try {
      const result = await invoke<ScanResult>("scan_file", { path });
      setScanResult(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  };

  const handleRestore = async (id: string) => {
    try {
      await invoke("restore_quarantine_file", { id });
      setQuarantine((q) => q.map((e) => (e.id === id ? { ...e, restored: true } : e)));
    } catch (e) {
      setError(String(e));
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await invoke("delete_quarantine_file", { id });
      setQuarantine((q) => q.filter((e) => e.id !== id));
    } catch (e) {
      setError(String(e));
    }
  };

  const isProtected  = protection.enabled && (cloudStats?.critical ?? 0) === 0;
  const allThreats   = protection.threats_blocked + protection.threats_flagged;
  const quarantinedCount = quarantine.filter((e) => !e.restored).length;

  return (
    <div className="screen">
      {/* Header */}
      <div className="screen-header">
        <h2 className="screen-title">Dashboard</h2>
        {quarantinedCount > 0 && (
          <button
            onClick={() => setShowQuarantine(!showQuarantine)}
            className="btn btn-secondary"
            style={{
              fontSize: 12,
              padding: "6px 12px",
              border: "1px solid rgba(239,68,68,0.3)",
              color: "#fca5a5",
              background: "rgba(127,29,29,0.3)",
              gap: 6,
            }}
          >
            <Lock size={12} />
            {quarantinedCount} Quarantined
          </button>
        )}
      </div>

      {/* Protection hero */}
      <div className={`hero-card${isProtected ? " safe" : " danger"}`}>
        <div className={`hero-icon${isProtected ? " safe" : " danger"}`} style={{ position: "relative" }}>
          {protection.enabled && (
            <>
              <div className={`pulse-ring${isProtected ? " green" : " red"}`} />
              <div className={`pulse-ring${isProtected ? " green" : " red"} delay`} />
            </>
          )}
          {isProtected ? (
            <ShieldCheck size={28} color="var(--green)" />
          ) : (
            <ShieldAlert size={28} color="var(--red)" />
          )}
        </div>
        <div style={{ flex: 1 }}>
          <div
            style={{
              fontSize: 18,
              fontWeight: 700,
              color: isProtected ? "var(--green)" : "var(--red)",
              marginBottom: 3,
            }}
          >
            {protection.enabled
              ? isProtected ? "You're Protected" : "Threats Detected"
              : "Protection Disabled"}
          </div>
          <div style={{ color: "var(--text-3)", fontSize: 12.5 }}>
            {protection.enabled
              ? isProtected
                ? "Real-time monitoring active — all high-risk locations covered."
                : "Review the threats below and take action."
              : "Enable real-time protection to monitor your system."}
          </div>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0 }}>
          <div style={{ fontSize: 10, color: "var(--text-3)", marginBottom: 2, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Files scanned
          </div>
          <div
            style={{
              fontSize: 26,
              fontWeight: 700,
              color: "var(--text-2)",
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {protection.files_analyzed.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="stat-grid">
        <StatCard
          label="Threats Blocked"
          value={protection.threats_blocked}
          accent={protection.threats_blocked > 0 ? "var(--red)" : undefined}
        />
        <StatCard
          label="Flagged"
          value={protection.threats_flagged}
          accent={protection.threats_flagged > 0 ? "var(--amber)" : undefined}
        />
        <StatCard
          label="Cloud Alerts"
          value={cloudStats?.total_alerts ?? "—"}
          accent={cloudStats && cloudStats.total_alerts > 0 ? "#eab308" : undefined}
        />
        <StatCard
          label="VPN"
          value={vpnConnected ? "On" : "Off"}
          accent={vpnConnected ? "var(--green)" : "var(--text-3)"}
        />
      </div>

      {/* Toggles */}
      <div className="toggle-grid">
        <ToggleCard
          title="Malware Protection"
          subtitle={
            protection.enabled
              ? `Active — ${allThreats} threat${allThreats !== 1 ? "s" : ""} caught`
              : "Disabled — system unmonitored"
          }
          icon={<Shield size={17} color={protection.enabled ? "var(--red)" : "var(--text-3)"} />}
          checked={protection.enabled}
          onChange={handleProtectionToggle}
          loading={togglingProtection}
        />
        <ToggleCard
          title="VPN Protection"
          subtitle={vpnConnected ? "US East — New York" : "Not connected"}
          icon={<Globe size={17} color={vpnConnected ? "var(--green)" : "var(--text-3)"} />}
          checked={vpnConnected}
          onChange={handleVpnToggle}
        />
      </div>

      {/* Error */}
      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button className="error-dismiss" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Quick scan button */}
      <div style={{ marginBottom: 22, display: "flex", alignItems: "center", gap: 12 }}>
        <button
          onClick={handleScanFile}
          disabled={scanning}
          className="btn btn-secondary"
          style={{ gap: 8 }}
        >
          <FileSearch size={15} />
          {scanning ? "Scanning…" : "Scan a file"}
        </button>
        {scanResult && (
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <StatusBadge label={scanResult.threat_level} />
            <span style={{ color: "var(--text-3)", fontSize: 12 }}>
              {(scanResult.score * 100).toFixed(1)}% confidence
            </span>
          </div>
        )}
      </div>

      {/* Quarantine vault */}
      {showQuarantine && quarantine.length > 0 && (
        <div className="vault-card">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "10px 14px",
              borderBottom: "1px solid rgba(239,68,68,0.15)",
            }}
          >
            <span style={{ fontSize: 12, fontWeight: 600, color: "#fca5a5", display: "flex", alignItems: "center", gap: 6 }}>
              <Lock size={12} color="#ef4444" /> Quarantine Vault
            </span>
            <span style={{ fontSize: 10, color: "var(--text-3)" }}>XOR-encrypted — cannot execute</span>
          </div>
          {quarantine.map((entry, i) => (
            <div
              key={entry.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 14px",
                borderBottom: i < quarantine.length - 1 ? "1px solid var(--border-sub)" : "none",
                opacity: entry.restored ? 0.45 : 1,
              }}
            >
              <Lock size={12} color="#ef4444" style={{ flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12.5, color: "var(--text-1)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {entry.filename}
                </div>
                <div style={{ fontSize: 10, color: "var(--text-3)" }}>
                  {entry.sha256.slice(0, 14)}… · {(entry.score * 100).toFixed(0)}% · {timeAgo(entry.timestamp)}
                </div>
              </div>
              <StatusBadge label={entry.threat_level} />
              {!entry.restored && (
                <div style={{ display: "flex", gap: 5 }}>
                  <button
                    onClick={() => handleRestore(entry.id)}
                    title="Restore"
                    className="btn-ghost"
                    style={{ padding: "4px 6px" }}
                  >
                    <RotateCcw size={12} />
                  </button>
                  <button
                    onClick={() => handleDelete(entry.id)}
                    title="Delete permanently"
                    className="btn-ghost"
                    style={{ padding: "4px 6px", color: "#ef4444" }}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              )}
              {entry.restored && (
                <span style={{ fontSize: 10, color: "var(--text-3)" }}>Restored</span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Live alert feed */}
      <div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <h3 style={{ fontSize: 12, fontWeight: 600, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.07em" }}>
              Real-time Alerts
            </h3>
            {liveAlerts.length > 0 && (
              <span className="live-dot green" style={{ marginTop: 1 }} />
            )}
          </div>
          <button
            onClick={() => onNavigate("threats")}
            className="btn-ghost"
            style={{ fontSize: 12, color: "var(--red)", padding: "4px 8px" }}
          >
            Cloud alerts →
          </button>
        </div>

        {liveAlerts.length === 0 ? (
          <div
            style={{
              padding: "24px",
              textAlign: "center",
              color: "var(--text-3)",
              fontSize: 13,
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: "var(--r-md)",
            }}
          >
            No threats detected this session
          </div>
        ) : (
          <div className="card-list">
            {liveAlerts.map((alert, i) => (
              <div
                key={`${alert.timestamp}-${i}`}
                className="alert-row"
                style={{ borderLeft: `3px solid ${severityColor(alert.threat_level)}` }}
              >
                <AlertTriangle size={13} color={severityColor(alert.threat_level)} style={{ flexShrink: 0, marginTop: 2 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2 }}>
                    <span
                      style={{
                        fontSize: 12.5,
                        fontWeight: 600,
                        color: "var(--text-1)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        maxWidth: 200,
                      }}
                    >
                      {alert.filename}
                    </span>
                    <span
                      style={{
                        fontSize: 9.5,
                        padding: "1px 6px",
                        borderRadius: 4,
                        background: alert.action === "quarantined" ? "rgba(127,29,29,0.5)" : "rgba(67,20,7,0.5)",
                        color: alert.action === "quarantined" ? "#fca5a5" : "#fed7aa",
                        fontWeight: 700,
                        textTransform: "uppercase",
                        letterSpacing: "0.05em",
                        flexShrink: 0,
                      }}
                    >
                      {alert.action}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {alert.detail}
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3, flexShrink: 0 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: severityColor(alert.threat_level) }}>
                    {(alert.score * 100).toFixed(0)}%
                  </span>
                  <span style={{ fontSize: 10, color: "var(--text-3)" }}>{timeAgo(alert.timestamp)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
