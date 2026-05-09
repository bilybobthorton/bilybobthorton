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

// ── Types ─────────────────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────────

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
    case "MALICIOUS": return "#ef4444";
    case "SUSPICIOUS": return "#f97316";
    default: return "#eab308";
  }
}

// ── Sub-components ────────────────────────────────────────────────────────────

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
        background: checked ? "#dc2626" : "#1e293b",
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
    <div
      style={{
        background: "#0d0d14",
        border: `1px solid ${checked ? "#1e293b" : "#1e293b"}`,
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
    <div
      style={{
        background: "#0d0d14",
        border: "1px solid #1e1e2e",
        borderRadius: 10,
        padding: "14px 16px",
      }}
    >
      <div
        style={{
          fontSize: 22,
          fontWeight: 700,
          color: accent ?? "#f1f5f9",
          marginBottom: 2,
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: 10,
          color: "#64748b",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Home({ onNavigate }: HomeProps) {
  const [protection, setProtection] = useState<ProtectionStatus>({
    enabled: true,
    files_analyzed: 0,
    threats_blocked: 0,
    threats_flagged: 0,
  });
  const [cloudStats, setCloudStats] = useState<CloudStats | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<RealtimeAlert[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
  const [vpnConnected, setVpnConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [togglingProtection, setTogglingProtection] = useState(false);
  const [showQuarantine, setShowQuarantine] = useState(false);

  // Keep liveAlerts capped at 20 entries
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
    } catch { /* cloud stats optional */ }
    try {
      const q = await invoke<QuarantineEntry[]>("get_quarantine");
      setQuarantine(q);
    } catch { /* quarantine optional */ }
  }, []);

  // Initial load + periodic refresh of counters
  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Listen for real-time protection alerts emitted by Rust
  const unlistenRef = useRef<(() => void) | null>(null);
  useEffect(() => {
    let cancelled = false;
    listen<RealtimeAlert>("protection-alert", (event) => {
      if (!cancelled) {
        addLiveAlert(event.payload);
        // Refresh quarantine list when a file is quarantined
        if (event.payload.action === "quarantined") {
          invoke<QuarantineEntry[]>("get_quarantine")
            .then(setQuarantine)
            .catch(() => {});
        }
      }
    }).then((unlisten) => {
      unlistenRef.current = unlisten;
    });
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

  const isProtected = protection.enabled && (cloudStats?.critical ?? 0) === 0;
  const allThreats = protection.threats_blocked + protection.threats_flagged;

  return (
    <div style={{ padding: "28px 32px", height: "100%", overflowY: "auto" }}>
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
          Dashboard
        </h2>
        {quarantine.filter((e) => !e.restored).length > 0 && (
          <button
            onClick={() => setShowQuarantine(!showQuarantine)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "6px 12px",
              background: "#7f1d1d",
              border: "1px solid #ef4444",
              borderRadius: 6,
              color: "#fca5a5",
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            <Lock size={12} />
            {quarantine.filter((e) => !e.restored).length} Quarantined
          </button>
        )}
      </div>

      {/* Protection status hero */}
      <div
        style={{
          background: "#0d0d14",
          border: `1px solid ${isProtected ? "#166534" : "#7f1d1d"}`,
          borderRadius: 12,
          padding: "24px",
          display: "flex",
          alignItems: "center",
          gap: 20,
          marginBottom: 20,
        }}
      >
        <div
          style={{
            width: 60,
            height: 60,
            borderRadius: "50%",
            background: isProtected ? "#14532d" : "#450a0a",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            boxShadow: isProtected ? "0 0 28px #22c55e28" : "0 0 28px #ef444428",
          }}
        >
          {isProtected ? (
            <ShieldCheck size={30} color="#22c55e" />
          ) : (
            <ShieldAlert size={30} color="#ef4444" />
          )}
        </div>
        <div style={{ flex: 1 }}>
          <div
            style={{
              fontSize: 19,
              fontWeight: 700,
              color: isProtected ? "#22c55e" : "#ef4444",
              marginBottom: 3,
            }}
          >
            {protection.enabled
              ? isProtected
                ? "You're Protected"
                : "Threats Detected"
              : "Protection Disabled"}
          </div>
          <div style={{ color: "#64748b", fontSize: 13 }}>
            {protection.enabled
              ? isProtected
                ? "Real-time scanning is active — monitoring all high-risk locations."
                : "Review the threats below and take action."
              : "Enable real-time protection to monitor your system."}
          </div>
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-end",
            gap: 4,
          }}
        >
          <div style={{ fontSize: 11, color: "#475569" }}>Files scanned</div>
          <div
            style={{
              fontSize: 26,
              fontWeight: 700,
              color: "#94a3b8",
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {protection.files_analyzed.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr 1fr",
          gap: 10,
          marginBottom: 16,
        }}
      >
        <StatCard
          label="Threats Blocked"
          value={protection.threats_blocked}
          accent={protection.threats_blocked > 0 ? "#ef4444" : "#f1f5f9"}
        />
        <StatCard
          label="Flagged"
          value={protection.threats_flagged}
          accent={protection.threats_flagged > 0 ? "#f97316" : "#f1f5f9"}
        />
        <StatCard
          label="Cloud Alerts"
          value={cloudStats?.total_alerts ?? "—"}
          accent={cloudStats && cloudStats.total_alerts > 0 ? "#eab308" : "#f1f5f9"}
        />
        <StatCard
          label="VPN"
          value={vpnConnected ? "On" : "Off"}
          accent={vpnConnected ? "#22c55e" : "#64748b"}
        />
      </div>

      {/* Toggle cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 10,
          marginBottom: 16,
        }}
      >
        <ToggleCard
          title="Malware Protection"
          subtitle={
            protection.enabled
              ? `Active — ${allThreats} threat${allThreats !== 1 ? "s" : ""} caught`
              : "Disabled — system unmonitored"
          }
          icon={
            <Shield
              size={18}
              color={protection.enabled ? "#dc2626" : "#64748b"}
            />
          }
          checked={protection.enabled}
          onChange={handleProtectionToggle}
          loading={togglingProtection}
        />
        <ToggleCard
          title="VPN Protection"
          subtitle={vpnConnected ? "US East — New York" : "Not connected"}
          icon={<Globe size={18} color={vpnConnected ? "#22c55e" : "#64748b"} />}
          checked={vpnConnected}
          onChange={handleVpnToggle}
        />
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            marginBottom: 14,
            padding: "8px 12px",
            background: "#ef444418",
            border: "1px solid #ef444430",
            borderRadius: 7,
            color: "#ef4444",
            fontSize: 12,
          }}
        >
          {error}
          <button
            onClick={() => setError(null)}
            style={{
              float: "right",
              background: "none",
              border: "none",
              color: "#ef4444",
              cursor: "pointer",
              fontSize: 14,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Scan file */}
      <div style={{ marginBottom: 20 }}>
        <button
          onClick={handleScanFile}
          disabled={scanning}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "9px 16px",
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
          <FileSearch size={15} />
          {scanning ? "Scanning…" : "Scan a file"}
        </button>

        {scanResult && (
          <div
            style={{
              marginTop: 10,
              padding: "10px 14px",
              background: "#0d0d14",
              border: "1px solid #1e1e2e",
              borderRadius: 8,
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <span style={{ color: "#94a3b8", fontSize: 13 }}>Result:</span>
            <StatusBadge label={scanResult.threat_level} />
            <span style={{ color: "#64748b", fontSize: 12 }}>
              {(scanResult.score * 100).toFixed(1)}% confidence
            </span>
          </div>
        )}
      </div>

      {/* Quarantine panel */}
      {showQuarantine && quarantine.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 10,
            }}
          >
            <h3
              style={{
                fontSize: 14,
                fontWeight: 600,
                color: "#fca5a5",
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <Lock size={13} color="#ef4444" />
              Quarantine Vault
            </h3>
            <span style={{ fontSize: 11, color: "#64748b" }}>
              XOR-encrypted — cannot execute
            </span>
          </div>
          <div
            style={{
              background: "#0d0d14",
              border: "1px solid #7f1d1d",
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            {quarantine.map((entry, i) => (
              <div
                key={entry.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "10px 14px",
                  borderBottom:
                    i < quarantine.length - 1
                      ? "1px solid #1e1e2e"
                      : "none",
                  opacity: entry.restored ? 0.45 : 1,
                }}
              >
                <Lock size={13} color="#ef4444" style={{ flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      color: "#f1f5f9",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {entry.filename}
                  </div>
                  <div style={{ fontSize: 10, color: "#475569" }}>
                    {entry.sha256.slice(0, 16)}… · {(entry.score * 100).toFixed(0)}%
                    · {timeAgo(entry.timestamp)}
                  </div>
                </div>
                <StatusBadge label={entry.threat_level} />
                {!entry.restored && (
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      onClick={() => handleRestore(entry.id)}
                      title="Restore file"
                      style={{
                        background: "none",
                        border: "1px solid #334155",
                        borderRadius: 5,
                        padding: "4px 6px",
                        color: "#94a3b8",
                        cursor: "pointer",
                        display: "flex",
                      }}
                    >
                      <RotateCcw size={12} />
                    </button>
                    <button
                      onClick={() => handleDelete(entry.id)}
                      title="Delete permanently"
                      style={{
                        background: "none",
                        border: "1px solid #7f1d1d",
                        borderRadius: 5,
                        padding: "4px 6px",
                        color: "#ef4444",
                        cursor: "pointer",
                        display: "flex",
                      }}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                )}
                {entry.restored && (
                  <span style={{ fontSize: 11, color: "#64748b" }}>Restored</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live threat feed */}
      <div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 10,
          }}
        >
          <h3 style={{ fontSize: 14, fontWeight: 600, color: "#94a3b8" }}>
            Real-time Alerts
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
            View cloud alerts →
          </button>
        </div>

        {liveAlerts.length === 0 ? (
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
            No threats detected this session
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
            {liveAlerts.map((alert, i) => (
              <div
                key={`${alert.timestamp}-${i}`}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 10,
                  padding: "11px 14px",
                  borderBottom:
                    i < liveAlerts.length - 1 ? "1px solid #1e1e2e" : "none",
                  borderLeft: `3px solid ${severityColor(alert.threat_level)}`,
                }}
              >
                <AlertTriangle
                  size={14}
                  color={severityColor(alert.threat_level)}
                  style={{ flexShrink: 0, marginTop: 2 }}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      marginBottom: 2,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        color: "#f1f5f9",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        maxWidth: 220,
                      }}
                    >
                      {alert.filename}
                    </span>
                    <span
                      style={{
                        fontSize: 10,
                        padding: "1px 6px",
                        borderRadius: 4,
                        background:
                          alert.action === "quarantined" ? "#7f1d1d" : "#431407",
                        color:
                          alert.action === "quarantined" ? "#fca5a5" : "#fed7aa",
                        fontWeight: 600,
                        textTransform: "uppercase",
                        letterSpacing: "0.05em",
                        flexShrink: 0,
                      }}
                    >
                      {alert.action}
                    </span>
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
                    {alert.detail}
                  </div>
                </div>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "flex-end",
                    gap: 3,
                    flexShrink: 0,
                  }}
                >
                  <span
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: severityColor(alert.threat_level),
                    }}
                  >
                    {(alert.score * 100).toFixed(0)}%
                  </span>
                  <span style={{ fontSize: 10, color: "#475569" }}>
                    {timeAgo(alert.timestamp)}
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
