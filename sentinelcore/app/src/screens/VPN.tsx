import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Wifi, WifiOff, Server } from "lucide-react";

interface VpnStatus {
  connected: boolean;
  server: string | null;
}

interface VpnDevice {
  id: number;
  name: string;
}

const SERVERS = [
  {
    id: "us-east",
    label: "US East — New York",
    location: "New York, USA",
    flag: "🇺🇸",
  },
];

export default function VPN() {
  const [status, setStatus] = useState<VpnStatus>({
    connected: false,
    server: null,
  });
  const [devices, setDevices] = useState<VpnDevice[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = async () => {
    try {
      const [s, d] = await Promise.all([
        invoke<VpnStatus>("get_vpn_status"),
        invoke<VpnDevice[]>("get_vpn_keys"),
      ]);
      setStatus(s);
      setDevices(d);
    } catch (e) {
      console.warn("Failed to load VPN status:", e);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleConnect = async () => {
    setError(null);
    setLoading(true);
    try {
      // Auto-provisions a device if the user has none — no config needed.
      await invoke("connect_vpn");
      setStatus({ connected: true, server: "US East — New York" });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnect = async () => {
    setError(null);
    setLoading(true);
    try {
      await invoke("disconnect_vpn");
      setStatus({ connected: false, server: null });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "28px 32px", overflowY: "auto", height: "100%" }}>
      <h2
        style={{
          fontSize: 18,
          fontWeight: 700,
          color: "#f1f5f9",
          marginBottom: 24,
          letterSpacing: "-0.02em",
        }}
      >
        VPN
      </h2>

      {/* Status banner */}
      <div
        style={{
          background: status.connected ? "#14532d" : "#0d0d14",
          border: `1px solid ${status.connected ? "#166534" : "#1e1e2e"}`,
          borderRadius: 12,
          padding: "24px",
          display: "flex",
          alignItems: "center",
          gap: 20,
          marginBottom: 24,
        }}
      >
        <div
          style={{
            width: 52,
            height: 52,
            borderRadius: "50%",
            background: status.connected ? "#166534" : "#1e1e2e",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            boxShadow: status.connected ? "0 0 20px #22c55e30" : "none",
          }}
        >
          {status.connected ? (
            <Wifi size={24} color="#22c55e" />
          ) : (
            <WifiOff size={24} color="#64748b" />
          )}
        </div>
        <div style={{ flex: 1 }}>
          <div
            style={{
              fontSize: 18,
              fontWeight: 700,
              color: status.connected ? "#22c55e" : "#94a3b8",
              marginBottom: 2,
            }}
          >
            {status.connected ? "Connected" : "Disconnected"}
          </div>
          <div style={{ fontSize: 13, color: "#64748b" }}>
            {status.connected
              ? `Tunneled via ${status.server ?? "RedGuard VPN"}`
              : "Your traffic is not encrypted"}
          </div>
        </div>

        {/* Connect / Disconnect button */}
        <button
          onClick={status.connected ? handleDisconnect : handleConnect}
          disabled={loading}
          style={{
            padding: "11px 28px",
            background: status.connected ? "#1e1e2e" : "#dc2626",
            color: status.connected ? "#94a3b8" : "#fff",
            border: status.connected ? "1px solid #334155" : "none",
            borderRadius: 8,
            fontWeight: 600,
            fontSize: 14,
            cursor: loading ? "not-allowed" : "pointer",
            transition: "all 0.15s",
            minWidth: 130,
          }}
        >
          {loading
            ? status.connected
              ? "Disconnecting…"
              : "Connecting…"
            : status.connected
            ? "Disconnect"
            : "Connect"}
        </button>
      </div>

      {error && (
        <div
          style={{
            marginBottom: 20,
            padding: "10px 14px",
            background: "#ef444418",
            border: "1px solid #ef444430",
            borderRadius: 8,
            color: "#ef4444",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      {/* Server list */}
      <h3
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: "#64748b",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          marginBottom: 12,
        }}
      >
        Available Servers
      </h3>

      <div
        style={{
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          overflow: "hidden",
          marginBottom: 24,
        }}
      >
        {SERVERS.map((srv, i) => {
          const active = status.connected && status.server === srv.label;
          return (
            <div
              key={srv.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 14,
                padding: "14px 16px",
                borderBottom:
                  i < SERVERS.length - 1 ? "1px solid #1e1e2e" : "none",
                background: active ? "#14532d20" : "transparent",
              }}
            >
              <span style={{ fontSize: 22 }}>{srv.flag}</span>
              <div style={{ flex: 1 }}>
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 600,
                    color: active ? "#22c55e" : "#f1f5f9",
                  }}
                >
                  {srv.location}
                </div>
                <div style={{ fontSize: 11, color: "#64748b" }}>
                  {srv.label}
                </div>
              </div>
              <Server
                size={14}
                color={active ? "#22c55e" : "#334155"}
              />
              {active && (
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: "#22c55e",
                    boxShadow: "0 0 6px #22c55e",
                  }}
                />
              )}
            </div>
          );
        })}
      </div>

      {/* Connection stats (placeholder) */}
      {status.connected && (
        <>
          <h3
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "#64748b",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              marginBottom: 12,
            }}
          >
            Connection Stats
          </h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: 12,
              marginBottom: 24,
            }}
          >
            <StatCard label="Latency" value="—" unit="ms" />
            <StatCard label="Data Sent" value="—" unit="MB" />
            <StatCard label="Data Received" value="—" unit="MB" />
          </div>
        </>
      )}

      {/* Info note */}
      <div
        style={{
          padding: "12px 16px",
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          color: "#475569",
          fontSize: 12,
        }}
      >
        RedGuard VPN automatically configures your device on first connect. WireGuard must be installed on your PC.
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  unit,
}: {
  label: string;
  value: string | number;
  unit: string;
}) {
  return (
    <div
      style={{
        background: "#0d0d14",
        border: "1px solid #1e1e2e",
        borderRadius: 10,
        padding: "14px",
      }}
    >
      <div
        style={{
          fontSize: 18,
          fontWeight: 700,
          color: "#f1f5f9",
          marginBottom: 2,
        }}
      >
        {value}{" "}
        <span style={{ fontSize: 12, color: "#64748b", fontWeight: 400 }}>
          {unit}
        </span>
      </div>
      <div
        style={{
          fontSize: 11,
          color: "#475569",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {label}
      </div>
    </div>
  );
}
