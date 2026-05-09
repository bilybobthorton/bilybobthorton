import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Wifi, WifiOff, Server, ShieldCheck } from "lucide-react";

interface VpnStatus {
  connected: boolean;
  server: string | null;
}

const SERVERS = [
  { id: "us-east", label: "US East — New York", location: "New York, USA", flag: "🇺🇸" },
];

export default function VPN() {
  const [status, setStatus]         = useState<VpnStatus>({ connected: false, server: null });
  const [loading, setLoading]       = useState(false);
  const [phase, setPhase]           = useState<string | null>(null);
  const [error, setError]           = useState<string | null>(null);
  const [trialExpired, setTrialExpired] = useState(false);

  useEffect(() => {
    invoke<VpnStatus>("get_vpn_status")
      .then(setStatus)
      .catch((e) => console.warn("VPN status:", e));
  }, []);

  useEffect(() => {
    const unlisten = listen<{ phase: string; message: string }>("vpn-phase", (e) => {
      setPhase(e.payload.message);
    });
    return () => { unlisten.then((f) => f()); };
  }, []);

  const handleConnect = async () => {
    setError(null);
    setTrialExpired(false);
    setLoading(true);
    setPhase(null);
    try {
      await invoke("connect_vpn");
      setStatus({ connected: true, server: "US East — New York" });
    } catch (e) {
      const msg = String(e);
      if (msg.includes("vpn_trial_expired") || msg.includes("402")) {
        setTrialExpired(true);
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
      setPhase(null);
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
    <div className="screen">
      <div className="screen-header">
        <h2 className="screen-title">VPN</h2>
        {status.connected && (
          <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12, color: "var(--green)" }}>
            <span className="live-dot green" />
            Tunnel active
          </div>
        )}
      </div>

      {/* Connection hero */}
      <div className={`vpn-hero${status.connected ? " connected" : " disconnected"}`}>
        {/* Icon with pulse */}
        <div
          style={{
            width: 64,
            height: 64,
            borderRadius: "50%",
            background: status.connected ? "var(--green-12)" : "var(--raised)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            position: "relative",
            boxShadow: status.connected ? "0 0 28px var(--green-glow)" : "none",
            transition: "all 0.3s ease",
          }}
        >
          {status.connected && (
            <>
              <div className="pulse-ring green" />
              <div className="pulse-ring green delay" />
            </>
          )}
          {status.connected ? (
            <Wifi size={26} color="var(--green)" />
          ) : (
            <WifiOff size={26} color="var(--text-3)" />
          )}
        </div>

        {/* Status text */}
        <div style={{ flex: 1 }}>
          <div
            style={{
              fontSize: 20,
              fontWeight: 700,
              color: status.connected ? "var(--green)" : "var(--text-2)",
              marginBottom: 4,
              letterSpacing: "-0.01em",
            }}
          >
            {loading
              ? (status.connected ? "Disconnecting…" : (phase ?? "Connecting…"))
              : (status.connected ? "Connected" : "Disconnected")}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--text-3)" }}>
            {status.connected
              ? `Encrypted tunnel via ${status.server ?? "RedGuard VPN"}`
              : "Your traffic is not encrypted"}
          </div>
        </div>

        {/* CTA button */}
        <button
          onClick={status.connected ? handleDisconnect : handleConnect}
          disabled={loading}
          className={`btn ${status.connected ? "btn-secondary" : "btn-primary"}`}
          style={{ minWidth: 120, justifyContent: "center", fontSize: 14, padding: "11px 24px" }}
        >
          {loading
            ? (status.connected ? "Disconnecting…" : "Setting up…")
            : (status.connected ? "Disconnect" : "Connect")}
        </button>
      </div>

      {/* Trial expired */}
      {trialExpired && (
        <div
          style={{
            marginBottom: 20,
            padding: "18px 20px",
            background: "#110707",
            border: "1px solid rgba(239,68,68,0.2)",
            borderRadius: "var(--r-lg)",
          }}
        >
          <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-1)", marginBottom: 5 }}>
            Your VPN trial has ended
          </div>
          <div style={{ fontSize: 12.5, color: "var(--text-3)", marginBottom: 14 }}>
            Upgrade to RedGuard Pro or the Security Bundle to keep VPN protection.
          </div>
          <a
            href="https://redgaurd.com"
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary"
            style={{ textDecoration: "none", display: "inline-flex" }}
          >
            Upgrade now →
          </a>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="error-banner" style={{ marginBottom: 20 }}>
          <span>{error}</span>
          <button className="error-dismiss" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Server list */}
      <div className="section-label">
        <Server size={12} /> Available Servers
      </div>

      <div className="card-list" style={{ marginBottom: 20 }}>
        {SERVERS.map((srv) => {
          const active = status.connected && status.server === srv.label;
          return (
            <div
              key={srv.id}
              className="card-list-row"
              style={{ background: active ? "var(--green-12)" : undefined }}
            >
              <span style={{ fontSize: 20, marginRight: 2 }}>{srv.flag}</span>
              <div style={{ flex: 1, paddingLeft: 4 }}>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: active ? "var(--green)" : "var(--text-1)" }}>
                  {srv.location}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-3)" }}>{srv.label}</div>
              </div>
              {active ? (
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <ShieldCheck size={14} color="var(--green)" />
                  <span className="live-dot green" />
                </div>
              ) : (
                <Server size={14} color="var(--text-3)" />
              )}
            </div>
          );
        })}
      </div>

      {/* Connection stats when active */}
      {status.connected && (
        <>
          <div className="section-label">Connection Stats</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 20 }}>
            {[
              { label: "Latency", value: "—", unit: "ms" },
              { label: "Data Sent", value: "—", unit: "MB" },
              { label: "Data Received", value: "—", unit: "MB" },
            ].map((s) => (
              <div key={s.label} className="stat-card">
                <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 2 }}>
                  <span className="stat-value" style={{ fontSize: 18 }}>{s.value}</span>
                  <span style={{ fontSize: 11, color: "var(--text-3)" }}>{s.unit}</span>
                </div>
                <div className="stat-label">{s.label}</div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Info note */}
      <div
        style={{
          padding: "12px 16px",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r-md)",
          color: "var(--text-3)",
          fontSize: 12,
          lineHeight: 1.5,
        }}
      >
        RedGuard VPN automatically sets up everything needed on first connect — no manual steps required.
      </div>
    </div>
  );
}
