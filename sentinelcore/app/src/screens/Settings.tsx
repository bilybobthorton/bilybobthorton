import { useState } from "react";
import {
  User,
  CreditCard,
  Shield,
  Globe,
  Info,
  LogOut,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import type { AuthState } from "../App";
import StatusBadge from "../components/StatusBadge";

interface SettingsProps {
  auth: AuthState;
  onLogout: () => void;
}

function Toggle({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      style={{
        width: 40,
        height: 22,
        borderRadius: 11,
        border: "none",
        background: checked ? "#dc2626" : "#1e1e2e",
        position: "relative",
        cursor: "pointer",
        transition: "background 0.2s",
        flexShrink: 0,
      }}
    >
      <span
        style={{
          position: "absolute",
          top: 2,
          left: checked ? 20 : 2,
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

function SectionHeader({
  icon,
  title,
}: {
  icon: React.ReactNode;
  title: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginBottom: 10,
        marginTop: 28,
      }}
    >
      {icon}
      <h3
        style={{
          fontSize: 12,
          fontWeight: 600,
          color: "#64748b",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        {title}
      </h3>
    </div>
  );
}

function SettingRow({
  label,
  sub,
  right,
}: {
  label: string;
  sub?: string;
  right: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        padding: "13px 16px",
        borderBottom: "1px solid #1e1e2e",
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, color: "#f1f5f9" }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: "#475569", marginTop: 1 }}>{sub}</div>}
      </div>
      <div style={{ flexShrink: 0 }}>{right}</div>
    </div>
  );
}

export default function Settings({ auth, onLogout }: SettingsProps) {
  const [realTimeProtection, setRealTimeProtection] = useState(true);
  const [startOnLogin, setStartOnLogin] = useState(true);
  const [autoQuarantine, setAutoQuarantine] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);

  const handleCheckUpdate = () => {
    setCheckingUpdate(true);
    setUpdateMsg(null);
    setTimeout(() => {
      setCheckingUpdate(false);
      setUpdateMsg("You're on the latest version (0.1.0).");
    }, 1500);
  };

  return (
    <div style={{ padding: "28px 32px", height: "100%", overflowY: "auto" }}>
      <h2
        style={{
          fontSize: 18,
          fontWeight: 700,
          color: "#f1f5f9",
          letterSpacing: "-0.02em",
          marginBottom: 4,
        }}
      >
        Settings
      </h2>
      <p style={{ fontSize: 12, color: "#475569", marginBottom: 4 }}>
        Manage your account and preferences
      </p>

      {/* Account */}
      <SectionHeader icon={<User size={14} color="#64748b" />} title="Account" />
      <div
        style={{
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <SettingRow
          label="Email"
          sub={auth.email}
          right={null}
        />
        <SettingRow
          label="Plan"
          right={<StatusBadge label={auth.tier} />}
        />
        <SettingRow
          label="Manage subscription"
          sub="Billing, invoices, and plan changes"
          right={
            <a
              href="https://redgaurd.com/billing"
              target="_blank"
              rel="noreferrer"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 4,
                color: "#dc2626",
                fontSize: 12,
              }}
            >
              Open <ExternalLink size={12} />
            </a>
          }
        />
      </div>

      {/* Protection */}
      <SectionHeader
        icon={<Shield size={14} color="#64748b" />}
        title="Protection"
      />
      <div
        style={{
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <SettingRow
          label="Real-time protection"
          sub="Monitor files and processes continuously"
          right={
            <Toggle
              checked={realTimeProtection}
              onChange={setRealTimeProtection}
            />
          }
        />
        <SettingRow
          label="Start on login"
          sub="Launch RedGuard automatically at startup"
          right={
            <Toggle checked={startOnLogin} onChange={setStartOnLogin} />
          }
        />
        <SettingRow
          label="Auto-quarantine"
          sub="Automatically isolate detected threats"
          right={
            <Toggle
              checked={autoQuarantine}
              onChange={setAutoQuarantine}
            />
          }
        />
      </div>

      {/* VPN */}
      <SectionHeader icon={<Globe size={14} color="#64748b" />} title="VPN" />
      <div
        style={{
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <SettingRow
          label="Manage VPN devices"
          sub="Add, revoke, or download device configs"
          right={
            <a
              href="https://dashboard.redgaurd.com/vpn/keys"
              target="_blank"
              rel="noreferrer"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 4,
                color: "#dc2626",
                fontSize: 12,
              }}
            >
              Open <ExternalLink size={12} />
            </a>
          }
        />
      </div>

      {/* About */}
      <SectionHeader icon={<Info size={14} color="#64748b" />} title="About" />
      <div
        style={{
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <SettingRow
          label="Version"
          sub="RedGuard Desktop"
          right={
            <span style={{ fontSize: 12, color: "#475569" }}>0.1.0</span>
          }
        />
        <div
          style={{
            display: "flex",
            alignItems: "center",
            padding: "13px 16px",
            borderBottom: "1px solid #1e1e2e",
          }}
        >
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, color: "#f1f5f9" }}>
              Check for updates
            </div>
            {updateMsg && (
              <div
                style={{ fontSize: 11, color: "#22c55e", marginTop: 2 }}
              >
                {updateMsg}
              </div>
            )}
          </div>
          <button
            onClick={handleCheckUpdate}
            disabled={checkingUpdate}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "6px 14px",
              background: "#1e1e2e",
              border: "1px solid #334155",
              borderRadius: 6,
              color: "#94a3b8",
              fontSize: 12,
              cursor: checkingUpdate ? "not-allowed" : "pointer",
            }}
          >
            <RefreshCw
              size={13}
              style={{
                animation: checkingUpdate ? "spin 1s linear infinite" : "none",
              }}
            />
            {checkingUpdate ? "Checking…" : "Check"}
          </button>
        </div>
      </div>

      {/* Danger zone */}
      <div style={{ marginTop: 28 }}>
        <button
          onClick={onLogout}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "10px 18px",
            background: "transparent",
            border: "1px solid #7f1d1d",
            borderRadius: 8,
            color: "#ef4444",
            fontSize: 13,
            fontWeight: 500,
            cursor: "pointer",
            transition: "background 0.15s",
          }}
          onMouseEnter={(e) =>
            ((e.currentTarget as HTMLButtonElement).style.background =
              "#ef444418")
          }
          onMouseLeave={(e) =>
            ((e.currentTarget as HTMLButtonElement).style.background =
              "transparent")
          }
        >
          <LogOut size={15} />
          Sign out
        </button>
      </div>

      {/* Spinner keyframe (injected inline since we're not using CSS modules) */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
