import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { User, Shield, Globe, Info, LogOut, ExternalLink, RefreshCw } from "lucide-react";
import type { AuthState } from "../App";
import StatusBadge from "../components/StatusBadge";

interface SettingsProps {
  auth: AuthState;
  onLogout: () => void;
}

interface UpdateInfo {
  version: string;
  release_notes: string;
  download_url: string;
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`toggle${checked ? " on" : ""}`}
    />
  );
}

function SectionLabel({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="section-label">
      {icon}
      {title}
    </div>
  );
}

function SettingRow({ label, sub, right }: { label: string; sub?: string; right: React.ReactNode }) {
  return (
    <div className="card-list-row" style={{ cursor: "default" }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, color: "var(--text-1)" }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 1 }}>{sub}</div>}
      </div>
      <div style={{ flexShrink: 0, marginLeft: 16 }}>{right}</div>
    </div>
  );
}

export default function Settings({ auth, onLogout }: SettingsProps) {
  const [realTime,       setRealTime]       = useState(true);
  const [startOnLogin,   setStartOnLogin]   = useState(true);
  const [autoQuarantine, setAutoQuarantine] = useState(false);
  const [checking,       setChecking]       = useState(false);
  const [updateMsg,      setUpdateMsg]      = useState<string | null>(null);
  const [update,         setUpdate]         = useState<UpdateInfo | null>(null);

  const handleCheckUpdate = async () => {
    setChecking(true);
    setUpdateMsg(null);
    setUpdate(null);
    try {
      const current = await getVersion();
      const info = await invoke<UpdateInfo | null>("check_for_update", { currentVersion: current });
      if (info) {
        setUpdate(info);
        setUpdateMsg(`v${info.version} available — ${info.release_notes}`);
      } else {
        setUpdateMsg("You're on the latest version.");
      }
    } catch {
      setUpdateMsg("Could not check for updates.");
    } finally {
      setChecking(false);
    }
  };

  const linkStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    gap: 4,
    color: "var(--red)",
    fontSize: 12,
    textDecoration: "none",
  };

  return (
    <div className="screen">
      <div style={{ marginBottom: 24 }}>
        <h2 className="screen-title" style={{ marginBottom: 3 }}>Settings</h2>
        <p style={{ fontSize: 12, color: "var(--text-3)" }}>Account, protection preferences, and app info</p>
      </div>

      {/* Account */}
      <SectionLabel icon={<User size={12} />} title="Account" />
      <div className="card-list">
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
            <a href="https://redgaurd.com/billing" target="_blank" rel="noreferrer" style={linkStyle}>
              Open <ExternalLink size={11} />
            </a>
          }
        />
      </div>

      {/* Protection */}
      <SectionLabel icon={<Shield size={12} />} title="Protection" />
      <div className="card-list">
        <SettingRow
          label="Real-time protection"
          sub="Monitor files and processes continuously"
          right={<Toggle checked={realTime} onChange={setRealTime} />}
        />
        <SettingRow
          label="Start on login"
          sub="Launch RedGuard automatically at startup"
          right={<Toggle checked={startOnLogin} onChange={setStartOnLogin} />}
        />
        <SettingRow
          label="Auto-quarantine"
          sub="Automatically isolate detected threats"
          right={<Toggle checked={autoQuarantine} onChange={setAutoQuarantine} />}
        />
      </div>

      {/* VPN */}
      <SectionLabel icon={<Globe size={12} />} title="VPN" />
      <div className="card-list">
        <SettingRow
          label="Manage VPN devices"
          sub="Add, revoke, or download WireGuard configs"
          right={
            <a href="https://dashboard.redgaurd.com/vpn/keys" target="_blank" rel="noreferrer" style={linkStyle}>
              Open <ExternalLink size={11} />
            </a>
          }
        />
      </div>

      {/* About */}
      <SectionLabel icon={<Info size={12} />} title="About" />
      <div className="card-list" style={{ marginBottom: 28 }}>
        <SettingRow
          label="App"
          sub="RedGuard Desktop"
          right={<span style={{ fontSize: 12, color: "var(--text-3)" }}>v0.1.5</span>}
        />
        <div className="card-list-row" style={{ cursor: "default", flexDirection: "column", alignItems: "flex-start", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%" }}>
            <div>
              <div style={{ fontSize: 13, color: "var(--text-1)" }}>Check for updates</div>
              {updateMsg && (
                <div style={{ fontSize: 11, color: update ? "var(--amber)" : "var(--green)", marginTop: 2 }}>
                  {updateMsg}
                </div>
              )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {update && (
                <a
                  href={update.download_url}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-primary"
                  style={{ textDecoration: "none", fontSize: 12, padding: "6px 12px" }}
                >
                  Download
                </a>
              )}
              <button
                onClick={handleCheckUpdate}
                disabled={checking}
                className="btn btn-secondary"
                style={{ padding: "6px 12px", gap: 6, fontSize: 12 }}
              >
                <RefreshCw size={12} className={checking ? "spin" : ""} />
                {checking ? "Checking…" : "Check"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Sign out */}
      <button onClick={onLogout} className="btn-danger-ghost">
        <LogOut size={14} />
        Sign out
      </button>
    </div>
  );
}
