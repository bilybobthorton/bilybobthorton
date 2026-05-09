import { Shield, Globe, AlertTriangle, Settings, LogOut, ScanLine, ShieldAlert } from "lucide-react";
import type { Screen } from "../App";

interface NavBarProps {
  screen: Screen;
  onNavigate: (s: Screen) => void;
  email: string;
  tier: string;
  onLogout: () => void;
}

interface NavItem {
  id: Screen;
  label: string;
  icon: React.ReactNode;
}

const NAV_MAIN: NavItem[] = [
  { id: "home",  label: "Home",           icon: <Shield size={17} /> },
  { id: "scan",  label: "System Scan",    icon: <ScanLine size={17} /> },
  { id: "vpn",   label: "VPN",            icon: <Globe size={17} /> },
  { id: "threats",       label: "Threats",         icon: <AlertTriangle size={17} /> },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: <ShieldAlert size={17} /> },
];

const TIER_COLORS: Record<string, string> = {
  free:       "#64748b",
  pro:        "#3b82f6",
  enterprise: "#8b5cf6",
  bundle:     "#8b5cf6",
};

export default function NavBar({ screen, onNavigate, email, tier, onLogout }: NavBarProps) {
  const tierColor = TIER_COLORS[tier.toLowerCase()] ?? "#64748b";

  return (
    <nav
      style={{
        width: 212,
        minWidth: 212,
        height: "100%",
        background: "var(--surface)",
        borderRight: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        userSelect: "none",
      }}
    >
      {/* Logo */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "18px 16px 14px",
          borderBottom: "1px solid var(--border-sub)",
        }}
      >
        <div
          style={{
            width: 30,
            height: 30,
            background: "var(--red)",
            borderRadius: 8,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            boxShadow: "0 2px 10px var(--red-25)",
          }}
        >
          <Shield size={16} color="#fff" />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15, color: "var(--text-1)", letterSpacing: "-0.02em", lineHeight: 1.2 }}>
            RedGuard
          </div>
          <div style={{ fontSize: 10, color: "var(--text-3)", letterSpacing: "0.04em" }}>
            SECURITY
          </div>
        </div>
      </div>

      {/* Main nav */}
      <div style={{ flex: 1, padding: "10px 8px" }}>
        <div style={{ marginBottom: 4, padding: "0 6px 6px" }}>
          <span style={{ fontSize: 10, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600 }}>
            Protection
          </span>
        </div>
        {NAV_MAIN.map((item) => (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            className={`nav-item${screen === item.id ? " active" : ""}`}
          >
            {item.icon}
            {item.label}
          </button>
        ))}

        <div style={{ height: 1, background: "var(--border-sub)", margin: "12px 4px" }} />

        <button
          onClick={() => onNavigate("settings")}
          className={`nav-item${screen === "settings" ? " active" : ""}`}
        >
          <Settings size={17} />
          Settings
        </button>
      </div>

      {/* Footer — user + logout */}
      <div style={{ borderTop: "1px solid var(--border-sub)", padding: "10px 10px 12px" }}>
        <div
          style={{
            padding: "8px 8px 10px",
            display: "flex",
            alignItems: "center",
            gap: 9,
          }}
        >
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: "50%",
              background: "var(--raised)",
              border: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
              fontSize: 11,
              fontWeight: 700,
              color: "var(--text-2)",
            }}
          >
            {email.charAt(0).toUpperCase()}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: 11.5,
                color: "var(--text-2)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                lineHeight: 1.3,
              }}
              title={email}
            >
              {email}
            </div>
            <span
              style={{
                fontSize: 9.5,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                color: tierColor,
              }}
            >
              {tier}
            </span>
          </div>
        </div>

        <button
          onClick={onLogout}
          className="nav-item"
          style={{ color: "var(--text-3)", fontSize: 12.5 }}
        >
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </nav>
  );
}
