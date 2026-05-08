import { Shield, Globe, AlertTriangle, Settings, LogOut, ScanLine, ShieldAlert } from "lucide-react";
import type { Screen } from "../App";
import StatusBadge from "./StatusBadge";

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

const NAV_ITEMS: NavItem[] = [
  { id: "home", label: "Home", icon: <Shield size={18} /> },
  { id: "scan", label: "Scan", icon: <ScanLine size={18} /> },
  { id: "vpn", label: "VPN", icon: <Globe size={18} /> },
  { id: "threats", label: "Threats", icon: <AlertTriangle size={18} /> },
  { id: "vulnerabilities", label: "Vulns", icon: <ShieldAlert size={18} /> },
  { id: "settings", label: "Settings", icon: <Settings size={18} /> },
];

export default function NavBar({
  screen,
  onNavigate,
  email,
  tier,
  onLogout,
}: NavBarProps) {
  return (
    <nav
      style={{
        width: 200,
        minWidth: 200,
        height: "100%",
        background: "#0d0d14",
        borderRight: "1px solid #1e1e2e",
        display: "flex",
        flexDirection: "column",
        padding: "0",
        userSelect: "none",
      }}
    >
      {/* Logo */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "20px 16px 16px",
          borderBottom: "1px solid #1e1e2e",
        }}
      >
        <div
          style={{
            width: 32,
            height: 32,
            background: "#dc2626",
            borderRadius: 8,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Shield size={18} color="#fff" />
        </div>
        <span
          style={{
            fontWeight: 700,
            fontSize: 16,
            color: "#f1f5f9",
            letterSpacing: "-0.02em",
          }}
        >
          RedGuard
        </span>
      </div>

      {/* Nav items */}
      <div style={{ flex: 1, padding: "8px 8px" }}>
        {NAV_ITEMS.map((item) => {
          const active = screen === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                width: "100%",
                padding: "9px 12px",
                borderRadius: 7,
                border: "none",
                background: active ? "#dc2626" : "transparent",
                color: active ? "#fff" : "#94a3b8",
                fontWeight: active ? 600 : 400,
                fontSize: 14,
                cursor: "pointer",
                transition: "background 0.15s, color 0.15s",
                marginBottom: 2,
                textAlign: "left",
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  (e.currentTarget as HTMLButtonElement).style.background =
                    "#1e1e2e";
                  (e.currentTarget as HTMLButtonElement).style.color = "#cbd5e1";
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  (e.currentTarget as HTMLButtonElement).style.background =
                    "transparent";
                  (e.currentTarget as HTMLButtonElement).style.color = "#94a3b8";
                }
              }}
            >
              {item.icon}
              {item.label}
            </button>
          );
        })}
      </div>

      {/* User info + logout */}
      <div
        style={{
          borderTop: "1px solid #1e1e2e",
          padding: "12px 8px",
        }}
      >
        <div style={{ padding: "0 8px 10px" }}>
          <div
            style={{
              fontSize: 12,
              color: "#64748b",
              marginBottom: 4,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={email}
          >
            {email}
          </div>
          <StatusBadge label={tier} />
        </div>
        <button
          onClick={onLogout}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            width: "100%",
            padding: "8px 12px",
            borderRadius: 7,
            border: "none",
            background: "transparent",
            color: "#64748b",
            fontSize: 13,
            cursor: "pointer",
            transition: "background 0.15s, color 0.15s",
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLButtonElement).style.background = "#1e1e2e";
            (e.currentTarget as HTMLButtonElement).style.color = "#ef4444";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLButtonElement).style.background =
              "transparent";
            (e.currentTarget as HTMLButtonElement).style.color = "#64748b";
          }}
        >
          <LogOut size={15} />
          Sign out
        </button>
      </div>
    </nav>
  );
}
