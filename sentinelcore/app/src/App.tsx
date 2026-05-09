import { useEffect, useState } from "react";
import { load } from "@tauri-apps/plugin-store";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { Shield, X, Download } from "lucide-react";
import NavBar from "./components/NavBar";
import Login from "./screens/Login";
import Home from "./screens/Home";
import VPN from "./screens/VPN";
import Threats from "./screens/Threats";
import Settings from "./screens/Settings";
import Scan from "./screens/Scan";
import Vulnerabilities from "./screens/Vulnerabilities";

interface UpdateInfo {
  version: string;
  release_notes: string;
  download_url: string;
}

export type Screen = "home" | "vpn" | "threats" | "scan" | "vulnerabilities" | "settings";

export interface AuthState {
  token: string;
  email: string;
  tier: string;
}

const STORE_FILE = "redguard.dat";

export default function App() {
  const [auth, setAuth]       = useState<AuthState | null>(null);
  const [screen, setScreen]   = useState<Screen>("home");
  const [loading, setLoading] = useState(true);
  const [update, setUpdate]   = useState<UpdateInfo | null>(null);

  // Check for updates 10s after launch.
  useEffect(() => {
    const timer = setTimeout(async () => {
      try {
        const current = await getVersion();
        const info = await invoke<UpdateInfo | null>("check_for_update", { currentVersion: current });
        if (info) setUpdate(info);
      } catch {
        // Non-critical.
      }
    }, 10_000);
    return () => clearTimeout(timer);
  }, []);

  // Restore session.
  useEffect(() => {
    (async () => {
      try {
        const store = await load(STORE_FILE, { autoSave: false, defaults: {} });
        const token = await store.get<string>("token");
        const email = await store.get<string>("email");
        const tier  = await store.get<string>("tier");
        if (token && email) {
          // Restore token into Rust memory so commands work without re-login
          await invoke("set_token", { token });
          setAuth({ token, email, tier: tier ?? "free" });
        }
      } catch {
        // First launch.
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const handleLogin = async (token: string, email: string, tier: string) => {
    setAuth({ token, email, tier });
    try {
      const store = await load(STORE_FILE, { autoSave: false, defaults: {} });
      await store.set("token", token);
      await store.set("email", email);
      await store.set("tier", tier);
      await store.save();
    } catch (e) {
      console.warn("Failed to persist auth:", e);
    }
  };

  const handleLogout = async () => {
    try { await invoke("logout"); } catch { /* best effort */ }
    try {
      const store = await load(STORE_FILE, { autoSave: false, defaults: {} });
      await store.delete("token");
      await store.delete("email");
      await store.delete("tier");
      await store.save();
    } catch (e) {
      console.warn("Failed to clear store:", e);
    }
    setAuth(null);
    setScreen("home");
  };

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          background: "var(--bg)",
          gap: 16,
        }}
      >
        <div
          style={{
            width: 44,
            height: 44,
            background: "var(--red)",
            borderRadius: 12,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 0 24px var(--red-25)",
          }}
        >
          <Shield size={24} color="#fff" />
        </div>
        <div style={{ fontSize: 12, color: "var(--text-3)" }}>Loading…</div>
      </div>
    );
  }

  if (!auth) return <Login onLogin={handleLogin} />;

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      {/* Update toast */}
      {update && (
        <div className="update-toast">
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
            <div style={{ fontWeight: 700, color: "var(--text-1)", fontSize: 13 }}>
              Update Available — v{update.version}
            </div>
            <button
              onClick={() => setUpdate(null)}
              style={{ background: "none", border: "none", color: "var(--text-3)", cursor: "pointer", padding: 0, lineHeight: 1 }}
            >
              <X size={14} />
            </button>
          </div>
          <div style={{ fontSize: 11.5, color: "var(--text-3)", marginBottom: 14, lineHeight: 1.5 }}>
            {update.release_notes}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              onClick={() => invoke("open_browser_url", { url: update.download_url })}
              className="btn btn-primary"
              style={{ flex: 1, justifyContent: "center", gap: 6, padding: "8px 0", fontSize: 12 }}
            >
              <Download size={12} />
              Download
            </button>
            <button
              onClick={() => setUpdate(null)}
              className="btn btn-secondary"
              style={{ padding: "8px 14px", fontSize: 12 }}
            >
              Later
            </button>
          </div>
        </div>
      )}

      <NavBar
        screen={screen}
        onNavigate={setScreen}
        email={auth.email}
        tier={auth.tier}
        onLogout={handleLogout}
      />

      <main style={{ flex: 1, overflow: "auto", background: "var(--bg)" }}>
        {screen === "home"            && <Home auth={auth} onNavigate={setScreen} />}
        {screen === "vpn"             && <VPN />}
        {screen === "threats"         && <Threats />}
        {screen === "scan"            && <Scan />}
        {screen === "vulnerabilities" && <Vulnerabilities />}
        {screen === "settings"        && <Settings auth={auth} onLogout={handleLogout} />}
      </main>
    </div>
  );
}
