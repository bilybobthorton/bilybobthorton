import { useEffect, useState } from "react";
import { load } from "@tauri-apps/plugin-store";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
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
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [screen, setScreen] = useState<Screen>("home");
  const [loading, setLoading] = useState(true);
  const [update, setUpdate] = useState<UpdateInfo | null>(null);

  // Check for app updates ~10s after launch (let the UI settle first).
  useEffect(() => {
    const timer = setTimeout(async () => {
      try {
        const current = await getVersion();
        const info = await invoke<UpdateInfo | null>("check_for_update", {
          currentVersion: current,
        });
        if (info) setUpdate(info);
      } catch {
        // Non-critical — silently ignore network errors.
      }
    }, 10_000);
    return () => clearTimeout(timer);
  }, []);

  // Restore session from persisted store on mount.
  useEffect(() => {
    (async () => {
      try {
        const store = await load(STORE_FILE, { autoSave: false, defaults: {} });
        const token = await store.get<string>("token");
        const email = await store.get<string>("email");
        const tier = await store.get<string>("tier");
        if (token && email) {
          setAuth({ token, email, tier: tier ?? "free" });
        }
      } catch {
        // Store not yet initialised — first launch.
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
    // Show the main window after login (in case it was hidden).
    try {
      await invoke("show_window");
    } catch {
      // Not critical if this fails in dev.
    }
  };

  const handleLogout = async () => {
    try {
      await invoke("logout");
    } catch {
      // Best effort.
    }
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
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          background: "#0a0a0f",
          color: "#64748b",
        }}
      >
        Loading…
      </div>
    );
  }

  if (!auth) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      {/* Update available banner */}
      {update && (
        <div
          style={{
            position: "fixed",
            bottom: 20,
            right: 20,
            zIndex: 1000,
            background: "#1e1e2e",
            border: "1px solid #dc2626",
            borderRadius: 10,
            padding: "16px 20px",
            width: 300,
            boxShadow: "0 4px 24px rgba(0,0,0,0.5)",
          }}
        >
          <div style={{ fontWeight: 700, color: "#f1f5f9", marginBottom: 4 }}>
            Update Available — v{update.version}
          </div>
          <div style={{ fontSize: 12, color: "#94a3b8", marginBottom: 12 }}>
            {update.release_notes}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              onClick={() =>
                invoke("open_browser_url", { url: update.download_url })
              }
              style={{
                flex: 1,
                padding: "8px 0",
                borderRadius: 6,
                border: "none",
                background: "#dc2626",
                color: "#fff",
                fontWeight: 600,
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              Download
            </button>
            <button
              onClick={() => setUpdate(null)}
              style={{
                padding: "8px 14px",
                borderRadius: 6,
                border: "1px solid #334155",
                background: "transparent",
                color: "#64748b",
                fontSize: 13,
                cursor: "pointer",
              }}
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
      <main style={{ flex: 1, overflow: "auto" }}>
        {screen === "home" && <Home auth={auth} onNavigate={setScreen} />}
        {screen === "vpn" && <VPN />}
        {screen === "threats" && <Threats />}
        {screen === "scan" && <Scan />}
        {screen === "vulnerabilities" && <Vulnerabilities />}
        {screen === "settings" && (
          <Settings auth={auth} onLogout={handleLogout} />
        )}
      </main>
    </div>
  );
}
