import { useEffect, useState } from "react";
import { load } from "@tauri-apps/plugin-store";
import { invoke } from "@tauri-apps/api/core";
import NavBar from "./components/NavBar";
import Login from "./screens/Login";
import Home from "./screens/Home";
import VPN from "./screens/VPN";
import Threats from "./screens/Threats";
import Settings from "./screens/Settings";

export type Screen = "home" | "vpn" | "threats" | "settings";

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
        {screen === "settings" && (
          <Settings auth={auth} onLogout={handleLogout} />
        )}
      </main>
    </div>
  );
}
