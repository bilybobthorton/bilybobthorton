import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Shield } from "lucide-react";

interface LoginProps {
  onLogin: (token: string, email: string, tier: string) => void;
}

interface LoginResponse {
  access_token: string;
  tier: string;
  email: string;
}

export default function Login({ onLogin }: LoginProps) {
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setError(null);
    setLoading(true);
    try {
      const result = await invoke<LoginResponse>("login", { email, password });
      onLogin(result.access_token, result.email, result.tier);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrap">
      {/* Brand */}
      <div style={{ marginBottom: 30, textAlign: "center" }}>
        <div
          style={{
            width: 54,
            height: 54,
            background: "var(--red)",
            borderRadius: 16,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 14px",
            boxShadow: "0 0 40px var(--red-25)",
          }}
        >
          <Shield size={28} color="#fff" />
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--text-1)", letterSpacing: "-0.02em", marginBottom: 4 }}>
          RedGuard
        </h1>
        <p style={{ color: "var(--text-3)", fontSize: 13 }}>Sign in to your account</p>
      </div>

      {/* Card */}
      <div className="login-card">
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label className="form-label">Email</label>
            <input
              type="email"
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              autoFocus
            />
          </div>

          <div style={{ marginBottom: 22 }}>
            <label className="form-label">Password</label>
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          {error && (
            <div className="error-banner" style={{ marginBottom: 16 }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ width: "100%", justifyContent: "center", padding: "11px", fontSize: 14 }}
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p style={{ marginTop: 20, textAlign: "center", fontSize: 12, color: "var(--text-3)" }}>
          Don&apos;t have an account?{" "}
          <a href="https://redgaurd.com" target="_blank" rel="noreferrer">
            Sign up at redgaurd.com
          </a>
        </p>
      </div>
    </div>
  );
}
