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
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        background: "#0a0a0f",
        padding: "0 24px",
      }}
    >
      {/* Logo mark */}
      <div style={{ marginBottom: 32, textAlign: "center" }}>
        <div
          style={{
            width: 56,
            height: 56,
            background: "#dc2626",
            borderRadius: 16,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 12px",
            boxShadow: "0 0 32px #dc262640",
          }}
        >
          <Shield size={30} color="#fff" />
        </div>
        <h1
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: "#f1f5f9",
            letterSpacing: "-0.02em",
            marginBottom: 4,
          }}
        >
          RedGuard
        </h1>
        <p style={{ color: "#64748b", fontSize: 13 }}>
          Sign in to your account
        </p>
      </div>

      {/* Card */}
      <div
        style={{
          width: "100%",
          maxWidth: 360,
          background: "#0d0d14",
          border: "1px solid #1e1e2e",
          borderRadius: 12,
          padding: "28px 24px",
        }}
      >
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label
              style={{
                display: "block",
                fontSize: 12,
                fontWeight: 500,
                color: "#94a3b8",
                marginBottom: 6,
                textTransform: "uppercase",
                letterSpacing: "0.04em",
              }}
            >
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              autoFocus
              style={{
                width: "100%",
                padding: "10px 12px",
                background: "#0a0a0f",
                border: "1px solid #1e1e2e",
                borderRadius: 7,
                color: "#f1f5f9",
                outline: "none",
                transition: "border-color 0.15s",
              }}
              onFocus={(e) =>
                (e.currentTarget.style.borderColor = "#dc2626")
              }
              onBlur={(e) =>
                (e.currentTarget.style.borderColor = "#1e1e2e")
              }
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label
              style={{
                display: "block",
                fontSize: 12,
                fontWeight: 500,
                color: "#94a3b8",
                marginBottom: 6,
                textTransform: "uppercase",
                letterSpacing: "0.04em",
              }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              style={{
                width: "100%",
                padding: "10px 12px",
                background: "#0a0a0f",
                border: "1px solid #1e1e2e",
                borderRadius: 7,
                color: "#f1f5f9",
                outline: "none",
                transition: "border-color 0.15s",
              }}
              onFocus={(e) =>
                (e.currentTarget.style.borderColor = "#dc2626")
              }
              onBlur={(e) =>
                (e.currentTarget.style.borderColor = "#1e1e2e")
              }
            />
          </div>

          {error && (
            <div
              style={{
                marginBottom: 16,
                padding: "10px 12px",
                background: "#ef444420",
                border: "1px solid #ef444440",
                borderRadius: 7,
                color: "#ef4444",
                fontSize: 13,
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "11px",
              background: loading ? "#7f1d1d" : "#dc2626",
              color: "#fff",
              border: "none",
              borderRadius: 7,
              fontWeight: 600,
              fontSize: 14,
              cursor: loading ? "not-allowed" : "pointer",
              transition: "background 0.15s",
              letterSpacing: "0.01em",
            }}
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p
          style={{
            marginTop: 20,
            textAlign: "center",
            fontSize: 12,
            color: "#475569",
          }}
        >
          Don&apos;t have an account?{" "}
          <a
            href="https://redgaurd.com/register"
            target="_blank"
            rel="noreferrer"
            style={{ color: "#ef4444" }}
          >
            Sign up at redgaurd.com
          </a>
        </p>
      </div>
    </div>
  );
}
