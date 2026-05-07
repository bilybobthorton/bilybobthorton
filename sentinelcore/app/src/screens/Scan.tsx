import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ScanLine, ShieldCheck, ShieldAlert, X, Play, Square } from "lucide-react";

interface ScanProgress {
  scanned: number;
  threats: number;
  current_file: string;
  done: boolean;
}

interface SystemThreat {
  path: string;
  sha256: string;
  source: string;
}

type ScanState = "idle" | "running" | "done" | "cancelled";

export default function Scan() {
  const [state, setState] = useState<ScanState>("idle");
  const [scanned, setScanned] = useState(0);
  const [currentFile, setCurrentFile] = useState("");
  const [threats, setThreats] = useState<SystemThreat[]>([]);
  const [error, setError] = useState<string | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

  const startScan = async () => {
    setError(null);
    setScanned(0);
    setCurrentFile("");
    setThreats([]);
    setState("running");

    // Listen for progress events
    const unlisten = await listen<ScanProgress>("scan-progress", (event) => {
      const p = event.payload;
      setScanned(p.scanned);
      setCurrentFile(p.current_file);
      if (p.done) {
        setState("done");
      }
    });
    unlistenRef.current = unlisten;

    try {
      const result = await invoke<SystemThreat[]>("scan_system");
      setThreats(result);
    } catch (e) {
      setError(String(e));
      setState("idle");
    } finally {
      unlistenRef.current?.();
      unlistenRef.current = null;
    }
  };

  const cancelScan = async () => {
    await invoke("cancel_scan");
    setState("cancelled");
    unlistenRef.current?.();
    unlistenRef.current = null;
  };

  useEffect(() => {
    return () => {
      unlistenRef.current?.();
    };
  }, []);

  const isRunning = state === "running";

  return (
    <div style={{ padding: "28px 32px", height: "100%", overflowY: "auto" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em", marginBottom: 4 }}>
            System Scan
          </h2>
          <p style={{ fontSize: 12, color: "#475569" }}>
            Scans executables and scripts across common Windows directories
          </p>
        </div>
        {!isRunning ? (
          <button
            onClick={startScan}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "10px 20px", background: "#dc2626",
              border: "none", borderRadius: 8, color: "#fff",
              fontSize: 14, fontWeight: 600, cursor: "pointer",
            }}
          >
            <Play size={15} />
            Start Scan
          </button>
        ) : (
          <button
            onClick={cancelScan}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "10px 20px", background: "#1e1e2e",
              border: "1px solid #334155", borderRadius: 8, color: "#94a3b8",
              fontSize: 14, fontWeight: 600, cursor: "pointer",
            }}
          >
            <Square size={15} />
            Cancel
          </button>
        )}
      </div>

      {/* Progress */}
      {(isRunning || state === "done" || state === "cancelled") && (
        <div style={{ background: "#0d0d14", border: "1px solid #1e1e2e", borderRadius: 10, padding: "20px 24px", marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
            <span style={{ fontSize: 13, color: "#94a3b8" }}>
              {isRunning ? "Scanning…" : state === "cancelled" ? "Cancelled" : "Complete"}
            </span>
            <span style={{ fontSize: 13, color: "#f1f5f9", fontWeight: 600 }}>
              {scanned.toLocaleString()} files
            </span>
          </div>

          {/* Animated progress bar */}
          <div style={{ height: 4, background: "#1e1e2e", borderRadius: 2, overflow: "hidden", marginBottom: 12 }}>
            <div
              style={{
                height: "100%",
                background: threats.length > 0 ? "#dc2626" : "#22c55e",
                borderRadius: 2,
                width: isRunning ? "100%" : "100%",
                transition: isRunning ? "none" : "width 0.4s",
                animation: isRunning ? "pulse-bar 1.5s ease-in-out infinite" : "none",
              }}
            />
          </div>

          {isRunning && currentFile && (
            <p style={{ fontSize: 11, color: "#475569", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {currentFile}
            </p>
          )}

          <div style={{ display: "flex", gap: 24, marginTop: 12 }}>
            <Stat label="Files scanned" value={scanned.toLocaleString()} />
            <Stat label="Threats found" value={String(threats.length)} accent={threats.length > 0} />
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "12px 16px", marginBottom: 20, color: "#ef4444", fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Results */}
      {state === "done" && (
        threats.length === 0 ? (
          <div style={{ textAlign: "center", padding: "40px 0" }}>
            <ShieldCheck size={48} color="#22c55e" style={{ marginBottom: 12 }} />
            <p style={{ fontSize: 16, fontWeight: 600, color: "#f1f5f9" }}>No threats found</p>
            <p style={{ fontSize: 13, color: "#475569", marginTop: 4 }}>Your system looks clean.</p>
          </div>
        ) : (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
              <ShieldAlert size={18} color="#dc2626" />
              <h3 style={{ fontSize: 14, fontWeight: 600, color: "#f1f5f9" }}>
                {threats.length} threat{threats.length !== 1 ? "s" : ""} detected
              </h3>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {threats.map((t, i) => (
                <ThreatCard key={i} threat={t} />
              ))}
            </div>
          </div>
        )
      )}

      {/* Idle state */}
      {state === "idle" && (
        <div style={{ textAlign: "center", padding: "48px 0", color: "#475569" }}>
          <ScanLine size={48} color="#1e1e2e" style={{ marginBottom: 16 }} />
          <p style={{ fontSize: 14 }}>Press Start Scan to check your system for malware.</p>
          <p style={{ fontSize: 12, marginTop: 6 }}>
            Scans executables in Users, Program Files, ProgramData, and Temp directories.
          </p>
        </div>
      )}

      <style>{`
        @keyframes pulse-bar {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "#64748b", marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: accent ? "#dc2626" : "#f1f5f9" }}>{value}</div>
    </div>
  );
}

function ThreatCard({ threat }: { threat: SystemThreat }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      style={{
        background: "#1c0a0a",
        border: "1px solid #7f1d1d",
        borderRadius: 8,
        padding: "12px 16px",
        cursor: "pointer",
      }}
      onClick={() => setExpanded((v) => !v)}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <X size={14} color="#ef4444" style={{ flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: "#f1f5f9", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {threat.path}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 600, padding: "2px 8px",
          background: "#7f1d1d", color: "#fca5a5", borderRadius: 4,
          flexShrink: 0,
        }}>
          {threat.source === "local-blocklist" ? "KNOWN MALWARE" : "CLOUD MATCH"}
        </span>
      </div>
      {expanded && (
        <div style={{ marginTop: 10, fontSize: 11, color: "#64748b", fontFamily: "monospace", wordBreak: "break-all" }}>
          SHA256: {threat.sha256}
        </div>
      )}
    </div>
  );
}
