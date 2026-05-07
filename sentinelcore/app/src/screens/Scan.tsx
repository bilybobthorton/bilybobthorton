import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ScanLine, ShieldCheck, ShieldAlert, X, Play, Square, Zap, Search } from "lucide-react";

interface ScanProgress {
  scanned: number;
  threats: number;
  current_file: string;
  done: boolean;
  phase: string;
}

interface SystemThreat {
  path: string;
  sha256: string;
  source: string;
  threat_level: string;
  score: number;
  detail: string;
}

type ScanState = "idle" | "running" | "done" | "cancelled";
type ScanMode = "quick" | "full";

const SOURCE_LABELS: Record<string, { label: string; color: string; bg: string }> = {
  "local-blocklist": { label: "KNOWN MALWARE", color: "#fca5a5", bg: "#7f1d1d" },
  "heuristic":       { label: "SUSPICIOUS",    color: "#fde68a", bg: "#78350f" },
  "cloud-hash":      { label: "CLOUD MATCH",   color: "#fca5a5", bg: "#7f1d1d" },
  "cloud-full":      { label: "DEEP SCAN",     color: "#fca5a5", bg: "#7f1d1d" },
};

export default function Scan() {
  const [state, setState] = useState<ScanState>("idle");
  const [mode, setMode] = useState<ScanMode>("quick");
  const [scanned, setScanned] = useState(0);
  const [currentFile, setCurrentFile] = useState("");
  const [phase, setPhase] = useState("scanning");
  const [threats, setThreats] = useState<SystemThreat[]>([]);
  const [error, setError] = useState<string | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

  const startScan = async () => {
    setError(null);
    setScanned(0);
    setCurrentFile("");
    setThreats([]);
    setPhase("scanning");
    setState("running");

    const unlisten = await listen<ScanProgress>("scan-progress", (event) => {
      const p = event.payload;
      setScanned(p.scanned);
      setCurrentFile(p.current_file);
      setPhase(p.phase);
      if (p.done) {
        setState("done");
      }
    });
    unlistenRef.current = unlisten;

    try {
      const result = await invoke<SystemThreat[]>("scan_system", { scanMode: mode });
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
  const malicious = threats.filter((t) => t.threat_level === "MALICIOUS");
  const suspicious = threats.filter((t) => t.threat_level === "SUSPICIOUS");

  return (
    <div style={{ padding: "28px 32px", height: "100%", overflowY: "auto" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em", marginBottom: 4 }}>
            System Scan
          </h2>
          <p style={{ fontSize: 12, color: "#475569" }}>
            Multi-layer detection: local blocklist → PE heuristics → cloud analysis
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

      {/* Mode selector — only show when idle */}
      {state === "idle" && (
        <div style={{ display: "flex", gap: 10, marginBottom: 24 }}>
          <ModeButton
            active={mode === "quick"}
            onClick={() => setMode("quick")}
            icon={<Zap size={14} />}
            label="Quick Scan"
            desc="Downloads, AppData, Temp (~5 min)"
          />
          <ModeButton
            active={mode === "full"}
            onClick={() => setMode("full")}
            icon={<Search size={14} />}
            label="Full Scan"
            desc="All directories incl. System32 (~30 min)"
          />
        </div>
      )}

      {/* Progress */}
      {(isRunning || state === "done" || state === "cancelled") && (
        <div style={{ background: "#0d0d14", border: "1px solid #1e1e2e", borderRadius: 10, padding: "20px 24px", marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
            <span style={{ fontSize: 13, color: "#94a3b8" }}>
              {isRunning
                ? phase === "uploading" ? "Deep-analyzing suspicious file…" : "Scanning…"
                : state === "cancelled" ? "Cancelled"
                : "Complete"}
            </span>
            <span style={{ fontSize: 13, color: "#f1f5f9", fontWeight: 600 }}>
              {scanned.toLocaleString()} files
            </span>
          </div>

          <div style={{ height: 4, background: "#1e1e2e", borderRadius: 2, overflow: "hidden", marginBottom: 12 }}>
            <div
              style={{
                height: "100%",
                background: malicious.length > 0 ? "#dc2626" : suspicious.length > 0 ? "#f59e0b" : "#22c55e",
                borderRadius: 2,
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
            <Stat label="Malicious" value={String(malicious.length)} accent={malicious.length > 0} color="#dc2626" />
            <Stat label="Suspicious" value={String(suspicious.length)} accent={suspicious.length > 0} color="#f59e0b" />
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
                {threats.length} item{threats.length !== 1 ? "s" : ""} detected
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
        <div style={{ textAlign: "center", padding: "40px 0", color: "#475569" }}>
          <ScanLine size={48} color="#1e1e2e" style={{ marginBottom: 16 }} />
          <p style={{ fontSize: 14 }}>
            {mode === "quick"
              ? "Quick Scan checks Downloads, AppData, and Temp directories."
              : "Full Scan checks your entire system including Program Files and Windows directories."}
          </p>
          <p style={{ fontSize: 12, marginTop: 6 }}>
            Uses local hash blocklist + PE heuristics + cloud intelligence.
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

function ModeButton({
  active, onClick, icon, label, desc,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  desc: string;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        flex: 1, padding: "14px 16px", textAlign: "left",
        background: active ? "#1a0e0e" : "#0d0d14",
        border: `1px solid ${active ? "#dc2626" : "#1e1e2e"}`,
        borderRadius: 10, cursor: "pointer",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, color: active ? "#ef4444" : "#64748b" }}>
        {icon}
        <span style={{ fontSize: 13, fontWeight: 600, color: active ? "#f1f5f9" : "#94a3b8" }}>{label}</span>
      </div>
      <span style={{ fontSize: 11, color: "#475569" }}>{desc}</span>
    </button>
  );
}

function Stat({ label, value, accent, color }: { label: string; value: string; accent?: boolean; color?: string }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "#64748b", marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: accent && color ? color : "#f1f5f9" }}>{value}</div>
    </div>
  );
}

function ThreatCard({ threat }: { threat: SystemThreat }) {
  const [expanded, setExpanded] = useState(false);
  const badge = SOURCE_LABELS[threat.source] ?? { label: threat.source.toUpperCase(), color: "#fca5a5", bg: "#7f1d1d" };
  const borderColor = threat.threat_level === "MALICIOUS" ? "#7f1d1d" : "#78350f";
  const bgColor = threat.threat_level === "MALICIOUS" ? "#1c0a0a" : "#1c1200";

  return (
    <div
      style={{ background: bgColor, border: `1px solid ${borderColor}`, borderRadius: 8, padding: "12px 16px", cursor: "pointer" }}
      onClick={() => setExpanded((v) => !v)}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <X size={14} color={threat.threat_level === "MALICIOUS" ? "#ef4444" : "#f59e0b"} style={{ flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: "#f1f5f9", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {threat.path.split(/[/\\]/).pop() ?? threat.path}
        </span>
        <span style={{ fontSize: 10, fontWeight: 600, padding: "2px 8px", background: badge.bg, color: badge.color, borderRadius: 4, flexShrink: 0 }}>
          {badge.label}
        </span>
      </div>
      {expanded && (
        <div style={{ marginTop: 10, fontSize: 11, color: "#64748b" }}>
          <p style={{ marginBottom: 4 }}>{threat.detail}</p>
          <p style={{ fontFamily: "monospace", wordBreak: "break-all", color: "#475569" }}>
            {threat.path}
          </p>
          <p style={{ fontFamily: "monospace", wordBreak: "break-all", marginTop: 4, color: "#334155" }}>
            SHA256: {threat.sha256}
          </p>
          {threat.score > 0 && (
            <p style={{ marginTop: 4, color: "#475569" }}>
              Score: {(threat.score * 100).toFixed(0)}%
            </p>
          )}
        </div>
      )}
    </div>
  );
}
