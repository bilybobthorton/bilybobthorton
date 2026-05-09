import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ScanLine, ShieldCheck, ShieldAlert, ChevronDown, ChevronRight, Play, Square, Zap, Search } from "lucide-react";

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
type ScanMode  = "quick" | "full";

const SOURCE_LABELS: Record<string, { label: string; color: string; bg: string }> = {
  "local-blocklist": { label: "KNOWN MALWARE", color: "#fca5a5", bg: "rgba(127,29,29,0.5)" },
  "heuristic":       { label: "SUSPICIOUS",    color: "#fde68a", bg: "rgba(120,53,15,0.5)" },
  "cloud-hash":      { label: "CLOUD MATCH",   color: "#fca5a5", bg: "rgba(127,29,29,0.5)" },
  "cloud-full":      { label: "DEEP SCAN",     color: "#fca5a5", bg: "rgba(127,29,29,0.5)" },
};

export default function Scan() {
  const [state, setState]           = useState<ScanState>("idle");
  const [mode, setMode]             = useState<ScanMode>("quick");
  const [scanned, setScanned]       = useState(0);
  const [currentFile, setCurrentFile] = useState("");
  const [phase, setPhase]           = useState("scanning");
  const [threats, setThreats]       = useState<SystemThreat[]>([]);
  const [error, setError]           = useState<string | null>(null);
  const unlistenRef                 = useRef<(() => void) | null>(null);

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
      if (p.done) setState("done");
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

  useEffect(() => { return () => { unlistenRef.current?.(); }; }, []);

  const isRunning  = state === "running";
  const malicious  = threats.filter((t) => t.threat_level === "MALICIOUS");
  const suspicious = threats.filter((t) => t.threat_level === "SUSPICIOUS");
  const progressColor = malicious.length > 0 ? "danger" : suspicious.length > 0 ? "warn" : "clean";

  return (
    <div className="screen">
      {/* Header */}
      <div className="screen-header">
        <div>
          <h2 className="screen-title" style={{ marginBottom: 3 }}>System Scan</h2>
          <p style={{ fontSize: 11.5, color: "var(--text-3)" }}>
            Hash blocklist → PE heuristics → cloud ML + VT + OTX
          </p>
        </div>
        {!isRunning ? (
          <button onClick={startScan} className="btn btn-primary" style={{ gap: 8 }}>
            <Play size={14} />
            Start Scan
          </button>
        ) : (
          <button onClick={cancelScan} className="btn btn-secondary" style={{ gap: 8 }}>
            <Square size={14} />
            Cancel
          </button>
        )}
      </div>

      {/* Mode selector */}
      {state === "idle" && (
        <div style={{ display: "flex", gap: 10, marginBottom: 22 }}>
          <button
            onClick={() => setMode("quick")}
            className={`mode-btn${mode === "quick" ? " active" : ""}`}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 4, color: mode === "quick" ? "var(--red)" : "var(--text-3)" }}>
              <Zap size={13} />
              <span style={{ fontSize: 13, fontWeight: 600, color: mode === "quick" ? "var(--text-1)" : "var(--text-2)" }}>Quick Scan</span>
            </div>
            <span style={{ fontSize: 11, color: "var(--text-3)" }}>Downloads, AppData, Temp (~5 min)</span>
          </button>
          <button
            onClick={() => setMode("full")}
            className={`mode-btn${mode === "full" ? " active" : ""}`}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 4, color: mode === "full" ? "var(--red)" : "var(--text-3)" }}>
              <Search size={13} />
              <span style={{ fontSize: 13, fontWeight: 600, color: mode === "full" ? "var(--text-1)" : "var(--text-2)" }}>Full Scan</span>
            </div>
            <span style={{ fontSize: 11, color: "var(--text-3)" }}>All dirs incl. System32 (~30 min)</span>
          </button>
        </div>
      )}

      {/* Progress card */}
      {(isRunning || state === "done" || state === "cancelled") && (
        <div className="scan-progress-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {isRunning && <span className="live-dot green" />}
              <span style={{ fontSize: 13, color: "var(--text-2)" }}>
                {isRunning
                  ? phase === "uploading" ? "Deep-analyzing suspicious file…" : "Scanning…"
                  : state === "cancelled" ? "Cancelled"
                  : "Scan complete"}
              </span>
            </div>
            <span style={{ fontSize: 14, color: "var(--text-1)", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
              {scanned.toLocaleString()} files
            </span>
          </div>

          <div className="progress-track">
            <div className={`progress-fill ${progressColor}${isRunning ? " running" : ""}`} style={{ width: "100%" }} />
          </div>

          {isRunning && currentFile && (
            <p style={{ fontSize: 10.5, color: "var(--text-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 10 }}>
              {currentFile}
            </p>
          )}

          <div style={{ display: "flex", gap: 28 }}>
            <ScanStat label="Files scanned" value={scanned.toLocaleString()} />
            <ScanStat label="Malicious"     value={String(malicious.length)}  accent={malicious.length > 0}  color="var(--red)" />
            <ScanStat label="Suspicious"    value={String(suspicious.length)} accent={suspicious.length > 0} color="var(--amber)" />
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button className="error-dismiss" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Results */}
      {state === "done" && (
        threats.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={44} color="var(--green)" />
            <div className="empty-state-title">No threats found</div>
            <div>Your system looks clean.</div>
          </div>
        ) : (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
              <ShieldAlert size={17} color="var(--red)" />
              <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-1)" }}>
                {threats.length} item{threats.length !== 1 ? "s" : ""} detected
              </h3>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {threats.map((t, i) => (
                <ThreatCard key={i} threat={t} />
              ))}
            </div>
          </div>
        )
      )}

      {/* Idle placeholder */}
      {state === "idle" && (
        <div className="empty-state">
          <ScanLine size={44} />
          <div className="empty-state-title" style={{ color: "var(--text-3)" }}>
            {mode === "quick" ? "Quick Scan" : "Full Scan"} Ready
          </div>
          <div style={{ color: "var(--text-3)" }}>
            {mode === "quick"
              ? "Checks Downloads, AppData, and Temp for threats."
              : "Scans your entire system including Program Files and Windows directories."}
          </div>
        </div>
      )}

      <style>{`
        @keyframes pulse-bar {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}

function ScanStat({
  label, value, accent, color,
}: {
  label: string; value: string; accent?: boolean; color?: string;
}) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: accent && color ? color : "var(--text-1)" }}>
        {value}
      </div>
    </div>
  );
}

function ThreatCard({ threat }: { threat: SystemThreat }) {
  const [expanded, setExpanded] = useState(false);
  const badge = SOURCE_LABELS[threat.source] ?? { label: threat.source.toUpperCase(), color: "#fca5a5", bg: "rgba(127,29,29,0.5)" };
  const cls = threat.threat_level === "MALICIOUS" ? "malicious" : "suspicious";
  const iconColor = threat.threat_level === "MALICIOUS" ? "var(--red)" : "var(--amber)";

  return (
    <div className={`threat-card ${cls}`} onClick={() => setExpanded((v) => !v)}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {expanded ? (
          <ChevronDown size={13} color={iconColor} style={{ flexShrink: 0 }} />
        ) : (
          <ChevronRight size={13} color={iconColor} style={{ flexShrink: 0 }} />
        )}
        <span
          style={{
            fontSize: 12.5,
            color: "var(--text-1)",
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {threat.path.split(/[/\\]/).pop() ?? threat.path}
        </span>
        <span
          style={{
            fontSize: 9.5,
            fontWeight: 700,
            padding: "2px 8px",
            background: badge.bg,
            color: badge.color,
            borderRadius: 4,
            flexShrink: 0,
            letterSpacing: "0.04em",
          }}
        >
          {badge.label}
        </span>
      </div>
      {expanded && (
        <div style={{ marginTop: 10, paddingLeft: 23, fontSize: 11, color: "var(--text-3)", lineHeight: 1.6 }}>
          <p style={{ marginBottom: 4, color: "var(--text-2)" }}>{threat.detail}</p>
          <p style={{ fontFamily: "monospace", wordBreak: "break-all", fontSize: 10.5 }}>
            {threat.path}
          </p>
          <p style={{ fontFamily: "monospace", wordBreak: "break-all", marginTop: 4, fontSize: 10, color: "var(--text-3)" }}>
            SHA256: {threat.sha256}
          </p>
          {threat.score > 0 && (
            <p style={{ marginTop: 4 }}>Score: {(threat.score * 100).toFixed(0)}%</p>
          )}
        </div>
      )}
    </div>
  );
}
