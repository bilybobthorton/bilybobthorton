import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ShieldAlert, ShieldCheck, ChevronDown, ChevronRight, Play, Square, ExternalLink } from "lucide-react";

interface VulnProgress {
  checked: number;
  total: number;
  done: boolean;
}

interface CveItem {
  cve_id: string;
  description: string;
  severity: string;
  cvss_score: number;
  published: string;
  references: string[];
}

interface VulnResult {
  name: string;
  version: string | null;
  publisher: string | null;
  cves: CveItem[];
  highest_severity: string;
  cve_count: number;
}

const SEV: Record<string, { bg: string; border: string; color: string; badge: string }> = {
  CRITICAL: { bg: "#100808", border: "rgba(224,52,58,0.25)", color: "#fca5a5", badge: "#dc2626" },
  HIGH:     { bg: "#100c04", border: "rgba(245,158,11,0.2)",  color: "#fde68a", badge: "#d97706" },
  MEDIUM:   { bg: "#080e08", border: "rgba(101,163,13,0.2)",  color: "#bef264", badge: "#65a30d" },
  LOW:      { bg: "#08080e", border: "rgba(59,130,246,0.2)",  color: "#93c5fd", badge: "#3b82f6" },
};
const sevStyle = (s: string) => SEV[s] ?? SEV.LOW;

export default function Vulnerabilities() {
  const [state, setState]     = useState<"idle" | "running" | "done">("idle");
  const [checked, setChecked] = useState(0);
  const [total, setTotal]     = useState(0);
  const [results, setResults] = useState<VulnResult[]>([]);
  const [error, setError]     = useState<string | null>(null);
  const unlistenRef           = useRef<(() => void) | null>(null);

  const startScan = async () => {
    setError(null);
    setResults([]);
    setChecked(0);
    setState("running");

    const unlisten = await listen<VulnProgress>("vuln-progress", (e) => {
      setChecked(e.payload.checked);
      setTotal(e.payload.total);
      if (e.payload.done) setState("done");
    });
    unlistenRef.current = unlisten;

    try {
      const res = await invoke<VulnResult[]>("scan_vulnerabilities");
      setResults(res);
    } catch (e) {
      setError(String(e));
      setState("idle");
    } finally {
      unlistenRef.current?.();
      unlistenRef.current = null;
    }
  };

  useEffect(() => () => { unlistenRef.current?.(); }, []);

  const critical = results.filter((r) => r.highest_severity === "CRITICAL").length;
  const high     = results.filter((r) => r.highest_severity === "HIGH").length;
  const pct      = total > 0 ? Math.round((checked / total) * 100) : 0;
  const isRunning = state === "running";

  return (
    <div className="screen">
      {/* Header */}
      <div className="screen-header">
        <div>
          <h2 className="screen-title" style={{ marginBottom: 3 }}>Vulnerability Scan</h2>
          <p style={{ fontSize: 11.5, color: "var(--text-3)" }}>
            Checks installed software against the NIST NVD CVE database
          </p>
        </div>
        {!isRunning ? (
          <button onClick={startScan} className="btn btn-primary" style={{ gap: 8 }}>
            <Play size={14} /> Scan Now
          </button>
        ) : (
          <button disabled className="btn btn-secondary" style={{ gap: 8 }}>
            <Square size={14} /> Scanning…
          </button>
        )}
      </div>

      {/* Progress */}
      {isRunning && (
        <div className="scan-progress-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="live-dot green" />
              <span style={{ fontSize: 13, color: "var(--text-2)" }}>Checking against NVD CVE database…</span>
            </div>
            <span style={{ fontSize: 13, color: "var(--text-1)", fontWeight: 600 }}>{pct}%</span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill running"
              style={{ width: `${Math.max(pct, 5)}%`, background: "var(--red)", transition: "width 0.3s" }}
            />
          </div>
          <p style={{ fontSize: 11, color: "var(--text-3)", marginTop: 8 }}>
            {checked} of {total} software items checked
          </p>
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
        results.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={44} color="var(--green)" />
            <div className="empty-state-title">No known vulnerabilities found</div>
            <div>Your installed software looks up to date.</div>
          </div>
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 20 }}>
              <div className="stat-card">
                <div className="stat-value">{results.length}</div>
                <div className="stat-label">Vulnerable Apps</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: "var(--red)" }}>{critical}</div>
                <div className="stat-label">Critical</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: "var(--amber)" }}>{high}</div>
                <div className="stat-label">High</div>
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {results.map((r, i) => <VulnCard key={i} result={r} />)}
            </div>
          </>
        )
      )}

      {/* Idle */}
      {state === "idle" && (
        <div className="empty-state">
          <ShieldAlert size={44} />
          <div className="empty-state-title" style={{ color: "var(--text-3)" }}>Ready to Scan</div>
          <div style={{ color: "var(--text-3)" }}>
            Scans all installed software for known CVEs. Includes severity scores, descriptions, and patch guidance.
          </div>
        </div>
      )}
    </div>
  );
}

function VulnCard({ result }: { result: VulnResult }) {
  const [expanded, setExpanded] = useState(false);
  const s = sevStyle(result.highest_severity);

  return (
    <div style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: "var(--r-md)", overflow: "hidden" }}>
      <button
        onClick={() => setExpanded((v) => !v)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "13px 16px",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span
          style={{
            fontSize: 9.5,
            fontWeight: 700,
            padding: "2px 7px",
            background: s.badge,
            color: "#fff",
            borderRadius: 4,
            flexShrink: 0,
            letterSpacing: "0.04em",
          }}
        >
          {result.highest_severity}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-1)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {result.name}
          </div>
          {result.version && (
            <div style={{ fontSize: 10.5, color: "var(--text-3)" }}>v{result.version}</div>
          )}
        </div>
        <span style={{ fontSize: 12, color: s.color, flexShrink: 0 }}>
          {result.cve_count} CVE{result.cve_count !== 1 ? "s" : ""}
        </span>
        {expanded
          ? <ChevronDown size={14} color="var(--text-3)" />
          : <ChevronRight size={14} color="var(--text-3)" />}
      </button>

      {expanded && (
        <div style={{ borderTop: `1px solid ${s.border}`, padding: "12px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
          {result.cves.map((cve, i) => <CveCard key={i} cve={cve} />)}
        </div>
      )}
    </div>
  );
}

function CveCard({ cve }: { cve: CveItem }) {
  const s = sevStyle(cve.severity);
  return (
    <div style={{ background: "var(--bg)", border: `1px solid ${s.border}`, borderRadius: "var(--r-sm)", padding: "11px 14px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: s.color, fontFamily: "monospace" }}>{cve.cve_id}</span>
        <span style={{ fontSize: 9.5, padding: "2px 6px", background: s.badge, color: "#fff", borderRadius: 3, fontWeight: 700 }}>
          {cve.severity}{cve.cvss_score > 0 ? ` ${cve.cvss_score.toFixed(1)}` : ""}
        </span>
        <span style={{ fontSize: 10, color: "var(--text-3)", marginLeft: "auto" }}>{cve.published}</span>
      </div>
      <p style={{ fontSize: 12, color: "var(--text-2)", lineHeight: 1.5, marginBottom: cve.references.length > 0 ? 8 : 0 }}>
        {cve.description}
      </p>
      {cve.references.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {cve.references.map((ref, i) => (
            <a
              key={i}
              href={ref}
              target="_blank"
              rel="noreferrer"
              style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--blue)", textDecoration: "none" }}
            >
              <ExternalLink size={10} /> Ref {i + 1}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
