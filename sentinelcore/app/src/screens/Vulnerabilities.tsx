import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ShieldAlert, ShieldCheck, ChevronDown, ChevronUp, Play, Square, ExternalLink } from "lucide-react";

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

const SEVERITY_STYLE: Record<string, { bg: string; border: string; color: string; badge: string }> = {
  CRITICAL: { bg: "#1c0a0a", border: "#7f1d1d", color: "#fca5a5", badge: "#dc2626" },
  HIGH:     { bg: "#1c1000", border: "#78350f", color: "#fde68a", badge: "#d97706" },
  MEDIUM:   { bg: "#0f110a", border: "#3f4a1a", color: "#bef264", badge: "#65a30d" },
  LOW:      { bg: "#0a0f1c", border: "#1e3a5f", color: "#93c5fd", badge: "#3b82f6" },
};

function severityStyle(s: string) {
  return SEVERITY_STYLE[s] ?? SEVERITY_STYLE.LOW;
}

export default function Vulnerabilities() {
  const [state, setState] = useState<"idle" | "running" | "done">("idle");
  const [checked, setChecked] = useState(0);
  const [total, setTotal] = useState(0);
  const [results, setResults] = useState<VulnResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

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
  const high = results.filter((r) => r.highest_severity === "HIGH").length;
  const pct = total > 0 ? Math.round((checked / total) * 100) : 0;

  return (
    <div style={{ padding: "28px 32px", height: "100%", overflowY: "auto" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em", marginBottom: 4 }}>
            Vulnerability Scan
          </h2>
          <p style={{ fontSize: 12, color: "#475569" }}>
            Checks installed software against the NVD CVE database
          </p>
        </div>
        {state !== "running" ? (
          <button
            onClick={startScan}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "10px 20px", background: "#dc2626",
              border: "none", borderRadius: 8, color: "#fff",
              fontSize: 14, fontWeight: 600, cursor: "pointer",
            }}
          >
            <Play size={15} /> Scan Now
          </button>
        ) : (
          <button
            disabled
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "10px 20px", background: "#1e1e2e",
              border: "1px solid #334155", borderRadius: 8, color: "#475569",
              fontSize: 14, fontWeight: 600, cursor: "not-allowed",
            }}
          >
            <Square size={15} /> Scanning…
          </button>
        )}
      </div>

      {/* Progress */}
      {state === "running" && (
        <div style={{ background: "#0d0d14", border: "1px solid #1e1e2e", borderRadius: 10, padding: "20px 24px", marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 13, color: "#94a3b8" }}>Checking against NVD CVE database…</span>
            <span style={{ fontSize: 13, color: "#f1f5f9", fontWeight: 600 }}>{pct}%</span>
          </div>
          <div style={{ height: 4, background: "#1e1e2e", borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${pct}%`, background: "#dc2626", borderRadius: 2, transition: "width 0.3s" }} />
          </div>
          <p style={{ fontSize: 11, color: "#475569", marginTop: 8 }}>
            {checked} of {total} software items checked
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "12px 16px", marginBottom: 20, color: "#ef4444", fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Summary */}
      {state === "done" && (
        results.length === 0 ? (
          <div style={{ textAlign: "center", padding: "40px 0" }}>
            <ShieldCheck size={48} color="#22c55e" style={{ marginBottom: 12 }} />
            <p style={{ fontSize: 16, fontWeight: 600, color: "#f1f5f9" }}>No known vulnerabilities found</p>
            <p style={{ fontSize: 13, color: "#475569", marginTop: 4 }}>Your installed software looks up to date.</p>
          </div>
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
              <SummaryCard label="Vulnerable apps" value={results.length} color="#f1f5f9" />
              <SummaryCard label="Critical severity" value={critical} color="#ef4444" />
              <SummaryCard label="High severity" value={high} color="#f59e0b" />
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {results.map((r, i) => <VulnCard key={i} result={r} />)}
            </div>
          </>
        )
      )}

      {/* Idle */}
      {state === "idle" && (
        <div style={{ textAlign: "center", padding: "48px 0", color: "#475569" }}>
          <ShieldAlert size={48} color="#1e1e2e" style={{ marginBottom: 16 }} />
          <p style={{ fontSize: 14 }}>Scans all installed software for known CVEs from the NIST NVD database.</p>
          <p style={{ fontSize: 12, marginTop: 6 }}>Includes severity scores, descriptions, and patch guidance.</p>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ background: "#0d0d14", border: "1px solid #1e1e2e", borderRadius: 10, padding: "14px 16px" }}>
      <div style={{ fontSize: 22, fontWeight: 700, color, marginBottom: 4 }}>{value}</div>
      <div style={{ fontSize: 11, color: "#475569", textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</div>
    </div>
  );
}

function VulnCard({ result }: { result: VulnResult }) {
  const [expanded, setExpanded] = useState(false);
  const s = severityStyle(result.highest_severity);

  return (
    <div style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 10, overflow: "hidden" }}>
      <button
        onClick={() => setExpanded((v) => !v)}
        style={{
          width: "100%", display: "flex", alignItems: "center", gap: 12,
          padding: "14px 16px", background: "transparent", border: "none",
          cursor: "pointer", textAlign: "left",
        }}
      >
        <span style={{ fontSize: 10, fontWeight: 700, padding: "3px 8px", background: s.badge, color: "#fff", borderRadius: 4, flexShrink: 0 }}>
          {result.highest_severity}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f1f5f9", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {result.name}
          </div>
          {result.version && (
            <div style={{ fontSize: 11, color: "#64748b" }}>v{result.version}</div>
          )}
        </div>
        <span style={{ fontSize: 12, color: s.color, flexShrink: 0 }}>
          {result.cve_count} CVE{result.cve_count !== 1 ? "s" : ""}
        </span>
        {expanded ? <ChevronUp size={14} color="#64748b" /> : <ChevronDown size={14} color="#64748b" />}
      </button>

      {expanded && (
        <div style={{ borderTop: `1px solid ${s.border}`, padding: "12px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
          {result.cves.map((cve, i) => <CveCard key={i} cve={cve} />)}
        </div>
      )}
    </div>
  );
}

function CveCard({ cve }: { cve: CveItem }) {
  const s = severityStyle(cve.severity);
  return (
    <div style={{ background: "#0a0a10", border: `1px solid ${s.border}40`, borderRadius: 8, padding: "12px 14px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: s.color, fontFamily: "monospace" }}>{cve.cve_id}</span>
        <span style={{ fontSize: 10, padding: "2px 6px", background: s.badge, color: "#fff", borderRadius: 3, fontWeight: 600 }}>
          {cve.severity} {cve.cvss_score > 0 ? `(${cve.cvss_score.toFixed(1)})` : ""}
        </span>
        <span style={{ fontSize: 10, color: "#475569", marginLeft: "auto" }}>{cve.published}</span>
      </div>
      <p style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.5, marginBottom: cve.references.length > 0 ? 8 : 0 }}>
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
              style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#3b82f6", textDecoration: "none" }}
            >
              <ExternalLink size={10} /> Reference {i + 1}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
