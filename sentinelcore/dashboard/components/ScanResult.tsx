"use client";
import { ScanResult as ScanResultType } from "@/lib/api";
import { ThreatBadge } from "./ThreatBadge";
import { ShieldCheck, ShieldAlert, AlertTriangle, Hash, Brain, Globe } from "lucide-react";

interface ExtendedScanResult extends ScanResultType {
  ml?: { score: number; malicious: boolean; threshold: number };
  virustotal?: { found: boolean; malicious: number; total_engines: number; popular_threat_name?: string; vt_link?: string };
  otx?: { found: boolean; pulse_count: number; malware_families?: string[]; tags?: string[]; otx_link?: string };
}

export function ScanResult({ result }: { result: ExtendedScanResult }) {
  const pct = result.confidence != null ? Math.round(result.confidence * 100) : null;
  const ml = result.ml;
  const vt = result.virustotal;
  const otx = result.otx;

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400 mb-1 truncate max-w-sm">{result.filename}</p>
          <ThreatBadge level={result.threat_level} />
        </div>
        {pct != null && (
          <div className="text-right">
            <p className="text-2xl font-bold text-white">{pct}%</p>
            <p className="text-xs text-slate-500">confidence</p>
          </div>
        )}
      </div>

      {/* Hash */}
      {result.sha256 && (
        <div className="flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2">
          <Hash size={14} className="text-slate-500 shrink-0" />
          <code className="text-xs text-slate-400 break-all">{result.sha256}</code>
        </div>
      )}

      {/* Intelligence layer pills */}
      {(ml || vt || otx) && (
        <div className="flex flex-wrap gap-2">
          {ml && (
            <div className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border ${
              ml.malicious
                ? "bg-red-900/30 border-red-700 text-red-300"
                : "bg-slate-800 border-slate-700 text-slate-400"
            }`}>
              <Brain size={11} />
              ML: {Math.round(ml.score * 100)}%
            </div>
          )}
          {vt && vt.found && (
            <a
              href={vt.vt_link}
              target="_blank"
              rel="noopener noreferrer"
              className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border transition-opacity hover:opacity-80 ${
                vt.malicious > 0
                  ? "bg-red-900/30 border-red-700 text-red-300"
                  : "bg-green-900/30 border-green-700 text-green-400"
              }`}
            >
              <Globe size={11} />
              VT: {vt.malicious}/{vt.total_engines}
              {vt.popular_threat_name ? ` · ${vt.popular_threat_name}` : ""}
            </a>
          )}
          {otx && otx.found && (
            <a
              href={otx.otx_link}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border bg-orange-900/30 border-orange-700 text-orange-300 transition-opacity hover:opacity-80"
            >
              <Globe size={11} />
              OTX: {otx.pulse_count} pulse{otx.pulse_count !== 1 ? "s" : ""}
              {otx.malware_families?.length ? ` · ${otx.malware_families[0]}` : ""}
            </a>
          )}
        </div>
      )}

      {/* Indicators */}
      {result.indicators.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Indicators ({result.indicators.length})
          </p>
          <ul className="space-y-1.5">
            {result.indicators.map((ind, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <AlertTriangle size={14} className="text-amber-500 mt-0.5 shrink-0" />
                {ind}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.indicators.length === 0 && result.status === "complete" && (
        <p className="flex items-center gap-2 text-sm text-green-400">
          <ShieldCheck size={16} /> No indicators of compromise detected
        </p>
      )}

      {result.error && (
        <p className="flex items-center gap-2 text-sm text-red-400">
          <ShieldAlert size={16} /> {result.error}
        </p>
      )}

      <p className="text-xs text-slate-600">Scan ID: {result.scan_id}</p>
    </div>
  );
}
