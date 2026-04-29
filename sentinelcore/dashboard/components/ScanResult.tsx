"use client";
import { ScanResult as ScanResultType } from "@/lib/api";
import { ThreatBadge } from "./ThreatBadge";
import { ShieldCheck, ShieldAlert, AlertTriangle, Hash, FileText } from "lucide-react";

export function ScanResult({ result }: { result: ScanResultType }) {
  const pct = result.confidence != null ? Math.round(result.confidence * 100) : null;

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
