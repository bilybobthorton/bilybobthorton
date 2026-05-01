"use client";
import { useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth";
import { ThreatBadge } from "@/components/ThreatBadge";
import { ShieldAlert, Clock, FileText, RefreshCw } from "lucide-react";

interface HistoryItem {
  scan_id: string;
  filename: string;
  sha256: string | null;
  status: string;
  threat_level: string | null;
  confidence: number | null;
  created_at: string;
  completed_at: string | null;
}

function formatDate(iso: string) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    complete: "bg-green-900/30 border-green-700 text-green-400",
    running:  "bg-blue-900/30 border-blue-700 text-blue-400",
    queued:   "bg-slate-800 border-slate-700 text-slate-400",
    failed:   "bg-red-900/30 border-red-700 text-red-400",
  };
  return (
    <span className={`text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full border ${styles[status] ?? styles.queued}`}>
      {status}
    </span>
  );
}

export default function HistoryPage() {
  const [items, setItems]     = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/scan/history?limit=100", {
        headers: authHeaders(),
      });
      if (res.status === 401) {
        setError("Sign in to view your scan history.");
        return;
      }
      if (!res.ok) throw new Error(`Error ${res.status}`);
      setItems(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load history");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan History</h1>
          <p className="text-sm text-slate-400 mt-1">All files you&apos;ve submitted for analysis</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 rounded-lg px-3 py-1.5 transition-colors"
        >
          <RefreshCw size={12} />
          Refresh
        </button>
      </div>

      {loading && (
        <div className="text-center py-20 text-slate-500 text-sm">Loading…</div>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded-xl border border-red-800 bg-red-900/20 px-4 py-3 text-sm text-red-300">
          <ShieldAlert size={15} className="shrink-0" />
          {error}
          {error.includes("Sign in") && (
            <a href="/login" className="ml-auto underline hover:text-red-200">Sign in →</a>
          )}
        </div>
      )}

      {!loading && !error && items.length === 0 && (
        <div className="text-center py-20 space-y-3">
          <FileText className="mx-auto h-10 w-10 text-slate-700" />
          <p className="text-slate-400">No scans yet.</p>
          <a href="/scan" className="inline-block text-sm text-red-400 hover:text-red-300 underline">
            Scan your first file →
          </a>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-[#0d0d14] overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 px-4 py-2.5 border-b border-slate-800 text-xs font-semibold text-slate-500 uppercase tracking-wider">
            <span>File</span>
            <span className="hidden sm:block">SHA256</span>
            <span>Threat</span>
            <span>Status</span>
            <span className="hidden md:block">Date</span>
          </div>

          {/* Rows */}
          <div className="divide-y divide-slate-800/60">
            {items.map((item) => (
              <a
                key={item.scan_id}
                href={item.status === "complete" ? `/api/v1/report/${item.scan_id}` : "#"}
                target={item.status === "complete" ? "_blank" : undefined}
                rel="noopener noreferrer"
                className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 px-4 py-3 items-center hover:bg-slate-800/30 transition-colors group"
              >
                <div className="min-w-0">
                  <p className="text-sm text-white truncate group-hover:text-slate-100">
                    {item.filename}
                  </p>
                  {item.confidence != null && (
                    <p className="text-xs text-slate-500 mt-0.5">
                      {Math.round(item.confidence * 100)}% confidence
                    </p>
                  )}
                </div>

                <span className="hidden sm:block text-[10px] font-mono text-slate-600 truncate max-w-[120px]">
                  {item.sha256 ? item.sha256.slice(0, 12) + "…" : "—"}
                </span>

                <span>
                  {item.threat_level ? (
                    <ThreatBadge level={item.threat_level as "clean" | "suspicious" | "malicious" | "unknown"} />
                  ) : (
                    <span className="text-xs text-slate-600">—</span>
                  )}
                </span>

                <StatusPill status={item.status} />

                <span className="hidden md:flex items-center gap-1 text-xs text-slate-500 whitespace-nowrap">
                  <Clock size={11} />
                  {formatDate(item.created_at)}
                </span>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
