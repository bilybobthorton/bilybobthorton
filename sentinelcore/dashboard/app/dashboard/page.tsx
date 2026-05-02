"use client";
import { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, AlertTriangle, Activity, BarChart2 } from "lucide-react";
import { getToken, getStoredTier } from "@/lib/auth";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

interface DailyCount { date: string; count: number }
interface Stats {
  scans_today: number;
  scans_this_week: number;
  scans_this_month: number;
  quota_today: number;
  quota_limit: number;
  threat_breakdown: { malicious: number; suspicious: number; clean: number };
  daily_counts: DailyCount[];
}

function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="h-1.5 w-full rounded-full bg-slate-800">
      <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function SparkBar({ counts }: { counts: DailyCount[] }) {
  const max = Math.max(...counts.map((c) => c.count), 1);
  return (
    <div className="flex items-end gap-1 h-16">
      {counts.map((c) => {
        const h = max > 0 ? Math.max(4, Math.round((c.count / max) * 64)) : 4;
        return (
          <div key={c.date} className="flex-1 flex flex-col items-center gap-1 group relative">
            <div
              className="w-full rounded-sm bg-red-600/70 hover:bg-red-500 transition-colors cursor-default"
              style={{ height: `${h}px` }}
            />
            <span className="absolute -top-6 left-1/2 -translate-x-1/2 bg-slate-800 text-slate-300 text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
              {c.date.slice(5)}: {c.count}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [tier, setTier] = useState("free");

  useEffect(() => {
    setTier(getStoredTier());
    if (!getToken()) { setLoading(false); return; }
    fetch(`${API}/api/v1/stats/me`, { headers: authHeaders() })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (d) setStats(d); })
      .finally(() => setLoading(false));
  }, []);

  if (!getToken()) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center">
        <ShieldAlert className="mx-auto mb-4 h-10 w-10 text-slate-600" />
        <p className="text-slate-400 mb-4">Sign in to view your dashboard.</p>
        <a href="/login" className="inline-block rounded-lg bg-red-600 px-5 py-2 text-sm font-semibold text-white">Sign in</a>
      </div>
    );
  }

  const quotaPct = stats ? Math.min(100, Math.round((stats.quota_today / Math.max(stats.quota_limit, 1)) * 100)) : 0;
  const totalThreats = stats ? stats.threat_breakdown.malicious + stats.threat_breakdown.suspicious : 0;
  const totalScans = stats ? totalThreats + stats.threat_breakdown.clean : 0;

  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-slate-400 mt-0.5 capitalize">{tier} plan</p>
        </div>
        <a href="/scan" className="rounded-lg bg-red-600 hover:bg-red-500 transition-colors px-4 py-2 text-sm font-semibold text-white">
          + New scan
        </a>
      </div>

      {loading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5 animate-pulse h-24" />
          ))}
        </div>
      ) : stats ? (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Scans today" value={stats.scans_today} icon={<Activity size={16} />} />
            <StatCard label="This week" value={stats.scans_this_week} icon={<BarChart2 size={16} />} />
            <StatCard label="This month" value={stats.scans_this_month} icon={<BarChart2 size={16} />} />
            <StatCard
              label="Threats found"
              value={totalThreats}
              icon={<ShieldAlert size={16} />}
              accent={totalThreats > 0 ? "text-red-400" : "text-green-400"}
            />
          </div>

          {/* Quota + threat breakdown */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Daily Quota</h2>
              <div className="flex items-end justify-between">
                <span className="text-3xl font-bold text-white">{stats.quota_today}</span>
                <span className="text-sm text-slate-500">/ {stats.quota_limit === 999999 ? "∞" : stats.quota_limit} scans</span>
              </div>
              <MiniBar value={stats.quota_today} max={stats.quota_limit} color="bg-red-600" />
              <p className="text-xs text-slate-500">{quotaPct}% used today — resets at midnight UTC</p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Breakdown</h2>
              {totalScans === 0 ? (
                <p className="text-sm text-slate-500 pt-2">No scans yet.</p>
              ) : (
                <div className="space-y-3">
                  <ThreatRow label="Malicious" count={stats.threat_breakdown.malicious} total={totalScans} color="bg-red-600" textColor="text-red-400" />
                  <ThreatRow label="Suspicious" count={stats.threat_breakdown.suspicious} total={totalScans} color="bg-orange-500" textColor="text-orange-400" />
                  <ThreatRow label="Clean" count={stats.threat_breakdown.clean} total={totalScans} color="bg-green-600" textColor="text-green-400" />
                </div>
              )}
            </div>
          </div>

          {/* 14-day chart */}
          <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-6 space-y-4">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Scans — last 14 days</h2>
            <SparkBar counts={stats.daily_counts} />
            <div className="flex justify-between text-[10px] text-slate-600">
              <span>{stats.daily_counts[0]?.date.slice(5)}</span>
              <span>{stats.daily_counts[13]?.date.slice(5)}</span>
            </div>
          </div>
        </>
      ) : (
        <div className="rounded-xl border border-slate-800 p-8 text-center">
          <p className="text-slate-500">No data yet — run your first scan to see stats.</p>
          <a href="/scan" className="mt-4 inline-block text-sm text-red-400 hover:text-red-300">Go to scanner →</a>
        </div>
      )}

      {/* Quick links */}
      <div className="grid sm:grid-cols-3 gap-4">
        {[
          { href: "/history",  label: "Scan history",    desc: "View all past scans" },
          { href: "/alerts",   label: "Agent alerts",    desc: "Endpoint security events" },
          { href: "/webhooks", label: "Webhooks",        desc: "Real-time notifications" },
        ].map((l) => (
          <a
            key={l.href}
            href={l.href}
            className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5 hover:border-slate-600 transition-colors"
          >
            <p className="text-sm font-semibold text-white">{l.label}</p>
            <p className="text-xs text-slate-500 mt-1">{l.desc}</p>
          </a>
        ))}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  accent = "text-white",
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5">
      <div className="flex items-center gap-2 text-slate-500 mb-2">
        {icon}
        <span className="text-xs uppercase tracking-wider">{label}</span>
      </div>
      <p className={`text-3xl font-bold ${accent}`}>{value.toLocaleString()}</p>
    </div>
  );
}

function ThreatRow({
  label,
  count,
  total,
  color,
  textColor,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
  textColor: string;
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className={textColor}>{label}</span>
        <span className="text-slate-400">{count} ({pct}%)</span>
      </div>
      <MiniBar value={count} max={total} color={color} />
    </div>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="h-1.5 w-full rounded-full bg-slate-800">
      <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}
