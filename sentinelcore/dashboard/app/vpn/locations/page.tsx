"use client";
import { Globe, Zap, CheckCircle, Lock, AlertCircle } from "lucide-react";
import { getStoredTier, getToken } from "@/lib/auth";
import { useEffect, useState } from "react";

interface Location {
  id: string;
  city: string;
  country: string;
  flag: string;
  region: string;
  latency: string;
  tier: "free" | "pro";
  status: "online" | "coming_soon";
}

const LOCATIONS: Location[] = [
  { id: "us-east",    city: "New York",       country: "United States", flag: "🇺🇸", region: "Americas",      latency: "~12ms",  tier: "free", status: "online"      },
  { id: "us-west",    city: "San Francisco",  country: "United States", flag: "🇺🇸", region: "Americas",      latency: "~28ms",  tier: "pro",  status: "coming_soon" },
  { id: "eu-west",    city: "Amsterdam",      country: "Netherlands",   flag: "🇳🇱", region: "Europe",        latency: "~35ms",  tier: "pro",  status: "coming_soon" },
  { id: "eu-central", city: "Frankfurt",      country: "Germany",       flag: "🇩🇪", region: "Europe",        latency: "~40ms",  tier: "pro",  status: "coming_soon" },
  { id: "ap-south",   city: "Singapore",      country: "Singapore",     flag: "🇸🇬", region: "Asia Pacific",  latency: "~110ms", tier: "pro",  status: "coming_soon" },
  { id: "ap-east",    city: "Tokyo",          country: "Japan",         flag: "🇯🇵", region: "Asia Pacific",  latency: "~130ms", tier: "pro",  status: "coming_soon" },
  { id: "sa-east",    city: "São Paulo",      country: "Brazil",        flag: "🇧🇷", region: "South America", latency: "~75ms",  tier: "pro",  status: "coming_soon" },
  { id: "au-east",    city: "Sydney",         country: "Australia",     flag: "🇦🇺", region: "Oceania",       latency: "~160ms", tier: "pro",  status: "coming_soon" },
];

const REGIONS = ["All", "Americas", "Europe", "Asia Pacific", "South America", "Oceania"];

export default function VpnLocationsPage() {
  const [tier, setTier] = useState("free");
  const [filter, setFilter] = useState("All");

  useEffect(() => { setTier(getStoredTier()); }, []);

  const visible = filter === "All" ? LOCATIONS : LOCATIONS.filter((l) => l.region === filter);
  const onlineCount = LOCATIONS.filter((l) => l.status === "online").length;

  return (
    <div className="mx-auto max-w-4xl px-6 py-10 space-y-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe size={22} className="text-indigo-400" /> Server Locations
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            {onlineCount} location{onlineCount !== 1 ? "s" : ""} online · More regions coming soon.
          </p>
        </div>
        <a
          href="/vpn/keys"
          className="shrink-0 rounded-lg bg-indigo-600 hover:bg-indigo-500 transition-colors px-4 py-2 text-sm font-semibold text-white"
        >
          My devices →
        </a>
      </div>

      {tier === "free" && (
        <div className="rounded-xl border border-indigo-700/40 bg-indigo-900/15 px-5 py-4 flex items-center gap-3">
          <Zap size={17} className="text-indigo-400 shrink-0" />
          <p className="text-sm text-indigo-300">
            Free plan includes US East only. Upgrade to Pro to connect from any location.{" "}
            <a href="/billing" className="underline">Upgrade →</a>
          </p>
        </div>
      )}

      {/* Region filter */}
      <div className="flex flex-wrap gap-2">
        {REGIONS.map((r) => (
          <button
            key={r}
            onClick={() => setFilter(r)}
            className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
              filter === r
                ? "bg-indigo-600 text-white"
                : "border border-slate-700 text-slate-400 hover:border-slate-500 hover:text-white"
            }`}
          >
            {r}
          </button>
        ))}
      </div>

      {/* Location grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {visible.map((loc) => {
          const locked = loc.tier === "pro" && tier === "free";
          const coming = loc.status === "coming_soon";

          return (
            <div
              key={loc.id}
              className={`rounded-xl border p-5 transition-colors ${
                coming
                  ? "border-slate-800 bg-[#0d0d14] opacity-60"
                  : locked
                  ? "border-slate-800 bg-[#0d0d14] opacity-75"
                  : "border-slate-700 bg-[#0d0d14] hover:border-slate-600"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className="text-2xl leading-none">{loc.flag}</span>
                  <div>
                    <p className="text-sm font-semibold text-white">{loc.city}</p>
                    <p className="text-xs text-slate-500">{loc.country}</p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  {coming ? (
                    <span className="text-xs text-slate-500 border border-slate-700 rounded px-2 py-0.5">
                      Coming soon
                    </span>
                  ) : locked ? (
                    <span className="flex items-center gap-1 text-xs text-indigo-400 border border-indigo-800/60 rounded px-2 py-0.5">
                      <Lock size={10} /> Pro
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-xs text-green-400">
                      <CheckCircle size={11} /> Online
                    </span>
                  )}
                  {!coming && (
                    <span className="flex items-center gap-1 text-xs text-slate-500">
                      <Zap size={10} /> {loc.latency}
                    </span>
                  )}
                </div>
              </div>

              {!coming && !locked && (
                <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between">
                  <span className="text-xs text-slate-500">{loc.region}</span>
                  <a
                    href="/vpn/keys"
                    className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors"
                  >
                    Connect →
                  </a>
                </div>
              )}

              {locked && !coming && (
                <div className="mt-3 pt-3 border-t border-slate-800">
                  <a href="/billing" className="text-xs text-indigo-400 hover:text-indigo-300 underline transition-colors">
                    Upgrade to Pro to use this location
                  </a>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="rounded-xl border border-slate-800 bg-[#0d0d14] p-5 flex items-start gap-3">
        <AlertCircle size={16} className="text-slate-500 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-500 space-y-1">
          <p>Latency estimates are from US East Coast. Your actual latency will vary by location.</p>
          <p>All servers run WireGuard on port 51820/UDP with ChaCha20-Poly1305 encryption.</p>
          <p>Zero-log policy: we never store connection timestamps, IP addresses, or DNS queries.</p>
        </div>
      </div>
    </div>
  );
}
