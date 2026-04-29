import clsx from "clsx";

const CONFIG = {
  clean:      { label: "Clean",      classes: "bg-green-900/40 text-green-400 border-green-800" },
  suspicious: { label: "Suspicious", classes: "bg-amber-900/40 text-amber-400 border-amber-800" },
  malicious:  { label: "Malicious",  classes: "bg-red-900/40 text-red-400 border-red-800" },
  unknown:    { label: "Unknown",    classes: "bg-slate-800 text-slate-400 border-slate-700" },
};

export function ThreatBadge({ level }: { level: string | null }) {
  const cfg = CONFIG[(level as keyof typeof CONFIG) ?? "unknown"] ?? CONFIG.unknown;
  return (
    <span className={clsx("inline-flex items-center rounded border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider", cfg.classes)}>
      {cfg.label}
    </span>
  );
}
