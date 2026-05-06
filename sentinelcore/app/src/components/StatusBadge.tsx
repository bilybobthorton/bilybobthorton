interface StatusBadgeProps {
  label: string;
  /** Optional explicit color override (CSS color string). */
  color?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
  clean: "#22c55e",
  suspicious: "#eab308",
  malicious: "#ef4444",
  unknown: "#64748b",
};

const TIER_COLORS: Record<string, string> = {
  free: "#64748b",
  pro: "#3b82f6",
  enterprise: "#8b5cf6",
  bundle: "#8b5cf6",
};

function resolveColor(label: string, override?: string): string {
  if (override) return override;
  const key = label.toLowerCase();
  return SEVERITY_COLORS[key] ?? TIER_COLORS[key] ?? "#64748b";
}

export default function StatusBadge({ label, color }: StatusBadgeProps) {
  const bg = resolveColor(label, color);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 10px",
        borderRadius: "9999px",
        fontSize: "11px",
        fontWeight: 600,
        letterSpacing: "0.04em",
        textTransform: "uppercase",
        background: `${bg}22`,
        color: bg,
        border: `1px solid ${bg}44`,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}
