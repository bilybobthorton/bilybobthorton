const API_BASE = "/api/v1";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("sc_token");
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

export interface ScanSubmitted {
  scan_id: string;
  filename: string;
  status: string;
}

export interface ScanResult {
  scan_id: string;
  filename: string;
  sha256: string | null;
  status: string;
  threat_level: "clean" | "suspicious" | "malicious" | "unknown" | null;
  confidence: number | null;
  indicators: string[];
  error: string | null;
}

export async function submitScan(file: File): Promise<ScanSubmitted> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/scan/file`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: form,
  });
  if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
  return res.json();
}

export async function pollScan(scanId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error(`Fetch failed: ${res.statusText}`);
  return res.json();
}

export async function lookupHash(hash: string) {
  const res = await fetch(`${API_BASE}/scan/hash`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAuthHeaders() },
    body: JSON.stringify({ hash }),
  });
  if (!res.ok) throw new Error(`Hash lookup failed: ${res.statusText}`);
  return res.json();
}

export interface AgentAlert {
  id: string;
  remote_id: string;
  agent_id: string;
  hostname: string;
  kind: string;
  severity: string;
  title: string;
  description: string;
  path: string | null;
  mitre_technique: string | null;
  process: Record<string, unknown> | null;
  hashes: { md5: string; sha256: string } | null;
  received_at: string;
  agent_timestamp: string;
}

export async function fetchAlerts(params?: {
  severity?: string;
  kind?: string;
  hostname?: string;
  limit?: number;
}): Promise<AgentAlert[]> {
  const query = new URLSearchParams();
  if (params?.severity) query.set("severity", params.severity);
  if (params?.kind) query.set("kind", params.kind);
  if (params?.hostname) query.set("hostname", params.hostname);
  if (params?.limit) query.set("limit", String(params.limit));

  const res = await fetch(`${API_BASE}/agent/alerts?${query}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error(`Alerts fetch failed: ${res.statusText}`);
  return res.json();
}

export async function fetchAgentStats() {
  const res = await fetch(`${API_BASE}/agent/stats`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error(`Stats fetch failed: ${res.statusText}`);
  return res.json();
}
