const API_BASE = "/api/v1";

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
  const res = await fetch(`${API_BASE}/scan/file`, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
  return res.json();
}

export async function pollScan(scanId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`);
  if (!res.ok) throw new Error(`Fetch failed: ${res.statusText}`);
  return res.json();
}

export async function lookupHash(hash: string) {
  const res = await fetch(`${API_BASE}/scan/hash`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash }),
  });
  if (!res.ok) throw new Error(`Hash lookup failed: ${res.statusText}`);
  return res.json();
}
