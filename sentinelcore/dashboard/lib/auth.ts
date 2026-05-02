const TOKEN_KEY    = "sc_token";
const EMAIL_KEY    = "sc_email";
const APIKEY_KEY   = "sc_apikey";
const TIER_KEY     = "sc_tier";
const TRIAL_KEY    = "sc_trial_ends";
const VERIFIED_KEY = "sc_verified";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredEmail(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(EMAIL_KEY);
}

export function getApiKey(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(APIKEY_KEY);
}

export function getStoredTier(): string {
  if (typeof window === "undefined") return "free";
  return localStorage.getItem(TIER_KEY) ?? "free";
}

export function getTrialEndsAt(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TRIAL_KEY);
}

export function isTrialActive(): boolean {
  const t = getTrialEndsAt();
  if (!t) return false;
  return new Date(t) > new Date();
}

export function trialDaysLeft(): number | null {
  const t = getTrialEndsAt();
  if (!t) return null;
  const diff = new Date(t).getTime() - Date.now();
  if (diff <= 0) return null;
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

export function isVerified(): boolean {
  if (typeof window === "undefined") return false;
  return localStorage.getItem(VERIFIED_KEY) === "true";
}

export function storeSession(
  token: string,
  email: string,
  apiKey: string,
  tier = "free",
  trialEndsAt: string | null = null,
  verified = false,
) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(EMAIL_KEY, email);
  localStorage.setItem(APIKEY_KEY, apiKey);
  localStorage.setItem(TIER_KEY, tier);
  localStorage.setItem(VERIFIED_KEY, String(verified));
  if (trialEndsAt) localStorage.setItem(TRIAL_KEY, trialEndsAt);
  else localStorage.removeItem(TRIAL_KEY);
}

export function clearSession() {
  [TOKEN_KEY, EMAIL_KEY, APIKEY_KEY, TIER_KEY, TRIAL_KEY, VERIFIED_KEY].forEach((k) =>
    localStorage.removeItem(k),
  );
}

export function authHeaders(): Record<string, string> {
  const token = getToken();
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

const API_BASE = "/api/v1";

export interface AuthResponse {
  access_token: string;
  token_type: string;
  api_key: string;
  tier: string;
  trial_ends_at?: string | null;
  is_verified?: boolean;
}

export async function apiRegister(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `Registration failed (${res.status})`);
  }
  return res.json();
}

export async function apiLogin(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `Login failed (${res.status})`);
  }
  return res.json();
}
