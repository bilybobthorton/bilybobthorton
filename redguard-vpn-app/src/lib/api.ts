import * as SecureStore from 'expo-secure-store';

export const API_URL = 'https://app.redgaurd.com/api/v1';

export async function getToken(): Promise<string | null> {
  return SecureStore.getItemAsync('rg_token');
}

export async function setToken(token: string): Promise<void> {
  await SecureStore.setItemAsync('rg_token', token);
}

export async function clearToken(): Promise<void> {
  await SecureStore.deleteItemAsync('rg_token');
  await SecureStore.deleteItemAsync('rg_tier');
}

export async function getTier(): Promise<string> {
  return (await SecureStore.getItemAsync('rg_tier')) ?? 'free';
}

async function authHeaders(): Promise<Record<string, string>> {
  const token = await getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(email: string, password: string) {
  const res = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error((await res.json()).detail ?? 'Login failed');
  const data = await res.json();
  await setToken(data.access_token);
  await SecureStore.setItemAsync('rg_tier', data.tier ?? 'free');
  return data;
}

export async function fetchVpnKeys() {
  const res = await fetch(`${API_URL}/vpn/keys`, {
    headers: await authHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch VPN keys');
  return res.json();
}

export async function createVpnKey(name: string) {
  const res = await fetch(`${API_URL}/vpn/keys`, {
    method: 'POST',
    headers: { ...(await authHeaders()), 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  if (!res.ok) throw new Error((await res.json()).detail ?? 'Failed to create key');
  return res.json();
}

export async function deleteVpnKey(id: string) {
  const res = await fetch(`${API_URL}/vpn/keys/${id}`, {
    method: 'DELETE',
    headers: await authHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete key');
}

export async function downloadVpnConfig(id: string): Promise<string> {
  const res = await fetch(`${API_URL}/vpn/keys/${id}/config`, {
    headers: await authHeaders(),
  });
  if (!res.ok) throw new Error('Failed to download config');
  return res.text();
}
