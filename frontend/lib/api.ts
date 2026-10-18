const CODE_KEY = "recon_access_code";

export function getCode(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(CODE_KEY) || "";
}

export function setCode(v: string) {
  localStorage.setItem(CODE_KEY, v);
}

export function clearCode() {
  if (typeof window === "undefined") return;
  localStorage.removeItem(CODE_KEY);
}

// Verify an access code against the server without saving it.
export async function verifyCode(code: string): Promise<boolean> {
  try {
    const r = await fetch("/api/plugins", { headers: { "X-Access-Code": code } });
    return r.ok;
  } catch {
    return false;
  }
}

export function headers(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const c = getCode();
  if (c) h["X-Access-Code"] = c;
  return h;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, { ...init, headers: { ...headers(), ...(init?.headers || {}) } });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`HTTP ${r.status}: ${t.slice(0, 200)}`);
  }
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("application/json")) return r.json();
  return (await r.text()) as unknown as T;
}

export interface PluginInfo {
  id: string; label: string; accepts: string[]; requires_keys: string[];
  passive: boolean; cost: string; group: string; description: string;
  key_status: Record<string, { configured: boolean }>;
}

export interface ClassifyResult { type: string; normalized: string; confidence: number; }
