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

// ------------------------------------------------------------ identity
// /api/me reports which door the app is behind: auth_mode "github"
// (sign-in mode - the access code is retired and no code field is
// shown anywhere) or "access_code" (the fallback gate). It answers for
// anonymous visitors too, so one cached fetch drives every page.
export interface MeInfo {
  auth_mode: "github" | "access_code";
  github_enabled: boolean;
  signed_in: boolean;
  is_owner: boolean;
  show_payment_ui: boolean;
  user: { login: string } | null;
  plan: { id: string; name: string } & Record<string, unknown>;
}

let _mePromise: Promise<MeInfo | null> | null = null;

export function fetchMe(): Promise<MeInfo | null> {
  if (!_mePromise) {
    _mePromise = fetch("/api/me")
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null);
  }
  return _mePromise;
}

export async function signOut(): Promise<void> {
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } catch {
    // The cookie may already be gone; signing out stays a no-op then.
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
