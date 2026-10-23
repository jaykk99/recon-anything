import { NextRequest, NextResponse } from "next/server";

// Server-side sign-in gate (Jay's order, 2026-10-23: "hide those
// from before you sign in").
//
// The backend is the source of truth for auth state (/api/me):
// auth_mode "github" means GitHub OAuth is configured, the access
// code is retired, and a GitHub session is the only door. Until now
// that was enforced only in the API and by client-side swaps after
// first paint, so the served pages still carried the full app nav
// and page chrome (and on the home page the retired access-code
// field) for signed-out visitors.
//
// This middleware decides per request and stamps the decision on
// the request headers (x-recon-auth-mode / x-recon-signed-in) so
// the layout and the home page render the signed-out shell
// server-side: header shows only the brand + "Sign in with
// GitHub", and protected pages are rewritten to the gate before
// any app chrome is served. In fallback (access-code) mode - and
// whenever the backend cannot be reached to decide - requests pass
// through untouched, exactly as before; the client-side gates
// still apply then.

const API_BASE = process.env.RECON_API_URL || "http://127.0.0.1:8000";
// billing.SESSION_COOKIE in the backend; the cookie is same-origin
// (set through this app's /api proxy), so middleware can see it.
const SESSION_COOKIE = "recon_session";
// Pages that exist only for signed-in users. "/" renders its own
// server-side gate card; "/pricing" is public by design.
const PROTECTED = [
  /^\/keys($|\/)/, /^\/settings($|\/)/, /^\/runs($|\/)/, /^\/run\//,
  /^\/hunters($|\/)/, /^\/checkout($|\/)/, /^\/admin\//,
];

// The auth mode only changes when the server env changes (a
// redeploy), so it is cached briefly; signed-in state is never
// cached - it is verified against /api/me whenever a session
// cookie is present, and is simply false when there is none.
let modeCache: { mode: string; at: number } | null = null;
const MODE_TTL_MS = 60_000;

async function fetchMe(cookie: string | null): Promise<any | null> {
  try {
    const r = await fetch(`${API_BASE}/api/me`, {
      headers: cookie ? { Cookie: cookie } : {},
      cache: "no-store",
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

export async function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const hasSession = !!req.cookies.get(SESSION_COOKIE)?.value;

  let mode: string | null =
    modeCache && Date.now() - modeCache.at < MODE_TTL_MS
      ? modeCache.mode
      : null;
  let signedIn = false;
  // "decided" means the auth state below is authoritative. When it
  // is false (backend unreachable while a cookie exists) the
  // request passes through unstamped, as before this gate existed.
  let decided = false;

  if (hasSession) {
    const me = await fetchMe(req.headers.get("cookie"));
    if (me) {
      mode = me.auth_mode;
      signedIn = !!me.signed_in;
      decided = true;
      modeCache = { mode: me.auth_mode, at: Date.now() };
    }
  } else {
    if (!mode) {
      const me = await fetchMe(null);
      if (me) {
        mode = me.auth_mode;
        modeCache = { mode: me.auth_mode, at: Date.now() };
      }
    }
    // No session cookie: signed out, definitively, once the mode
    // is known.
    if (mode) decided = true;
  }

  const requestHeaders = new Headers(req.headers);
  if (decided && mode) {
    requestHeaders.set("x-recon-auth-mode", mode);
    requestHeaders.set("x-recon-signed-in", signedIn ? "1" : "0");
  }

  const ghAnon = decided && mode === "github" && !signedIn;
  if (ghAnon && PROTECTED.some((re) => re.test(path))) {
    const url = req.nextUrl.clone();
    url.pathname = "/";
    url.search = "";
    return NextResponse.rewrite(url, {
      request: { headers: requestHeaders },
    });
  }
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: [
    "/", "/pricing", "/keys", "/settings", "/runs", "/run/:path*",
    "/hunters", "/checkout", "/admin/:path*",
  ],
};
