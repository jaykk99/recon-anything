import { NextResponse } from "next/server";

// Frontend-native health check.
//
// Render's health check hits /api/health on this frontend (port 10000),
// which used to proxy to the Python backend. When the backend was busy
// (plugin imports, sync DB calls on the event loop), the proxy timed out,
// Render marked the instance failed and restarted it — an endless flap
// loop that made the whole app look down. This route answers instantly
// from the frontend process so a busy backend no longer kills the service.
// Backend health is still visible in-app via the status pill, which calls
// the real API endpoints.

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ ok: true, service: "recon-anything" });
}
