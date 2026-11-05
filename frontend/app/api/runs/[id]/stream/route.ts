import { NextRequest } from "next/server";

// SSE proxy for the live scan feed.
//
// Why this exists: Next.js rewrites buffer server-sent events (the frontend
// never saw a single event even though the backend emits them fine), so the
// live feed always showed "stream down". This route fetches the backend
// stream and pipes it through chunk-by-chunk with no buffering.
//
// NOTE: an explicit route handler takes precedence over the /api/* rewrite
// in next.config.mjs for this exact path only; every other /api/* call
// still goes through the rewrite.

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const API_BASE = process.env.RECON_API_URL || "http://127.0.0.1:8000";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  // Same auth fix as the /live proxy: forward the session cookie first.
  // In GitHub sign-in mode the retired ?code= value is ignored by the
  // backend, so forwarding only the code made every signed-in stream
  // 401 while EventSource auto-retried forever.
  const code = req.nextUrl.searchParams.get("code") || "";
  const cookie = req.headers.get("cookie") || "";
  const upstream = `${API_BASE}/api/runs/${params.id}/stream`;

  let res: Response;
  try {
    res = await fetch(upstream, {
      headers: {
        ...(cookie ? { Cookie: cookie } : {}),
        ...(code ? { "X-Access-Code": code } : {}),
        Accept: "text/event-stream",
      },
      // The upstream stream stays open for the life of the scan; never cache.
      cache: "no-store",
      signal: req.signal,
    });
  } catch {
    return new Response("event: error\ndata: {\"message\":\"backend unreachable\"}\n\n", {
      status: 502,
      headers: { "Content-Type": "text/event-stream" },
    });
  }

  if (!res.ok || !res.body) {
    return new Response(
      `event: error\ndata: ${JSON.stringify({ message: `upstream ${res.status}` })}\n\n`,
      { status: res.status, headers: { "Content-Type": "text/event-stream" } }
    );
  }

  // Pipe the upstream body straight through, unbuffered.
  const stream = new ReadableStream({
    async start(controller) {
      const reader = res.body!.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) controller.enqueue(value);
        }
      } catch {
        // Client disconnected or upstream dropped; end quietly.
      } finally {
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      }
    },
    cancel() {
      // Client went away: stop reading the upstream stream.
      res.body?.cancel().catch(() => {});
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "X-SSE-Route": "nextjs-proxy-v1",
    },
  });
}
