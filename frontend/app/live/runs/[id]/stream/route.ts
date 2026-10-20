import { NextRequest } from "next/server";

// SSE proxy for the live scan feed, served at /live/runs/[id]/stream.
//
// This lives OUTSIDE /api on purpose: the next.config.mjs rewrite
// (/api/:path* -> backend) was swallowing the /api route handler for the
// stream and buffering server-sent events, so the UI's live feed never
// received a single event even though the backend emits them fine.
// This path never matches the rewrite, so this handler always serves it
// and pipes the backend stream through chunk-by-chunk, unbuffered.

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const API_BASE = process.env.RECON_API_URL || "http://127.0.0.1:8000";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const code = req.nextUrl.searchParams.get("code") || "";
  const upstream = `${API_BASE}/api/runs/${params.id}/stream`;

  let res: Response;
  try {
    res = await fetch(upstream, {
      headers: {
        "X-Access-Code": code,
        Accept: "text/event-stream",
      },
      cache: "no-store",
      signal: req.signal,
    });
  } catch {
    return new Response(
      'event: error\ndata: {"message":"backend unreachable"}\n\n',
      { status: 502, headers: { "Content-Type": "text/event-stream" } }
    );
  }

  if (!res.ok || !res.body) {
    return new Response(
      `event: error\ndata: ${JSON.stringify({ message: `upstream ${res.status}` })}\n\n`,
      { status: res.status, headers: { "Content-Type": "text/event-stream" } }
    );
  }

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
      "X-SSE-Route": "live-proxy-v2",
    },
  });
}
