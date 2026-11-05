// Live-connection policy for the run page (connection-lost loop fix,
// 2026-10-27). Pure functions, no React, so the math is testable
// without a browser.
//
// The old page did two things that made a dead connection look like a
// loop: EventSource auto-retried forever on every error (and the
// browser never tells JS the HTTP status), and the 4s poll kept firing
// forever on every failure, even a terminal 401. The new page owns
// reconnects itself: it closes the stream on error, backs off
// exponentially, and stops entirely on a terminal auth error.

export const POLL_BASE_MS = 4000;
export const BACKOFF_CAP_MS = 30000;
export const MAX_CONSECUTIVE_FAILURES = 6;

export function isTerminalAuth(status: number): boolean {
  // 401 = signed out / session expired / retired code in sign-in mode.
  // Retrying this can never succeed; only a fresh sign-in can.
  // 403 is NOT terminal here: it can be a plan gate, not a lost
  // session, and the page already surfaces plan errors elsewhere.
  return status === 401;
}

/** Next delay after `failures` consecutive failures (1-based). */
export function nextBackoffMs(
  failures: number,
  baseMs: number = POLL_BASE_MS,
  capMs: number = BACKOFF_CAP_MS
): number {
  if (failures <= 0) return baseMs;
  const ms = baseMs * Math.pow(2, failures - 1);
  return Math.min(ms, capMs);
}

/** True once failures have hit the stop-and-wait-for-Retry threshold. */
export function shouldStopAfterFailures(
  failures: number,
  max: number = MAX_CONSECUTIVE_FAILURES
): boolean {
  return failures >= max;
}

/** Connection states the UI may show. "live" is reserved for a stream
 *  or poll that actually delivered data; a reconnecting page must
 *  never claim to be live. */
export type ConnState =
  | "connecting"
  | "live"
  | "reconnecting"
  | "stopped";

export function connLabel(state: ConnState): string {
  switch (state) {
    case "live":
      return "Live";
    case "connecting":
      return "Connecting to the live scan feed…";
    case "reconnecting":
      return "Connection lost, reconnecting…";
    case "stopped":
      return "Connection stopped";
  }
}
