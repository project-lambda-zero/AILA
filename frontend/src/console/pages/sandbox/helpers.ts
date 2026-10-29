/** Shared helpers for the sandbox page. */

/** Best-effort error message: unwraps FastAPI-style `{"detail": ...}` JSON
 * error bodies before falling back to the raw message. */
export function apiErrMessage(err: unknown): string {
  if (err instanceof Error) {
    try {
      const parsed = JSON.parse(err.message);
      if (parsed && typeof parsed === "object" && parsed.detail) {
        return String(parsed.detail);
      }
    } catch {
      // not JSON, use message directly
    }
    return err.message;
  }
  return String(err);
}

export function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "\u2014";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  return `${seconds.toFixed(2)}s`;
}
