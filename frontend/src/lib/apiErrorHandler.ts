import { toast } from "@/components/ui/sonner";

import { isErrorEnvelope, type ErrorEnvelope } from "./errorEnvelope";

/**
 * Shared react-query error handler (D-10c, D-24).
 *
 * Wired into QueryClient via QueryCache/MutationCache constructor onError
 * (TanStack Query v5 — preflight FE-A) at the providers.tsx call site.
 * The handler is defensive:
 *   - parses ErrorEnvelope shapes (direct or nested under `.response.data`)
 *   - treats network-layer TypeError as an offline-style toast
 *   - never rethrows; any internal failure is swallowed with console.error
 *   - never surfaces the literal "Internal Server Error" (D-10c)
 */

function renderEnvelope(envelope: ErrorEnvelope): void {
  const description = envelope.hint ?? undefined;
  const tail = envelope.trace_id
    ? `trace_id: ${envelope.trace_id}`
    : `Contact support with the timestamp below: ${new Date().toISOString()}`;
  const body = description ? `${description}\n${tail}` : tail;
  toast.error(envelope.message, { description: body });
}

/**
 * Attempt to lift a candidate envelope off a well-known location on an error.
 * Supports direct envelopes, envelopes thrown by fetch wrappers that attach
 * `.envelope` on the error, and Axios-style `error.response.data`.
 */
function pickEnvelope(err: unknown): ErrorEnvelope | null {
  if (isErrorEnvelope(err)) return err;
  if (!err || typeof err !== "object") return null;

  const direct = (err as { envelope?: unknown }).envelope;
  if (isErrorEnvelope(direct)) return direct;

  const response = (err as { response?: { data?: unknown } }).response;
  if (response && isErrorEnvelope(response.data)) {
    return response.data;
  }

  return null;
}

function handleAuthFailure(err: unknown): boolean {
  // A bubbled-up 401 means our in-flight refresh-once retry in
  // authorizedRequestJson already failed (refresh token also dead). The
  // only safe thing is to clear the session and punt the user back to
  // /login instead of flashing an "Invalid token" toast on a page they
  // no longer have access to.
  if (!err || typeof err !== "object") return false;
  const status = (err as { status?: number }).status;
  const msg = (err as { message?: string }).message ?? "";
  const looksLikeAuthError =
    status === 401 ||
    status === 403 ||
    /invalid token|token.*expired|unauthorized/i.test(msg);
  if (!looksLikeAuthError) return false;

  void (async () => {
    try {
      const { useAuthStore } = await import("@platform/auth/useAuthStore");
      useAuthStore.getState().logout();
    } catch {
      /* swallow — fall through to hard redirect below */
    }
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      const next = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.assign(`/login?next=${next}`);
    }
  })();
  return true;
}

export function apiErrorHandler(err: unknown): void {
  try {
    if (handleAuthFailure(err)) {
      return;
    }

    const envelope = pickEnvelope(err);
    if (envelope) {
      renderEnvelope(envelope);
      return;
    }

    // Network-layer failures (fetch offline, CORS) surface as TypeError.
    if (err instanceof TypeError && /fetch|network/i.test(err.message)) {
      toast.error("Network request failed — check your connection.");
      return;
    }

    // Generic fallback. Explicitly scrub the literal "Internal Server Error"
    // that some legacy backends emit so operators always see an intelligible
    // message (D-10c).
    if (err instanceof Error) {
      const raw = err.message || err.name || "An error occurred.";
      const cleaned = raw.replace(/Internal Server Error/gi, "Server error").trim();
      toast.error(cleaned.length > 0 ? cleaned : "An error occurred.");
      return;
    }

    toast.error("An error occurred.");
  } catch (inner) {
    // Never rethrow from the handler — it runs in framework critical paths.
    console.error("apiErrorHandler failed", inner);
  }
}
