/**
 * ErrorEnvelope -- standardised non-2xx error shape emitted by every AILA API
 * endpoint (Phase 176a-01). Consumed by apiErrorHandler (Phase 176a-02).
 */
export type ErrorEnvelope = {
  code: string;
  message: string;
  hint: string | null;
  trace_id: string | null;
};

/**
 * Runtime type guard for ErrorEnvelope. A value is considered a valid envelope
 * when it has all four canonical fields with the right types. Extra fields
 * are tolerated (forward-compat), missing or wrong-typed fields reject.
 */
export function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (!value || typeof value !== "object") return false;
  const o = value as Record<string, unknown>;
  return (
    typeof o.code === "string" &&
    typeof o.message === "string" &&
    (o.hint === null || typeof o.hint === "string") &&
    (o.trace_id === null || typeof o.trace_id === "string")
  );
}

/**
 * Best-effort parse of a fetch Response body into an ErrorEnvelope. Falls back
 * to a synthesised envelope if the body is missing / non-JSON / not-envelope
 * shaped so downstream code always has a well-formed object to toast.
 */
export async function parseErrorEnvelope(response: Response): Promise<ErrorEnvelope> {
  try {
    const body = await response.clone().json();
    if (isErrorEnvelope(body)) return body;
  } catch {
    // Non-JSON body -- fall through.
  }
  return {
    code: "UNKNOWN",
    message: response.statusText || "Request failed",
    hint: null,
    trace_id: null,
  };
}
