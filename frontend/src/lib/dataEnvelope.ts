/**
 * Shared DataEnvelope type + unwrap helper for new code (Phase 176a-02, FE-D).
 *
 * The backend wraps every successful 2xx response in this envelope. Existing
 * call sites declared DataEnvelope inline in multiple files -- this module
 * provides the single canonical shape for NEW code. Pre-existing inline
 * duplicates are intentionally left alone; a future cleanup phase can migrate
 * them without widening this plan's blast radius.
 */
export interface DataEnvelope<T> {
  data: T;
  meta?: {
    limit?: number;
    offset?: number;
    total?: number;
    [key: string]: unknown;
  };
}

/**
 * Pull the `data` field off a DataEnvelope with a strict runtime guard.
 *
 * Throws when the envelope is missing or malformed -- downstream toast UI
 * (apiErrorHandler) then surfaces a useful error instead of the UI silently
 * rendering `undefined`.
 */
export function unwrap<T>(envelope: DataEnvelope<T> | null | undefined): T {
  if (!envelope || typeof envelope !== "object" || !("data" in envelope)) {
    throw new Error("Missing data field in DataEnvelope response");
  }
  return envelope.data;
}
