/**
 * Boundary-parser toolkit for opaque JSON responses.
 *
 * The console pages consume backend rows that TypeScript sees as
 * `Record<string, unknown>` (the DataPage row-callback signature) or
 * `unknown` (payload dicts inside malware/vr messages). Every page parses
 * the row ONCE at the boundary with the narrowers below instead of
 * re-deriving each field with an inline `typeof` check and an `as` cast at
 * every render site (the pattern flagged by anti-slop -- see #229).
 *
 * The narrowers return `null` when a field is missing or has the wrong
 * shape; callers apply their own default (`?? "\u2014"`, `?? 0`, `?? []`),
 * keeping intent explicit at the call site.
 *
 * Deliberately dependency-free: the row shapes are few and stable, and
 * hand-rolled narrowers keep the boundary explicit.
 */

import { ApiError } from "./client";

/** Surface a backend rejection as clean text. FastAPI's HTTPException body is
 * `{"detail": "..."}` which `apiFetch` throws verbatim as the ApiError message;
 * parse it out so the operator sees the sentence, not the JSON wrapper. Falls
 * back to the raw message / status for non-JSON bodies and non-ApiError values. */
export function apiErrDetail(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const parsed: unknown = JSON.parse(err.message);
      const obj = asRecord(parsed);
      const detail = obj ? obj.detail : null;
      if (typeof detail === "string" && detail.trim() !== "") return detail;
    } catch {
      // Body was not JSON -- fall through to the raw message.
    }
    return err.message || `HTTP ${err.status}`;
  }
  return err instanceof Error ? err.message : String(err);
}

/** Narrow `v` to a plain object or `null`. */
export function asRecord(v: unknown): Record<string, unknown> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  // SAFETY: a non-null, non-array object is a JSON object; its member values stay `unknown`
  // and every reader in this module narrows them before use.
  return v as Record<string, unknown>;
}

/** Read `o[k]` when it's a string; `null` otherwise. */
export function readStr(o: Record<string, unknown>, k: string): string | null {
  const v = o[k];
  return typeof v === "string" ? v : null;
}

/** Read `o[k]` when it's a finite number; `null` otherwise. */
export function readNum(o: Record<string, unknown>, k: string): number | null {
  const v = o[k];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Read `o[k]` when it's an array; `null` otherwise. */
export function readArray(o: Record<string, unknown>, k: string): unknown[] | null {
  const v = o[k];
  return Array.isArray(v) ? v : null;
}

/** Read `o[k]` when it's a boolean; `null` otherwise. */
export function readBool(o: Record<string, unknown>, k: string): boolean | null {
  const v = o[k];
  return typeof v === "boolean" ? v : null;
}

/** Read `o[k]` as an array keeping only its plain-object elements; `[]` when
 * the field is missing or not an array. */
export function readRecordArray(o: Record<string, unknown>, k: string): Record<string, unknown>[] {
  const v = o[k];
  if (!Array.isArray(v)) return [];
  const out: Record<string, unknown>[] = [];
  for (const el of v) {
    const r = asRecord(el);
    if (r) out.push(r);
  }
  return out;
}

/** Read `o[k]` as an array keeping only its string elements; `[]` when the
 * field is missing or not an array. */
export function readStrArray(o: Record<string, unknown>, k: string): string[] {
  const v = o[k];
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const el of v) {
    if (typeof el === "string") out.push(el);
  }
  return out;
}
