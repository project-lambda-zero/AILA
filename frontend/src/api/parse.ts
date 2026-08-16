/**
 * Boundary-parser toolkit for opaque JSON responses.
 *
 * The console pages consume backend rows that TypeScript sees as
 * `Record<string, unknown>` (the DataPage row-callback signature) or
 * `unknown` (payload dicts inside malware/vr messages). Instead of
 * re-deriving each field with an inline `typeof` check + `as` cast at
 * every render site (the pattern flagged by anti-slop -- see #229),
 * every page parses the row ONCE at the boundary using the narrowers
 * below.
 *
 * Two layers:
 *
 * 1. Primitive narrowers (`asRecord`, `readStr`, `readNum`, `readBool`,
 *    `readArray`). Return `null` when the field is missing or the wrong
 *    shape; callers apply their own default with `?? "\u2014"` / `?? 0`
 *    / `?? []`, keeping intent explicit. These replace the ~180 inline
 *    `typeof v === "string" ? v : null` sites.
 *
 * 2. `parseRow<S>(raw, shape)` -- a shape-driven bulk narrower for the
 *    common case where a whole row is parsed into a typed record. Each
 *    shape entry is a `Reader<T>` (a `(v: unknown) => T` function); the
 *    return type is inferred from the shape so callers get a typed
 *    result without hand-writing an interface + N field reads.
 *
 * Deliberately dependency-free -- the shell adds no runtime deps lightly,
 * the row shapes are few and stable, and hand-rolled narrowers keep
 * the boundary explicit. If per-field validation messages become a
 * product requirement, swap this for zod's `object({...}).safeParse()`
 * without touching call sites (they consume the parsed value only).
 *
 * This is the shell's single canonical type-guard module; call sites
 * import `asRecord`/`isRecord` from here rather than re-defining them.
 */

/** Type guard: `v` is a plain object (not array, not null).
 * Canonical shell-wide guard -- do not re-define at call sites. */
export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Narrow `v` to a plain object or `null`. */
export function asRecord(v: unknown): Record<string, unknown> | null {
  return isRecord(v) ? v : null;
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

/** Read `o[k]` when it's a boolean; `null` otherwise. */
export function readBool(o: Record<string, unknown>, k: string): boolean | null {
  const v = o[k];
  return typeof v === "boolean" ? v : null;
}

/** Read `o[k]` when it's an array; `null` otherwise. */
export function readArray(o: Record<string, unknown>, k: string): unknown[] | null {
  const v = o[k];
  return Array.isArray(v) ? v : null;
}

/* --- parseRow: shape-driven bulk narrower --------------------------- */

/** A field reader takes an unknown value and returns the narrowed shape. */
export type Reader<T> = (v: unknown) => T;

/** The record type inferred from a shape spec. */
export type ShapeOf<S extends Record<string, Reader<unknown>>> = {
  [K in keyof S]: S[K] extends Reader<infer T> ? T : never;
};

/**
 * Parse a raw JSON row against a shape spec. Missing fields feed
 * `undefined` into the reader (readers return their sentinel -- usually
 * `null` -- for missing/wrong types). If `raw` is not a plain object,
 * every reader is invoked with `undefined` so the result carries the
 * shape's defaults throughout.
 *
 * ```ts
 * const row = parseRow(raw, { name: rStr, count: rNumOr(0) });
 * // row: { name: string | null; count: number }
 * ```
 */
export function parseRow<S extends Record<string, Reader<unknown>>>(
  raw: unknown,
  shape: S,
): ShapeOf<S> {
  const src = asRecord(raw);
  const out: Record<string, unknown> = {};
  for (const k in shape) {
    out[k] = shape[k](src ? src[k] : undefined);
  }
  return out as ShapeOf<S>;
}

/* --- Reader factories (shape-spec callbacks; identity matters) ------ */

/** Reader that returns the value if it's a string, else `null`. */
export const rStr: Reader<string | null> = (v) => (typeof v === "string" ? v : null);

/** Reader that returns the value if it's a finite number, else `null`. */
export const rNum: Reader<number | null> = (v) =>
  typeof v === "number" && Number.isFinite(v) ? v : null;

/** Reader that returns the value if it's a boolean, else `null`. */
export const rBool: Reader<boolean | null> = (v) => (typeof v === "boolean" ? v : null);

/** Reader that returns the value if it's a plain object, else `null`. */
export const rRec: Reader<Record<string, unknown> | null> = asRecord;

/** Reader for an array of `inner`-typed elements; missing/wrong -> `[]`. */
export const rArray = <T>(inner: Reader<T>): Reader<T[]> => (v) =>
  Array.isArray(v) ? v.map(inner) : [];

/** Reader that returns a string or a fallback (never `null`). */
export const rStrOr = (fallback: string): Reader<string> => (v) =>
  typeof v === "string" ? v : fallback;

/** Reader that returns a finite number or a fallback (never `null`). */
export const rNumOr = (fallback: number): Reader<number> => (v) =>
  typeof v === "number" && Number.isFinite(v) ? v : fallback;

/** Reader that returns a boolean or a fallback (never `null`). */
export const rBoolOr = (fallback: boolean): Reader<boolean> => (v) =>
  typeof v === "boolean" ? v : fallback;
