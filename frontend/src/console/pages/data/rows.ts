/** Row extraction, cell text, and client-side filter matching for DataPage. */

import type { FieldOption } from "../../../api/mutations";
import { asRecord, readArray, readNum } from "../../../api/parse";
import type { DataRow, FilterValue, ActionField, PageAction, PageFilter, RangeVal } from "./types";

/** Narrow a cell to a printable JSON scalar. */
export function isScalar(v: unknown): v is string | number | boolean {
  const t = typeof v;
  return t === "string" || t === "number" || t === "boolean";
}

function isRange(v: FilterValue | undefined): v is RangeVal {
  return v != null && !Array.isArray(v) && typeof v === "object";
}

export const asScalar = (v: FilterValue | undefined): string => (isScalar(v) ? v : "");
export const asList = (v: FilterValue | undefined): string[] => (Array.isArray(v) ? v : []);
export const asRange = (v: FilterValue | undefined): RangeVal => (isRange(v) ? v : { lo: "", hi: "" });

const ROW_KEYS = ["items", "results", "rows", "entries", "records", "data", "findings", "investigations", "targets", "workspaces"];

const wrap = (arr: unknown[]): DataRow[] => arr.map((x) => asRecord(x) ?? { value: x });

function rowsFrom(obj: DataRow, itemsKey: string | undefined): DataRow[] | null {
  const preferred = itemsKey ? readArray(obj, itemsKey) : null;
  if (preferred) return wrap(preferred);
  for (const k of ROW_KEYS) {
    const arr = readArray(obj, k);
    if (arr) return wrap(arr);
  }
  return null;
}

/** Locate the row array in a list response: a bare array, an `itemsKey`
 * array, a well-known collection key, or the same under a nested `data`
 * envelope. A lone object renders as a single row. */
export function toRows(data: unknown, itemsKey?: string): DataRow[] {
  if (Array.isArray(data)) return wrap(data);
  const obj = asRecord(data);
  if (!obj) return [];
  const nested = Array.isArray(obj.data) ? null : asRecord(obj.data);
  return (nested ? rowsFrom(nested, itemsKey) : null) ?? rowsFrom(obj, itemsKey) ?? [obj];
}

/** Total row count reported by a paginated envelope: `total`, `pages` x page
 * size, or (offset/limit endpoints) `meta.total`. */
export function envelopeTotal(data: unknown, pageSize: number, offsetParams: boolean): number | null {
  const obj = asRecord(data);
  if (!obj) return null;
  const total = readNum(obj, "total");
  if (total !== null) return total;
  const pages = readNum(obj, "pages");
  if (pages !== null) return pages * pageSize;
  const meta = offsetParams ? asRecord(obj["meta"]) : null;
  return meta ? readNum(meta, "total") : null;
}

/** Table-cell text: scalars verbatim, arrays and objects as a short count. */
export function cellText(v: unknown): string {
  if (v === null || v === undefined) return "\u2014";
  if (isScalar(v)) return String(v);
  if (Array.isArray(v)) return v.length ? `[${v.length}]` : "\u2014";
  const obj = asRecord(v);
  if (obj) {
    // Inline object summary for TABLE cells: never a raw JSON blob.
    // Detail panels use <StructuredValue> to render the actual shape.
    const n = Object.keys(obj).length;
    return n === 0 ? "\u2014" : `{${n} field${n === 1 ? "" : "s"}}`;
  }
  return String(v);
}

/** Turn a reveal action's response payload into ordered [label, value] pairs
 * for the one-shot reveal modal. Named `reveal.fields` win; otherwise every
 * top-level key of the payload object is shown. */
export function revealEntries(action: PageAction, payload: unknown): [string, string][] {
  const obj = asRecord(payload);
  if (!obj) return [["result", isScalar(payload) ? String(payload) : JSON.stringify(payload, null, 2)]];
  const want = action.reveal?.fields;
  const keys = want && want.length > 0 ? want : Object.keys(obj);
  return keys.map((k): [string, string] => {
    const v = obj[k];
    return [k, v == null ? "\u2014" : isScalar(v) ? String(v) : JSON.stringify(v)];
  });
}

/** True when the filter currently holds a narrowing value. */
export function filterHasValue(f: PageFilter, v: FilterValue | undefined): boolean {
  if (f.type === "multi-select") return asList(v).length > 0;
  if (f.type === "date-range" || f.type === "numeric-range") {
    const r = asRange(v);
    return r.lo.trim() !== "" || r.hi.trim() !== "";
  }
  return asScalar(v).trim() !== "";
}

/** Distinct non-empty row values for a field, as {value,label} options. */
export function deriveOptions(rows: DataRow[], field: string): FieldOption[] {
  const seen = new Set<string>();
  for (const row of rows) {
    const raw = row[field];
    if (!isScalar(raw)) continue;
    const s = String(raw);
    if (s !== "") seen.add(s);
  }
  return [...seen].sort().map((v) => ({ value: v, label: v }));
}

function inDateRange(r: RangeVal, cell: unknown): boolean {
  const t = Date.parse(String(cell ?? ""));
  if (Number.isNaN(t)) return false;
  if (r.lo.trim() !== "") {
    const loT = Date.parse(r.lo);
    if (!Number.isNaN(loT) && t < loT) return false;
  }
  if (r.hi.trim() !== "") {
    const hiT = Date.parse(r.hi);
    // Date inputs yield a bare day at UTC midnight; include the whole hi day.
    if (!Number.isNaN(hiT) && t > hiT + 86_399_999) return false;
  }
  return true;
}

/** Whether a single row passes one client-side filter. */
export function matchFilter(f: PageFilter, v: FilterValue | undefined, row: DataRow): boolean {
  const cell = f.deriveValue ? f.deriveValue(row) : row[f.name];
  if (f.type === "multi-select") {
    const sel = asList(v);
    return sel.length === 0 || sel.includes(String(cell ?? ""));
  }
  if (f.type === "numeric-range") {
    const r = asRange(v);
    const n = Number(cell);
    if (!Number.isFinite(n)) return false;
    if (r.lo.trim() !== "" && n < Number(r.lo)) return false;
    if (r.hi.trim() !== "" && n > Number(r.hi)) return false;
    return true;
  }
  if (f.type === "date-range") return inDateRange(asRange(v), cell);
  const needle = asScalar(v).trim();
  if (f.type === "select" || f.type === "segmented") return String(cell ?? "") === needle;
  return String(cell ?? "").toLowerCase().includes(needle.toLowerCase());
}

/** Query string for the filters the backend applies (`server: true`). */
export function serverFilterQuery(filters: PageFilter[], vals: Record<string, FilterValue>): string {
  const parts: string[] = [];
  const enc = encodeURIComponent;
  for (const f of filters) {
    if (!f.server) continue;
    const v = vals[f.name];
    if (f.type === "multi-select") {
      for (const item of asList(v)) {
        const s = item.trim();
        if (s) parts.push(`${enc(f.name)}=${enc(s)}`);
      }
    } else if (f.type === "date-range" || f.type === "numeric-range") {
      const r = asRange(v);
      const lo = r.lo.trim();
      const hi = r.hi.trim();
      const loSuf = f.type === "date-range" ? "since" : "min";
      const hiSuf = f.type === "date-range" ? "until" : "max";
      if (lo) parts.push(`${enc(f.name)}_${loSuf}=${enc(lo)}`);
      if (hi) parts.push(`${enc(f.name)}_${hiSuf}=${enc(hi)}`);
    } else {
      const s = asScalar(v).trim();
      if (s) parts.push(`${enc(f.name)}=${enc(s)}`);
    }
  }
  return parts.join("&");
}

/** Fields collected by an action's pre-flight modal. `godTierOnly` fields
 * are hidden (and never submitted) for team-scoped callers. */
export function visibleFields(a: PageAction, isGodTier: boolean): ActionField[] {
  return (a.fields ?? []).filter((f) => !f.godTierOnly || isGodTier);
}

/** Row actions whose `whenStatus` gate matches the row's gate field
 * (`whenField`, else `status`/`is_active`). Empty gate means always. */
export function visibleRowActions(actions: PageAction[] | undefined, row: DataRow): PageAction[] {
  return (actions ?? []).filter((a) => {
    if (!a.whenStatus || a.whenStatus.length === 0) return true;
    const gate = a.whenField ? row[a.whenField] : (row["status"] ?? row["is_active"]);
    return a.whenStatus.includes(String(gate ?? "").toLowerCase());
  });
}

/** Substitute `{scope}` and `{id}` in an endpoint or body template. */
export function fillTemplate(template: string, scope: string, id: string): string {
  return template.replace("{scope}", encodeURIComponent(scope)).replace("{id}", encodeURIComponent(id));
}

function isActiveRow(r: DataRow): boolean {
  return String(r["status"] ?? r["is_active"] ?? "").toLowerCase() === "active";
}

function createdAt(r: DataRow): number {
  const t = Date.parse(String(r["created_at"] ?? ""));
  return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
}

/** Partition rows by `row[field]`: keys sorted by localeCompare; within each
 * group, active rows first, then created_at ascending (oldest first). */
export function groupRows(rows: DataRow[], field: string): [string, DataRow[]][] {
  const groups = new Map<string, DataRow[]>();
  for (const row of rows) {
    const gk = String(row[field] ?? "");
    const bucket = groups.get(gk);
    if (bucket) bucket.push(row);
    else groups.set(gk, [row]);
  }
  return [...groups.keys()]
    .sort((a, b) => a.localeCompare(b))
    .map((gk): [string, DataRow[]] => [
      gk,
      [...(groups.get(gk) ?? [])].sort((a, b) => {
        const ax = isActiveRow(a);
        const bx = isActiveRow(b);
        if (ax !== bx) return ax ? -1 : 1;
        return createdAt(a) - createdAt(b);
      }),
    ]);
}
