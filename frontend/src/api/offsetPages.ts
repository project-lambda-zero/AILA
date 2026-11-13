/** Envelope-aware offset paging for list endpoints that answer
 * `{ data: T[], meta: { offset, limit, total } }`.
 *
 * `apiFetch` unwraps `.data` and drops `meta`, so a single-window read cannot
 * tell whether another page exists. These helpers read the full envelope,
 * follow `offset` until `meta.total` is reached, and say so explicitly when
 * the page bound stops the walk early. */
import { apiFetchEnvelope } from "./client";
import { asRecord, readNum } from "./parse";

/** Hard bound on pages fetched per call so a server that never reports a
 *  consistent total cannot loop the client forever. */
const MAX_OFFSET_PAGES = 50;

export type OffsetQuery = Readonly<Record<string, string | number | boolean>>;

export interface OffsetPages<T> {
  /** Rows in server order, de-duplicated by id (first appearance wins). */
  rows: T[];
  /** `meta.total` from the last page, or the loaded row count when absent. */
  total: number;
  /** True when the page bound stopped the walk while more rows remained. */
  truncated: boolean;
}

interface PageRows<T> {
  rows: T[];
  total: number | null;
}

function pagePath(path: string, params: OffsetQuery, offset: number, limit: number): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) query.set(key, String(value));
  query.set("limit", String(limit));
  query.set("offset", String(offset));
  return `${path}?${query.toString()}`;
}

async function fetchPage<T>(path: string, params: OffsetQuery, offset: number, limit: number): Promise<PageRows<T>> {
  const env = asRecord(await apiFetchEnvelope<unknown>(pagePath(path, params, offset, limit)));
  const data = env?.data;
  if (!Array.isArray(data)) throw new Error(`${path}: list response carried no data array`);
  const meta = asRecord(env?.meta);
  // SAFETY: the caller's T declares the row shape of this list endpoint; rows are untrusted JSON narrowed by consumers.
  return { rows: data as T[], total: meta ? readNum(meta, "total") : null };
}

/** Fetch consecutive pages starting at `startOffset` until `meta.total` rows
 *  are covered, a page comes back short, or {@link MAX_OFFSET_PAGES} pages
 *  were read. `rows` holds only what was fetched from `startOffset` onward;
 *  `total` is the server-wide total. */
export async function fetchOffsetPagesFrom<T extends { id: string }>(
  path: string,
  params: OffsetQuery,
  pageSize: number,
  startOffset: number,
): Promise<OffsetPages<T>> {
  const seen = new Set<string>();
  const rows: T[] = [];
  let offset = startOffset;
  let total: number | null = null;
  let more = true;
  let pages = 0;
  while (more && pages < MAX_OFFSET_PAGES) {
    const page = await fetchPage<T>(path, params, offset, pageSize);
    pages += 1;
    offset += page.rows.length;
    total = page.total;
    for (const row of page.rows) {
      if (seen.has(row.id)) continue;
      seen.add(row.id);
      rows.push(row);
    }
    more = page.rows.length >= pageSize && (total === null || offset < total);
  }
  return { rows, total: total ?? offset, truncated: more };
}

/** Fetch every row of a list endpoint from offset 0. */
export function fetchAllOffsetPages<T extends { id: string }>(
  path: string,
  params: OffsetQuery,
  pageSize: number,
): Promise<OffsetPages<T>> {
  return fetchOffsetPagesFrom<T>(path, params, pageSize, 0);
}

/** Surface a truncated walk instead of presenting a partial list as complete. */
export function warnIfTruncated(label: string, result: OffsetPages<unknown>): void {
  if (result.truncated) {
    console.warn(`${label}: loaded ${result.rows.length} of ${result.total} rows (page bound ${MAX_OFFSET_PAGES} reached)`);
  }
}
