/**
 * tableExport -- pure serialization + client-side download for tabular data.
 *
 * Shared by AilaTable's toolbar Export control, but callable directly by any
 * screen that already owns a row set. Zero dependencies on React or the table
 * runtime -- these are just functions.
 *
 * CSV output follows RFC 4180:
 *   - fields containing CR, LF, comma, or double quote are wrapped in `"..."`
 *   - embedded double quotes are escaped by doubling ("")
 *   - records are separated by CRLF
 * A UTF-8 BOM is prepended to CSV blobs so Excel opens non-ASCII cells
 * correctly without re-detecting the encoding.
 */

// ─────────────────────────────────────────────────────────
// Column spec
// ─────────────────────────────────────────────────────────

/**
 * Serialization descriptor for one exported column. Independent of TanStack
 * ColumnDef so callers can massage headers / values (e.g. flatten a nested
 * object, join tag arrays into a semicolon-delimited string) without
 * touching the table's render definition.
 */
export interface TableExportColumn<TRow> {
  /** JSON property name AND fallback CSV header. */
  id: string
  /** CSV header cell. Defaults to `id`. */
  header?: string
  /** Scalar-or-serializable value extractor for a single row. */
  accessor: (row: TRow) => unknown
}

// ─────────────────────────────────────────────────────────
// Value + field encoding
// ─────────────────────────────────────────────────────────

/**
 * Coerce any accessor result to a CSV-safe string. `null`/`undefined` -> "".
 * Dates -> ISO 8601. Objects/arrays -> compact JSON. Primitives -> String().
 * The final CSV field is still escaped by `escapeCsvField`.
 */
export function stringifyExportValue(value: unknown): string {
  if (value === null || value === undefined) return ""
  if (value instanceof Date) return value.toISOString()
  const t = typeof value
  if (t === "string") return value as string
  if (t === "number" || t === "boolean" || t === "bigint") return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

/**
 * RFC 4180 field escape. Wraps in double quotes when the field contains any
 * of CR, LF, comma, or double quote; embedded quotes are doubled.
 */
export function escapeCsvField(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

// ─────────────────────────────────────────────────────────
// Row-set serializers
// ─────────────────────────────────────────────────────────

export function rowsToCsv<TRow>(
  rows: readonly TRow[],
  columns: readonly TableExportColumn<TRow>[],
): string {
  if (columns.length === 0) return ""
  const CRLF = "\r\n"
  const header = columns.map((c) => escapeCsvField(c.header ?? c.id)).join(",")
  const body = rows.map((row) =>
    columns
      .map((c) => escapeCsvField(stringifyExportValue(c.accessor(row))))
      .join(","),
  )
  return [header, ...body].join(CRLF)
}

export function rowsToJson<TRow>(
  rows: readonly TRow[],
  columns: readonly TableExportColumn<TRow>[],
): string {
  const objects = rows.map((row) => {
    const record: Record<string, unknown> = {}
    for (const c of columns) {
      record[c.id] = c.accessor(row)
    }
    return record
  })
  return JSON.stringify(objects, null, 2)
}

// ─────────────────────────────────────────────────────────
// Client-side download
// ─────────────────────────────────────────────────────────

/**
 * Sanitize a base filename to a safe stem (alphanumerics, dot, dash,
 * underscore). Empty result falls back to `"table"`.
 */
export function sanitizeExportFilename(name: string): string {
  const cleaned = name.replace(/[^\w.-]+/g, "-").replace(/^-+|-+$/g, "")
  return cleaned || "table"
}

/**
 * Blob + anchor download. No-op in non-browser environments (SSR / tests
 * without a DOM stub).
 */
export function downloadBlob(blob: Blob, filename: string): void {
  if (
    typeof document === "undefined" ||
    typeof URL === "undefined" ||
    typeof URL.createObjectURL !== "function"
  ) {
    return
  }
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = filename
    anchor.rel = "noopener"
    // Detached anchors don't dispatch a click in every browser; append,
    // click, then remove.
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
  } finally {
    URL.revokeObjectURL(url)
  }
}

export function exportRowsAsCsv<TRow>(
  rows: readonly TRow[],
  columns: readonly TableExportColumn<TRow>[],
  filename: string,
): void {
  const csv = rowsToCsv(rows, columns)
  const stem = sanitizeExportFilename(filename)
  // Prepend UTF-8 BOM so Excel opens non-ASCII correctly.
  const blob = new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8" })
  downloadBlob(blob, `${stem}.csv`)
}

export function exportRowsAsJson<TRow>(
  rows: readonly TRow[],
  columns: readonly TableExportColumn<TRow>[],
  filename: string,
): void {
  const json = rowsToJson(rows, columns)
  const stem = sanitizeExportFilename(filename)
  const blob = new Blob([json], { type: "application/json;charset=utf-8" })
  downloadBlob(blob, `${stem}.json`)
}
