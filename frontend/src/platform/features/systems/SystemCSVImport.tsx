import { useCallback, useEffect, useRef, useState } from "react";
import Papa from "papaparse";

import { DataGrid, MonoBadge, SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  useImportCSV,
  type SystemMutationInput,
  type CSVImportResponse,
} from "./api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ParsedRow {
  rowIndex: number;
  name: string;
  host: string;
  port: number;
  username: string;
  distro: string;
  description: string;
  valid: boolean;
  reason: string | null;
}

interface SystemCSVImportProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REQUIRED_COLUMNS = [
  "name",
  "host",
  "username",
  "port",
  "distro",
] as const;
const PREVIEW_MAX_ROWS = 10;

// ---------------------------------------------------------------------------
// Inline mock styles
// ---------------------------------------------------------------------------

const HEADER_BUTTON: React.CSSProperties = {
  height: 26,
  padding: "0 11px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  borderRadius: 3,
  cursor: "pointer",
};

const ACCENT_BUTTON: React.CSSProperties = {
  ...HEADER_BUTTON,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 15%, transparent)",
  color: "var(--accent)",
};

const ERROR_BOX: React.CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "8px 12px",
  fontSize: 11,
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

const OK_BOX: React.CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-ok) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-ok) 10%, transparent)",
  color: "var(--status-ok)",
  padding: "8px 12px",
  fontSize: 11,
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeHeaders(headers: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const header of headers) {
    map[header.trim().toLowerCase()] = header;
  }
  return map;
}

function validateRow(
  rawRow: Record<string, string>,
  rowIndex: number,
): ParsedRow {
  const name = rawRow.name?.trim() ?? "";
  const host = rawRow.host?.trim() ?? "";
  const portRaw = rawRow.port?.trim() ?? "";
  const username = rawRow.username?.trim() || "root";
  const distro = rawRow.distro?.trim() || "unknown";
  const description = rawRow.description?.trim() ?? "";

  if (!name) {
    return {
      rowIndex,
      name,
      host,
      port: 0,
      username,
      distro,
      description,
      valid: false,
      reason: "name is required",
    };
  }
  if (!host) {
    return {
      rowIndex,
      name,
      host,
      port: 0,
      username,
      distro,
      description,
      valid: false,
      reason: "host is required",
    };
  }

  const portNum = parseInt(portRaw, 10);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return {
      rowIndex,
      name,
      host,
      port: portNum || 0,
      username,
      distro,
      description,
      valid: false,
      reason: `port must be 1-65535 (got ${portRaw || "empty"})`,
    };
  }

  return {
    rowIndex,
    name,
    host,
    port: portNum,
    username,
    distro,
    description,
    valid: true,
    reason: null,
  };
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * SystemCSVImport -- CSV import modal rebuilt to the mock language.
 *
 * A fixed-position backdrop + WindowPanel(title='import systems from csv')
 * replaces the shadcn Dialog. The upload zone is a mock-styled dashed border
 * region; the preview table is a DataGrid; every parse/validate/mutation
 * behavior (papaparse, RFC 4180, required-column check, injection-safe
 * rendering) is preserved verbatim (D-07, D-08).
 */
export function SystemCSVImport({ open, onOpenChange }: SystemCSVImportProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [missingColumns, setMissingColumns] = useState<string[]>([]);
  const [parsedRows, setParsedRows] = useState<ParsedRow[]>([]);
  const [importResult, setImportResult] = useState<CSVImportResponse | null>(
    null,
  );
  const importCSV = useImportCSV();

  const validRows = parsedRows.filter((r) => r.valid);
  const hasPreview = parsedRows.length > 0;

  const resetState = useCallback(() => {
    setFileName(null);
    setMissingColumns([]);
    setParsedRows([]);
    setImportResult(null);
  }, []);

  const parseFile = useCallback(
    (file: File) => {
      resetState();
      setFileName(file.name);

      const reader = new FileReader();
      reader.onload = (event) => {
        const csvText = event.target?.result as string;

        const result = Papa.parse<Record<string, string>>(csvText, {
          header: true,
          skipEmptyLines: true,
        });

        const headers = result.meta.fields ?? [];
        const normalizedMap = normalizeHeaders(headers);

        const missing = REQUIRED_COLUMNS.filter(
          (col) => !(col in normalizedMap),
        );
        if (missing.length > 0) {
          setMissingColumns(missing);
          setParsedRows([]);
          return;
        }

        const normalizedData = result.data.map((row) => {
          const normalized: Record<string, string> = {};
          for (const [lowerKey, originalKey] of Object.entries(normalizedMap)) {
            normalized[lowerKey] = row[originalKey] ?? "";
          }
          return normalized;
        });

        const rows = normalizedData
          .slice(0, PREVIEW_MAX_ROWS)
          .map((row, idx) => validateRow(row, idx));
        setParsedRows(rows);
        setMissingColumns([]);
      };
      reader.readAsText(file);
    },
    [resetState],
  );

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) parseFile(file);
      e.target.value = "";
    },
    [parseFile],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) parseFile(file);
    },
    [parseFile],
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => setIsDragOver(false), []);

  const handleImport = useCallback(() => {
    if (validRows.length === 0) return;

    const systems: SystemMutationInput[] = validRows.map((r) => ({
      name: r.name,
      host: r.host,
      port: r.port,
      username: r.username,
      distro: r.distro,
      description: r.description,
    }));

    importCSV.mutate(
      { systems },
      {
        onSuccess: (data) => {
          setImportResult(data);
          if (data.errors.length === 0) {
            setTimeout(() => {
              onOpenChange(false);
              resetState();
            }, 1500);
          }
        },
      },
    );
  }, [validRows, importCSV, onOpenChange, resetState]);

  const handleOpenChange = useCallback(
    (nextOpen: boolean) => {
      if (!nextOpen) {
        resetState();
        importCSV.reset();
      }
      onOpenChange(nextOpen);
    },
    [importCSV, onOpenChange, resetState],
  );

  // Esc to close (parity with the previous Dialog behavior)
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleOpenChange(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, handleOpenChange]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Import systems from CSV"
      className="fixed inset-0 flex items-center justify-center"
      style={{
        zIndex: 60,
        background:
          "color-mix(in srgb, var(--surface-page) 78%, transparent)",
        backdropFilter: "blur(2px)",
        padding: 20,
      }}
      onClick={() => handleOpenChange(false)}
    >
      <div
        className="flex flex-col"
        style={{
          width: "min(720px, 96vw)",
          maxHeight: "90vh",
          overflowY: "auto",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <WindowPanel title="import systems from csv" tone="accent">
          <div className="flex flex-col" style={{ gap: 12 }}>
            <SectionHeader
              icon={"\u25b3"}
              title="csv import"
              size={16}
              actions={
                <button
                  type="button"
                  aria-label="Close"
                  onClick={() => handleOpenChange(false)}
                  style={{
                    ...HEADER_BUTTON,
                    width: 26,
                    padding: 0,
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  {"\u00d7"}
                </button>
              }
            />

            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              upload a csv with columns: name, host, port, username, distro
              (optional: description). required column headers are
              case-insensitive.
            </p>

            {/* File drop zone */}
            <div
              role="button"
              tabIndex={0}
              className="flex flex-col items-center justify-center font-mono"
              style={{
                gap: 10,
                padding: "24px 20px",
                borderRadius: 4,
                border: `2px dashed ${isDragOver ? "var(--accent)" : "var(--border)"}`,
                background: isDragOver
                  ? "color-mix(in srgb, var(--accent) 8%, transparent)"
                  : "var(--surface-sunk)",
                cursor: "pointer",
                transition: "background 100ms, border-color 100ms",
              }}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => fileInputRef.current?.click()}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  fileInputRef.current?.click();
                }
              }}
            >
              <div
                aria-hidden="true"
                style={{
                  fontSize: 22,
                  color: isDragOver
                    ? "var(--accent)"
                    : "var(--text-muted)",
                }}
              >
                {"\u2191"}
              </div>
              <div style={{ textAlign: "center" }}>
                <div
                  style={{
                    fontSize: 12,
                    color: "var(--text-primary)",
                    letterSpacing: "0.04em",
                  }}
                >
                  drop a csv file or click to browse
                </div>
                {fileName && (
                  <div
                    style={{
                      marginTop: 4,
                      fontSize: 10.5,
                      color: "var(--accent)",
                    }}
                  >
                    {fileName}
                  </div>
                )}
              </div>
              <input
                aria-label="Choose CSV file"
                ref={fileInputRef}
                type="file"
                accept=".csv"
                className="sr-only"
                onChange={handleFileChange}
              />
            </div>

            {missingColumns.length > 0 && (
              <div style={ERROR_BOX}>
                Missing required columns: {missingColumns.join(", ")}
              </div>
            )}

            {hasPreview && (
              <div className="flex flex-col" style={{ gap: 6 }}>
                <div
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.14em",
                    color: "var(--text-faint)",
                  }}
                >
                  PREVIEW (FIRST {PREVIEW_MAX_ROWS} ROWS) --{" "}
                  <span style={{ color: "var(--status-ok)" }}>
                    {validRows.length} VALID
                  </span>
                  {", "}
                  <span
                    style={{
                      color:
                        parsedRows.length - validRows.length > 0
                          ? "var(--status-warn)"
                          : "var(--text-faint)",
                    }}
                  >
                    {parsedRows.length - validRows.length} INVALID
                  </span>
                </div>
                <DataGrid<ParsedRow>
                  columns={[
                    { label: "#", width: "40px" },
                    { label: "name", width: "minmax(100px, 1fr)" },
                    { label: "host", width: "minmax(120px, 1.2fr)" },
                    { label: "port", width: "60px", align: "right" },
                    { label: "user", width: "100px" },
                    { label: "distro", width: "100px" },
                    { label: "status", width: "minmax(140px, 1.4fr)" },
                  ]}
                  rows={parsedRows}
                  getKey={(r) => r.rowIndex}
                  renderCells={(row) => [
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-faint)", fontSize: 11 }}
                    >
                      {row.rowIndex + 1}
                    </span>,
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-primary)", fontSize: 11 }}
                    >
                      {row.name || "--"}
                    </span>,
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-muted)", fontSize: 11 }}
                    >
                      {row.host || "--"}
                    </span>,
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-primary)", fontSize: 11 }}
                    >
                      {row.port || "--"}
                    </span>,
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-primary)", fontSize: 11 }}
                    >
                      {row.username}
                    </span>,
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-primary)", fontSize: 11 }}
                    >
                      {row.distro}
                    </span>,
                    row.valid ? (
                      <MonoBadge tone="ok">VALID</MonoBadge>
                    ) : (
                      <MonoBadge tone="critical" title={row.reason ?? undefined}>
                        {row.reason ?? "invalid"}
                      </MonoBadge>
                    ),
                  ]}
                />
              </div>
            )}

            {importResult && (
              <div className="flex flex-col" style={{ gap: 6 }}>
                {importResult.created.length > 0 && (
                  <div style={OK_BOX}>
                    {importResult.created.length} system
                    {importResult.created.length === 1 ? "" : "s"} imported
                    successfully.
                  </div>
                )}
                {importResult.errors.length > 0 && (
                  <div style={ERROR_BOX}>
                    <div style={{ fontWeight: 600, marginBottom: 6 }}>
                      Import errors ({importResult.errors.length}):
                    </div>
                    <ul
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 3,
                        listStyle: "none",
                        margin: 0,
                        padding: 0,
                      }}
                    >
                      {importResult.errors.map((err) => (
                        <li key={`${err.row_index}-${err.name}`}>
                          Row {err.row_index + 1} ({err.name || "unnamed"}):{" "}
                          {err.reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {importCSV.isError && !importResult && (
              <div style={ERROR_BOX}>
                Import failed: {(importCSV.error as Error).message}
              </div>
            )}

            {/* Footer actions */}
            <div
              className="flex items-center justify-end"
              style={{
                gap: 8,
                paddingTop: 10,
                borderTop: "1px solid var(--border-faint)",
              }}
            >
              <button
                type="button"
                style={HEADER_BUTTON}
                onClick={() => handleOpenChange(false)}
              >
                cancel
              </button>
              <button
                type="button"
                disabled={validRows.length === 0 || importCSV.isPending}
                onClick={handleImport}
                style={{
                  ...ACCENT_BUTTON,
                  opacity:
                    validRows.length === 0 || importCSV.isPending ? 0.5 : 1,
                  cursor:
                    validRows.length === 0 || importCSV.isPending
                      ? "not-allowed"
                      : "pointer",
                }}
              >
                {importCSV.isPending
                  ? "importing…"
                  : `import ${validRows.length} valid row${validRows.length === 1 ? "" : "s"}`}
              </button>
            </div>
          </div>
        </WindowPanel>
      </div>
    </div>
  );
}
