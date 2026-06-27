import { useCallback, useRef, useState } from "react";
import Papa from "papaparse";
import { Upload } from "lucide-react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
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

const REQUIRED_COLUMNS = ["name", "host", "username", "port", "distro"] as const;
const PREVIEW_MAX_ROWS = 10;

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

function validateRow(rawRow: Record<string, string>, rowIndex: number): ParsedRow {
  const name = rawRow.name?.trim() ?? "";
  const host = rawRow.host?.trim() ?? "";
  const portRaw = rawRow.port?.trim() ?? "";
  const username = rawRow.username?.trim() || "root";
  const distro = rawRow.distro?.trim() || "unknown";
  const description = rawRow.description?.trim() ?? "";

  if (!name) {
    return { rowIndex, name, host, port: 0, username, distro, description, valid: false, reason: "name is required" };
  }
  if (!host) {
    return { rowIndex, name, host, port: 0, username, distro, description, valid: false, reason: "host is required" };
  }

  const portNum = parseInt(portRaw, 10);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return { rowIndex, name, host, port: portNum || 0, username, distro, description, valid: false, reason: `port must be 1-65535 (got ${portRaw || "empty"})` };
  }

  return { rowIndex, name, host, port: portNum, username, distro, description, valid: true, reason: null };
}

// ---------------------------------------------------------------------------
// Sub-component: PreviewTable
// ---------------------------------------------------------------------------

function PreviewTable({ rows }: { rows: ParsedRow[] }) {
  return (
    <div className="overflow-x-auto rounded-[2px] border border-border">
      <table className="w-full min-w-[600px] font-mono text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface">
            {["#", "Name", "Host", "Port", "Username", "Distro", "Status"].map((col) => (
              <th key={col} className="px-2 py-1.5 text-left text-text-muted font-medium">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.rowIndex}
              className={row.valid ? "" : "bg-destructive/10"}
            >
              <td className="px-2 py-1.5 text-text-muted">{row.rowIndex + 1}</td>
              <td className="px-2 py-1.5 text-text">{row.name || "--"}</td>
              <td className="px-2 py-1.5 text-text">{row.host || "--"}</td>
              <td className="px-2 py-1.5 text-text">{row.port || "--"}</td>
              <td className="px-2 py-1.5 text-text">{row.username}</td>
              <td className="px-2 py-1.5 text-text">{row.distro}</td>
              <td className="px-2 py-1.5">
                {row.valid ? (
                  <AilaBadge severity="info" size="sm">Valid</AilaBadge>
                ) : (
                  <AilaBadge severity="critical" size="sm">
                    Invalid: {row.reason}
                  </AilaBadge>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * SystemCSVImport -- CSV import dialog with papaparse parsing, preview, and import action.
 *
 * Implements D-07 (CSV UX flow) and D-08 (column spec, injection prevention).
 * Security: all cell values rendered as React text nodes (no dangerouslySetInnerHTML).
 * papaparse parses RFC 4180 CSV to structured JS objects submitted as JSON.
 */
export function SystemCSVImport({ open, onOpenChange }: SystemCSVImportProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [missingColumns, setMissingColumns] = useState<string[]>([]);
  const [parsedRows, setParsedRows] = useState<ParsedRow[]>([]);
  const [importResult, setImportResult] = useState<CSVImportResponse | null>(null);
  const importCSV = useImportCSV();

  const validRows = parsedRows.filter((r) => r.valid);
  const hasPreview = parsedRows.length > 0;

  const resetState = useCallback(() => {
    setFileName(null);
    setMissingColumns([]);
    setParsedRows([]);
    setImportResult(null);
  }, []);

  const parseFile = useCallback((file: File) => {
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

      // Check required columns
      const missing = REQUIRED_COLUMNS.filter((col) => !(col in normalizedMap));
      if (missing.length > 0) {
        setMissingColumns(missing);
        setParsedRows([]);
        return;
      }

      // Remap headers to lowercase for consistent access
      const normalizedData = result.data.map((row) => {
        const normalized: Record<string, string> = {};
        for (const [lowerKey, originalKey] of Object.entries(normalizedMap)) {
          normalized[lowerKey] = row[originalKey] ?? "";
        }
        return normalized;
      });

      const rows = normalizedData.slice(0, PREVIEW_MAX_ROWS).map((row, idx) =>
        validateRow(row, idx),
      );
      setParsedRows(rows);
      setMissingColumns([]);
    };
    reader.readAsText(file);
  }, [resetState]);

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) parseFile(file);
      // Reset value so the same file can be re-selected
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
            // All imported successfully -- close after short delay
            setTimeout(() => {
              onOpenChange(false);
              resetState();
            }, 1500);
          }
        },
      },
    );
  }, [validRows, importCSV, onOpenChange, resetState]);

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen) {
      resetState();
      importCSV.reset();
    }
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="font-mono text-sm font-semibold">Import Systems from CSV</DialogTitle>
          <DialogDescription className="font-mono text-xs text-text-muted">
            Upload a CSV file with columns: name, host, port, username, distro (optional: description).
            Required column headers are case-insensitive.
          </DialogDescription>
        </DialogHeader>

        {/* File drop zone */}
        <div
          role="button"
          tabIndex={0}
          className={[
            "flex flex-col items-center justify-center gap-3 rounded-[4px] border-2 border-dashed px-6 py-8 transition-colors duration-100 cursor-pointer",
            isDragOver
              ? "border-accent bg-accent/10"
              : "border-border hover:border-border-hover hover:bg-surface",
          ].join(" ")}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") fileInputRef.current?.click();
          }}
        >
          <Upload className="h-8 w-8 text-text-muted" />
          <div className="text-center">
            <p className="font-mono text-sm text-text">Drop a CSV file or click to browse</p>
            {fileName && (
              <p className="font-mono text-xs text-accent mt-1">{fileName}</p>
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

        {/* Missing columns error */}
        {missingColumns.length > 0 && (
          <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
            Missing required columns: {missingColumns.join(", ")}
          </div>
        )}

        {/* Preview table */}
        {hasPreview && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <p className="font-mono text-xs text-text-muted">
                Preview (first {PREVIEW_MAX_ROWS} rows) -- {validRows.length} valid,{" "}
                {parsedRows.length - validRows.length} invalid
              </p>
            </div>
            <PreviewTable rows={parsedRows} />
          </div>
        )}

        {/* Import result */}
        {importResult && (
          <div className="flex flex-col gap-2">
            {importResult.created.length > 0 && (
              <div className="rounded-[4px] border border-info/40 bg-info/10 px-4 py-3 font-mono text-xs text-info">
                {importResult.created.length} system{importResult.created.length === 1 ? "" : "s"} imported successfully.
              </div>
            )}
            {importResult.errors.length > 0 && (
              <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
                <p className="font-semibold mb-2">Import errors ({importResult.errors.length}):</p>
                <ul className="flex flex-col gap-1 list-none">
                  {importResult.errors.map((err) => (
                    <li key={`${err.row_index}-${err.name}`}>
                      Row {err.row_index + 1} ({err.name || "unnamed"}): {err.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Mutation error */}
        {importCSV.isError && !importResult && (
          <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
            Import failed: {(importCSV.error as Error).message}
          </div>
        )}

        {/* Footer actions */}
        <div className="flex gap-2 pt-2 border-t border-border justify-end">
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={validRows.length === 0 || importCSV.isPending}
            onClick={handleImport}
          >
            {importCSV.isPending
              ? "Importing..."
              : `Import ${validRows.length} valid row${validRows.length === 1 ? "" : "s"}`}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
