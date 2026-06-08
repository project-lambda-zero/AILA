import { useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";

import { useProjectArtifacts } from "../queries";
import { useDownloadCarvedFile } from "../mutations";
import type { NormalizedArtifact } from "../types";

interface CarvedFile {
  sha256: string;
  size_bytes: number;
  mime_type: string;
  filename_guess: string | null;
  protocol: string | null;
  tx_hosts: string[];
  rx_hosts: string[];
  ts_first_seen: string | null;
}

interface MimeCount {
  mime_type: string;
  count: number;
}

function toCarvedFile(a: NormalizedArtifact): CarvedFile | null {
  const d = (a.data ?? {}) as Record<string, unknown>;
  const sha = typeof d.sha256 === "string" ? d.sha256 : "";
  if (!sha) return null;
  const txHosts = Array.isArray(d.tx_hosts)
    ? (d.tx_hosts as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const rxHosts = Array.isArray(d.rx_hosts)
    ? (d.rx_hosts as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  return {
    sha256: sha.toLowerCase(),
    size_bytes: typeof d.size_bytes === "number" ? d.size_bytes : 0,
    mime_type:
      typeof d.mime_type === "string" ? d.mime_type : "application/octet-stream",
    filename_guess:
      typeof d.filename_guess === "string" ? d.filename_guess : null,
    protocol: typeof d.protocol === "string" ? d.protocol : null,
    tx_hosts: txHosts,
    rx_hosts: rxHosts,
    ts_first_seen:
      typeof d.ts_first_seen === "string" ? d.ts_first_seen : null,
  };
}

function formatBytes(n: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function filenameFor(f: CarvedFile): string {
  if (f.filename_guess && f.filename_guess.trim()) return f.filename_guess;
  // Synthesise something sensible from the MIME.
  const ext =
    f.mime_type === "application/pdf"
      ? ".pdf"
      : f.mime_type === "application/x-dosexec"
        ? ".exe"
        : f.mime_type === "application/zip"
          ? ".zip"
          : f.mime_type === "image/jpeg"
            ? ".jpg"
            : f.mime_type === "image/png"
              ? ".png"
              : f.mime_type === "text/html"
                ? ".html"
                : ".bin";
  return `carved_${f.sha256.slice(0, 12)}${ext}`;
}

export function CarvedFilesPanel({ projectId }: { projectId: string }) {
  const filesQuery = useProjectArtifacts(projectId, {
    family: "network",
    type: "carved_file",
    pageSize: 500,
  });
  const typesQuery = useProjectArtifacts(projectId, {
    family: "network",
    type: "carved_file_types",
    pageSize: 1,
  });
  const download = useDownloadCarvedFile(projectId);

  const [mimeFilter, setMimeFilter] = useState<string | null>(null);
  const [filterText, setFilterText] = useState("");

  const files = useMemo<CarvedFile[]>(() => {
    const rows = filesQuery.data?.items ?? [];
    return rows
      .map(toCarvedFile)
      .filter((f): f is CarvedFile => f !== null);
  }, [filesQuery.data]);

  const mimeCounts = useMemo<MimeCount[]>(() => {
    const row = typesQuery.data?.items?.[0];
    const rowsField = row?.data?.rows;
    if (Array.isArray(rowsField)) {
      const out: MimeCount[] = [];
      for (const r of rowsField) {
        if (r && typeof r === "object" && "mime_type" in (r as object)) {
          const rec = r as Record<string, unknown>;
          const mime = typeof rec.mime_type === "string" ? rec.mime_type : "";
          const count = typeof rec.count === "number" ? rec.count : 0;
          if (mime) out.push({ mime_type: mime, count });
        }
      }
      return out;
    }
    // Derive client-side if the summary artifact is missing.
    const m = new Map<string, number>();
    for (const f of files) m.set(f.mime_type, (m.get(f.mime_type) ?? 0) + 1);
    return [...m.entries()]
      .map(([mime_type, count]) => ({ mime_type, count }))
      .sort((a, b) => b.count - a.count);
  }, [typesQuery.data, files]);

  const filtered = useMemo(() => {
    return files.filter((f) => {
      if (mimeFilter && f.mime_type !== mimeFilter) return false;
      if (!filterText) return true;
      const q = filterText.toLowerCase();
      return (
        f.sha256.includes(q) ||
        f.mime_type.toLowerCase().includes(q) ||
        (f.filename_guess || "").toLowerCase().includes(q) ||
        (f.protocol || "").toLowerCase().includes(q) ||
        f.tx_hosts.some((h) => h.toLowerCase().includes(q)) ||
        f.rx_hosts.some((h) => h.toLowerCase().includes(q))
      );
    });
  }, [files, filterText, mimeFilter]);

  if (filesQuery.isLoading || typesQuery.isLoading) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  if (files.length === 0) {
    return (
      <AilaCard  techBorder glow>
        <h3 className="text-sm font-semibold text-foreground mb-1">
          Files carved from PCAP
        </h3>
        <p className="text-xs text-text-muted">
          No files were carved. This typically means the pcap carried no
          reconstructible file transfers, or Zeek is not installed on the
          analyzer — check the worker log for a <code>zeek_skipped</code> event.
        </p>
      </AilaCard>
    );
  }

  return (
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-foreground">
          Files carved from PCAP
          <span className="ml-2 text-xs font-normal text-text-muted">
            {filtered.length} of {files.length} file
            {files.length === 1 ? "" : "s"}
          </span>
        </h3>
      </div>

      {/* Most common file types */}
      {mimeCounts.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-2xs text-text-muted mr-1">
            Most common types:
          </span>
          <button
            type="button"
            onClick={() => setMimeFilter(null)}
            className={`px-2 py-0.5 text-2xs rounded-full font-medium ${
              mimeFilter === null
                ? "bg-primary text-white"
                : "bg-surface-secondary text-text-muted hover:text-foreground"
            }`}
          >
            All ({files.length})
          </button>
          {mimeCounts.slice(0, 10).map((mc) => (
            <button
              key={mc.mime_type}
              type="button"
              onClick={() =>
                setMimeFilter((curr) =>
                  curr === mc.mime_type ? null : mc.mime_type,
                )
              }
              className={`px-2 py-0.5 text-2xs rounded-full font-mono ${
                mimeFilter === mc.mime_type
                  ? "bg-primary text-white"
                  : "bg-surface-secondary text-text-muted hover:text-foreground"
              }`}
              title={mc.mime_type}
            >
              {mc.mime_type} <span className="opacity-70">({mc.count})</span>
            </button>
          ))}
        </div>
      )}

      {/* Filter */}
      <input
        aria-label="Search carved files"
        type="search"
        value={filterText}
        onChange={(e) => setFilterText(e.target.value)}
        placeholder="Filter by filename, sha256, host, mime…"
        className="h-8 w-80 max-w-full rounded border border-border bg-background px-2 text-xs"
      />

      {/* Table */}
      <div className="border border-border rounded-lg bg-surface text-foreground overflow-hidden">
        <div className="overflow-y-auto" style={{ maxHeight: 500 }}>
          <table className="w-full text-xs">
            <thead className="bg-surface-secondary sticky top-0 z-10">
              <tr>
                <th className="text-left px-3 py-2 text-text-muted font-medium w-72">
                  Filename
                </th>
                <th className="text-left px-3 py-2 text-text-muted font-medium w-48">
                  MIME
                </th>
                <th className="text-right px-3 py-2 text-text-muted font-medium w-24">
                  Size
                </th>
                <th className="text-left px-3 py-2 text-text-muted font-medium w-48">
                  Source
                </th>
                <th className="text-left px-3 py-2 text-text-muted font-medium">
                  sha256
                </th>
                <th className="text-right px-3 py-2 text-text-muted font-medium w-24">
                  &nbsp;
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 1000).map((f) => {
                const fname = filenameFor(f);
                const source =
                  f.tx_hosts.length && f.rx_hosts.length
                    ? `${f.tx_hosts[0]} → ${f.rx_hosts[0]}`
                    : f.protocol || "?";
                return (
                  <tr
                    key={f.sha256}
                    className="border-t border-border hover:bg-surface-secondary/30"
                  >
                    <td
                      className="px-3 py-1.5 text-foreground truncate max-w-xs"
                      title={fname}
                    >
                      {fname}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-text-muted">
                      <AilaBadge severity="info" size="sm">
                        {f.mime_type}
                      </AilaBadge>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-text-muted text-right">
                      {formatBytes(f.size_bytes)}
                    </td>
                    <td
                      className="px-3 py-1.5 font-mono text-text-muted truncate max-w-xs"
                      title={source}
                    >
                      {source}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-text-muted">
                      {f.sha256.slice(0, 16)}…
                    </td>
                    <td className="px-3 py-1.5 text-right">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() =>
                          download.mutate({
                            sha256: f.sha256,
                            filename: fname,
                          })
                        }
                        disabled={download.isPending}
                      >
                        ⬇
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
