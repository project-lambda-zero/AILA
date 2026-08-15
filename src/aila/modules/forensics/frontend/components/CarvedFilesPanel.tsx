import { useMemo, useState } from "react";

import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, FilterChip, MonoBadge, toneColor } from "@/components/aila/mock";

import { useProjectArtifacts } from "../queries";
import { useDownloadCarvedFile } from "../mutations";
import type { NormalizedArtifact } from "../types";

// ---------------------------------------------------------------------------
// Types + helpers (preserved verbatim).
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

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
    const derived = new Map<string, number>();
    for (const f of files) {
      derived.set(f.mime_type, (derived.get(f.mime_type) ?? 0) + 1);
    }
    return [...derived.entries()]
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
      <WindowPanel title="carved files" tone="muted" status="no carved files yet">
        <EmptyState
          title="No files were carved."
          description="This typically means the pcap carried no reconstructible file transfers, or Zeek is not installed on the analyzer -- check the worker log for a zeek_skipped event."
        />
      </WindowPanel>
    );
  }

  const totalBytes = formatBytes(files.reduce((s, f) => s + f.size_bytes, 0));

  return (
    <WindowPanel
      title="carved files"
      tone="accent"
      status={`${files.length} carved ; ${totalBytes} total`}
    >
      <div className="space-y-3">
        {/* Mime distribution row + search input (aria-label preserved) */}
        <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
          <FilterChip
            active={mimeFilter === null}
            color={toneColor("accent")}
            onClick={() => setMimeFilter(null)}
          >
            {`All (${files.length})`}
          </FilterChip>
          {mimeCounts.slice(0, 10).map((mc) => (
            <FilterChip
              key={mc.mime_type}
              active={mimeFilter === mc.mime_type}
              color={toneColor("info")}
              onClick={() =>
                setMimeFilter((curr) =>
                  curr === mc.mime_type ? null : mc.mime_type,
                )
              }
            >
              {`${mc.mime_type} (${mc.count})`}
            </FilterChip>
          ))}
          <span style={{ flex: 1 }} />
          <input
            aria-label="Search carved files"
            type="search"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder="filename, sha256, host, mime\u2026"
            className="font-mono"
            style={{
              height: 26,
              width: 240,
              padding: "0 10px",
              fontSize: 11,
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              color: "var(--text-primary)",
              borderRadius: 3,
            }}
          />
        </div>

        <div
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-faint)", letterSpacing: "0.08em" }}
        >
          {`Showing ${filtered.length} of ${files.length} file${files.length === 1 ? "" : "s"}`}
        </div>

        <DataGrid<CarvedFile>
          columns={[
            { label: "SHA256", width: "110px" },
            { label: "FILENAME", width: "1fr" },
            { label: "MIME", width: "160px" },
            { label: "SIZE", width: "110px", align: "right" },
            { label: "PROTO", width: "80px" },
            { label: "HOSTS", width: "2fr" },
            { label: "DOWNLOAD", width: "120px", align: "right" },
          ]}
          rows={filtered.slice(0, 1000)}
          getKey={(f) => f.sha256}
          renderCells={(f) => {
            const fname = filenameFor(f);
            const hosts =
              f.tx_hosts.length && f.rx_hosts.length
                ? `${f.tx_hosts[0]} \u2192 ${f.rx_hosts[0]}`
                : f.tx_hosts[0] || f.rx_hosts[0] || (f.protocol ?? "?");
            return [
              <span
                key="sha"
                title={f.sha256}
                style={{ fontSize: 10, color: "var(--text-faint)" }}
              >
                {f.sha256.slice(0, 8)}
              </span>,
              <span
                key="fn"
                title={fname}
                className="truncate"
                style={{
                  fontSize: 11,
                  color: "var(--text-primary)",
                  display: "block",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {fname}
              </span>,
              <MonoBadge key="mime" tone="muted" title={f.mime_type}>
                {f.mime_type}
              </MonoBadge>,
              <span
                key="size"
                style={{ fontSize: 11, color: "var(--text-muted)" }}
              >
                {formatBytes(f.size_bytes)}
              </span>,
              f.protocol ? (
                <MonoBadge key="proto" tone="info">
                  {f.protocol}
                </MonoBadge>
              ) : (
                <span
                  key="proto"
                  style={{ fontSize: 10, color: "var(--text-faint)" }}
                >
                  --
                </span>
              ),
              <span
                key="hosts"
                title={hosts}
                className="truncate"
                style={{
                  fontSize: 10,
                  color: "var(--text-muted)",
                  display: "block",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {hosts}
              </span>,
              <button
                key="dl"
                type="button"
                aria-label={`Download ${fname}`}
                disabled={download.isPending}
                onClick={() =>
                  download.mutate({
                    sha256: f.sha256,
                    filename: fname,
                  })
                }
                className="font-mono uppercase"
                style={{
                  height: 22,
                  padding: "0 10px",
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-on-accent)",
                  background: "var(--accent)",
                  border: "1px solid var(--accent)",
                  borderRadius: 3,
                  cursor: download.isPending ? "wait" : "pointer",
                  opacity: download.isPending ? 0.6 : 1,
                }}
              >
                Download
              </button>,
            ];
          }}
        />
      </div>
    </WindowPanel>
  );
}
