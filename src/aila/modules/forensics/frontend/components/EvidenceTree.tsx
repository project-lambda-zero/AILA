import { type CSSProperties, useMemo, useState } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";

import { useProjectEvidence } from "../queries";
import type { EvidenceItem } from "../types";

type SortKey = "name" | "type" | "size" | "path";
type SortDir = "asc" | "desc";

const TYPE_TONE: Record<string, CSSProperties> = {
  disk_image: { background: "color-mix(in srgb, var(--color-lavender) 15%, transparent)", color: "var(--color-lavender)" },
  memory_dump: { background: "color-mix(in srgb, var(--color-medium) 15%, transparent)", color: "var(--color-medium)" },
  pcap: { background: "color-mix(in srgb, var(--color-mint) 15%, transparent)", color: "var(--color-mint)" },
  log_file: { background: "color-mix(in srgb, var(--color-amber) 15%, transparent)", color: "var(--color-amber)" },
  extracted_dir: { background: "color-mix(in srgb, var(--color-peach) 15%, transparent)", color: "var(--color-peach)" },
  unknown: { background: "var(--color-elevated)", color: "var(--color-text-muted)" },
};

function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined || bytes === 0) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes < 1099511627776) return `${(bytes / 1073741824).toFixed(2)} GB`;
  return `${(bytes / 1099511627776).toFixed(2)} TB`;
}

function basename(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || path;
}

function dirname(path: string): string {
  const normalised = path.replace(/\\/g, "/");
  const idx = normalised.lastIndexOf("/");
  if (idx <= 0) return "";
  return normalised.slice(0, idx);
}

function SortHeader({
  label,
  columnKey,
  currentKey,
  dir,
  onClick,
  align = "left",
  width,
}: {
  label: string;
  columnKey: SortKey;
  currentKey: SortKey;
  dir: SortDir;
  onClick: (k: SortKey) => void;
  align?: "left" | "right";
  width?: string;
}) {
  const active = currentKey === columnKey;
  const arrow = active ? (dir === "asc" ? "▲" : "▼") : "";
  return (
    <th
      className={`px-3 py-2 text-${align} text-text-muted font-medium cursor-pointer select-none hover:text-foreground`}
      style={width ? { width } : undefined}
      onClick={() => onClick(columnKey)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        <span className="text-4xs opacity-70">{arrow}</span>
      </span>
    </th>
  );
}

export function EvidenceTree({ projectId }: { projectId: string }) {
  const { data: evidence, isLoading, isError } = useProjectEvidence(projectId);
  const [filterText, setFilterText] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("size");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const items = evidence ?? [];

  const typeCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const it of items) {
      const k = it.evidence_type || "unknown";
      out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  }, [items]);

  const filtered = useMemo(() => {
    const q = filterText.trim().toLowerCase();
    return items.filter((it) => {
      if (typeFilter && (it.evidence_type || "unknown") !== typeFilter) return false;
      if (q) {
        const hay = `${it.file_path} ${it.file_hash_sha256 ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [items, filterText, typeFilter]);

  const sorted = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "name") cmp = basename(a.file_path).localeCompare(basename(b.file_path));
      else if (sortKey === "type") cmp = (a.evidence_type || "").localeCompare(b.evidence_type || "");
      else if (sortKey === "size") cmp = (a.size_bytes ?? -1) - (b.size_bytes ?? -1);
      else if (sortKey === "path") cmp = a.file_path.localeCompare(b.file_path);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [filtered, sortKey, sortDir]);

  const totalSize = useMemo(
    () => items.reduce((sum, it) => sum + (it.size_bytes ?? 0), 0),
    [items],
  );
  const shownSize = useMemo(
    () => filtered.reduce((sum, it) => sum + (it.size_bytes ?? 0), 0),
    [filtered],
  );

  const handleSort = (k: SortKey) => {
    if (k === sortKey) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else {
      setSortKey(k);
      setSortDir(k === "size" ? "desc" : "asc");
    }
  };

  if (isLoading) return <LoadingSkeleton size="md" width="full" />;

  if (isError) {
    return (
      <WindowPanel title="evidence" tone="warn" status="forensics ; evidence unavailable">
        <p className="text-sm text-critical">Failed to load evidence.</p>
      </WindowPanel>
    );
  }

  if (items.length === 0) {
    return (
      <WindowPanel title="evidence" tone="muted" status="forensics ; no evidence discovered">
        <p className="text-sm text-text-muted text-center py-4">
          No evidence files discovered yet. Run analysis to scan the evidence directory.
        </p>
      </WindowPanel>
    );
  }

  return (
    <div className="space-y-3">
      {/* Header row: title + totals */}
      <div className="flex items-baseline justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
          <PixelIcon name="folder" size={12} className="text-accent" />
          Evidence
          <span className="ml-2 text-xs font-normal text-text-muted">
            {filtered.length === items.length
              ? `${items.length} file${items.length === 1 ? "" : "s"} · ${formatBytes(totalSize)}`
              : `${filtered.length} of ${items.length} · ${formatBytes(shownSize)} shown`}
          </span>
        </h3>
      </div>

      {/* Controls: search + type chips */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          aria-label="Search evidence by path or sha256"
          type="text"
          placeholder="Search path or sha256..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="w-full max-w-xs px-2.5 py-1.5 text-xs rounded border border-border bg-surface text-foreground placeholder:text-text-muted focus:outline-none focus:border-primary"
        />
        <button
          type="button"
          onClick={() => setTypeFilter(null)}
          className={`px-2.5 py-1 text-3xs rounded-[3px] font-mono uppercase tracking-cyber-sm ${
            !typeFilter
              ? "bg-primary text-badge-text"
              : "bg-elevated text-text-muted hover:text-foreground"
          }`}
        >
          All ({items.length})
        </button>
        {Object.entries(typeCounts).map(([t, n]) => (
          <button
            key={t}
            type="button"
            onClick={() => setTypeFilter(typeFilter === t ? null : t)}
            className={`px-2.5 py-1 text-3xs rounded-[3px] font-mono uppercase tracking-cyber-sm ${
              typeFilter === t ? "bg-primary text-badge-text" : ""
            }`}
            style={typeFilter === t ? undefined : TYPE_TONE[t] || TYPE_TONE.unknown}
          >
            {t.replace(/_/g, " ")} ({n})
          </button>
        ))}
      </div>

      {/* Table */}
      {sorted.length === 0 ? (
        <WindowPanel tone="muted" status="evidence ; filter matched nothing">
          <p className="text-sm text-text-muted text-center py-4">
            No evidence matches the current filter.
          </p>
        </WindowPanel>
      ) : (
        <div className="border border-border rounded-lg bg-surface text-foreground overflow-hidden">
          <div className="overflow-y-auto" style={{ maxHeight: 620 }}>
            <table className="w-full text-xs" aria-label="Evidence artifacts">
              <caption className="sr-only">Evidence artifacts grouped by source with size, hash, and status.</caption>
              <thead className="bg-elevated sticky top-0 z-10">
                <tr>
                  <SortHeader
                    label="Name"
                    columnKey="name"
                    currentKey={sortKey}
                    dir={sortDir}
                    onClick={handleSort}
                  />
                  <SortHeader
                    label="Type"
                    columnKey="type"
                    currentKey={sortKey}
                    dir={sortDir}
                    onClick={handleSort}
                    width="120px"
                  />
                  <SortHeader
                    label="Size"
                    columnKey="size"
                    currentKey={sortKey}
                    dir={sortDir}
                    onClick={handleSort}
                    align="right"
                    width="100px"
                  />
                  <SortHeader
                    label="Path"
                    columnKey="path"
                    currentKey={sortKey}
                    dir={sortDir}
                    onClick={handleSort}
                  />
                  <th
                    className="px-3 py-2 text-left text-text-muted font-medium"
                    style={{ width: "160px" }}
                  >
                    SHA-256
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((f) => {
                  const type = f.evidence_type || "unknown";
                  const tone = TYPE_TONE[type] || TYPE_TONE.unknown;
                  const name = basename(f.file_path);
                  const dir = dirname(f.file_path);
                  const sha = f.file_hash_sha256;
                  return (
                    <tr
                      key={f.id}
                      className="border-t border-border hover:bg-elevated/30"
                    >
                      <td
                        className="px-3 py-1.5 font-mono text-foreground truncate max-w-xs align-top"
                        title={name}
                      >
                        {name}
                      </td>
                      <td className="px-3 py-1.5 align-top">
                        <span
                          className="px-1.5 py-0.5 rounded text-3xs font-medium whitespace-nowrap"
                          style={tone}
                        >
                          {type.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 font-mono text-text-muted whitespace-nowrap text-right align-top">
                        {formatBytes(f.size_bytes)}
                      </td>
                      <td
                        className="px-3 py-1.5 font-mono text-text-muted truncate max-w-md align-top"
                        title={f.file_path}
                      >
                        {dir}
                      </td>
                      <td
                        className="px-3 py-1.5 font-mono text-text-muted whitespace-nowrap align-top"
                        title={sha ?? "no hash computed"}
                      >
                        {sha ? (
                          <span className="select-all">{sha.slice(0, 12)}…</span>
                        ) : (
                          <span className="text-text-muted/50">--</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
