import { useMemo, useState } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  FilterChip,
  MonoBadge,
  toneColor,
} from "@/components/aila/mock";

import { useProjectEvidence } from "../queries";
import type { EvidenceItem } from "../types";

type SortKey = "name" | "type" | "size" | "path";
type SortDir = "asc" | "desc";

// Evidence type -> mock semantic tone. Same colour intent as the old shadcn
// palette, remapped to the mock's tone tokens.
const TYPE_TONE: Record<string, string> = {
  disk_image: "info",
  memory_dump: "medium",
  pcap: "ok",
  log_file: "warn",
  extracted_dir: "signal",
  unknown: "muted",
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

// ---------------------------------------------------------------------------
// SortHeader -- clickable mono uppercase label used inside the DataGrid
// header row. Keyboard focus + Space/Enter fall out of the native <button>.
// ---------------------------------------------------------------------------
function SortHeader({
  label,
  columnKey,
  currentKey,
  dir,
  align = "left",
  onClick,
}: {
  label: string;
  columnKey: SortKey;
  currentKey: SortKey;
  dir: SortDir;
  align?: "left" | "right";
  onClick: (k: SortKey) => void;
}) {
  const active = currentKey === columnKey;
  const arrow = active ? (dir === "asc" ? "\u25b4" : "\u25be") : "";
  return (
    <button
      type="button"
      onClick={() => onClick(columnKey)}
      aria-label={`Sort by ${label}`}
      aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}
      className="font-mono uppercase"
      style={{
        border: 0,
        padding: 0,
        background: "transparent",
        color: active ? "var(--text-primary)" : "var(--text-faint)",
        fontSize: 9,
        letterSpacing: "0.14em",
        cursor: "pointer",
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        width: "100%",
        justifyContent: align === "right" ? "flex-end" : "flex-start",
      }}
    >
      <span>{label}</span>
      {arrow ? <span style={{ opacity: 0.7 }}>{arrow}</span> : null}
    </button>
  );
}

export function EvidenceTree({ projectId }: { projectId: string }) {
  const { data: evidence, isLoading, isError } = useProjectEvidence(projectId);
  const [filterText, setFilterText] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("size");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const items: EvidenceItem[] = evidence ?? [];

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

  if (isLoading) {
    return (
      <WindowPanel title="evidence" tone="accent" status="loading">
        <LoadingSkeleton size="md" width="full" />
      </WindowPanel>
    );
  }

  if (isError) {
    return (
      <WindowPanel title="evidence" tone="warn" status="forensics ; evidence unavailable">
        <p style={{ color: "var(--accent)", fontSize: 12 }}>Failed to load evidence.</p>
      </WindowPanel>
    );
  }

  if (items.length === 0) {
    return (
      <WindowPanel title="evidence" tone="muted" status="forensics ; no evidence discovered">
        <p
          className="font-mono"
          style={{
            padding: "16px 0",
            textAlign: "center",
            fontSize: 11,
            color: "var(--text-muted)",
          }}
        >
          No evidence files discovered yet. Run analysis to scan the evidence directory.
        </p>
      </WindowPanel>
    );
  }

  const statusLine = `${items.length} item${items.length === 1 ? "" : "s"}`;

  return (
    <WindowPanel title="evidence" tone="accent" status={statusLine} flush>
      {/* Header summary row */}
      <div
        className="flex items-center justify-between"
        style={{
          padding: "8px 12px",
          borderBottom: "1px solid var(--border-soft)",
          background: "var(--surface-sunk)",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <div
          className="flex items-center font-mono"
          style={{ gap: 10, fontSize: 10, letterSpacing: "0.08em", color: "var(--text-muted)" }}
        >
          <span style={{ color: "var(--text-primary)" }}>
            {filtered.length === items.length
              ? `${items.length} FILE${items.length === 1 ? "" : "S"}`
              : `${filtered.length} / ${items.length}`}
          </span>
          <span style={{ color: "var(--text-faint)" }}>|</span>
          <span>
            {filtered.length === items.length
              ? formatBytes(totalSize)
              : `${formatBytes(shownSize)} shown`}
          </span>
        </div>
        <input
          aria-label="Search evidence by path or sha256"
          type="text"
          placeholder="path or sha256..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="font-mono"
          style={{
            height: 26,
            padding: "0 10px",
            fontSize: 11,
            background: "var(--surface-card)",
            border: "1px solid var(--border-soft)",
            color: "var(--text-primary)",
            borderRadius: 3,
            minWidth: 240,
          }}
        />
      </div>

      {/* Type filter chips */}
      <div
        style={{
          padding: "8px 12px",
          borderBottom: "1px solid var(--border-soft)",
          display: "flex",
          gap: 6,
          flexWrap: "wrap",
        }}
      >
        <FilterChip
          active={!typeFilter}
          color={toneColor("info")}
          onClick={() => setTypeFilter(null)}
        >
          ALL ({items.length})
        </FilterChip>
        {Object.entries(typeCounts).map(([t, n]) => (
          <FilterChip
            key={t}
            active={typeFilter === t}
            color={toneColor(TYPE_TONE[t] ?? "muted")}
            onClick={() => setTypeFilter(typeFilter === t ? null : t)}
          >
            {t.replace(/_/g, " ")} ({n})
          </FilterChip>
        ))}
      </div>

      {/* Body: sorted DataGrid */}
      <div style={{ padding: 12 }}>
        {sorted.length === 0 ? (
          <WindowPanel tone="muted" flush status="evidence ; filter matched nothing">
            <p
              className="font-mono"
              style={{
                padding: "12px 0",
                textAlign: "center",
                fontSize: 11,
                color: "var(--text-muted)",
              }}
            >
              No evidence matches the current filter.
            </p>
          </WindowPanel>
        ) : (
          <div
            aria-label="Evidence artifacts"
            style={{ maxHeight: 620, overflow: "auto" }}
          >
            <DataGrid<EvidenceItem>
              columns={[
                {
                  label: (
                    <SortHeader
                      label="Name"
                      columnKey="name"
                      currentKey={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  ),
                  width: "1fr",
                },
                {
                  label: (
                    <SortHeader
                      label="Type"
                      columnKey="type"
                      currentKey={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  ),
                  width: "160px",
                },
                {
                  label: (
                    <SortHeader
                      label="Size"
                      columnKey="size"
                      currentKey={sortKey}
                      dir={sortDir}
                      align="right"
                      onClick={handleSort}
                    />
                  ),
                  width: "110px",
                  align: "right",
                },
                {
                  label: (
                    <SortHeader
                      label="Path"
                      columnKey="path"
                      currentKey={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  ),
                  width: "2fr",
                },
              ]}
              rows={sorted}
              getKey={(f) => f.id}
              renderCells={(f) => {
                const type = f.evidence_type || "unknown";
                const tone = TYPE_TONE[type] ?? "muted";
                const name = basename(f.file_path);
                const dir = dirname(f.file_path);
                const sha = f.file_hash_sha256;
                const pathTitle = sha
                  ? `${f.file_path}  ·  sha256 ${sha}`
                  : f.file_path;
                return [
                  <span
                    title={name}
                    style={{
                      fontSize: 11,
                      color: "var(--text-primary)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      display: "block",
                    }}
                  >
                    {name}
                  </span>,
                  <MonoBadge tone={tone}>{type.replace(/_/g, " ")}</MonoBadge>,
                  <span
                    style={{
                      fontSize: 11,
                      color: "var(--text-muted)",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {formatBytes(f.size_bytes)}
                  </span>,
                  <span
                    title={pathTitle}
                    style={{
                      fontSize: 10.5,
                      color: "var(--text-faint)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      display: "block",
                    }}
                  >
                    {dir || "\u00b7"}
                  </span>,
                ];
              }}
            />
          </div>
        )}
      </div>
    </WindowPanel>
  );
}
