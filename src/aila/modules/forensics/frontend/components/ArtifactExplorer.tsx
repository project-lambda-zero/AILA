import { type CSSProperties, useMemo, useState } from "react";

import { Folder } from "@phosphor-icons/react/dist/csr/Folder";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  FilterChip,
  MonoBadge,
  Segmented,
  toneColor,
} from "@/components/aila/mock";

import { useProjectArtifacts } from "../queries";

// Family -> mock semantic tone. Same severity buckets as the old shadcn
// palette, remapped to the mock's critical/high/medium/low/info tokens.
type FamilyTone = "critical" | "high" | "medium" | "low" | "info";
const familyColors: Record<string, FamilyTone> = {
  malware: "critical",
  execution: "high",
  network: "medium",
  host: "low",
  user: "info",
  browser: "info",
  memory: "medium",
  filesystem: "low",
};

// Dissect record fields that carry no human signal -- they're metadata for
// the record library itself. Hide them from the default table view.
const HIDDEN_RECORD_KEYS: Record<string, true> = {
  _classification: true,
  _generated: true,
  _source: true,
  _version: true,
  hostname: true,
  domain: true,
  user_group: true,
  user_home: true,
};

function renderCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/** Download helper -- CSV for records, one row per record. */
function downloadCsv(records: Array<Record<string, unknown>>, filename: string) {
  const cols = Array.from(
    records.reduce((acc, rec) => {
      for (const k of Object.keys(rec)) if (!HIDDEN_RECORD_KEYS[k]) acc.add(k);
      return acc;
    }, new Set<string>()),
  );
  const escape = (v: unknown) => {
    const s = renderCell(v);
    if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [cols.join(",")];
  for (const rec of records) {
    lines.push(cols.map((c) => escape(rec[c])).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadJson(payload: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Common styled button used across the toolbar and action strips. Muted
// mono-uppercase pill matching the mock cookbook.
const MUTED_BTN: CSSProperties = {
  height: 26,
  padding: "0 10px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const CTRL_INPUT: CSSProperties = {
  height: 26,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const CTRL_SELECT: CSSProperties = {
  ...CTRL_INPUT,
  paddingRight: 22,
};

interface ArtifactWithData {
  id: string;
  artifact_family: string;
  artifact_type: string;
  source_tool?: string | null;
  source_evidence_id?: string | null;
  source_investigation_id?: string | null;
  lead_score?: number | null;
  // Backend serialises the parsed dict as `data`, not `data_json`.
  data?: Record<string, unknown> | null;
}

interface ParsedPayload {
  rawOutput: string;
  records: Array<Record<string, unknown>>;
  totalRecordCount: number | null;
  truncated: boolean;
  structuredEntries: Array<[string, unknown]>;
  nestedObservables: Record<string, unknown> | null;
}

// Investigation-emitted artifacts (and any future structured row) store
// findings as plain object fields on `data`, NOT inside `records[]` or
// `raw_output`. This helper mirrors the previous ArtifactRow logic verbatim
// so the surface reasoning about "collector vs investigation row" stays
// intact.
const COLLECTOR_KEYS: Record<string, true> = {
  raw_output: true,
  records: true,
  record_count: true,
  truncated: true,
  evidence_path: true,
};

function parsePayload(parsed: Record<string, unknown> | null): ParsedPayload {
  let rawOutput = "";
  let records: Array<Record<string, unknown>> = [];
  let totalRecordCount: number | null = null;
  let truncated = false;
  const structuredEntries: Array<[string, unknown]> = [];
  let nestedObservables: Record<string, unknown> | null = null;
  if (parsed && typeof parsed === "object") {
    const p = parsed as {
      raw_output?: unknown;
      records?: unknown;
      record_count?: unknown;
      truncated?: unknown;
    };
    if (typeof p.raw_output === "string") rawOutput = p.raw_output;
    if (Array.isArray(p.records)) {
      records = p.records as Array<Record<string, unknown>>;
    }
    if (typeof p.record_count === "number") totalRecordCount = p.record_count;
    if (p.truncated === true) truncated = true;
  }
  if (parsed && typeof parsed === "object" && records.length === 0 && !rawOutput) {
    for (const [k, v] of Object.entries(parsed)) {
      if (COLLECTOR_KEYS[k]) continue;
      if (v === null || v === undefined || v === "") continue;
      if (k === "observables" && v && typeof v === "object" && !Array.isArray(v)) {
        nestedObservables = v as Record<string, unknown>;
        continue;
      }
      structuredEntries.push([k, v]);
    }
  }
  return {
    rawOutput,
    records,
    totalRecordCount,
    truncated,
    structuredEntries,
    nestedObservables,
  };
}

// ---------------------------------------------------------------------------
// RecordsGrid -- dynamic-column DataGrid for parsed dissect records.
// Row click expands an inline detail row with the full record JSON.
// ---------------------------------------------------------------------------
function RecordsGrid({
  records,
  fullscreen,
}: {
  records: Array<Record<string, unknown>>;
  fullscreen: boolean;
}) {
  const cols = useMemo(
    () =>
      Array.from(
        records.reduce((acc, rec) => {
          for (const k of Object.keys(rec)) if (!HIDDEN_RECORD_KEYS[k]) acc.add(k);
          return acc;
        }, new Set<string>()),
      ),
    [records],
  );

  const [filter, setFilter] = useState("");
  const [openRow, setOpenRow] = useState<number | null>(null);

  if (cols.length === 0) {
    return (
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}
      >
        records are all metadata -- nothing human-readable.
      </p>
    );
  }

  const filtered = filter
    ? records.filter((rec) =>
        JSON.stringify(rec).toLowerCase().includes(filter.toLowerCase()),
      )
    : records;

  const MAX_ROWS = fullscreen ? 1000 : 200;
  const shown = filtered.slice(0, MAX_ROWS);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <input
          aria-label="Filter artifacts by name"
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter records..."
          className="font-mono flex-1"
          style={CTRL_INPUT}
        />
        <span
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-muted)", whiteSpace: "nowrap" }}
        >
          {filtered.length}
          {filtered.length !== records.length ? ` of ${records.length}` : ""}
          {filtered.length > MAX_ROWS ? ` (first ${MAX_ROWS})` : ""}
        </span>
      </div>
      <div
        aria-label="Forensics artifacts"
        style={{ maxHeight: fullscreen ? "70vh" : "32rem", overflow: "auto" }}
      >
        <DataGrid
          columns={cols.map((c) => ({
            label: c,
            width: c === "suspicious_reasons" ? "minmax(180px, 2fr)" : "minmax(140px, 1fr)",
          }))}
          rows={shown}
          getKey={(_, i) => i}
          onRowClick={(_, i) =>
            setOpenRow((prev) => (prev === i ? null : i))
          }
          renderCells={(rec, i) =>
            cols.map((c) => {
              const v = rec[c];
              if (c === "suspicious_reasons" && Array.isArray(v)) {
                return (
                  <span className="flex flex-wrap" style={{ gap: 3 }}>
                    {(v as string[]).map((r, j) => (
                      <MonoBadge key={j} tone="critical">
                        {r}
                      </MonoBadge>
                    ))}
                  </span>
                );
              }
              return (
                <span
                  style={{
                    fontSize: 10.5,
                    color: "var(--text-primary)",
                    display: "block",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={openRow === i ? undefined : renderCell(v)}
                >
                  {renderCell(v)}
                </span>
              );
            })
          }
        />
        {openRow != null && openRow < shown.length && (
          <div style={{ marginTop: 6 }}>
            <WindowPanel tone="muted" flush status={`record ${openRow + 1} / ${shown.length}`}>
              <pre
                className="font-mono"
                style={{
                  margin: 0,
                  padding: 10,
                  fontSize: 10,
                  lineHeight: 1.5,
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-soft)",
                  color: "var(--text-primary)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: fullscreen ? "60vh" : "24rem",
                  overflow: "auto",
                }}
              >
                {JSON.stringify(shown[openRow], null, 2)}
              </pre>
            </WindowPanel>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// StructuredView -- key/value fields for investigation-emitted artifacts
// (no dissect records / raw_output).
// ---------------------------------------------------------------------------
function StructuredView({
  entries,
  nestedObservables,
}: {
  entries: Array<[string, unknown]>;
  nestedObservables: Record<string, unknown> | null;
}) {
  return (
    <div className="space-y-3">
      {entries.length > 0 && (
        <div aria-label="Artifact structured fields">
          <DataGrid
          columns={[
            { label: "FIELD", width: "220px" },
            { label: "VALUE", width: "1fr" },
          ]}
          rows={entries}
          getKey={([k]) => k}
          renderCells={([k, v]) => [
            <span style={{ color: "var(--text-muted)" }}>{k}</span>,
            Array.isArray(v) ? (
              <ul className="space-y-0.5" style={{ margin: 0, padding: 0, listStyle: "none" }}>
                {(v as unknown[]).map((item, i) => (
                  <li key={i}>
                    <span style={{ color: "var(--text-faint)" }}>{"\u00b7"}</span>{" "}
                    {renderCell(item)}
                  </li>
                ))}
              </ul>
            ) : typeof v === "object" ? (
              <pre
                className="font-mono"
                style={{
                  margin: 0,
                  fontSize: 10,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  color: "var(--text-muted)",
                }}
              >
                {JSON.stringify(v, null, 2)}
              </pre>
            ) : (
              <span>{String(v)}</span>
            ),
          ]}
          />
        </div>
      )}
      {nestedObservables && Object.keys(nestedObservables).length > 0 && (
        <WindowPanel
          tone="info"
          title={`observables (${Object.keys(nestedObservables).length})`}
          flush
        >
          <div aria-label="Artifact nested observables">
            <DataGrid
              columns={[
                { label: "KEY", width: "220px" },
                { label: "VALUE", width: "1fr" },
              ]}
              rows={Object.entries(nestedObservables)}
              getKey={([k]) => k}
              renderCells={([k, v]) => [
                <span style={{ color: "var(--status-info)" }}>{k}</span>,
                <span style={{ color: "var(--text-primary)" }}>
                  {typeof v === "object" ? JSON.stringify(v) : String(v ?? "")}
                </span>,
              ]}
            />
          </div>
        </WindowPanel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ArtifactRow -- one collapsible artifact card in the outer list.
// Grid template: 56px icon | 1fr name/tool | 100px family badge | 80px count.
// ---------------------------------------------------------------------------
function ArtifactRow({
  a,
  view,
  fullscreen,
}: {
  a: ArtifactWithData;
  view: "records" | "json";
  fullscreen: boolean;
}) {
  const [open, setOpen] = useState(false);
  const parsed = a.data ?? null;
  const { rawOutput, records, totalRecordCount, truncated, structuredEntries, nestedObservables } =
    useMemo(() => parsePayload(parsed), [parsed]);
  const tone: FamilyTone = familyColors[a.artifact_family] ?? "info";

  const body =
    view === "json" ? (
      <pre
        className="font-mono"
        style={{
          margin: 0,
          padding: 10,
          fontSize: 10,
          lineHeight: 1.5,
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          color: "var(--text-primary)",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          maxHeight: fullscreen ? "70vh" : "32rem",
          overflow: "auto",
        }}
      >
        {JSON.stringify(parsed ?? {}, null, 2)}
      </pre>
    ) : (
      <div className="space-y-3">
        {truncated && totalRecordCount != null && (
          <div
            className="flex items-center font-mono"
            style={{
              gap: 6,
              padding: "4px 8px",
              fontSize: 10,
              color: "var(--status-warn)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              borderRadius: 3,
            }}
          >
            <Warning size={12} weight="fill" />
            <span>
              truncated: showing first {records.length} of {totalRecordCount.toLocaleString()} record(s).
            </span>
          </div>
        )}
        {records.length > 0 ? (
          <RecordsGrid records={records} fullscreen={fullscreen} />
        ) : rawOutput ? (
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: 10,
              fontSize: 10,
              lineHeight: 1.5,
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              color: "var(--text-primary)",
              whiteSpace: "pre-wrap",
              maxHeight: fullscreen ? "70vh" : "32rem",
              overflow: "auto",
            }}
          >
            {rawOutput}
          </pre>
        ) : structuredEntries.length > 0 || nestedObservables ? (
          <StructuredView entries={structuredEntries} nestedObservables={nestedObservables} />
        ) : (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}
          >
            no parsed records for this artifact.
          </p>
        )}
      </div>
    );

  return (
    <div
      style={{
        border: "1px solid var(--border-soft)",
        borderRadius: 4,
        background: "var(--surface-card)",
        overflow: "hidden",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((p) => !p)}
        className="grid font-mono w-full"
        style={{
          gridTemplateColumns: "56px 1fr 100px 80px",
          gap: 10,
          padding: "10px 12px",
          alignItems: "center",
          border: 0,
          background: open ? "var(--surface-hover)" : "transparent",
          color: "var(--text-primary)",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span className="flex items-center" style={{ gap: 6, color: toneColor(tone) }}>
          <span style={{ color: "var(--text-faint)", fontSize: 10 }}>{open ? "\u25be" : "\u25b8"}</span>
          <PixelIcon name="folder" size={14} />
        </span>
        <span className="flex items-center" style={{ gap: 8, minWidth: 0 }}>
          <span
            style={{
              fontSize: 11,
              color: "var(--text-primary)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {a.artifact_type}
          </span>
          <span
            style={{
              fontSize: 9.5,
              color: "var(--text-faint)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            via {a.source_tool || "?"}
          </span>
          {a.source_investigation_id && (
            <MonoBadge tone="info" title={`from investigation ${a.source_investigation_id.slice(0, 8)}`}>
              I
            </MonoBadge>
          )}
        </span>
        <span style={{ justifySelf: "start" }}>
          <MonoBadge tone={tone}>{a.artifact_family}</MonoBadge>
        </span>
        <span
          style={{
            fontSize: 10,
            color: "var(--text-muted)",
            textAlign: "right",
          }}
        >
          {records.length > 0
            ? `${records.length} rec`
            : a.lead_score != null
              ? `score ${a.lead_score.toFixed(1)}`
              : "--"}
        </span>
      </button>
      {open && (
        <div
          style={{
            borderTop: "1px solid var(--border-soft)",
            background: "var(--surface-chrome)",
            padding: 12,
          }}
        >
          <div
            className="flex items-center flex-wrap"
            style={{ gap: 6, marginBottom: 10 }}
          >
            {records.length > 0 && (
              <button
                type="button"
                onClick={() =>
                  downloadCsv(
                    records,
                    `${a.artifact_family}-${a.artifact_type}-${a.id.slice(0, 8)}.csv`,
                  )
                }
                className="font-mono uppercase"
                style={MUTED_BTN}
              >
                download csv
              </button>
            )}
            <button
              type="button"
              onClick={() =>
                downloadJson(
                  parsed ?? {},
                  `${a.artifact_family}-${a.artifact_type}-${a.id.slice(0, 8)}.json`,
                )
              }
              className="font-mono uppercase"
              style={MUTED_BTN}
            >
              download json
            </button>
          </div>
          {body}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ArtifactExplorer -- root panel.
// ---------------------------------------------------------------------------
export function ArtifactExplorer({ projectId }: { projectId: string }) {
  const [familyFilter, setFamilyFilter] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [sourceFilter, setSourceFilter] =
    useState<"" | "investigations" | "collectors">("");
  const [search, setSearch] = useState<string>("");
  const [fullscreen, setFullscreen] = useState<boolean>(false);
  const [view, setView] = useState<"records" | "json">("records");

  const { data: result, isLoading, isError } = useProjectArtifacts(projectId, {
    family: familyFilter || undefined,
    type: typeFilter || undefined,
    source: sourceFilter || undefined,
  });

  if (isLoading) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  if (isError) {
    return (
      <WindowPanel title="artifacts" tone="warn" status="forensics ; artifacts unavailable">
        <p style={{ color: "var(--accent)", fontSize: 12 }}>Failed to load artifacts.</p>
      </WindowPanel>
    );
  }

  const artifacts = (result?.items ?? []) as ArtifactWithData[];
  const total = result?.total ?? 0;

  // Family + type facets derived from the current fetch. Keep the fixed
  // family list as a fallback so filter chips render even when the current
  // page is empty for the selected family.
  const KNOWN_FAMILIES = [
    "host", "user", "execution", "browser", "network",
    "memory", "malware", "filesystem", "log",
  ];
  const familyCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of artifacts) c[a.artifact_family] = (c[a.artifact_family] ?? 0) + 1;
    return c;
  }, [artifacts]);
  const familyOptions = useMemo(() => {
    const s = new Set<string>(KNOWN_FAMILIES);
    for (const a of artifacts) s.add(a.artifact_family);
    return Array.from(s).sort();
  }, [artifacts]);
  const typeOptions = useMemo(() => {
    const s = new Set<string>();
    for (const a of artifacts) s.add(a.artifact_type);
    return Array.from(s).sort();
  }, [artifacts]);

  const filtered = useMemo(() => {
    if (!search.trim()) return artifacts;
    const q = search.trim().toLowerCase();
    return artifacts.filter((a) => {
      const hay = `${a.artifact_family} ${a.artifact_type} ${a.source_tool ?? ""} ${a.source_investigation_id ?? ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [artifacts, search]);

  const statusLine = `${familyFilter || "all families"} ; ${total} records`;

  return (
    <WindowPanel title="artifacts" tone="accent" status={statusLine} flush>
      {/* Toolbar */}
      <div
        style={{
          padding: 10,
          borderBottom: "1px solid var(--border-soft)",
          background: "var(--surface-sunk)",
          display: "flex",
          gap: 8,
          flexWrap: "wrap",
          alignItems: "center",
        }}
      >
        <select
          aria-label="Filter by family"
          value={familyFilter}
          onChange={(e) => setFamilyFilter(e.target.value)}
          className="font-mono"
          style={CTRL_SELECT}
        >
          <option value="">all families</option>
          {familyOptions.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by type"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="font-mono"
          style={CTRL_SELECT}
        >
          <option value="">all types</option>
          {typeOptions.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by source"
          value={sourceFilter}
          onChange={(e) =>
            setSourceFilter(e.target.value as "" | "investigations" | "collectors")
          }
          className="font-mono"
          style={CTRL_SELECT}
        >
          <option value="">all sources</option>
          <option value="collectors">collectors</option>
          <option value="investigations">investigations</option>
        </select>
        <input
          aria-label="Search artifacts"
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="search family / type / tool..."
          className="font-mono"
          style={{ ...CTRL_INPUT, flex: 1, minWidth: 180 }}
        />
        <button
          type="button"
          onClick={() => setFullscreen((f) => !f)}
          className="font-mono uppercase"
          style={{
            ...MUTED_BTN,
            color: fullscreen ? "var(--accent)" : "var(--text-muted)",
            borderColor: fullscreen ? "var(--accent)" : "var(--border-soft)",
          }}
          aria-pressed={fullscreen}
        >
          {fullscreen ? "min" : "max"}
        </button>
        <Segmented
          options={[
            { value: "records", label: "RECORDS" },
            { value: "json", label: "JSON" },
          ]}
          value={view}
          onChange={setView}
        />
      </div>

      {/* Family filter chips */}
      <div
        style={{
          padding: "8px 10px",
          borderBottom: "1px solid var(--border-soft)",
          display: "flex",
          gap: 6,
          flexWrap: "wrap",
          alignItems: "center",
        }}
      >
        <FilterChip
          active={!familyFilter}
          color={toneColor("info")}
          onClick={() => setFamilyFilter("")}
        >
          ALL ({total})
        </FilterChip>
        {familyOptions.map((f) => {
          const n = familyCounts[f] ?? 0;
          return (
            <FilterChip
              key={f}
              active={familyFilter === f}
              color={toneColor(familyColors[f] ?? "info")}
              onClick={() => setFamilyFilter(familyFilter === f ? "" : f)}
            >
              {f} ({n})
            </FilterChip>
          );
        })}
      </div>

      {/* Body */}
      <div style={{ padding: 12 }}>
        {filtered.length === 0 ? (
          <EmptyState
            icon={<Folder className="h-10 w-10" />}
            title="No artifacts"
            description={
              familyFilter
                ? `No artifacts in the ${familyFilter} family.`
                : search
                  ? "No artifacts match the search query."
                  : "No artifacts collected yet."
            }
          />
        ) : (
          <div className="space-y-2">
            {filtered.map((a) => (
              <ArtifactRow key={a.id} a={a} view={view} fullscreen={fullscreen} />
            ))}
          </div>
        )}
      </div>
    </WindowPanel>
  );
}
