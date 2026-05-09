import { Fragment, useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useProjectArtifacts } from "../queries";

const familyColors: Record<string, "info" | "low" | "medium" | "high" | "critical"> = {
  malware: "critical",
  execution: "high",
  network: "medium",
  host: "low",
  user: "info",
  browser: "info",
  memory: "medium",
  filesystem: "low",
};

// Dissect record fields that carry no human signal — they're metadata for
// the record library itself. Hide them from the default table view.
const HIDDEN_RECORD_KEYS = new Set([
  "_classification", "_generated", "_source", "_version",
  "hostname", "domain", "user_group", "user_home",
]);

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

/** Download helper — CSV for records, one row per record. */
function downloadCsv(records: Array<Record<string, unknown>>, filename: string) {
  const cols = Array.from(
    records.reduce((acc, rec) => {
      for (const k of Object.keys(rec)) if (!HIDDEN_RECORD_KEYS.has(k)) acc.add(k);
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
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function RecordTable({
  records,
  fullscreen,
}: {
  records: Array<Record<string, unknown>>;
  fullscreen: boolean;
}) {
  // Collect column names from every record so sparse fields still show.
  const cols = useMemo(
    () =>
      Array.from(
        records.reduce((acc, rec) => {
          for (const k of Object.keys(rec)) if (!HIDDEN_RECORD_KEYS.has(k)) acc.add(k);
          return acc;
        }, new Set<string>()),
      ),
    [records],
  );

  const [filter, setFilter] = useState("");
  const [openRow, setOpenRow] = useState<number | null>(null);

  if (cols.length === 0) {
    return <p className="text-sm text-text-muted italic">records are all metadata — nothing human-readable.</p>;
  }

  const filtered = filter
    ? records.filter((rec) => {
        const blob = JSON.stringify(rec).toLowerCase();
        return blob.includes(filter.toLowerCase());
      })
    : records;

  const MAX_ROWS = fullscreen ? 1000 : 200;
  const shown = filtered.slice(0, MAX_ROWS);

  return (
    <div className="space-y-2 text-sm">
      <div className="flex items-center gap-3">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter records…"
          className="flex-1 text-xs px-2 py-1 rounded border border-border bg-surface text-foreground placeholder:text-text-muted"
        />
        <span className="text-xs text-text-muted whitespace-nowrap">
          {filtered.length}
          {filtered.length !== records.length ? ` of ${records.length}` : ""}
          {filtered.length > MAX_ROWS ? ` (showing first ${MAX_ROWS})` : ""}
        </span>
      </div>
      <div className={`overflow-auto rounded border border-border ${fullscreen ? "max-h-[70vh]" : "max-h-[32rem]"}`}>
        <table className="min-w-full text-xs font-mono">
          <thead className="bg-surface-secondary sticky top-0 z-10">
            <tr>
              <th className="px-2 py-1.5 text-left text-text-muted font-semibold w-6" />
              {cols.map((c) => (
                <th
                  key={c}
                  className="px-2 py-1.5 text-left text-text-muted font-semibold whitespace-nowrap"
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((rec, i) => {
              const sus = Array.isArray(rec.suspicious_reasons) && rec.suspicious_reasons.length > 0;
              const expanded = openRow === i;
              return (
                <Fragment key={i}>
                  <tr
                    onClick={() => setOpenRow((prev) => (prev === i ? null : i))}
                    className={`border-t border-border/40 cursor-pointer ${
                      sus ? "bg-red-950/30 hover:bg-red-950/50" : "hover:bg-surface-secondary/50"
                    }`}
                    title={sus ? `Suspicious: ${(rec.suspicious_reasons as string[]).join(", ")}` : undefined}
                  >
                    <td className="px-2 py-1.5 text-text-muted select-none align-top">
                      {expanded ? "▾" : "▸"}
                    </td>
                    {cols.map((c) => (
                      <td
                        key={c}
                        className="px-2 py-1.5 text-foreground align-top break-words max-w-[28rem]"
                      >
                        {c === "suspicious_reasons" && Array.isArray(rec[c]) ? (
                          (rec[c] as string[]).map((r, j) => (
                            <span
                              key={j}
                              className="inline-block mr-1 mb-0.5 px-1.5 py-0.5 rounded bg-red-900/60 text-red-200 text-[10px]"
                            >
                              {r}
                            </span>
                          ))
                        ) : (
                          renderCell(rec[c])
                        )}
                      </td>
                    ))}
                  </tr>
                  {expanded && (
                    <tr className="bg-black/40 border-t border-border/30">
                      <td colSpan={cols.length + 1} className="px-3 py-2">
                        <dl className="grid grid-cols-[min-content_1fr] gap-x-4 gap-y-1 text-xs">
                          {Object.entries(rec).map(([k, v]) => (
                            <div key={k} className="contents">
                              <dt className="text-text-muted whitespace-nowrap">{k}</dt>
                              <dd className="text-foreground break-all whitespace-pre-wrap">
                                {renderCell(v)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface ArtifactWithData {
  id: string;
  artifact_family: string;
  artifact_type: string;
  source_tool?: string | null;
  source_evidence_id?: string | null;
  source_investigation_id?: string | null;
  lead_score?: number | null;
  // Backend serializes the parsed dict as `data`, not `data_json`.
  // See NormalizedArtifact in api_router.py.
  data?: Record<string, unknown> | null;
}

function ArtifactRow({ a }: { a: ArtifactWithData }) {
  const [open, setOpen] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const parsed = a.data ?? null;

  let rawOutput = "";
  let records: Array<Record<string, unknown>> = [];
  let totalRecordCount: number | null = null;
  let truncated = false;
  if (parsed && typeof parsed === "object") {
    const p = parsed as {
      raw_output?: unknown;
      records?: unknown;
      record_count?: unknown;
      truncated?: unknown;
    };
    if (typeof p.raw_output === "string") rawOutput = p.raw_output;
    if (Array.isArray(p.records)) records = p.records as Array<Record<string, unknown>>;
    if (typeof p.record_count === "number") totalRecordCount = p.record_count;
    if (p.truncated === true) truncated = true;
  }

  // Investigation-emitted artifacts (and any future structured row)
  // store findings as plain object fields on `data`, NOT inside
  // `records[]` or `raw_output`. Build a generic key/value view from
  // anything that isn't already consumed by the collector renderer.
  const COLLECTOR_KEYS = new Set([
    "raw_output", "records", "record_count", "truncated", "evidence_path",
  ]);
  const structuredEntries: Array<[string, unknown]> = [];
  let nestedObservables: Record<string, unknown> | null = null;
  if (parsed && typeof parsed === "object" && records.length === 0 && !rawOutput) {
    for (const [k, v] of Object.entries(parsed)) {
      if (COLLECTOR_KEYS.has(k)) continue;
      if (v === null || v === undefined || v === "") continue;
      // Recognise the catch-all `observables_snapshot` payload and
      // promote its inner map into a dedicated table.
      if (k === "observables" && v && typeof v === "object" && !Array.isArray(v)) {
        nestedObservables = v as Record<string, unknown>;
        continue;
      }
      structuredEntries.push([k, v]);
    }
  }

  const body = (
    <div className="space-y-3">
      {truncated && totalRecordCount != null && (
        <div className="px-2 py-1 rounded border border-amber-800 bg-amber-950/30 text-amber-300 text-xs">
          ⚠ truncated: showing first {records.length} of {totalRecordCount.toLocaleString()} record(s).
        </div>
      )}
      {records.length > 0 ? (
        <RecordTable records={records} fullscreen={fullscreen} />
      ) : rawOutput ? (
        <pre className="text-xs font-mono whitespace-pre-wrap text-foreground bg-black/30 p-3 rounded border border-border max-h-[32rem] overflow-auto">
          {rawOutput}
        </pre>
      ) : structuredEntries.length > 0 || nestedObservables ? (
        <div className="space-y-3">
          {structuredEntries.length > 0 && (
            <div className="rounded border border-border bg-card text-card-foreground overflow-hidden">
              <table className="w-full text-xs">
                <tbody>
                  {structuredEntries.map(([k, v]) => (
                    <tr key={k} className="border-b border-border last:border-b-0">
                      <td className="px-3 py-1.5 font-mono text-text-muted bg-surface-secondary align-top whitespace-nowrap w-1/4">
                        {k}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-foreground break-all">
                        {Array.isArray(v) ? (
                          <ul className="space-y-0.5">
                            {(v as unknown[]).map((item, i) => (
                              <li key={i}>· {renderCell(item)}</li>
                            ))}
                          </ul>
                        ) : typeof v === "object" ? (
                          <pre className="whitespace-pre-wrap text-text-muted">
                            {JSON.stringify(v, null, 2)}
                          </pre>
                        ) : (
                          String(v)
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {nestedObservables && Object.keys(nestedObservables).length > 0 && (
            <div className="rounded border border-border bg-card text-card-foreground overflow-hidden">
              <div className="px-3 py-1.5 bg-surface-secondary text-xs font-mono text-text-muted border-b border-border">
                observables ({Object.keys(nestedObservables).length})
              </div>
              <table className="w-full text-xs">
                <tbody>
                  {Object.entries(nestedObservables).map(([k, v]) => (
                    <tr key={k} className="border-b border-border last:border-b-0">
                      <td className="px-3 py-1.5 font-mono text-blue-400 align-top whitespace-nowrap w-1/4">
                        {k}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-foreground break-all">
                        {typeof v === "object"
                          ? JSON.stringify(v)
                          : String(v ?? "")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        <p className="text-sm text-text-muted italic">no parsed records for this artifact.</p>
      )}
    </div>
  );

  return (
    <>
      <div className="border border-border rounded-md bg-surface overflow-hidden text-sm">
        <button
          type="button"
          onClick={() => setOpen((p) => !p)}
          className="w-full px-3 py-2 flex items-center justify-between hover:bg-surface-secondary transition-colors text-left"
        >
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-text-muted shrink-0 w-3">{open ? "▾" : "▸"}</span>
            <AilaBadge severity={familyColors[a.artifact_family] ?? "info"} size="sm">
              {a.artifact_family}
            </AilaBadge>
            <span className="font-mono text-foreground truncate">{a.artifact_type}</span>
            <span className="text-text-muted text-xs truncate">via {a.source_tool || "?"}</span>
            {a.source_investigation_id && (
              <a
                href={`#/forensics/projects/${encodeURIComponent(
                  a.source_investigation_id ? "" : ""
                )}/investigations/${encodeURIComponent(a.source_investigation_id)}`}
                onClick={(e) => e.stopPropagation()}
                title={`From investigation ${a.source_investigation_id.slice(0, 8)}`}
                className="shrink-0"
              >
                <AilaBadge severity="info" size="sm">I</AilaBadge>
              </a>
            )}
            {records.length > 0 && (
              <span className="text-text-muted text-xs shrink-0">· {records.length} rec</span>
            )}
          </div>
          {a.lead_score != null && (
            <span className="text-text-muted text-xs shrink-0">score {a.lead_score.toFixed(1)}</span>
          )}
        </button>
        {open && (
          <div className="border-t border-border bg-black/20 px-3 py-3 space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={() => setFullscreen(true)}
                className="text-xs px-2 py-1 rounded border border-border bg-surface hover:bg-surface-secondary"
              >
                maximize
              </button>
              {records.length > 0 && (
                <button
                  type="button"
                  onClick={() =>
                    downloadCsv(records, `${a.artifact_family}-${a.artifact_type}-${a.id.slice(0, 8)}.csv`)
                  }
                  className="text-xs px-2 py-1 rounded border border-border bg-surface hover:bg-surface-secondary"
                >
                  download csv
                </button>
              )}
              <button
                type="button"
                onClick={() =>
                  downloadJson(parsed ?? {}, `${a.artifact_family}-${a.artifact_type}-${a.id.slice(0, 8)}.json`)
                }
                className="text-xs px-2 py-1 rounded border border-border bg-surface hover:bg-surface-secondary"
              >
                download json
              </button>
              {rawOutput && records.length > 0 && (
                <details className="ml-auto">
                  <summary className="cursor-pointer text-xs text-text-muted hover:text-foreground">
                    raw output
                  </summary>
                  <pre className="mt-2 text-xs font-mono whitespace-pre-wrap text-foreground bg-black/30 p-3 rounded border border-border max-h-80 overflow-auto">
                    {rawOutput}
                  </pre>
                </details>
              )}
            </div>
            {body}
          </div>
        )}
      </div>

      {fullscreen && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-6"
          onClick={() => setFullscreen(false)}
        >
          <div
            className="bg-surface border border-border rounded-lg w-full max-w-7xl max-h-[90vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div className="flex items-center gap-2 min-w-0">
                <AilaBadge severity={familyColors[a.artifact_family] ?? "info"} size="sm">
                  {a.artifact_family}
                </AilaBadge>
                <span className="font-mono text-foreground truncate">{a.artifact_type}</span>
                <span className="text-text-muted text-xs truncate">via {a.source_tool || "?"}</span>
              </div>
              <button
                type="button"
                onClick={() => setFullscreen(false)}
                className="text-sm px-2 py-1 rounded border border-border hover:bg-surface-secondary"
              >
                close ✕
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4">{body}</div>
          </div>
        </div>
      )}
    </>
  );
}

export function ArtifactExplorer({ projectId }: { projectId: string }) {
  const [familyFilter, setFamilyFilter] = useState<string>("");
  const [sourceFilter, setSourceFilter] = useState<"" | "investigations" | "collectors">("");
  const { data: result, isLoading } = useProjectArtifacts(projectId, {
    family: familyFilter || undefined,
    source: sourceFilter || undefined,
  });

  if (isLoading) return <LoadingSkeleton size="md" width="full" />;

  const artifacts = (result?.items ?? []) as ArtifactWithData[];
  const total = result?.total ?? 0;

  const families = [
    "", "host", "user", "execution", "browser", "network",
    "memory", "malware", "filesystem", "log",
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="text-sm font-semibold text-foreground">Artifacts ({total})</h3>
        <div className="flex items-center gap-2">
          <div className="flex items-center text-xs border border-border rounded-md bg-card text-card-foreground overflow-hidden">
            {([
              { key: "", label: "All" },
              { key: "collectors", label: "Collectors" },
              { key: "investigations", label: "Investigations" },
            ] as const).map((b) => (
              <button
                key={b.key || "all"}
                type="button"
                onClick={() => setSourceFilter(b.key)}
                className={
                  "px-2 py-1 transition-colors " +
                  (sourceFilter === b.key
                    ? "bg-blue-600 text-white"
                    : "bg-surface text-foreground hover:bg-surface-secondary")
                }
              >
                {b.label}
              </button>
            ))}
          </div>
          <select
            value={familyFilter}
            onChange={(e) => setFamilyFilter(e.target.value)}
            className="text-xs px-2 py-1 rounded-md border border-border bg-surface text-foreground"
          >
            {families.map((f) => (
              <option key={f} value={f}>
                {f || "All Families"}
              </option>
            ))}
          </select>
        </div>
      </div>

      {artifacts.length === 0 ? (
        <AilaCard>
          <p className="text-sm text-text-muted text-center py-4">
            No artifacts {familyFilter ? `in ${familyFilter} family` : "collected yet"}.
          </p>
        </AilaCard>
      ) : (
        <div className="space-y-1.5">
          {artifacts.map((a) => (
            <ArtifactRow key={a.id} a={a} />
          ))}
        </div>
      )}
    </div>
  );
}
