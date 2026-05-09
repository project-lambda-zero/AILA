import { useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useOccurrences, useTimeline } from "../queries";

type Confidence = "low" | "medium" | "high";

const SOURCE_COLORS: Record<string, string> = {
  dissect: "bg-blue-500/20 text-blue-400",
  volatility: "bg-purple-500/20 text-purple-400",
  tshark: "bg-green-500/20 text-green-400",
  strings: "bg-orange-500/20 text-orange-400",
  capa: "bg-red-500/20 text-red-400",
  yara: "bg-yellow-500/20 text-yellow-400",
  ghidra: "bg-pink-500/20 text-pink-400",
  script: "bg-cyan-500/20 text-cyan-400",
  investigator: "bg-emerald-500/20 text-emerald-400",
  unknown: "bg-gray-500/20 text-gray-400",
};

function timestampOriginLabel(origin?: string): { text: string; tone: string } | null {
  if (!origin) return null;
  if (origin.startsWith("observable:")) {
    // Mined from a nested observable key — surface the key name so the
    // analyst knows which time-field this entry represents
    // (e.g. `obs:lnk_modified` vs `obs:first_seen`).
    return {
      text: origin.replace("observable:", "obs:"),
      tone: "bg-blue-500/20 text-blue-300",
    };
  }
  // data:timestamp / data:time / data:created — canonical, no badge
  return null;
}

function ConfidenceSelector({
  value,
  onChange,
}: {
  value: Confidence;
  onChange: (c: Confidence) => void;
}) {
  return (
    <div className="flex items-center text-xs border border-border rounded bg-card text-card-foreground overflow-hidden">
      {(["low", "medium", "high"] as Confidence[]).map((c) => (
        <button
          key={c}
          type="button"
          onClick={() => onChange(c)}
          className={
            "px-2 py-1 transition-colors capitalize " +
            (value === c
              ? "bg-blue-600 text-white"
              : "bg-surface text-foreground hover:bg-surface-secondary")
          }
          title={
            c === "low"
              ? "any row with a real event-time"
              : c === "medium"
                ? "typed agent findings + scored collector rows (default)"
                : "confirmed agent answers + critical collector rows"
          }
        >
          {c}
        </button>
      ))}
    </div>
  );
}

function flattenScalars(
  obj: unknown,
  prefix = "",
  out: Array<{ key: string; value: string }> = [],
  depth = 0,
): Array<{ key: string; value: string }> {
  if (obj == null) return out;
  if (depth > 3) return out;
  if (typeof obj !== "object") {
    out.push({ key: prefix || "value", value: String(obj) });
    return out;
  }
  if (Array.isArray(obj)) {
    // Summarise arrays — the timeline row already knows the row count,
    // so we don't dump array contents into the key table.
    out.push({ key: prefix || "items", value: `[${obj.length} item(s)]` });
    return out;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (v == null) continue;
    if (k === "observables" || k === "raw_output_sample" ||
        k === "summary_prompt") continue;
    const nextKey = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "object") {
      flattenScalars(v, nextKey, out, depth + 1);
    } else {
      out.push({ key: nextKey, value: String(v).slice(0, 240) });
    }
  }
  return out;
}

function InspectRow({
  payload,
}: {
  payload: Record<string, unknown> | undefined;
}) {
  const rows = flattenScalars(payload ?? {}).slice(0, 60);
  if (rows.length === 0) {
    return (
      <div className="px-3 py-2 text-[11px] text-text-muted">
        No structured fields available for this entry.
      </div>
    );
  }
  return (
    <div className="px-3 py-2 bg-black/20 border-t border-border">
      <table className="w-full text-[11px]">
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="align-top">
              <td className="pr-3 py-0.5 font-mono text-text-muted whitespace-nowrap max-w-[220px] truncate">
                {r.key}
              </td>
              <td className="py-0.5 font-mono text-foreground break-all">
                {r.value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TimelineViewer({ projectId }: { projectId: string }) {
  const [confidence, setConfidence] = useState<Confidence>("medium");
  const [filterText, setFilterText] = useState("");
  const [sourceFilter, setSourceFilter] = useState<string | null>(null);
  const [inspectIdx, setInspectIdx] = useState<string | null>(null);

  const { data: entries, isLoading, isError } = useTimeline(projectId, {
    minConfidence: confidence,
  });
  const { data: occurrences, isLoading: occLoading } = useOccurrences(projectId, {
    minConfidence: confidence,
  });

  if (isLoading || occLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load timeline.</p>
      </AilaCard>
    );
  }

  const safeEntries = entries ?? [];
  const safeOcc = occurrences ?? [];
  const sources = [...new Set([
    ...safeEntries.map((e) => e.source),
    ...safeOcc.map((e) => e.source),
  ])];

  const matchesQuery = (text: string) => {
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return text.toLowerCase().includes(q);
  };

  const filteredEntries = safeEntries.filter((e) => {
    if (sourceFilter && e.source !== sourceFilter) return false;
    return matchesQuery(
      `${e.description} ${e.event_type} ${e.timestamp}`,
    );
  });
  const filteredOcc = safeOcc.filter((o) => {
    if (sourceFilter && o.source !== sourceFilter) return false;
    return matchesQuery(`${o.description} ${o.event_type}`);
  });

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Search events & occurrences..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="w-full max-w-xs px-2.5 py-1.5 text-xs rounded border border-border bg-surface text-foreground placeholder:text-text-muted focus:outline-none focus:border-primary"
        />
        <ConfidenceSelector value={confidence} onChange={setConfidence} />
        <div className="flex gap-1 flex-wrap">
          <button
            type="button"
            onClick={() => setSourceFilter(null)}
            className={`px-2.5 py-1 text-[10px] rounded-full font-medium ${
              !sourceFilter
                ? "bg-primary text-white"
                : "bg-surface-secondary text-text-muted hover:text-foreground"
            }`}
          >
            All sources
          </button>
          {sources.map((src) => (
            <button
              key={src}
              type="button"
              onClick={() => setSourceFilter(sourceFilter === src ? null : src)}
              className={`px-2.5 py-1 text-[10px] rounded-full font-medium ${
                sourceFilter === src
                  ? "bg-primary text-white"
                  : SOURCE_COLORS[src] || SOURCE_COLORS.unknown
              }`}
            >
              {src}
            </button>
          ))}
        </div>
      </div>

      {/* Section 1 — Timeline (event-time correlation) */}
      <div className="space-y-1">
        <div className="flex items-baseline justify-between">
          <h3 className="text-sm font-semibold text-foreground">
            Timeline
            <span className="ml-2 text-xs font-normal text-text-muted">
              when it happened — {filteredEntries.length} event
              {filteredEntries.length === 1 ? "" : "s"}
            </span>
          </h3>
        </div>
        {filteredEntries.length === 0 ? (
          <AilaCard>
            <p className="text-sm text-text-muted text-center py-4">
              No event-time entries at <code>{confidence}</code> confidence.
              Try lowering the bar or check the Occurrences table below.
            </p>
          </AilaCard>
        ) : (
          <div className="border border-border rounded-lg overflow-hidden bg-card text-card-foreground">
            <div className="overflow-y-auto max-h-[500px]">
              <table className="w-full text-xs">
                <thead className="bg-surface-secondary sticky top-0 z-10">
                  <tr>
                    <th className="text-left px-3 py-2 text-text-muted font-medium w-44">Timestamp</th>
                    <th className="text-left px-3 py-2 text-text-muted font-medium w-32">Source</th>
                    <th className="text-left px-3 py-2 text-text-muted font-medium w-28">Type</th>
                    <th className="text-left px-3 py-2 text-text-muted font-medium">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEntries.slice(0, 1000).map((entry, i) => {
                    const colorClass =
                      SOURCE_COLORS[entry.source] || SOURCE_COLORS.unknown;
                    const originBadge = timestampOriginLabel(entry.timestamp_origin);
                    const rowKey = `t-${i}`;
                    const isOpen = inspectIdx === rowKey;
                    return (
                      <>
                        <tr key={rowKey} className="border-t border-border hover:bg-surface-secondary/30">
                          <td className="px-3 py-1.5 font-mono text-text-muted whitespace-nowrap align-top">
                            <div className="flex items-center gap-1.5">
                              <span>{entry.timestamp}</span>
                              {originBadge && (
                                <span
                                  className={`px-1 py-0 rounded text-[9px] font-medium ${originBadge.tone}`}
                                  title={`timestamp source: ${entry.timestamp_origin}`}
                                >
                                  {originBadge.text}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-1.5 align-top">
                            <div className="flex items-center gap-1">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${colorClass}`}
                              >
                                {entry.source}
                              </span>
                              {entry.source_investigation_id && (
                                <span
                                  className="px-1 py-0 rounded text-[9px] font-medium bg-emerald-500/20 text-emerald-300"
                                  title={`from investigation ${entry.source_investigation_id.slice(0, 8)}`}
                                >
                                  I
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-1.5 font-mono text-foreground align-top">
                            {entry.event_type}
                          </td>
                          <td
                            className="px-3 py-1.5 text-foreground align-top"
                            title={entry.description}
                          >
                            <div className="flex items-start gap-2">
                              <span className="flex-1 truncate max-w-lg">
                                {entry.description}
                              </span>
                              <button
                                type="button"
                                onClick={() =>
                                  setInspectIdx((curr) =>
                                    curr === rowKey ? null : rowKey,
                                  )
                                }
                                className="shrink-0 text-[10px] text-text-muted hover:text-foreground underline decoration-dotted"
                                aria-expanded={isOpen}
                              >
                                {isOpen ? "hide" : "inspect"}
                              </button>
                            </div>
                          </td>
                        </tr>
                        {isOpen && (
                          <tr key={`${rowKey}-detail`} className="border-t border-border">
                            <td colSpan={4} className="p-0">
                              <InspectRow
                                payload={entry.data as Record<string, unknown> | undefined}
                              />
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Section 2 — Occurrences (no event-time) */}
      <div className="space-y-1">
        <div className="flex items-baseline justify-between">
          <h3 className="text-sm font-semibold text-foreground">
            Occurrences
            <span className="ml-2 text-xs font-normal text-text-muted">
              what we found, no event-time — {filteredOcc.length} finding
              {filteredOcc.length === 1 ? "" : "s"}
            </span>
          </h3>
        </div>
        {filteredOcc.length === 0 ? (
          <AilaCard>
            <p className="text-sm text-text-muted text-center py-4">
              No untimed findings at <code>{confidence}</code> confidence.
            </p>
          </AilaCard>
        ) : (
          <div className="border border-border rounded-lg overflow-hidden bg-card text-card-foreground">
            <div className="overflow-y-auto max-h-[500px]">
              <table className="w-full text-xs">
                <thead className="bg-surface-secondary sticky top-0 z-10">
                  <tr>
                    <th className="text-left px-3 py-2 text-text-muted font-medium w-32">Source</th>
                    <th className="text-left px-3 py-2 text-text-muted font-medium w-28">Type</th>
                    <th className="text-left px-3 py-2 text-text-muted font-medium">Description</th>
                    <th className="text-left px-3 py-2 text-text-muted font-medium w-44">Recorded</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredOcc.slice(0, 1000).map((occ, i) => {
                    const colorClass =
                      SOURCE_COLORS[occ.source] || SOURCE_COLORS.unknown;
                    const rowKey = `o-${i}`;
                    const isOpen = inspectIdx === rowKey;
                    return (
                      <>
                        <tr key={rowKey} className="border-t border-border hover:bg-surface-secondary/30">
                          <td className="px-3 py-1.5 align-top">
                            <div className="flex items-center gap-1">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${colorClass}`}
                              >
                                {occ.source}
                              </span>
                              {occ.source_investigation_id && (
                                <span
                                  className="px-1 py-0 rounded text-[9px] font-medium bg-emerald-500/20 text-emerald-300"
                                  title={`from investigation ${occ.source_investigation_id.slice(0, 8)}`}
                                >
                                  I
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-1.5 font-mono text-foreground align-top">
                            {occ.event_type}
                          </td>
                          <td
                            className="px-3 py-1.5 text-foreground align-top"
                            title={occ.description}
                          >
                            <div className="flex items-start gap-2">
                              <span className="flex-1 truncate max-w-lg">
                                {occ.description}
                              </span>
                              <button
                                type="button"
                                onClick={() =>
                                  setInspectIdx((curr) =>
                                    curr === rowKey ? null : rowKey,
                                  )
                                }
                                className="shrink-0 text-[10px] text-text-muted hover:text-foreground underline decoration-dotted"
                                aria-expanded={isOpen}
                              >
                                {isOpen ? "hide" : "inspect"}
                              </button>
                            </div>
                          </td>
                          <td className="px-3 py-1.5 font-mono text-text-muted whitespace-nowrap align-top">
                            {occ.recorded_at.replace("T", " ").slice(0, 19)}
                          </td>
                        </tr>
                        {isOpen && (
                          <tr key={`${rowKey}-detail`} className="border-t border-border">
                            <td colSpan={4} className="p-0">
                              <InspectRow
                                payload={occ.data as Record<string, unknown> | undefined}
                              />
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
