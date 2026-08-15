import { type CSSProperties, useMemo, useState } from "react";

import { Clock } from "@phosphor-icons/react/dist/csr/Clock";

import { EmptyState } from "@/components/aila/EmptyState";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  MonoBadge,
  Segmented,
  toneColor,
} from "@/components/aila/mock";

import { useOccurrences, useTimeline } from "../queries";
import type { Occurrence, TimelineEntry } from "../types";
import { PanelBoundary } from "./PanelBoundary";
import { TableSkeleton } from "./skeletons";
import { TimelineDistribution } from "./TimelineDistribution";
import { TimelineTrack } from "./TimelineTrack";

type Confidence = "low" | "medium" | "high";

// Source -> mock tone. Remapped from the old palette classes.
const SOURCE_TONE: Record<string, string> = {
  dissect: "info",
  volatility: "medium",
  tshark: "ok",
  strings: "warn",
  capa: "critical",
  yara: "warn",
  ghidra: "signal",
  script: "ok",
  investigator: "ok",
  unknown: "muted",
};

// Confidence -> mock tone for the CONFIDENCE column badge.
const CONFIDENCE_TONE: Record<string, string> = {
  high: "critical",
  medium: "medium",
  low: "info",
  confirmed: "critical",
  suspected: "medium",
  unknown: "muted",
};

/**
 * Preserved verbatim from the previous implementation: mark rows whose
 * timestamp was mined from a nested observable key so the analyst knows
 * which time-field the entry represents (e.g. `obs:lnk_modified` vs
 * `obs:first_seen`). Canonical `data:*` timestamps carry no badge.
 */
function timestampOriginLabel(origin?: string): { text: string; tone: string } | null {
  if (!origin) return null;
  if (origin.startsWith("observable:")) {
    return {
      text: origin.replace("observable:", "obs:"),
      tone: "info",
    };
  }
  return null;
}

/**
 * Preserved verbatim (behaviour + limits): recursively flatten a nested
 * object into a flat key/value list, capped at depth 3 and skipping the
 * `observables` / `raw_output_sample` / `summary_prompt` payload keys.
 */
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

// ---------------------------------------------------------------------------
// InspectRow -- key/value dl for the currently expanded timeline / occurrence
// entry. Rendered as an inline WindowPanel(flush, tone="muted") pane.
// ---------------------------------------------------------------------------
function InspectRow({
  payload,
}: {
  payload: Record<string, unknown> | undefined;
}) {
  const rows = flattenScalars(payload ?? {}).slice(0, 60);
  return (
    <WindowPanel tone="muted" flush status={`inspect ; ${rows.length} field${rows.length === 1 ? "" : "s"}`}>
      {rows.length === 0 ? (
        <p
          className="font-mono"
          style={{ padding: 10, fontSize: 11, color: "var(--text-muted)" }}
        >
          No structured fields available for this entry.
        </p>
      ) : (
        <dl
          className="font-mono"
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(160px, 220px) 1fr",
            gap: "2px 12px",
            padding: "8px 12px",
            fontSize: 10.5,
            margin: 0,
          }}
        >
          {rows.map((r, i) => (
            <div key={i} className="contents">
              <dt
                style={{
                  color: "var(--text-muted)",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {r.key}
              </dt>
              <dd
                style={{
                  color: "var(--text-primary)",
                  margin: 0,
                  wordBreak: "break-all",
                }}
              >
                {r.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </WindowPanel>
  );
}

const CTRL_INPUT: CSSProperties = {
  height: 26,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const MUTED_BTN_BASE: CSSProperties = {
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

// Cell helper: mono monochrome span with column-relevant defaults.
function textCell(
  value: React.ReactNode,
  color = "var(--text-primary)",
): React.ReactNode {
  return (
    <span
      style={{
        fontSize: 10.5,
        color,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        display: "block",
      }}
    >
      {value}
    </span>
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

  if (isLoading || occLoading) {
    return (
      <WindowPanel title="timeline" tone="accent" status="loading">
        <TableSkeleton rows={8} cells={4} />
      </WindowPanel>
    );
  }

  if (isError) {
    return (
      <WindowPanel title="timeline" tone="warn" status="forensics ; timeline unavailable">
        <p style={{ color: "var(--accent)", fontSize: 12 }}>Failed to load timeline.</p>
      </WindowPanel>
    );
  }

  const safeEntries = entries ?? [];
  const safeOcc = occurrences ?? [];

  const sources = useMemo(() => {
    const s = new Set<string>();
    for (const e of safeEntries) s.add(e.source);
    for (const o of safeOcc) s.add(o.source);
    return Array.from(s).sort();
  }, [safeEntries, safeOcc]);

  const q = filterText.trim().toLowerCase();
  const filteredEntries = useMemo(
    () =>
      safeEntries.filter((e) => {
        if (sourceFilter && e.source !== sourceFilter) return false;
        if (!q) return true;
        return `${e.description} ${e.event_type} ${e.timestamp}`.toLowerCase().includes(q);
      }),
    [safeEntries, sourceFilter, q],
  );
  const filteredOcc = useMemo(
    () =>
      safeOcc.filter((o) => {
        if (sourceFilter && o.source !== sourceFilter) return false;
        if (!q) return true;
        return `${o.description} ${o.event_type}`.toLowerCase().includes(q);
      }),
    [safeOcc, sourceFilter, q],
  );

  if (safeEntries.length === 0 && safeOcc.length === 0) {
    return (
      <WindowPanel
        title="timeline"
        tone="accent"
        status={`0 events ; ${confidence} confidence`}
      >
        <EmptyState
          icon={<Clock className="h-10 w-10" />}
          title={`No timeline entries at ${confidence} confidence.`}
          description="Lower the confidence bar, run Full Analysis on the dashboard, or start an investigation -- collector + agent findings both feed the timeline."
        />
      </WindowPanel>
    );
  }

  const displayedEntries = filteredEntries.slice(0, 1000);
  const displayedOcc = filteredOcc.slice(0, 1000);

  return (
    <div className="space-y-4">
      <WindowPanel
        title="timeline"
        tone="accent"
        status={`${safeEntries.length} events ; ${confidence} confidence`}
      >
        <div className="space-y-4">
          {/* Controls */}
          <div
            className="flex items-center flex-wrap"
            style={{ gap: 8 }}
          >
            <input
              aria-label="Search timeline events and occurrences"
              type="text"
              placeholder="search events & occurrences..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              className="font-mono"
              style={{ ...CTRL_INPUT, flex: 1, minWidth: 220 }}
            />
            <Segmented
              options={[
                { value: "low", label: "ALL" },
                { value: "medium", label: "M+" },
                { value: "high", label: "H ONLY" },
              ]}
              value={confidence}
              onChange={setConfidence}
            />
            <button
              type="button"
              onClick={() => setSourceFilter(null)}
              className="font-mono uppercase"
              style={{
                ...MUTED_BTN_BASE,
                color: !sourceFilter ? "var(--text-primary)" : "var(--text-muted)",
                borderColor: !sourceFilter ? "var(--accent)" : "var(--border-soft)",
              }}
            >
              all sources
            </button>
            {sources.map((src) => {
              const active = sourceFilter === src;
              const color = toneColor(SOURCE_TONE[src] ?? "muted");
              return (
                <button
                  key={src}
                  type="button"
                  onClick={() => setSourceFilter(active ? null : src)}
                  className="font-mono uppercase"
                  style={{
                    ...MUTED_BTN_BASE,
                    color: active ? color : "var(--text-muted)",
                    borderColor: active ? color : "var(--border-soft)",
                    background: active
                      ? `color-mix(in srgb, ${color} 11%, transparent)`
                      : "transparent",
                  }}
                >
                  {src}
                </button>
              );
            })}
          </div>

          {/* Visual timeline (existing components, restyled shell) */}
          {safeEntries.length > 0 && (
            <PanelBoundary label="Visual timeline">
              <div className="space-y-3">
                <TimelineTrack
                  entries={safeEntries}
                  activeSource={sourceFilter}
                  onSourceClick={(src) =>
                    setSourceFilter((cur) => (cur === src ? null : src))
                  }
                />
                <TimelineDistribution entries={safeEntries} />
              </div>
            </PanelBoundary>
          )}

          {/* Timeline event grid */}
          {filteredEntries.length === 0 ? (
            <WindowPanel tone="muted" flush status={`timeline ; ${confidence} confidence`}>
              <p
                className="font-mono"
                style={{
                  padding: "16px 12px",
                  textAlign: "center",
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                No event-time entries at <code>{confidence}</code> confidence.
                Try lowering the bar or check the Occurrences table below.
              </p>
            </WindowPanel>
          ) : (
            <div>
              <div
                aria-label="Timeline events"
                style={{ maxHeight: 500, overflow: "auto" }}
              >
                <DataGrid<TimelineEntry>
                  columns={[
                    { label: "TS", width: "190px" },
                    { label: "SOURCE", width: "140px" },
                    { label: "EVENT", width: "1fr" },
                    { label: "CONFIDENCE", width: "110px" },
                  ]}
                  rows={displayedEntries}
                  getKey={(_, i) => `t-${i}`}
                  onRowClick={(_, i) => {
                    const key = `t-${i}`;
                    setInspectIdx((curr) => (curr === key ? null : key));
                  }}
                  renderCells={(entry) => {
                    const originBadge = timestampOriginLabel(entry.timestamp_origin);
                    const sourceTone = SOURCE_TONE[entry.source] ?? "muted";
                    const rawConf = entry.data && typeof entry.data === "object"
                      ? (entry.data as Record<string, unknown>).confidence
                      : undefined;
                    const confLabel = typeof rawConf === "string" && rawConf.length > 0
                      ? rawConf
                      : confidence;
                    const confTone = CONFIDENCE_TONE[confLabel.toLowerCase()] ?? "muted";
                    return [
                      <span
                        className="flex items-center"
                        style={{ gap: 6, fontSize: 10.5, color: "var(--text-muted)" }}
                      >
                        <span
                          style={{
                            fontFamily: "var(--font-mono)",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {entry.timestamp}
                        </span>
                        {originBadge && (
                          <MonoBadge
                            tone={originBadge.tone}
                            title={`timestamp source: ${entry.timestamp_origin}`}
                          >
                            {originBadge.text}
                          </MonoBadge>
                        )}
                      </span>,
                      <span className="flex items-center" style={{ gap: 4 }}>
                        <MonoBadge tone={sourceTone}>{entry.source}</MonoBadge>
                        {entry.source_investigation_id && (
                          <MonoBadge
                            tone="ok"
                            title={`from investigation ${entry.source_investigation_id.slice(0, 8)}`}
                          >
                            I
                          </MonoBadge>
                        )}
                      </span>,
                      <span
                        className="flex items-center"
                        style={{ gap: 8, minWidth: 0 }}
                        title={entry.description}
                      >
                        <MonoBadge tone="muted">{entry.event_type}</MonoBadge>
                        <span
                          style={{
                            flex: 1,
                            minWidth: 0,
                            fontSize: 11,
                            color: "var(--text-primary)",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {entry.description}
                        </span>
                      </span>,
                      <span style={{ display: "inline-flex", justifyContent: "flex-start" }}>
                        <MonoBadge tone={confTone}>{confLabel}</MonoBadge>
                      </span>,
                    ];
                  }}
                />
              </div>
              {inspectIdx?.startsWith("t-") &&
                (() => {
                  const idx = Number(inspectIdx.slice(2));
                  const entry = displayedEntries[idx];
                  if (!entry) return null;
                  return (
                    <div style={{ marginTop: 8 }}>
                      <InspectRow
                        payload={entry.data as Record<string, unknown> | undefined}
                      />
                    </div>
                  );
                })()}
            </div>
          )}
        </div>
      </WindowPanel>

      {/* Occurrences */}
      <WindowPanel
        title="occurrences"
        tone="accent"
        status={`${safeOcc.length} findings ; ${confidence} confidence`}
      >
        {filteredOcc.length === 0 ? (
          <WindowPanel tone="muted" flush status={`occurrences ; ${confidence} confidence`}>
            <p
              className="font-mono"
              style={{
                padding: "16px 12px",
                textAlign: "center",
                fontSize: 11,
                color: "var(--text-muted)",
              }}
            >
              No untimed findings at <code>{confidence}</code> confidence.
            </p>
          </WindowPanel>
        ) : (
          <div>
            <div
              aria-label="Occurrences"
              style={{ maxHeight: 500, overflow: "auto" }}
            >
              <DataGrid<Occurrence>
                columns={[
                  { label: "SOURCE", width: "140px" },
                  { label: "EVENT", width: "180px" },
                  { label: "DESCRIPTION", width: "1fr" },
                  { label: "RECORDED", width: "190px" },
                ]}
                rows={displayedOcc}
                getKey={(_, i) => `o-${i}`}
                onRowClick={(_, i) => {
                  const key = `o-${i}`;
                  setInspectIdx((curr) => (curr === key ? null : key));
                }}
                renderCells={(occ) => {
                  const sourceTone = SOURCE_TONE[occ.source] ?? "muted";
                  return [
                    <span className="flex items-center" style={{ gap: 4 }}>
                      <MonoBadge tone={sourceTone}>{occ.source}</MonoBadge>
                      {occ.source_investigation_id && (
                        <MonoBadge
                          tone="ok"
                          title={`from investigation ${occ.source_investigation_id.slice(0, 8)}`}
                        >
                          I
                        </MonoBadge>
                      )}
                    </span>,
                    textCell(occ.event_type),
                    textCell(occ.description, "var(--text-primary)"),
                    textCell(occ.recorded_at.replace("T", " ").slice(0, 19), "var(--text-muted)"),
                  ];
                }}
              />
            </div>
            {inspectIdx?.startsWith("o-") &&
              (() => {
                const idx = Number(inspectIdx.slice(2));
                const occ = displayedOcc[idx];
                if (!occ) return null;
                return (
                  <div style={{ marginTop: 8 }}>
                    <InspectRow
                      payload={occ.data as Record<string, unknown> | undefined}
                    />
                  </div>
                );
              })()}
          </div>
        )}
      </WindowPanel>
    </div>
  );
}
