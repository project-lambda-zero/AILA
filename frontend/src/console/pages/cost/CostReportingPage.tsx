/**
 * CostReportingPage -- bespoke admin window merging the former cost / cost-roi /
 * executive views into one page (req 47).
 *
 * Three in-page segments toggled by a button strip (not by nav):
 *   - overview: spend-over-time chart (/cost/history) + per-model / per-task /
 *     per-module breakdowns + the ROI trio (/cost/roi).
 *   - detail:   filterable, paginated LLM interaction log (/admin/llm-log) with
 *     a per-run cost drill-in (/cost/runs/{id}).
 *   - configs:  inline editors for the cost-family ConfigRegistry keys.
 *
 * The active segment deep-links via the `?segment=` query string (the SPA has
 * no router, so the param is seeded on mount and mirrored with replaceState).
 * Clicking a breakdown slice in the overview sets a shared dimension that both
 * re-series the chart AND seeds the detail segment's filters.
 */
import { useState } from "react";
import type { JSX } from "react";

import type { ModulePageProps } from "../../contract";
import { ConsoleWindow } from "../../window";
import CostConfigs from "./CostConfigs";
import CostDetail from "./CostDetail";
import CostOverview from "./CostOverview";
import {
  EMPTY_DETAIL_FILTERS,
  SEGMENTS,
  segButton,
} from "./kit";
import type { DetailFilters, Dim, Segment } from "./kit";

const SEGMENT_LABEL: Record<Segment, string> = {
  overview: "overview",
  detail: "detail",
  configs: "configs",
};

export default function CostReportingPage(props: ModulePageProps): JSX.Element {
  const { windowId, title, isFocused, onFocus, onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;

  const [segment, setSegment] = useState<Segment>(() => {
    const raw = new URLSearchParams(window.location.search).get("segment");
    return SEGMENTS.includes(raw as Segment) ? (raw as Segment) : "overview";
  });
  const [dim, setDim] = useState<Dim | null>(null);
  const [detailFilters, setDetailFilters] = useState<DetailFilters>(EMPTY_DETAIL_FILTERS);

  const goSegment = (next: Segment) => {
    setSegment(next);
    const url = new URL(window.location.href);
    url.searchParams.set("segment", next);
    window.history.replaceState(null, "", url);
  };

  // A breakdown drill-in sets the overview highlight (re-series the chart) AND
  // seeds the detail filters so switching to `detail` lands pre-filtered.
  const applyDim = (next: Dim | null) => {
    setDim(next);
    if (!next) {
      setDetailFilters(EMPTY_DETAIL_FILTERS);
      return;
    }
    if (next.kind === "model") {
      setDetailFilters({ ...EMPTY_DETAIL_FILTERS, model: next.value });
    } else {
      setDetailFilters({
        ...EMPTY_DETAIL_FILTERS,
        taskType: next.taskTypes.length > 0 ? next.taskTypes : [next.value],
      });
    }
  };

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--status-ok)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        admin &middot; cost
      </span>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          textTransform: "none",
          letterSpacing: "0.03em",
          color: "var(--text-muted)",
        }}
      >
        /cost/* &middot; /admin/llm-log &middot; /config/platform
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: 1,
            background: "var(--accent)",
            boxShadow: "0 0 7px var(--accent)",
          }}
        />
        <span style={{ color: "var(--text-primary)", fontWeight: 700, letterSpacing: "0.16em" }}>
          admin &middot; cost &amp; reporting
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          spend, breakdowns, ROI, and cost configuration
        </span>
      </header>

      <nav
        aria-label="cost page segments"
        style={{
          flex: "0 0 auto",
          display: "flex",
          gap: 8,
          padding: "9px 14px",
          borderBottom: "1px solid var(--border)",
          background: "color-mix(in srgb,var(--surface-chrome) 60%,transparent)",
        }}
      >
        {SEGMENTS.map((seg) => (
          <button
            key={seg}
            type="button"
            aria-current={segment === seg ? "page" : undefined}
            onClick={() => goSegment(seg)}
            style={segButton(segment === seg)}
          >
            {SEGMENT_LABEL[seg]}
          </button>
        ))}
      </nav>

      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: 12 }}>
        {segment === "overview" ? (
          <CostOverview dim={dim} onDim={applyDim} />
        ) : segment === "detail" ? (
          <CostDetail filters={detailFilters} onFilters={setDetailFilters} />
        ) : (
          <CostConfigs />
        )}
      </main>
    </ConsoleWindow>
  );
}
