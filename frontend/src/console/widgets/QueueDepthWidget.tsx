/** QueueDepthWidget -- task counts by status.
 *
 * GET /tasks/queue-depth returns a map of task status -> count. Only present
 * statuses come back; absent ones are omitted (not zero). We render every
 * present status in the canonical order below, colored by tone. */

import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { css } from "../css";
import type { WidgetProps } from "./types";

const CANONICAL: readonly string[] = [
  "queued",
  "waiting",
  "running",
  "paused",
  "done",
  "failed",
  "cancelled",
  "dead_letter",
];

function toneFor(status: string): string {
  if (status === "running") return "var(--status-info)";
  if (status === "failed" || status === "dead_letter") return "var(--status-warn)";
  if (status === "done") return "var(--status-ok)";
  return "var(--text-muted)";
}

const ROOT = css(
  "flex:1;min-height:0;display:flex;flex-direction:column;overflow:auto;" +
  "padding:10px 12px;background:var(--surface-card);" +
  "font-family:var(--font-mono);color:var(--text-primary);gap:6px;",
);

const LABEL = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;" +
  "color:var(--text-faint);margin-bottom:4px;",
);

const ROW = css(
  "display:flex;align-items:baseline;justify-content:space-between;gap:8px;" +
  "font-size:11px;line-height:1.4;",
);

const EMPTY = css("font-size:11px;color:var(--text-faint);padding:6px 0;");

export default function QueueDepthWidget(_props: WidgetProps): JSX.Element {
  const q = useQuery({
    queryKey: ["tasks", "queue-depth"],
    queryFn: () => apiFetch<Record<string, number>>("/tasks/queue-depth"),
    staleTime: 15000,
  });

  if (q.isLoading) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>task queue by status</div>
        <div style={EMPTY}>loading...</div>
      </div>
    );
  }
  if (q.isError) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>task queue by status</div>
        <div style={{ ...EMPTY, color: "var(--status-warn)" }}>failed to load</div>
      </div>
    );
  }

  const map = q.data ?? {};
  const present = CANONICAL.filter((s) => Object.prototype.hasOwnProperty.call(map, s));

  if (present.length === 0) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>task queue by status</div>
        <div style={EMPTY}>no active tasks</div>
      </div>
    );
  }

  return (
    <div style={ROOT}>
      <div style={LABEL}>task queue by status</div>
      {present.map((s) => (
        <div key={s} style={ROW}>
          <span style={{ color: toneFor(s), textTransform: "uppercase", letterSpacing: "0.06em" }}>
            {s}
          </span>
          <span style={{ color: "var(--text-primary)", fontVariantNumeric: "tabular-nums" }}>
            {map[s]}
          </span>
        </div>
      ))}
    </div>
  );
}
