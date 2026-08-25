/**
 * In-window drill-down for the targets pages: when a target row is selected,
 * its right-hand detail panel lists the investigations scoped to that target
 * (server-side `?target_id=` filter). Clicking an investigation opens the
 * module's X-Ray window bound to that investigation -- same scene to X-Ray,
 * no intermediate list hops.
 */
import type { CSSProperties, JSX } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import type { Investigation } from "../../api/types";
import { css } from "../css";

export interface TargetInvestigationsProps {
  targetId: string;
  /** List endpoint carrying the `target_id` filter (e.g. "/vr/investigations"). */
  endpoint: string;
  /** Opens the X-Ray for one investigation. Caller wires the module key. */
  onOpenXray: (inv: Investigation) => void;
}

function invRowCss(): CSSProperties {
  return css(
    "display:flex;align-items:center;gap:8px;padding:6px 9px;border:0;border-bottom:1px solid var(--border-faint);background:transparent;color:var(--text-primary);font-family:var(--font-mono);font-size:10px;text-align:left;cursor:pointer;width:100%;",
  );
}

export default function TargetInvestigations({ targetId, endpoint, onOpenXray }: TargetInvestigationsProps): JSX.Element {
  const q = useQuery({
    queryKey: ["target-investigations", endpoint, targetId],
    queryFn: () => apiFetch<Investigation[]>(`${endpoint}?target_id=${encodeURIComponent(targetId)}&limit=100`),
    enabled: Boolean(targetId),
    retry: false,
    refetchInterval: 15000,
  });

  if (q.isLoading) {
    return <div style={css("grid-column:1/-1;color:var(--text-faint);font-size:10px;")}>loading investigations&#8230;</div>;
  }
  if (q.isError) {
    return (
      <div style={css("grid-column:1/-1;color:var(--status-warn);font-size:10px;")}>
        could not load investigations &mdash; {q.error instanceof Error ? q.error.message : "request failed"}
      </div>
    );
  }
  const invs = q.data ?? [];
  if (invs.length === 0) {
    return <div style={css("grid-column:1/-1;color:var(--text-faint);font-size:10px;")}>no investigation is running for this target.</div>;
  }

  return (
    <div style={css("grid-column:1/-1;display:flex;flex-direction:column;gap:2px;min-width:0;")}>
      <div style={css("font-size:8px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:2px;")}>
        investigations ({invs.length})
      </div>
      {invs.map((inv) => {
        const st = (inv.status ?? "").toLowerCase();
        const tone = st === "running" ? "var(--status-ok)" : st === "paused" ? "var(--status-warn)" : "var(--text-faint)";
        return (
          <button key={inv.id} type="button" title={`open x-ray for ${inv.title}`} onClick={() => onOpenXray(inv)} style={invRowCss()}>
            <span style={css(`flex:0 0 auto;width:6px;height:6px;border-radius:1px;background:${tone};`)} />
            <span style={css("flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{inv.title}</span>
            <span style={css("flex:0 0 auto;font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{inv.kind ?? "\u2014"}</span>
            <span style={css("flex:0 0 auto;font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{inv.status ?? "\u2014"}</span>
            {typeof inv.branch_count === "number" ? (
              <span style={css("flex:0 0 auto;font-size:8px;color:var(--text-faint);")}>{inv.branch_count} br</span>
            ) : null}
            <span style={css("flex:0 0 auto;font-size:10px;color:var(--text-muted);")}>{"\u25b8"}</span>
          </button>
        );
      })}
    </div>
  );
}
