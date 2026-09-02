/**
 * In-window drill-down for the VR workspaces page: selecting a workspace row
 * lists the targets scoped to that workspace (server-side `?workspace_id=`
 * filter), and expanding a target reveals its investigations (reusing
 * TargetInvestigations), each of which raises the module's X-Ray. The whole
 * Workspace -> Target -> Investigation drill happens inside the detail panel,
 * so the operator never hops out through the top-level targets list
 * (req 4 / vr-navigation-ia AC3).
 */
import { useState } from "react";
import type { CSSProperties, JSX } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import type { Investigation } from "../../api/types";
import { css } from "../css";
import TargetInvestigations from "./TargetInvestigations";

interface WorkspaceTarget {
  id: string;
  display_name?: string | null;
  kind?: string | null;
  status?: string | null;
  analysis_state?: string | null;
}

export interface WorkspaceTargetsProps {
  workspaceId: string;
  /** Targets list endpoint carrying the `workspace_id` filter (e.g. "/vr/targets"). */
  targetsEndpoint: string;
  /** Investigations list endpoint carrying the `target_id` filter (e.g. "/vr/investigations"). */
  investigationsEndpoint: string;
  /** Opens the X-Ray for one investigation. Caller wires the module key. */
  onOpenXray: (inv: Investigation) => void;
}

function targetRowCss(active: boolean): CSSProperties {
  return css(
    `display:flex;align-items:center;gap:8px;padding:6px 9px;border:0;border-bottom:1px solid var(--border-faint);background:${active ? "var(--surface-hover)" : "transparent"};color:var(--text-primary);font-family:var(--font-mono);font-size:10px;text-align:left;cursor:pointer;width:100%;`,
  );
}

function toneFor(t: WorkspaceTarget): string {
  const state = (t.analysis_state ?? t.status ?? "").toLowerCase();
  if (state.includes("fail") || state.includes("error")) return "var(--status-warn)";
  if (state.includes("ready") || state.includes("complete") || state.includes("done") || state.includes("active")) return "var(--status-ok)";
  return "var(--text-faint)";
}

export default function WorkspaceTargets({ workspaceId, targetsEndpoint, investigationsEndpoint, onOpenXray }: WorkspaceTargetsProps): JSX.Element {
  const [openTarget, setOpenTarget] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["workspace-targets", targetsEndpoint, workspaceId],
    queryFn: () => apiFetch<WorkspaceTarget[]>(`${targetsEndpoint}?workspace_id=${encodeURIComponent(workspaceId)}&limit=100`),
    enabled: Boolean(workspaceId),
    retry: false,
    refetchInterval: 15000,
  });

  if (q.isLoading) {
    return <div style={css("grid-column:1/-1;color:var(--text-faint);font-size:10px;")}>loading targets&#8230;</div>;
  }
  if (q.isError) {
    return (
      <div style={css("grid-column:1/-1;color:var(--status-warn);font-size:10px;")}>
        could not load targets &mdash; {q.error instanceof Error ? q.error.message : "request failed"}
      </div>
    );
  }
  const targets = q.data ?? [];
  if (targets.length === 0) {
    return <div style={css("grid-column:1/-1;color:var(--text-faint);font-size:10px;")}>no targets in this workspace.</div>;
  }

  return (
    <div style={css("grid-column:1/-1;display:flex;flex-direction:column;gap:2px;min-width:0;")}>
      <div style={css("font-size:8px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:2px;")}>
        targets ({targets.length})
      </div>
      {targets.map((t) => {
        const active = openTarget === t.id;
        const label = t.display_name ?? t.id;
        return (
          <div key={t.id} style={css("display:flex;flex-direction:column;min-width:0;")}>
            <button
              type="button"
              aria-expanded={active}
              title={`${active ? "hide" : "show"} investigations for ${label}`}
              onClick={() => setOpenTarget((cur) => (cur === t.id ? null : t.id))}
              style={targetRowCss(active)}
            >
              <span style={css(`flex:0 0 auto;width:6px;height:6px;border-radius:1px;background:${toneFor(t)};`)} />
              <span style={css("flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{label}</span>
              <span style={css("flex:0 0 auto;font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{t.kind ?? "\u2014"}</span>
              <span style={css("flex:0 0 auto;font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{t.analysis_state ?? t.status ?? "\u2014"}</span>
              <span style={css("flex:0 0 auto;font-size:10px;color:var(--text-muted);")}>{active ? "\u25be" : "\u25b8"}</span>
            </button>
            {active ? (
              <div style={css("display:grid;padding:4px 0 6px 15px;")}>
                <TargetInvestigations targetId={t.id} endpoint={investigationsEndpoint} onOpenXray={onOpenXray} />
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
