/** BoundCaseWidget -- summary of the currently bound investigation.
 *
 * Reads live investigations from GET /investigations via `useInvestigations`
 * and finds the row whose id matches `props.boundId`. Renders the module,
 * short case id (`shortCaseId(moduleId, id)`), state (status || phase),
 * updated_at wall clock, and branch_count. No fabrication: when the bind
 * is null or the id is unknown the widget shows an honest empty state. */

import type { JSX } from "react";

import { useInvestigations } from "../../api/hooks";
import { css } from "../css";
import { shortCaseId } from "../ids";
import type { WidgetProps } from "./types";

const ROOT = css(
  "flex:1;min-height:0;display:flex;flex-direction:column;overflow:auto;" +
  "padding:10px 12px;background:var(--surface-card);" +
  "font-family:var(--font-mono);color:var(--text-primary);gap:8px;",
);

const LABEL = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;" +
  "color:var(--text-faint);",
);

const ROW = css(
  "display:flex;align-items:baseline;justify-content:space-between;gap:8px;" +
  "font-size:11px;line-height:1.4;",
);

const KEY = css("color:var(--text-muted);");
const VAL = css("color:var(--text-primary);font-variant-numeric:tabular-nums;");
const EMPTY = css("font-size:11px;color:var(--text-faint);padding:6px 0;");

function formatTime(iso: string | undefined | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

export default function BoundCaseWidget(props: WidgetProps): JSX.Element {
  const { moduleId, boundId, onUnbind } = props;
  const q = useInvestigations();

  if (q.isLoading) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>bound case</div>
        <div style={EMPTY}>loading investigations...</div>
      </div>
    );
  }
  if (q.isError) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>bound case</div>
        <div style={{ ...EMPTY, color: "var(--status-warn)" }}>
          failed to load investigations
        </div>
      </div>
    );
  }
  if (!boundId) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>bound case</div>
        <div style={EMPTY}>no bound investigation</div>
      </div>
    );
  }

  const inv = (q.data ?? []).find((row) => row.id === boundId);
  if (!inv) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>bound case</div>
        <div style={EMPTY}>no bound investigation</div>
      </div>
    );
  }

  const state = inv.status ?? inv.phase ?? "?";
  const lastUpdate = formatTime(inv.updated_at);
  const branches = inv.branch_count ?? 0;

  return (
    <div style={ROOT}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={LABEL}>bound case</div>
        {onUnbind ? (
          <button
            type="button"
            onClick={onUnbind}
            title="Unbind this investigation"
            style={{
              background: "transparent",
              border: "1px solid var(--border-soft)",
              borderRadius: "2px",
              color: "var(--text-faint)",
              fontFamily: "var(--font-mono)",
              fontSize: "8.5px",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              padding: "1px 5px",
              cursor: "pointer",
            }}
          >
            unbind
          </button>
        ) : null}
      </div>
      <div style={ROW}>
        <span style={KEY}>module</span>
        <span style={VAL}>{moduleId}</span>
      </div>
      <div style={ROW}>
        <span style={KEY}>id</span>
        <span style={VAL}>{shortCaseId(moduleId, inv.id)}</span>
      </div>
      <div style={ROW}>
        <span style={KEY}>state</span>
        <span style={VAL}>{state}</span>
      </div>
      <div style={ROW}>
        <span style={KEY}>last update</span>
        <span style={VAL}>{lastUpdate || "--"}</span>
      </div>
      <div style={ROW}>
        <span style={KEY}>live branches</span>
        <span style={VAL}>{branches}</span>
      </div>
    </div>
  );
}
