/** The DataPage bulk-selection bar: shown when rows are selected on a config
 * with bulkActions; fires each action once per selected row. */

import type { JSX } from "react";

import { css } from "../../css";
import { actionBtn } from "./styles";
import type { PageAction } from "./types";

export interface BulkBarProps {
  selectedCount: number;
  bulkActions: PageAction[];
  actionPending: boolean;
  onBulk: (a: PageAction) => void;
  onClear: () => void;
  results: string | null;
}

export function BulkBar(props: BulkBarProps): JSX.Element | null {
  const { selectedCount, bulkActions, actionPending, onBulk, onClear, results } = props;
  if (bulkActions.length === 0 || selectedCount === 0) return null;
  return (
    <div style={css("display:flex;align-items:center;gap:8px;padding:6px 12px;border-bottom:1px solid var(--border-soft);background:color-mix(in srgb,var(--accent) 6%,transparent);flex-wrap:wrap;")}>
      <span style={css("font-size:11px;color:var(--accent);letter-spacing:0.06em;text-transform:uppercase;")}>{selectedCount} selected</span>
      {bulkActions.map((a) => (
        <button
          key={a.label}
          type="button"
          onClick={() => onBulk(a)}
          disabled={actionPending}
          style={actionBtn(a, "4px 10px")}
        >
          {a.label}
        </button>
      ))}
      <button
        type="button"
        onClick={onClear}
        style={css("min-height:28px;padding:3px 8px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
      >
        clear
      </button>
      {results ? <span style={css("font-size:11px;color:var(--text-muted);")}>{results}</span> : null}
    </div>
  );
}
