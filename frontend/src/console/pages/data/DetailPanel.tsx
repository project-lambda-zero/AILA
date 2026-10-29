/** The DataPage detail panel: header actions (edit/delete/row viewer/row
 * actions), the action error strip, and the field grid with detail links and
 * the optional event timeline. */

import type { JSX, ReactNode } from "react";

import { css } from "../../css";
import { StatusBadge } from "../badges";
import { EventTimeline } from "../EventTimeline";
import StructuredValue from "../StructuredValue";
import { actionBtn, H_WARN, PANEL_BOX, panelTitle, dot } from "./styles";
import type { DataRow, PageAction, PageDetailConfig } from "./types";

export interface DetailPanelProps {
  row: DataRow;
  detail: PageDetailConfig;
  /** Rendered instead of the generic field grid (bespoke drill-down body). */
  detailBody?: (row: DataRow) => ReactNode;
  rowActions: PageAction[];
  onAction: (a: PageAction, row: DataRow) => void;
  actionPending: boolean;
  actionError: Error | null;
  canEdit: boolean;
  onEdit: () => void;
  canDelete: boolean;
  onDelete: (row: DataRow) => void;
  onOpenViewer: (row: DataRow) => void;
  onOpenPage?: (moduleKey: string, section: string, label: string, investigationId?: string | null) => void;
  onClose: () => void;
}

export function DetailPanel(props: DetailPanelProps): JSX.Element {
  const {
    row: sel, detail, detailBody, rowActions, onAction, actionPending, actionError,
    canEdit, onEdit, canDelete, onDelete, onOpenViewer, onOpenPage, onClose,
  } = props;
  return (
    <div style={css("flex:1 1 38%;min-width:0;" + PANEL_BOX)}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);font-family:var(--font-display);font-weight:400;")}>detail</span>
        {sel["status"] != null ? <StatusBadge value={sel["status"]} /> : null}
        <span style={css("flex:1;")} />
        {canEdit ? (
          <button
            type="button"
            onClick={onEdit}
            style={css("min-height:28px;padding:3px 10px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
          >
            edit
          </button>
        ) : null}
        {canDelete ? (
          <button
            type="button"
            onClick={() => onDelete(sel)}
            style={css(`min-height:28px;padding:3px 10px;border:1px solid ${H_WARN}66;border-radius:2px;background:transparent;color:${H_WARN};font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`)}
          >
            delete
          </button>
        ) : null}
        {detail.rowViewer ? (
          <button
            type="button"
            onClick={() => onOpenViewer(sel)}
            style={css("min-height:28px;padding:3px 10px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
          >
            {detail.rowViewer.actionLabel}
          </button>
        ) : null}
        {rowActions.map((a) => (
          <button
            key={a.label}
            type="button"
            onClick={() => onAction(a, sel)}
            disabled={actionPending}
            style={actionBtn(a, "3px 10px")}
          >
            {a.label}
          </button>
        ))}
        <button type="button" onClick={onClose} style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;min-height:28px;display:inline-flex;align-items:center;font-size:13px;margin-left:4px;")}>
          {"\u2715"}
        </button>
      </div>
      {actionError ? (
        <div style={css("padding:6px 12px;border-bottom:1px solid #d64545;background:color-mix(in srgb,#d64545 10%,transparent);color:#d64545;font-family:var(--font-mono);font-size:11px;letter-spacing:0.02em;text-transform:none;word-break:break-word;")}>
          {actionError.message}
        </div>
      ) : null}
      <div style={css("flex:1;min-height:0;overflow:auto;padding:12px 14px;display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11px;align-content:start;")}>
        {detailBody ? (
          detailBody(sel)
        ) : (
          <>
            {Object.entries(sel).map(([k, v]) => {
              const link = detail.detailLinks?.[k];
              const linkVal = link && v != null && String(v) !== "" ? String(v) : null;
              return (
                <span key={k} style={{ display: "contents" }}>
                  <span style={css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;")}>{k}</span>
                  <span style={css("color:var(--text-primary);word-break:break-word;min-width:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap;")}>
                    {detail.detailRenderers?.[k]?.(v, sel) ?? <StructuredValue value={v} />}
                    {linkVal ? (
                      <button
                        type="button"
                        onClick={() => link && onOpenPage?.(link.module ?? "vr", link.section, link.label ?? link.section, linkVal)}
                        title={`open ${link?.section ?? ""} ${linkVal}`}
                        style={css("min-height:28px;padding:2px 7px;border:1px solid var(--accent)55;border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;")}
                      >
                        {"open \u25b8"}
                      </button>
                    ) : null}
                  </span>
                </span>
              );
            })}
            {detail.detailEvents ? (
              <span style={{ display: "contents" }}>
                <span style={css("color:var(--text-faint);letter-spacing:0.04em;")}>events</span>
                <span style={css("min-width:0;")}>
                  <EventTimeline
                    endpoint={detail.detailEvents.endpoint.replace(/{([a-zA-Z0-9_]+)}/g, (_m: string, f: string) =>
                      encodeURIComponent(String(sel[f] ?? "")),
                    )}
                    itemsKey={detail.detailEvents.itemsKey}
                  />
                </span>
              </span>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}
