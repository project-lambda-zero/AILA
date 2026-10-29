/**
 * Shared scaffolding for the forensics project tabs: tab props, the
 * loading/error/empty state line, the table + detail split layout, filter
 * labels, the timeline confidence options, and the Bearer-authenticated
 * download button.
 */
import type { JSX, ReactNode } from "react";

import { useMutation } from "@tanstack/react-query";

import { downloadForensicsFile } from "../../../../api/forensics";
import { apiErrDetail, asRecord } from "../../../../api/parse";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { CtlBtn, KV, Panel, emptyNote } from "../panels";

export interface TabProps {
  projectId: string;
  /** Sub-route callback shared with the page-level router (opens the
   *  Investigations drill-down via `section="inv:<id>"`). */
  onOpenInvestigation: (investigationId: string) => void;
}

/** Loading / error / empty placeholder for a tab query, or `null` when the
 * table should render. A plain function (not a component) so callers can
 * write `queryState(...) ?? <DataTable ... />`. */
export function queryState(
  q: { isLoading: boolean; isError: boolean; error: unknown },
  emptyLabel: string,
  endpoint: string,
  empty: boolean,
): JSX.Element | null {
  if (q.isLoading) return <div style={emptyNote}>{"loading\u2026"}</div>;
  if (q.isError) {
    const msg = q.error instanceof Error ? q.error.message : "request failed";
    return (
      <div style={emptyNote}>
        could not load {endpoint} &mdash; {msg}
      </div>
    );
  }
  if (empty) return <div style={emptyNote}>{emptyLabel}</div>;
  return null;
}

export const CONF_OPTIONS = [
  { value: "low", label: "low (any event-time)" },
  { value: "medium", label: "medium (default)" },
  { value: "high", label: "high (confirmed only)" },
];

/** Uppercase section caption used above detail sub-blocks. */
export const detailCaption = css(
  "font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:6px 0 4px;",
);

/** Download control: fetches `path` with the Bearer token, shows a pending
 * label while the request runs, and toasts the backend detail on failure. */
export function DownloadBtn({
  path,
  filename,
  label,
  tone = "muted",
  disabled,
}: {
  path: string;
  filename: string;
  label: string;
  tone?: "accent" | "muted";
  disabled?: boolean;
}): JSX.Element {
  const m = useMutation({
    mutationFn: () => downloadForensicsFile(path, filename),
    onError: (e) => toast.fail("download", apiErrDetail(e)),
  });
  return (
    <CtlBtn
      label={m.isPending ? "downloading\u2026" : label}
      title={filename}
      tone={tone}
      onClick={() => m.mutate()}
      disabled={disabled || m.isPending}
    />
  );
}

export function TableWithDetail<R>({
  title,
  tag,
  right,
  filters,
  table,
  detail,
  onClose,
  detailRenderer,
}: {
  title: string;
  tag?: string;
  right?: ReactNode;
  filters?: ReactNode;
  table: ReactNode;
  detail: R | null;
  onClose: () => void;
  detailRenderer?: (row: R) => ReactNode;
}): JSX.Element {
  const showDetail = detail !== null && detail !== undefined;
  return (
    <div style={css("flex:1;min-height:0;display:flex;gap:10px;flex-direction:column;")}>
      {filters ? (
        <div
          style={css(
            "display:flex;flex-wrap:wrap;gap:9px;align-items:end;padding:8px 10px;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);",
          )}
        >
          {filters}
        </div>
      ) : null}
      <div style={css("flex:1;min-height:0;display:flex;gap:10px;")}>
        <div style={{ flex: showDetail ? "1 1 62%" : "1 1 100%", minWidth: 0, display: "flex" }}>
          <Panel title={title} tag={tag} right={right}>
            {table}
          </Panel>
        </div>
        {showDetail ? (
          <div style={{ flex: "1 1 38%", minWidth: 0, display: "flex" }}>
            <Panel
              title="detail"
              right={
                <button
                  type="button"
                  onClick={onClose}
                  style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;min-height:28px;display:inline-flex;align-items:center;font-size:12px;")}
                >
                  {"\u2715"}
                </button>
              }
            >
              {detailRenderer && detail
                ? detailRenderer(detail)
                : detail
                ? (
                  <div style={css("padding:11px 13px;")}>
                    <KV entries={Object.entries(asRecord(detail) ?? {})} />
                  </div>
                )
                : null}
            </Panel>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function FilterField({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <label style={css("display:flex;flex-direction:column;gap:3px;min-width:130px;")}>
      <span style={css("font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>{label}</span>
      {children}
    </label>
  );
}
