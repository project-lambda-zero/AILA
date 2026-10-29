/** Step 5 (review) and the post-create confirmation panel for the
 * scheduled-report wizard. */

import type { ChangeEvent, JSX } from "react";

import type { ScheduledReportKind, ScheduledReportRow } from "../../../api/scheduledReports";
import { css } from "../../css";
import { helpText } from "../../wizards";
import { formatFireTime, humanizeCron } from "../cronPreview";
import { kvObjectFromRows } from "./fields";
import type { KVRow } from "./fields";

/** Step 5: the review grid the operator confirms before submit. */
export function ReportReview({
  name,
  selectedKind,
  typedOptions,
  kvRows,
  recipients,
  cronExpr,
  cronRuns,
  isActive,
  onToggleActive,
}: {
  name: string;
  selectedKind: ScheduledReportKind | null;
  typedOptions: Record<string, string | boolean>;
  kvRows: KVRow[];
  recipients: string[];
  cronExpr: string;
  cronRuns: Date[];
  isActive: boolean;
  onToggleActive: (active: boolean) => void;
}): JSX.Element {
  const humanCron = cronExpr ? humanizeCron(cronExpr) : "\u2014";
  const optionLines: Array<[string, string]> =
    selectedKind && selectedKind.config_schema.length > 0
      ? Object.entries(typedOptions).map(([k, v]) => [k, String(v)] as [string, string])
      : Object.entries(kvObjectFromRows(kvRows)).map(([k, v]) => [k, String(v)] as [string, string]);
  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <p style={helpText}>
        {"review the report below; step 5 submits `POST /scheduled-reports`. the server re-validates the cron and stores the recipient + config payloads as serialized JSON."}
      </p>
      <div
        style={css(
          "padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11.5px;",
        )}
      >
        <span style={css("color:var(--text-faint);")}>name</span>
        <span style={css("color:var(--text-primary);")}>{name}</span>
        <span style={css("color:var(--text-faint);")}>report kind</span>
        <span style={css("color:var(--text-primary);")}>
          {selectedKind ? (
            <>
              {selectedKind.name}{" "}
              <span style={css("color:var(--text-faint);font-family:var(--font-mono);")}>{selectedKind.report_type}</span>
            </>
          ) : (
            "\u2014"
          )}
        </span>
        <span style={css("color:var(--text-faint);")}>options</span>
        <span style={css("color:var(--text-primary);display:flex;flex-direction:column;gap:2px;font-family:var(--font-mono);font-size:11px;")}>
          {optionLines.length > 0
            ? optionLines.map(([k, v]) => <span key={k}>{`${k} = ${v}`}</span>)
            : <span style={css("color:var(--text-faint);font-family:var(--font-mono);")}>{"(none)"}</span>}
        </span>
        <span style={css("color:var(--text-faint);")}>recipients</span>
        <span style={css("color:var(--text-primary);display:flex;flex-wrap:wrap;gap:4px;")}>
          {recipients.map((r) => (
            <span
              key={r}
              style={css(
                "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-size:11px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
              )}
            >
              {r}
            </span>
          ))}
        </span>
        <span style={css("color:var(--text-faint);")}>cron</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{cronExpr || "\u2014"}</span>
        <span style={css("color:var(--text-faint);")}>plain english</span>
        <span style={css("color:var(--text-primary);")}>{humanCron}</span>
        <span style={css("color:var(--text-faint);")}>next runs</span>
        <span style={css("color:var(--text-primary);display:flex;flex-direction:column;gap:2px;")}>
          {cronRuns.length > 0
            ? cronRuns.map((d) => <span key={d.toISOString()}>{formatFireTime(d)}</span>)
            : <span style={css("color:var(--status-warn);")}>{"no fire time in the next 370 days"}</span>}
        </span>
        <span style={css("color:var(--text-faint);")}>active</span>
        <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
          <input
            type="checkbox"
            checked={isActive}
            onChange={(e: ChangeEvent<HTMLInputElement>): void => onToggleActive(e.target.checked)}
          />
          {isActive ? "yes -- the scheduler will pick this up on its next tick" : "no -- created but paused"}
        </label>
      </div>
    </div>
  );
}

/** Post-submit confirmation panel: the created report's server-side fields. */
export function CreatedPanel({ created, recipients }: { created: ScheduledReportRow; recipients: string[] }): JSX.Element {
  return (
    <div
      style={css(
        "display:flex;flex-direction:column;gap:12px;padding:14px;border:1px solid var(--status-ok);border-radius:3px;background:color-mix(in srgb,var(--status-ok) 8%,transparent);",
      )}
    >
      <div style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--status-ok);")}>
        {"report created"}
      </div>
      <div style={css("display:grid;grid-template-columns:130px 1fr;gap:5px 12px;font-size:11.5px;")}>
        <span style={css("color:var(--text-faint);")}>id</span>
        <span style={css("color:var(--text-primary);word-break:break-all;")}>{String(created.id)}</span>
        <span style={css("color:var(--text-faint);")}>name</span>
        <span style={css("color:var(--text-primary);")}>{created.name}</span>
        <span style={css("color:var(--text-faint);")}>report type</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.report_type}</span>
        <span style={css("color:var(--text-faint);")}>cron</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.cron_expression}</span>
        <span style={css("color:var(--text-faint);")}>plain english</span>
        <span style={css("color:var(--text-primary);")}>{humanizeCron(created.cron_expression)}</span>
        <span style={css("color:var(--text-faint);")}>recipients</span>
        <span style={css("color:var(--text-primary);")}>{recipients.length} address{recipients.length === 1 ? "" : "es"}</span>
        <span style={css("color:var(--text-faint);")}>active</span>
        <span style={css("color:var(--text-primary);")}>{created.is_active ? "yes" : "no"}</span>
      </div>
    </div>
  );
}
