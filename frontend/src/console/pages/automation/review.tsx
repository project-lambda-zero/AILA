/** Step 5 (review) and the post-create confirmation panel for the automation
 * wizard. */

import type { ChangeEvent, JSX } from "react";

import type { AutomationActionInfo, AutomationSchedule } from "../../../api/automation";
import { css } from "../../css";
import { helpText } from "../../wizards";
import { formatFireTime, humanizeCron } from "../cronPreview";

/** Step 5: the review grid the operator confirms before submit. */
export function ScheduleReview({
  actionId,
  selectedAction,
  targetName,
  cronExpr,
  cronRuns,
  kwargsPreview,
  enabled,
  onToggleEnabled,
}: {
  actionId: string;
  selectedAction: AutomationActionInfo | null;
  targetName: string;
  cronExpr: string;
  cronRuns: Date[];
  kwargsPreview: string;
  enabled: boolean;
  onToggleEnabled: (enabled: boolean) => void;
}): JSX.Element {
  const humanCron = cronExpr ? humanizeCron(cronExpr) : "\u2014";
  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <p style={helpText}>
        {"review the schedule below; step 5 submits `POST /automation/schedules`. the server re-validates action_id, cron_expression, and target ownership."}
      </p>
      <div
        style={css(
          "padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:grid;grid-template-columns:130px 1fr;gap:6px 12px;font-size:11.5px;",
        )}
      >
        <span style={css("color:var(--text-faint);")}>action</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{actionId}</span>
        {selectedAction ? (
          <>
            <span style={css("color:var(--text-faint);")}>module</span>
            <span style={css("color:var(--text-primary);")}>{selectedAction.module_id}</span>
            <span style={css("color:var(--text-faint);")}>description</span>
            <span style={css("color:var(--text-primary);")}>{selectedAction.description}</span>
          </>
        ) : null}
        <span style={css("color:var(--text-faint);")}>target</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{targetName}</span>
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
        <span style={css("color:var(--text-faint);")}>arguments</span>
        <pre
          style={css(
            "margin:0;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;white-space:pre-wrap;word-break:break-word;",
          )}
        >
          {kwargsPreview}
        </pre>
        <span style={css("color:var(--text-faint);")}>enabled</span>
        <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e: ChangeEvent<HTMLInputElement>): void => onToggleEnabled(e.target.checked)}
          />
          {enabled ? "yes -- the runner will pick this up on its next tick" : "no -- created but paused"}
        </label>
      </div>
    </div>
  );
}

/** Post-submit confirmation panel: the created schedule's server-side fields. */
export function CreatedSchedulePanel({ created }: { created: AutomationSchedule }): JSX.Element {
  return (
    <div
      style={css(
        "display:flex;flex-direction:column;gap:12px;padding:14px;border:1px solid var(--status-ok);border-radius:3px;background:color-mix(in srgb,var(--status-ok) 8%,transparent);",
      )}
    >
      <div style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--status-ok);")}>
        {"schedule created"}
      </div>
      <div style={css("display:grid;grid-template-columns:130px 1fr;gap:5px 12px;font-size:11.5px;")}>
        <span style={css("color:var(--text-faint);")}>id</span>
        <span style={css("color:var(--text-primary);word-break:break-all;")}>{String(created.id)}</span>
        <span style={css("color:var(--text-faint);")}>action</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.action_id}</span>
        <span style={css("color:var(--text-faint);")}>target</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.target_name}</span>
        <span style={css("color:var(--text-faint);")}>cron</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{created.cron_expression}</span>
        <span style={css("color:var(--text-faint);")}>plain english</span>
        <span style={css("color:var(--text-primary);")}>{humanizeCron(created.cron_expression)}</span>
        <span style={css("color:var(--text-faint);")}>enabled</span>
        <span style={css("color:var(--text-primary);")}>{created.enabled ? "yes" : "no"}</span>
      </div>
    </div>
  );
}
