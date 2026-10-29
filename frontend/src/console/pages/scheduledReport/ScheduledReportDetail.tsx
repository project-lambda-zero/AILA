/** Detail body for the `admin:scheduled-reports` DataPage, rendered in place
 * of its generic grid. Shows the last run, a manual trigger + live task
 * status, then a 140px/1fr field grid. */

import { useEffect, useState } from "react";
import type { JSX } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../api/client";
import type { ScheduledReportTriggerResponse } from "../../../api/scheduledReports";
import { TASK_TERMINAL, useScheduledReportTask } from "../../../api/scheduledReports";
import { css } from "../../css";
import { apiErrMessage } from "../../wizards";
import { humanizeCron } from "../cronPreview";
import { StructuredValue } from "../StructuredValue";

const detailChip = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-size:11px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
);
const detailLabel = css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;");
const detailValue = css(
  "color:var(--text-primary);word-break:break-word;min-width:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap;",
);

export function ScheduledReportDetail({ row }: { row: Record<string, unknown> }): JSX.Element {
  const id = String(row["id"] ?? "");
  const reportType = String(row["report_type"] ?? "");
  const cronExpr = String(row["cron_expression"] ?? "");
  const isActive = row["is_active"] === true;
  const lastRunAt = row["last_run_at"] ? String(row["last_run_at"]) : null;
  const createdAt = String(row["created_at"] ?? "");
  const updatedAt = String(row["updated_at"] ?? "");

  const qc = useQueryClient();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [manualQueued, setManualQueued] = useState<boolean>(false);
  const [runOutcome, setRunOutcome] = useState<{ ok: boolean; text: string } | null>(null);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  // The caller keys this component per row; also guard in an effect so a new
  // selection never inherits the previous row's trigger/task state.
  useEffect(() => {
    setTaskId(null);
    setManualQueued(false);
    setRunOutcome(null);
    setTriggerError(null);
  }, [id]);

  const triggerMut = useMutation({
    mutationFn: () =>
      apiFetch<ScheduledReportTriggerResponse>(
        `/scheduled-reports/${encodeURIComponent(id)}/trigger`,
        { method: "POST" },
      ),
    onSuccess: (resp) => {
      setTriggerError(null);
      setRunOutcome(null);
      if (resp.task_id === "manual") {
        // No worker attached: the run happens on the next worker cycle, so
        // there is nothing to poll.
        setManualQueued(true);
        setTaskId(null);
        return;
      }
      setManualQueued(false);
      setTaskId(resp.task_id);
    },
    onError: (err) => setTriggerError(apiErrMessage(err)),
  });

  const taskQ = useScheduledReportTask(taskId);

  // When the polled task reaches a terminal state, stop and surface the
  // result; a done run refreshes the row so `last_run_at` updates.
  useEffect(() => {
    const task = taskQ.data;
    if (taskId === null || !task || !TASK_TERMINAL[task.status]) return;
    if (task.status === "done") {
      void qc.invalidateQueries({ queryKey: ["datapage", "/scheduled-reports"] });
      setRunOutcome({ ok: true, text: "run finished -- last_run_at refreshes on the row" });
    } else {
      setRunOutcome({ ok: false, text: `run ${task.status}${task.error ? ` \u2014 ${task.error}` : ""}` });
    }
    setTaskId(null);
  }, [taskQ.data, taskId, qc]);

  const onTrigger = (): void => {
    if (!window.confirm("Trigger this report now?")) return;
    setTriggerError(null);
    setManualQueued(false);
    setRunOutcome(null);
    triggerMut.mutate();
  };

  const pollStatus = taskId !== null ? (taskQ.data?.status ?? "queued") : null;

  /* ---- parsed row fields ------------------------------------------------ */

  const recipientsRaw = String(row["recipient_emails_json"] ?? "");
  let recipientList: string[] | null = null;
  try {
    const parsed: unknown = JSON.parse(recipientsRaw);
    if (Array.isArray(parsed)) recipientList = parsed.map(String);
  } catch {
    recipientList = null;
  }

  const configRaw = row["config_json"];
  let configParsed: unknown = null;
  let configRawStr = "";
  if (configRaw !== undefined && configRaw !== null) {
    configRawStr = String(configRaw);
    try {
      configParsed = JSON.parse(configRawStr);
    } catch {
      configParsed = null;
    }
  }

  /* ---- render ----------------------------------------------------------- */

  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;min-width:0;")}>
      <div
        style={css(
          "padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);display:flex;flex-direction:column;gap:4px;",
        )}
      >
        <span style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
          last run
        </span>
        <span style={css("font-size:13px;color:var(--text-primary);font-family:var(--font-mono);")}>
          {lastRunAt ?? "never"}
        </span>
      </div>

      <div style={css("display:flex;flex-direction:column;gap:8px;")}>
        <button
          type="button"
          onClick={onTrigger}
          disabled={id === "" || triggerMut.isPending}
          style={css(
            `align-self:flex-start;padding:0 14px;height:30px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:2px;cursor:${
              id === "" || triggerMut.isPending ? "not-allowed" : "pointer"
            };`,
          )}
        >
          {"trigger now"}
        </button>
        {triggerError ? (
          <span style={css("font-size:11px;color:var(--status-warn);")}>{triggerError}</span>
        ) : null}
        {manualQueued ? (
          <span style={css("font-size:11px;color:var(--text-muted);")}>
            {"queued -- no worker attached; the run happens on the next worker cycle"}
          </span>
        ) : null}
        {pollStatus !== null ? (
          <span style={css("font-size:11px;color:var(--text-muted);font-family:var(--font-mono);")}>
            {pollStatus}
          </span>
        ) : null}
        {runOutcome ? (
          <span
            style={css(
              `font-size:11px;${runOutcome.ok ? "color:var(--status-ok);" : "color:var(--status-warn);"}`,
            )}
          >
            {runOutcome.text}
          </span>
        ) : null}
      </div>

      <div
        style={css(
          "display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11px;align-content:start;",
        )}
      >
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>name</span>
          <span style={detailValue}>{String(row["name"] ?? "\u2014")}</span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>report type</span>
          <span style={detailValue}>
            <span style={css("font-family:var(--font-mono);")}>{reportType || "\u2014"}</span>
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>recipients</span>
          <span style={detailValue}>
            {recipientList !== null ? (
              recipientList.length > 0 ? (
                recipientList.map((r) => (
                  <span key={r} style={detailChip}>
                    {r}
                  </span>
                ))
              ) : (
                "\u2014"
              )
            ) : (
              recipientsRaw
            )}
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>options</span>
          <span style={detailValue}>
            {configParsed !== null ? (
              <StructuredValue value={configParsed} />
            ) : (
              (configRawStr || "\u2014")
            )}
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>cron</span>
          <span style={detailValue}>
            <span style={css("font-family:var(--font-mono);")}>{cronExpr || "\u2014"}</span>
            {cronExpr ? (
              <span style={css("color:var(--text-faint);font-size:11px;")}>{humanizeCron(cronExpr)}</span>
            ) : null}
          </span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>active</span>
          <span style={detailValue}>{isActive ? "yes" : "no"}</span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>created</span>
          <span style={detailValue}>{createdAt}</span>
        </span>
        <span style={{ display: "contents" }}>
          <span style={detailLabel}>updated</span>
          <span style={detailValue}>{updatedAt}</span>
        </span>
      </div>
    </div>
  );
}
