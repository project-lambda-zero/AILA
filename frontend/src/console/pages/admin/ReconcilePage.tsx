/** Task state reconcile console (god-tier admin only): run one reconcile pass
 * over a stuck workflow task and see exactly which of the three sources of
 * truth (TaskRecord, workflow cursor, Redis lock) the reconciler rewrote.
 * The backend refuses non-god-tier callers with 403; the page additionally
 * hides itself for anyone but a god-tier admin. */
import { useState } from "react";
import type { JSX } from "react";

import { useIsGodTierAdmin, useReconcileTask } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { toast } from "../../toast";
import { ActButton, actionRow, fieldStyle } from "../xray/actions";
import { AdminWindow, FAINT, KvGrid, QueryState, Section, fmtTime } from "./kit";

export default function ReconcilePage(props: ModulePageProps): JSX.Element {
  const godTier = useIsGodTierAdmin();
  const [draft, setDraft] = useState("");
  const [taskId, setTaskId] = useState("");
  const reconcile = useReconcileTask();

  if (!godTier) {
    return (
      <AdminWindow page={props}>
        <div style={css(FAINT + "font-size:11px;")}>Reconcile is restricted to god-tier admins (admin with no team).</div>
      </AdminWindow>
    );
  }

  const report = reconcile.data ?? null;

  return (
    <AdminWindow page={props}>
      <Section title="reconcile task" aside={<span style={css(FAINT + "font-size:11px;")}>POST /admin/reconcile · 30/min</span>}>
        <div style={actionRow}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }} placeholder="task id" maxLength={64} style={{ ...fieldStyle, width: 340 }} />
          <ActButton
            label="run reconcile"
            tone="accent"
            pending={reconcile.isPending}
            disabled={draft.trim() === "" || taskId === draft.trim()}
            onClick={() => {
              const id = draft.trim();
              setTaskId(id);
              reconcile.mutate(id, {
                onSuccess: (r) => toast.success(r.healed ? `task ${r.task_id} healed (${r.actions.length} actions)` : `task ${r.task_id} already consistent`),
                onError: (e) => toast.fail("reconcile", e),
              });
            }}
          />
        </div>
        <QueryState loading={false} error={reconcile.error} empty={report === null} emptyText="Run a reconcile pass to see the pre-heal signals and the actions taken." />
        {report ? (
          <KvGrid
            rows={[
              ["task id", report.task_id],
              ["healed", report.healed ? "yes" : "no"],
              ["action kinds", report.action_kinds.length > 0 ? report.action_kinds.join(", ") : "none"],
            ]}
          />
        ) : null}
      </Section>

      {report ? (
        <Section title="pre-heal signals">
          <KvGrid
            rows={[
              ["task status", report.signals.task_status ?? "—"],
              ["cursor state", report.signals.cursor_state ?? "—"],
              ["lock present", report.signals.lock_present == null ? "—" : report.signals.lock_present ? "yes" : "no"],
              ["started", fmtTime(report.signals.task_started_at)],
              ["heartbeat", fmtTime(report.signals.task_heartbeat_at)],
            ]}
          />
        </Section>
      ) : null}

      {report && report.actions.length > 0 ? (
        <Section title={`actions (${report.actions.length})`}>
          <div style={css("display:flex;flex-direction:column;gap:4px;")}>
            {report.actions.map((a, idx) => (
              <div key={idx} style={css("display:flex;gap:10px;align-items:baseline;font-size:11.5px;border-bottom:1px solid var(--border-soft);padding:5px 0;")}>
                <span style={css("font-family:var(--font-mono);color:var(--accent);flex:0 0 160px;")}>{a.kind}</span>
                <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-word;")}>{a.reason}</span>
              </div>
            ))}
          </div>
        </Section>
      ) : null}
    </AdminWindow>
  );
}
