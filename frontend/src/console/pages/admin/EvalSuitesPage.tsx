/** Benchmark-suite scoreboard over /vr/eval-suites (god-tier admin): start a
 * measurement run over a published benchmark suite, watch per-task solve/cost
 * results land, and compare suites on the leaderboard. The harness reads
 * vr.eval_suite_dataset_root for the dataset manifests; see the eval_suites
 * README for the operator run steps. */
import { useState } from "react";
import type { JSX } from "react";

import {
  useCollectEvalSuiteRun,
  useEvalSuiteLeaderboard,
  useEvalSuiteRun,
  useEvalSuiteRuns,
  useStartEvalSuiteRun,
} from "../../../api/admin";
import type { LeaderboardRow, SuiteRun } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { toast } from "../../toast";
import { ActButton, actionRow, fieldStyle } from "../xray/actions";
import { AdminWindow, FAINT, Field, KvGrid, QueryState, Section, Table, fmtTime } from "./kit";

const SUITE_SUGGESTIONS = ["cybench", "nyu_ctf", "htb_lite"] as const;

export default function EvalSuitesPage(props: ModulePageProps): JSX.Element {
  const boardQ = useEvalSuiteLeaderboard();
  const runsQ = useEvalSuiteRuns();
  const start = useStartEvalSuiteRun();
  const collect = useCollectEvalSuiteRun();

  const [suite, setSuite] = useState("");
  const [openRun, setOpenRun] = useState<string | null>(null);
  const detailQ = useEvalSuiteRun(openRun);

  const boardRows = boardQ.data ?? [];
  const runRows = runsQ.data ?? [];

  const boardColumns = [
    { label: "suite", cell: (r: LeaderboardRow) => r.suite },
    {
      label: "solved",
      cell: (r: LeaderboardRow) => (
        <span style={css(`color:${r.solve_rate > 0 ? "var(--status-ok)" : "var(--text-primary)"};`)}>
          {`${r.solved_count}/${r.total_count}`}
        </span>
      ),
    },
    { label: "solve rate", cell: (r: LeaderboardRow) => `${(r.solve_rate * 100).toFixed(1)}%` },
    { label: "avg cost/task", cell: (r: LeaderboardRow) => `$${r.avg_cost_usd.toFixed(2)}` },
    { label: "last run", cell: (r: LeaderboardRow) => fmtTime(r.last_run_at) },
  ] as const;

  const runColumns = [
    { label: "suite", cell: (r: SuiteRun) => r.suite },
    { label: "status", cell: (r: SuiteRun) => r.status },
    { label: "solved", cell: (r: SuiteRun) => `${r.solved_count}/${r.total_count}` },
    { label: "cost", cell: (r: SuiteRun) => `$${r.total_cost_usd.toFixed(2)}` },
    { label: "created", cell: (r: SuiteRun) => fmtTime(r.created_at) },
  ] as const;

  const startRun = (): void => {
    start.mutate(
      { suite: suite.trim() },
      {
        onSuccess: () => {
          toast.success(`measurement run started for ${suite.trim()}`);
          setSuite("");
          void runsQ.refetch();
        },
        onError: (e) => toast.fail("start measurement run", e),
      },
    );
  };

  const opened = detailQ.data ?? null;

  return (
    <AdminWindow page={props}>
      <Section title="leaderboard">
        <QueryState loading={boardQ.isLoading} error={boardQ.error} empty={boardRows.length === 0} emptyText="no measurement runs yet -- start one below" />
        {boardRows.length > 0 ? <Table rows={boardRows} columns={boardColumns} rowKey={(r) => r.suite} /> : null}
      </Section>

      <Section title="start measurement run">
        <Field label="suite">
          <input list="eval-suite-names" value={suite} onChange={(e) => setSuite(e.target.value)} maxLength={64} style={fieldStyle} placeholder="cybench" />
        </Field>
        <datalist id="eval-suite-names">
          {SUITE_SUGGESTIONS.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
        <div style={actionRow}>
          <span style={css(FAINT + "font-size:11px;")}>{"requires vr.eval_suite_dataset_root + running VR workers (see eval_suites README)"}</span>
          <span style={css("flex:1;")} />
          <ActButton label="start run" tone="accent" disabled={suite.trim() === ""} pending={start.isPending} onClick={startRun} />
        </div>
      </Section>

      <Section title={`runs (${runRows.length})`}>
        <QueryState loading={runsQ.isLoading} error={runsQ.error} empty={runRows.length === 0} emptyText="no runs yet" />
        {runRows.length > 0 ? (
          <Table rows={runRows} columns={runColumns} rowKey={(r) => r.id} onRowClick={(r) => setOpenRun(openRun === r.id ? null : r.id)} selectedKey={openRun} />
        ) : null}
      </Section>

      {opened ? (
        <Section
          title={`run detail -- ${opened.suite}`}
          aside={
            <ActButton
              label="collect now"
              pending={collect.isPending}
              onClick={() =>
                collect.mutate(opened.id, {
                  onSuccess: () => {
                    toast.success("collect enqueued");
                    void detailQ.refetch();
                  },
                  onError: (e) => toast.fail("collect", e),
                })
              }
            />
          }
        >
          <KvGrid
            rows={[
              ["run id", opened.id],
              ["status", opened.status],
              ["solved", `${opened.solved_count}/${opened.total_count}`],
              ["total cost", `$${opened.total_cost_usd.toFixed(2)}`],
              ["created", fmtTime(opened.created_at)],
              ["finished", fmtTime(opened.finished_at)],
            ]}
          />
          {opened.results.length > 0 ? (
            <Table
              rows={opened.results}
              columns={[
                { label: "task", cell: (r) => r.task_id },
                { label: "name", cell: (r) => r.name },
                { label: "status", cell: (r) => r.status },
                {
                  label: "solved",
                  cell: (r) => (
                    <span style={css(`color:${r.solved ? "var(--status-ok)" : r.status === "scored" ? "var(--status-warn)" : "var(--text-primary)"};`)}>
                      {r.solved ? "yes" : r.status === "scored" ? "no" : "pending"}
                    </span>
                  ),
                },
                { label: "cost", cell: (r) => `$${r.cost_usd.toFixed(2)}` },
                { label: "polarity", cell: (r) => r.polarity ?? "—" },
              ]}
              rowKey={(r) => r.task_id}
            />
          ) : null}
        </Section>
      ) : null}
    </AdminWindow>
  );
}
