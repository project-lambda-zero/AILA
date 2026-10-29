/** ML-Ops lifecycle console over /admin/lifecycle/* (god-tier admin): pick a
 * prompt key, inspect its per-version metrics, transition journal, shadow
 * report and cohort routing, and drive every lifecycle action the router
 * exposes. Promote, rollback and canary change what production traffic runs,
 * so they arm on the first click and commit on the second. */
import { useState } from "react";
import type { JSX } from "react";

import {
  useCanarySignal,
  useCohortRoute,
  useLifecycleAction,
  useLifecycleTransitions,
  usePromptKeys,
  useShadowReport,
  useShadowRun,
  useVersionMetrics,
} from "../../../api/admin";
import type { LifecycleAction, LifecycleTransition, VersionMetricsRow } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { toast } from "../../toast";
import { ActButton, ConfirmButton, actionRow, fieldStyle, formLabel } from "../xray/actions";
import { AdminWindow, FAINT, Field, KvGrid, MONO, QueryState, Section, SubmitButton, Table, fmtTime } from "./kit";

export default function LifecyclePage(props: ModulePageProps): JSX.Element {
  const keysQ = usePromptKeys();
  const [keyDraft, setKeyDraft] = useState("");
  const [key, setKey] = useState("");
  const [version, setVersion] = useState("");
  const [reason, setReason] = useState("");
  const [benchmarkId, setBenchmarkId] = useState("");
  const [targetVersion, setTargetVersion] = useState("");
  const [cohort, setCohort] = useState("10");
  const [drift, setDrift] = useState("0");
  const [cost, setCost] = useState("0");
  const [sampleN, setSampleN] = useState("5");
  const [invDraft, setInvDraft] = useState("");
  const [invId, setInvId] = useState("");

  const metricsQ = useVersionMetrics(key);
  const transitionsQ = useLifecycleTransitions(key);
  const shadowQ = useShadowReport(key, version);
  const routeQ = useCohortRoute(key, invId);
  const action = useLifecycleAction();
  const signal = useCanarySignal();
  const shadowRun = useShadowRun();

  const busy = action.isPending;
  const canAct = key !== "" && version.trim() !== "";
  const cohortN = Number(cohort);
  const pendingAction = action.isPending ? (action.variables?.action ?? null) : null;

  const run = (a: LifecycleAction): void => {
    action.mutate(a, {
      onSuccess: (t) => toast.success(`${a.action}: ${t.key} v${t.version} ${t.from_stage} → ${t.to_stage}`),
      onError: (e) => toast.fail(a.action, e),
    });
  };
  const base = { key, version: version.trim(), reason };

  const metricColumns = [
    { label: "version", cell: (r: VersionMetricsRow) => r.version },
    { label: "stage", cell: (r: VersionMetricsRow) => r.latest_stage ?? "—" },
    { label: "eval", cell: (r: VersionMetricsRow) => r.eval_verdict ?? "—" },
    { label: "approvers", cell: (r: VersionMetricsRow) => `${r.approver_count} / ${r.evaluated_count}` },
    { label: "quorum", cell: (r: VersionMetricsRow) => `${(r.quorum_accept_rate * 100).toFixed(0)}%` },
    { label: "cost", cell: (r: VersionMetricsRow) => `$${r.cost_usd_total.toFixed(4)} (${r.cost_call_count})` },
    { label: "drift", cell: (r: VersionMetricsRow) => r.drift_status ?? "—" },
  ] as const;

  const transitionColumns = [
    { label: "when", cell: (t: LifecycleTransition) => fmtTime(t.created_at) },
    { label: "version", cell: (t: LifecycleTransition) => t.version },
    { label: "transition", cell: (t: LifecycleTransition) => `${t.from_stage} → ${t.to_stage}` },
    { label: "actor", cell: (t: LifecycleTransition) => t.actor },
    { label: "reason", cell: (t: LifecycleTransition) => t.reason || "—" },
  ] as const;

  return (
    <AdminWindow page={props}>
      <form
        style={actionRow}
        onSubmit={(e) => {
          e.preventDefault();
          setKey(keyDraft.trim());
          setVersion("");
          setInvId("");
        }}
      >
        <span style={formLabel}>prompt key</span>
        <input
          list="lifecycle-keys"
          value={keyDraft}
          onChange={(e) => setKeyDraft(e.target.value)}
          placeholder="e.g. vr.researcher.system"
          style={{ ...fieldStyle, width: 340 }}
        />
        <datalist id="lifecycle-keys">
          {(keysQ.data ?? []).map((k) => (
            <option key={k.key} value={k.key} />
          ))}
        </datalist>
        <SubmitButton label="load" disabled={keyDraft.trim() === ""} />
      </form>

      {key === "" ? (
        <div style={css(FAINT + "font-size:11px;")}>Load a prompt key to inspect its lifecycle.</div>
      ) : (
        <>
          <Section title={`versions · ${key}`}>
            <QueryState loading={metricsQ.isLoading} error={metricsQ.error} empty={(metricsQ.data ?? []).length === 0} emptyText="no lifecycle activity for this key" />
            {(metricsQ.data ?? []).length > 0 ? (
              <Table
                rows={metricsQ.data ?? []}
                columns={metricColumns}
                rowKey={(r) => r.version}
                selectedKey={version}
                onRowClick={(r) => setVersion(r.version)}
              />
            ) : null}
          </Section>

          <Section title="actions">
            <div style={css("display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;")}>
              <Field label="version">
                <input value={version} onChange={(e) => setVersion(e.target.value)} style={fieldStyle} />
              </Field>
              <Field label="benchmark id (evaluate)">
                <input value={benchmarkId} onChange={(e) => setBenchmarkId(e.target.value)} style={fieldStyle} />
              </Field>
              <Field label="rollback target (optional)">
                <input value={targetVersion} onChange={(e) => setTargetVersion(e.target.value)} style={fieldStyle} />
              </Field>
              <Field label="canary cohort %">
                <input type="number" min={1} max={100} value={cohort} onChange={(e) => setCohort(e.target.value)} style={fieldStyle} />
              </Field>
            </div>
            <Field label="reason">
              <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={4096} style={fieldStyle} />
            </Field>
            <div style={actionRow}>
              <ActButton
                label="evaluate"
                tone="accent"
                pending={pendingAction === "evaluate"}
                disabled={!canAct || benchmarkId.trim() === "" || busy}
                onClick={() => run({ action: "evaluate", body: { key, version: version.trim(), benchmark_id: benchmarkId.trim() } })}
              />
              <ActButton label="approve" tone="ok" pending={pendingAction === "approve"} disabled={!canAct || busy} onClick={() => run({ action: "approve", body: base })} />
              <ActButton label="shadow" pending={pendingAction === "shadow"} disabled={!canAct || busy} onClick={() => run({ action: "shadow", body: base })} />
              <ConfirmButton
                label="canary"
                confirmLabel={`confirm canary ${cohortN}%`}
                pending={pendingAction === "canary"}
                disabled={!canAct || busy || !Number.isInteger(cohortN) || cohortN < 1 || cohortN > 100}
                onConfirm={() => run({ action: "canary", body: { ...base, cohort_percent: cohortN } })}
              />
              <ConfirmButton
                label="promote"
                confirmLabel="confirm promote to production"
                pending={pendingAction === "promote"}
                disabled={!canAct || busy}
                onConfirm={() => run({ action: "promote", body: base })}
              />
              <ConfirmButton
                label="rollback"
                confirmLabel="confirm rollback"
                pending={pendingAction === "rollback"}
                disabled={!canAct || busy}
                onConfirm={() => run({ action: "rollback", body: { ...base, target_version: targetVersion.trim() || null } })}
              />
            </div>
            <div style={css("display:flex;gap:18px;flex-wrap:wrap;align-items:flex-end;padding-top:6px;border-top:1px solid var(--border-soft);")}>
              <div style={actionRow}>
                <Field label="drift">
                  <input type="number" min={0} step="any" value={drift} onChange={(e) => setDrift(e.target.value)} style={{ ...fieldStyle, width: 90 }} />
                </Field>
                <Field label="cost usd">
                  <input type="number" min={0} step="any" value={cost} onChange={(e) => setCost(e.target.value)} style={{ ...fieldStyle, width: 90 }} />
                </Field>
                <ActButton
                  label="send canary signal"
                  pending={signal.isPending}
                  disabled={key === "" || Number(drift) < 0 || Number(cost) < 0 || drift === "" || cost === ""}
                  onClick={() =>
                    signal.mutate(
                      { key, drift: Number(drift), cost: Number(cost) },
                      {
                        onSuccess: (r) => (r.fired ? toast.error(`canary held: ${r.reason}`) : toast.info(`canary signal: ${r.reason || "within limits"}`)),
                        onError: (e) => toast.fail("canary signal", e),
                      },
                    )
                  }
                />
              </div>
              <div style={actionRow}>
                <Field label="shadow samples">
                  <input type="number" min={1} max={100} value={sampleN} onChange={(e) => setSampleN(e.target.value)} style={{ ...fieldStyle, width: 90 }} />
                </Field>
                <ActButton
                  label="run shadow comparison"
                  pending={shadowRun.isPending}
                  disabled={!canAct || Number(sampleN) < 1 || Number(sampleN) > 100}
                  onClick={() =>
                    shadowRun.mutate(
                      { key, version: version.trim(), sample_n: Number(sampleN) },
                      {
                        onSuccess: (r) => toast.success(`shadow run: ${r.sample_succeeded}/${r.sample_attempted} samples, ${r.regressions} regressions`),
                        onError: (e) => toast.fail("shadow run", e),
                      },
                    )
                  }
                />
              </div>
            </div>
          </Section>

          {version !== "" ? (
            <Section title={`shadow report · v${version}`}>
              <QueryState loading={shadowQ.isLoading} error={shadowQ.error} empty={shadowQ.isSuccess && shadowQ.data === null} emptyText="no shadow report recorded for this version" />
              {shadowQ.data ? (
                <>
                  <KvGrid
                    rows={[
                      ["samples", `${shadowQ.data.sample_succeeded} / ${shadowQ.data.sample_attempted}`],
                      ["faithfulness", shadowQ.data.mean_faithfulness.toFixed(3)],
                      ["determinism", shadowQ.data.mean_determinism.toFixed(3)],
                      ["regressions", String(shadowQ.data.regressions)],
                      ["actor", shadowQ.data.actor],
                      ["recorded", fmtTime(shadowQ.data.created_at)],
                    ]}
                  />
                  <pre style={css(MONO + "font-size:11px;margin:0;padding:8px;background:var(--surface-sunk);border:1px solid var(--border-soft);white-space:pre-wrap;word-break:break-word;max-height:240px;overflow:auto;")}>
                    {JSON.stringify(shadowQ.data.diff_summary, null, 2)}
                  </pre>
                </>
              ) : null}
            </Section>
          ) : null}

          <Section title="cohort route">
            <form
              style={actionRow}
              onSubmit={(e) => {
                e.preventDefault();
                setInvId(invDraft.trim());
              }}
            >
              <input value={invDraft} onChange={(e) => setInvDraft(e.target.value)} placeholder="investigation id" style={{ ...fieldStyle, width: 320 }} />
              <SubmitButton label="resolve" disabled={invDraft.trim() === ""} pending={routeQ.isFetching} />
            </form>
            {invId !== "" ? (
              <>
                <QueryState loading={routeQ.isLoading} error={routeQ.error} empty={false} emptyText="" />
                {routeQ.data ? (
                  <KvGrid
                    rows={[
                      ["resolved version", routeQ.data.version ?? "—"],
                      ["bucket", String(routeQ.data.bucket)],
                      ["on canary", routeQ.data.on_canary ? "yes" : "no"],
                      ["canary version", routeQ.data.canary_version ?? "—"],
                      ["production version", routeQ.data.production_version ?? "—"],
                      ["cohort %", routeQ.data.cohort_percent == null ? "—" : String(routeQ.data.cohort_percent)],
                    ]}
                  />
                ) : null}
              </>
            ) : null}
          </Section>

          <Section title="transition journal">
            <QueryState loading={transitionsQ.isLoading} error={transitionsQ.error} empty={(transitionsQ.data ?? []).length === 0} emptyText="no transitions journaled" />
            {(transitionsQ.data ?? []).length > 0 ? (
              <Table rows={transitionsQ.data ?? []} columns={transitionColumns} rowKey={(t) => t.id} onRowClick={(t) => setVersion(t.version)} selectedKey={null} />
            ) : null}
          </Section>
        </>
      )}
    </AdminWindow>
  );
}
