/** Eval benchmarks + runs over /admin/eval (god-tier admin): register a
 * benchmark of pre-scored cases, score a candidate prompt version against a
 * benchmark, and list the scored runs for a key with their verdict and report.
 * The backend has no benchmark list route, so a registered benchmark's id is
 * surfaced from the register response and from each run row. */
import { useState } from "react";
import type { JSX } from "react";

import { useEvalRuns, usePromptKeys, useRegisterBenchmark, useStartEvalRun } from "../../../api/admin";
import type { BenchmarkCase, BenchmarkInfo, EvalRun } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { toast } from "../../toast";
import { ActButton, actionRow, fieldStyle, formLabel } from "../xray/actions";
import { AdminWindow, FAINT, Field, KvGrid, MONO, QueryState, Section, SubmitButton, Table, fmtTime } from "./kit";

interface CaseDraft {
  id: number;
  outcome_kind: string;
  predicted_verdict: string;
  verified_verdict: string;
  confidence: string;
  version: string;
}

let caseSeq = 0;
function blankCase(): CaseDraft {
  caseSeq += 1;
  return { id: caseSeq, outcome_kind: "", predicted_verdict: "", verified_verdict: "", confidence: "0", version: "" };
}

const CASE_FIELDS = [
  ["outcome_kind", "outcome kind"],
  ["predicted_verdict", "predicted"],
  ["verified_verdict", "verified"],
  ["confidence", "confidence 0..1"],
  ["version", "version (optional)"],
] as const satisfies readonly (readonly [keyof Omit<CaseDraft, "id">, string])[];

function caseValid(c: CaseDraft): boolean {
  const conf = Number(c.confidence);
  return c.outcome_kind.trim() !== "" && c.predicted_verdict.trim() !== "" && c.verified_verdict.trim() !== "" && c.confidence !== "" && conf >= 0 && conf <= 1;
}

export default function EvalBenchmarksPage(props: ModulePageProps): JSX.Element {
  const keysQ = usePromptKeys();
  const register = useRegisterBenchmark();
  const start = useStartEvalRun();

  const [bKey, setBKey] = useState("");
  const [bName, setBName] = useState("");
  const [cases, setCases] = useState<CaseDraft[]>(() => [blankCase()]);
  const [registered, setRegistered] = useState<BenchmarkInfo | null>(null);

  const [rKey, setRKey] = useState("");
  const [rVersion, setRVersion] = useState("");
  const [rBenchmark, setRBenchmark] = useState("");

  const [listDraft, setListDraft] = useState("");
  const [listKey, setListKey] = useState("");
  const [openRun, setOpenRun] = useState<string | null>(null);
  const runsQ = useEvalRuns(listKey);

  const canRegister = bKey.trim() !== "" && bName.trim() !== "" && cases.length > 0 && cases.every(caseValid);
  const canRun = rKey.trim() !== "" && rVersion.trim() !== "" && rBenchmark.trim() !== "";

  const setCase = (id: number, field: keyof Omit<CaseDraft, "id">, value: string): void =>
    setCases((cur) => cur.map((c) => (c.id === id ? { ...c, [field]: value } : c)));

  const submitBenchmark = (): void => {
    const payload: BenchmarkCase[] = cases.map((c) => ({
      outcome_kind: c.outcome_kind.trim(),
      predicted_verdict: c.predicted_verdict.trim(),
      verified_verdict: c.verified_verdict.trim(),
      confidence: Number(c.confidence),
      version: c.version.trim() || null,
    }));
    register.mutate(
      { key: bKey.trim(), name: bName.trim(), cases: payload },
      {
        onSuccess: (b) => {
          setRegistered(b);
          toast.success(`benchmark ${b.name} registered (${b.case_count} cases)`);
        },
        onError: (e) => toast.fail("register benchmark", e),
      },
    );
  };

  const runColumns = [
    { label: "when", cell: (r: EvalRun) => fmtTime(r.created_at) },
    { label: "candidate", cell: (r: EvalRun) => r.candidate_version },
    { label: "baseline", cell: (r: EvalRun) => r.baseline_version ?? "—" },
    { label: "benchmark", cell: (r: EvalRun) => r.benchmark_id },
    {
      label: "verdict",
      cell: (r: EvalRun) => (
        <span style={css(`color:${r.verdict === "pass" ? "var(--status-ok)" : r.verdict === "fail" ? "var(--status-warn)" : "var(--text-primary)"};`)}>{r.verdict}</span>
      ),
    },
    { label: "actor", cell: (r: EvalRun) => r.actor },
  ] as const;

  const opened = (runsQ.data ?? []).find((r) => r.id === openRun) ?? null;

  return (
    <AdminWindow page={props}>
      <datalist id="eval-keys">
        {(keysQ.data ?? []).map((k) => (
          <option key={k.key} value={k.key} />
        ))}
      </datalist>

      <Section title="register benchmark">
        <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:8px;")}>
          <Field label="prompt key">
            <input list="eval-keys" value={bKey} onChange={(e) => setBKey(e.target.value)} maxLength={256} style={fieldStyle} />
          </Field>
          <Field label="name">
            <input value={bName} onChange={(e) => setBName(e.target.value)} maxLength={256} style={fieldStyle} />
          </Field>
        </div>
        <div style={css("display:flex;flex-direction:column;gap:6px;")}>
          <span style={formLabel}>{`cases (${cases.length})`}</span>
          {cases.map((c) => (
            <div key={c.id} style={css("display:grid;grid-template-columns:repeat(5,minmax(0,1fr)) auto;gap:6px;align-items:end;")}>
              {CASE_FIELDS.map(([field, label]) => (
                <Field key={field} label={label}>
                  <input
                    type={field === "confidence" ? "number" : "text"}
                    min={field === "confidence" ? 0 : undefined}
                    max={field === "confidence" ? 1 : undefined}
                    step={field === "confidence" ? "0.01" : undefined}
                    value={c[field]}
                    onChange={(e) => setCase(c.id, field, e.target.value)}
                    style={fieldStyle}
                  />
                </Field>
              ))}
              <ActButton label="remove" disabled={cases.length === 1} onClick={() => setCases((cur) => cur.filter((x) => x.id !== c.id))} />
            </div>
          ))}
        </div>
        <div style={actionRow}>
          <ActButton label="+ case" onClick={() => setCases((cur) => [...cur, blankCase()])} />
          <span style={css("flex:1;")} />
          <ActButton label="register" tone="accent" pending={register.isPending} disabled={!canRegister} onClick={submitBenchmark} />
        </div>
        {registered ? (
          <div style={css("display:flex;flex-direction:column;gap:8px;padding-top:8px;border-top:1px solid var(--border-soft);")}>
            <KvGrid
              rows={[
                ["benchmark id", registered.id],
                ["key", registered.key],
                ["name", registered.name],
                ["cases", String(registered.case_count)],
                ["created", `${fmtTime(registered.created_at)} by ${registered.created_by}`],
              ]}
            />
            <div style={actionRow}>
              <ActButton
                label="use for a run"
                onClick={() => {
                  setRKey(registered.key);
                  setRBenchmark(registered.id);
                }}
              />
            </div>
          </div>
        ) : null}
      </Section>

      <Section title="start eval run">
        <div style={css("display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;")}>
          <Field label="prompt key">
            <input list="eval-keys" value={rKey} onChange={(e) => setRKey(e.target.value)} maxLength={256} style={fieldStyle} />
          </Field>
          <Field label="candidate version">
            <input value={rVersion} onChange={(e) => setRVersion(e.target.value)} maxLength={32} style={fieldStyle} />
          </Field>
          <Field label="benchmark id">
            <input value={rBenchmark} onChange={(e) => setRBenchmark(e.target.value)} maxLength={64} style={fieldStyle} />
          </Field>
        </div>
        <div style={actionRow}>
          <span style={css("flex:1;")} />
          <ActButton
            label="start run"
            tone="accent"
            pending={start.isPending}
            disabled={!canRun}
            onClick={() =>
              start.mutate(
                { key: rKey.trim(), candidate_version: rVersion.trim(), benchmark_id: rBenchmark.trim() },
                {
                  onSuccess: (r) => {
                    toast.success(`eval run ${r.candidate_version}: ${r.verdict}`);
                    setListDraft(r.key);
                    setListKey(r.key);
                    setOpenRun(r.id);
                  },
                  onError: (e) => toast.fail("eval run", e),
                },
              )
            }
          />
        </div>
      </Section>

      <Section title="runs">
        <form
          style={actionRow}
          onSubmit={(e) => {
            e.preventDefault();
            setListKey(listDraft.trim());
            setOpenRun(null);
          }}
        >
          <input list="eval-keys" value={listDraft} onChange={(e) => setListDraft(e.target.value)} placeholder="prompt key" style={{ ...fieldStyle, width: 340 }} />
          <SubmitButton label="list runs" disabled={listDraft.trim() === ""} pending={runsQ.isFetching} />
        </form>
        {listKey === "" ? (
          <div style={css(FAINT + "font-size:11px;")}>Runs are listed per prompt key.</div>
        ) : (
          <>
            <QueryState loading={runsQ.isLoading} error={runsQ.error} empty={(runsQ.data ?? []).length === 0} emptyText="no eval runs for this key" />
            {(runsQ.data ?? []).length > 0 ? (
              <Table rows={runsQ.data ?? []} columns={runColumns} rowKey={(r) => r.id} selectedKey={openRun} onRowClick={(r) => setOpenRun(r.id === openRun ? null : r.id)} />
            ) : null}
            {opened ? (
              <pre style={css(MONO + "font-size:11px;margin:0;padding:8px;background:var(--surface-sunk);border:1px solid var(--border-soft);white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;")}>
                {JSON.stringify(opened.report, null, 2)}
              </pre>
            ) : null}
          </>
        )}
      </Section>
    </AdminWindow>
  );
}
