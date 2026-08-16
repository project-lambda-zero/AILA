/**
 * Investigation drill-down: opens from an Investigations-tab row and
 * mirrors the X-Ray gestalt for a single free-flow forensics investigation.
 * Header + status + attempts + confidence + reap banner + operator actions
 * (rerun/cancel/reap/tag). Body is a scrollable list of AgentStep panels:
 * reasoning + optional contract / hypotheses / rejected / observables /
 * provenance / expected_observation / submitted flag, plus the raw
 * command / script / stdout / stderr in code blocks. A "reasoning graphs"
 * pane shows the durable ReasoningGraphSnapshot list.
 *
 * Every action hits a real endpoint; no fabricated fallbacks. Auto-refresh
 * every 5s while status is running/pending.
 */
import type { JSX, ReactNode } from "react";
import { useState } from "react";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../api/client";
import { css } from "../../css";
import {
  CtlBtn,
  DictPanel,
  KV,
  Panel,
  StatusBadge,
  emptyNote,
  H,
} from "./panels";
import { RerunForm, TagInvestigationForm } from "./forms";

interface AgentStep {
  id: string;
  step_number: number;
  action: string;
  script_content: string | null;
  command: string | null;
  stdout: string | null;
  stderr: string | null;
  exit_code: number | null;
  reasoning: string;
  created_at: string | null;
  contract: Record<string, unknown> | null;
  hypotheses: Record<string, unknown>[];
  rejected: Record<string, unknown>[];
  observables: Record<string, unknown> | null;
  provenance: Record<string, unknown> | null;
  expected_observation: string | null;
  submitted: boolean;
}

interface InvestigationDetail {
  id: string;
  project_id: string;
  question: string;
  status: string;
  attempts_used: number;
  max_attempts: number;
  final_answer: string | null;
  confidence: string | null;
  parent_investigation_id: string | null;
  steps: AgentStep[];
  needs_reap: boolean;
  needs_reap_reason: string | null;
}

interface ReasoningSnapshot {
  id: string;
  step_number: number;
  strategy_family: string;
  graph: unknown;
  created_at: string | null;
  updated_at: string | null;
}

export function InvestigationSubView({
  projectId,
  investigationId,
  onBackToTabs,
}: {
  projectId: string;
  investigationId: string;
  onBackToTabs: () => void;
}): JSX.Element {
  const qc = useQueryClient();
  const detail = useQuery<InvestigationDetail>({
    queryKey: ["forensics", projectId, "investigation", investigationId],
    queryFn: () =>
      apiFetch<InvestigationDetail>(`/forensics/projects/${projectId}/investigations/${investigationId}`),
    enabled: Boolean(projectId && investigationId),
    retry: false,
    refetchInterval: (query) => {
      const s = (query.state.data?.status ?? "").toLowerCase();
      return s === "running" || s === "pending" ? 5000 : false;
    },
  });

  const graphs = useQuery<ReasoningSnapshot[]>({
    queryKey: ["forensics", projectId, "investigation", investigationId, "graphs"],
    queryFn: () =>
      apiFetch<ReasoningSnapshot[]>(
        `/forensics/projects/${projectId}/investigations/${investigationId}/reasoning-graphs`,
      ),
    enabled: Boolean(projectId && investigationId),
    retry: false,
  });

  const [rerunOpen, setRerunOpen] = useState(false);
  const [tagOpen, setTagOpen] = useState(false);
  const [openStepIds, setOpenStepIds] = useState<Record<string, true>>({});
  const [pane, setPane] = useState<"steps" | "graphs">("steps");

  const cancel = useMutation({
    mutationFn: () =>
      apiFetch(`/forensics/projects/${projectId}/investigations/${investigationId}/cancel`, {
        method: "POST",
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigation", investigationId] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigations"] });
    },
  });
  const reap = useMutation({
    mutationFn: () =>
      apiFetch(`/forensics/projects/${projectId}/investigations/${investigationId}/reap`, {
        method: "POST",
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigation", investigationId] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "investigations"] });
    },
  });

  if (detail.isLoading) return <div style={emptyNote}>{"loading investigation\u2026"}</div>;
  if (detail.isError) {
    const msg = detail.error instanceof Error ? detail.error.message : "request failed";
    return (
      <div style={emptyNote}>
        could not load investigation {investigationId} &mdash; {msg}
      </div>
    );
  }
  const d = detail.data;
  if (!d) return <div style={emptyNote}>investigation not found.</div>;

  const running = d.status === "running" || d.status === "pending";
  const paneBtn = (id: "steps" | "graphs", label: string): JSX.Element => (
    <button
      key={id}
      type="button"
      onClick={() => setPane(id)}
      style={css(
        `background:${pane === id ? "var(--accent)" : "transparent"};color:${pane === id ? "var(--text-on-accent)" : "var(--text-muted)"};border:1px solid ${pane === id ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;padding:2px 9px;cursor:pointer;`,
      )}
    >
      {label}
    </button>
  );

  return (
    <div style={css("flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;")}>
      {/* HEADER --------------------------------------------------- */}
      <Panel
        title="investigation"
        tag={`#${d.id.slice(0, 12)}`}
        right={
          <>
            <CtlBtn label="\u2190 back to tabs" tone="muted" onClick={onBackToTabs} />
          </>
        }
      >
        <div style={css("padding:12px 14px;display:grid;grid-template-columns:1fr 1fr;gap:14px;")}>
          <div>
            <KV
              entries={[
                ["question", d.question],
                ["status", <StatusBadge value={d.status} key="s" />],
                ["attempts", `${d.attempts_used} / ${d.max_attempts}`],
                ["confidence", d.confidence ?? "\u2014"],
                ["parent inv", d.parent_investigation_id ?? "\u2014"],
              ]}
            />
          </div>
          <div>
            <KV
              entries={[
                ["final answer", d.final_answer ?? "\u2014"],
                ["step count", d.steps.length],
              ]}
            />
            {d.needs_reap ? (
              <div
                style={css(
                  `margin:10px 0 0;padding:8px 10px;border:1px solid ${H.warn}66;border-radius:2px;background:${H.warn}11;color:${H.warn};font-family:var(--font-mono);font-size:10.5px;`,
                )}
              >
                zombie: {d.needs_reap_reason ?? "worker task settled without cleanup"}. reap to force-flip to failed.
              </div>
            ) : null}
          </div>
        </div>
        <div
          style={css(
            "display:flex;flex-wrap:wrap;gap:6px;padding:6px 14px 14px;border-top:1px solid var(--border-soft);",
          )}
        >
          <CtlBtn label="rerun" tone="accent" onClick={() => setRerunOpen(true)} />
          <CtlBtn label="cancel" tone="warn" onClick={() => window.confirm("Cancel this investigation?") && cancel.mutate()} disabled={!running} />
          <CtlBtn label="reap" tone="danger" onClick={() => reap.mutate()} disabled={!d.needs_reap} />
          <CtlBtn label="tag" tone="accent" onClick={() => setTagOpen(true)} />
          <span style={css("flex:1;")} />
          {paneBtn("steps", "steps")}
          {paneBtn("graphs", `reasoning graphs${graphs.data ? ` \u00b7 ${graphs.data.length}` : ""}`)}
        </div>
      </Panel>

      {/* BODY: STEPS or GRAPHS ------------------------------------- */}
      {pane === "steps" ? (
        <Panel title="agent steps" tag={`${d.steps.length}`}>
          {d.steps.length === 0 ? (
            <div style={emptyNote}>no steps recorded yet.</div>
          ) : (
            <div style={css("padding:10px 12px;display:flex;flex-direction:column;gap:9px;")}>
              {d.steps.map((s) => (
                <StepRow
                  key={s.id}
                  step={s}
                  open={Boolean(openStepIds[s.id])}
                  onToggle={() =>
                    setOpenStepIds((cur) => {
                      const next = { ...cur };
                      if (next[s.id]) delete next[s.id];
                      else next[s.id] = true;
                      return next;
                    })
                  }
                />
              ))}
            </div>
          )}
        </Panel>
      ) : (
        <Panel title="reasoning graph snapshots" tag={graphs.data ? `${graphs.data.length}` : ""}>
          {graphs.isLoading ? (
            <div style={emptyNote}>{"loading\u2026"}</div>
          ) : graphs.isError ? (
            <div style={emptyNote}>
              could not load reasoning-graphs &mdash;{" "}
              {graphs.error instanceof Error ? graphs.error.message : "request failed"}
            </div>
          ) : (graphs.data ?? []).length === 0 ? (
            <div style={emptyNote}>no reasoning graphs recorded.</div>
          ) : (
            <div style={css("padding:10px 12px;display:flex;flex-direction:column;gap:10px;")}>
              {(graphs.data ?? []).map((g) => (
                <div
                  key={g.id}
                  style={css(
                    "border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);",
                  )}
                >
                  <div
                    style={css(
                      "display:flex;align-items:center;gap:9px;padding:6px 10px;border-bottom:1px solid var(--border-soft);font-family:var(--font-mono);font-size:9.5px;color:var(--text-muted);",
                    )}
                  >
                    <span style={css("color:var(--accent);")}>step {g.step_number}</span>
                    <span>{g.strategy_family}</span>
                    <span style={css("flex:1;")} />
                    <span style={css("color:var(--text-faint);")}>{g.updated_at ?? g.created_at ?? ""}</span>
                  </div>
                  <div style={css("padding:8px 10px;")}>
                    <DictPanel data={((g.graph as Record<string, unknown>) ?? {})} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      {rerunOpen ? (
        <RerunForm projectId={projectId} investigationId={investigationId} onClose={() => setRerunOpen(false)} />
      ) : null}
      {tagOpen ? (
        <TagInvestigationForm projectId={projectId} investigationId={investigationId} onClose={() => setTagOpen(false)} />
      ) : null}
    </div>
  );
}

function StepRow({ step, open, onToggle }: { step: AgentStep; open: boolean; onToggle: () => void }): JSX.Element {
  const hyp = step.hypotheses ?? [];
  const rej = step.rejected ?? [];
  const observables = step.observables ?? null;
  return (
    <div
      style={css(
        "border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);overflow:hidden;",
      )}
    >
      <button
        type="button"
        onClick={onToggle}
        style={css(
          "width:100%;text-align:left;display:flex;align-items:center;gap:10px;padding:7px 10px;background:var(--surface-chrome);border:0;border-bottom:1px solid var(--border-soft);color:var(--text-primary);cursor:pointer;font-family:var(--font-mono);font-size:10.5px;",
        )}
      >
        <span style={css("color:var(--accent);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;")}>{open ? "\u25be" : "\u25b8"}</span>
        <span style={css("color:var(--text-faint);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;min-width:60px;")}>step {step.step_number}</span>
        <span style={css("color:var(--accent);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;min-width:110px;")}>{step.action}</span>
        <span style={css("flex:1;min-width:0;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>
          {(step.reasoning || step.expected_observation || "").slice(0, 200)}
        </span>
        {step.submitted ? <BadgeTag tone={H.mint} label="submitted" /> : null}
        {step.exit_code != null ? (
          <BadgeTag tone={step.exit_code === 0 ? H.mint : H.danger} label={`exit ${step.exit_code}`} />
        ) : null}
      </button>
      {open ? (
        <div style={css("padding:11px 12px;display:flex;flex-direction:column;gap:12px;")}>
          <StepSection label="reasoning" color={H.cream}>
            <p style={css("margin:0;font-family:var(--font-sans,system-ui);font-size:12.5px;line-height:1.62;color:var(--text-primary);white-space:pre-wrap;text-wrap:pretty;max-width:80ch;")}>{step.reasoning || "\u2014"}</p>
          </StepSection>
          {step.expected_observation ? (
            <StepSection label="expected observation" color={H.amber}>
              <p style={css("margin:0;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);white-space:pre-wrap;")}>{step.expected_observation}</p>
            </StepSection>
          ) : null}
          {step.contract ? (
            <StepSection label="contract" color={H.mint}>
              <DictPanel data={step.contract} initialOpen />
            </StepSection>
          ) : null}
          {hyp.length > 0 ? (
            <StepSection label={`hypotheses (${hyp.length})`} color={H.lav}>
              <div style={css("display:flex;flex-direction:column;gap:5px;")}>
                {hyp.map((h, i) => (
                  <DictPanel key={i} data={h} />
                ))}
              </div>
            </StepSection>
          ) : null}
          {rej.length > 0 ? (
            <StepSection label={`rejected (${rej.length})`} color={H.danger}>
              <div style={css("display:flex;flex-direction:column;gap:5px;")}>
                {rej.map((h, i) => (
                  <DictPanel key={i} data={h} />
                ))}
              </div>
            </StepSection>
          ) : null}
          {observables ? (
            <StepSection label="observables" color={H.sig}>
              <DictPanel data={observables} initialOpen />
            </StepSection>
          ) : null}
          {step.provenance ? (
            <StepSection label="provenance" color={H.acc}>
              <DictPanel data={step.provenance} />
            </StepSection>
          ) : null}
          {step.command ? <CodeSection label="command" body={step.command} /> : null}
          {step.script_content ? <CodeSection label="script" body={step.script_content} /> : null}
          {step.stdout ? <CodeSection label="stdout" body={step.stdout} /> : null}
          {step.stderr ? <CodeSection label="stderr" body={step.stderr} tone={H.danger} /> : null}
          {step.created_at ? (
            <div style={css("font-family:var(--font-mono);font-size:9px;color:var(--text-faint);letter-spacing:0.06em;")}>{step.created_at}</div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function StepSection({ label, color, children }: { label: string; color: string; children: ReactNode }): JSX.Element {
  return (
    <div
      style={css(
        `border-left:2px solid ${color}88;padding:2px 0 2px 10px;display:flex;flex-direction:column;gap:5px;`,
      )}
    >
      <div style={css(`font-family:var(--font-mono);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:${color};`)}>{label}</div>
      {children}
    </div>
  );
}

function CodeSection({ label, body, tone }: { label: string; body: string; tone?: string }): JSX.Element {
  const c = tone ?? H.mint;
  return (
    <StepSection label={label} color={c}>
      <pre
        style={css(
          "margin:0;padding:8px 10px;background:var(--surface-chrome);border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:10.5px;line-height:1.5;color:var(--text-primary);white-space:pre;overflow:auto;max-height:360px;",
        )}
      >
        {body}
      </pre>
    </StepSection>
  );
}

function BadgeTag({ tone, label }: { tone: string; label: string }): JSX.Element {
  return (
    <span
      style={css(
        `flex:0 0 auto;font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;padding:1px 6px;border:1px solid ${tone}66;border-radius:2px;color:${tone};`,
      )}
    >
      {label}
    </span>
  );
}
