import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useCreateInvestigation, useDeleteInvestigation } from "../mutations";
import {
  useInvestigations,
  useTargetMap,
  useTargets,
  useWorkspaces,
} from "../queries";
import type { InvestigationKind, InvestigationStatus } from "../types";

const statusColor: Record<
  InvestigationStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  created: "info",
  running: "medium",
  paused: "info",
  completed: "low",
  failed: "critical",
  abandoned: "high",
};

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function fmtUsd(n: number): string {
  return `$${n.toFixed(2)}`;
}

export function InvestigationsListPage() {
  const navigate = useNavigate();
  const { data: result, isLoading, isError } = useInvestigations();
  const targetMap = useTargetMap();
  const { data: targetsResult } = useTargets();
  const { data: workspacesResult } = useWorkspaces();
  const createMut = useCreateInvestigation();
  const deleteMut = useDeleteInvestigation();

  const [showForm, setShowForm] = useState(false);
  const [formTitle, setFormTitle] = useState("");
  const [formQuestion, setFormQuestion] = useState("");
  const [formTargetId, setFormTargetId] = useState("");
  const [formKind, setFormKind] = useState<InvestigationKind>("discovery");
  const [formBudget, setFormBudget] = useState("50");

  const investigations = result?.data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            Investigations
          </h1>
          <p className="text-sm text-text-muted mt-1">
            Hypothesis-driven investigations across targets. Each runs a
            HonestVulnResearcher loop with tool dispatch + outcome routing.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors"
        >
          {showForm ? "Cancel" : "New Investigation"}
        </button>
      </div>

      {showForm && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Start a new investigation
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Pick a target you already onboarded under Workspaces → Targets.
            Workflow VR_INVESTIGATE_V1 fires immediately on create.
          </p>
          <div className="space-y-2">
            <input
              type="text"
              value={formTitle}
              onChange={(e) => setFormTitle(e.target.value)}
              placeholder="Title (e.g. 'Audit V8 InferMaps for missing alias check')"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            <textarea
              value={formQuestion}
              onChange={(e) => setFormQuestion(e.target.value)}
              placeholder="Initial question — what are you asking the engine to investigate?"
              rows={2}
              className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            {(() => {
              const targets = targetsResult?.data ?? [];
              const workspaces = workspacesResult?.data ?? [];
              const byWs = new Map<string, typeof targets>();
              for (const t of targets) {
                const arr = byWs.get(t.workspace_id) ?? [];
                arr.push(t);
                byWs.set(t.workspace_id, arr);
              }
              const wsName = (id: string) =>
                workspaces.find((w) => w.id === id)?.name ?? "(unknown workspace)";
              const orderedWsIds = Array.from(byWs.keys()).sort(
                (a, b) => wsName(a).localeCompare(wsName(b)),
              );
              if (targetsResult === undefined) {
                return (
                  <div className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border-default text-text-muted">
                    Loading targets…
                  </div>
                );
              }
              if (targets.length === 0) {
                return (
                  <div className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border-danger text-text-danger">
                    No targets exist yet. Create one under Workspaces → Targets
                    before starting an investigation.
                  </div>
                );
              }
              return (
                <select
                  value={formTargetId}
                  onChange={(e) => setFormTargetId(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
                >
                  <option value="">— Pick a target —</option>
                  {orderedWsIds.map((wsId) => (
                    <optgroup key={wsId} label={wsName(wsId)}>
                      {(byWs.get(wsId) ?? [])
                        .slice()
                        .sort((a, b) => a.display_name.localeCompare(b.display_name))
                        .map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.display_name} · {t.kind} ·{" "}
                            {t.primary_language ?? "—"} · {t.analysis_state}
                          </option>
                        ))}
                    </optgroup>
                  ))}
                </select>
              );
            })()}
            <div className="flex gap-2 items-center">
              <select
                value={formKind}
                onChange={(e) => setFormKind(e.target.value as InvestigationKind)}
                className="px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default"
              >
                <option value="discovery">discovery</option>
                <option value="variant_hunt">variant_hunt</option>
                <option value="triage">triage</option>
                <option value="n_day">n_day</option>
                <option value="audit">audit</option>
              </select>
              <div className="flex items-center gap-1">
                <span className="text-sm text-text-muted">budget $</span>
                <input
                  type="number"
                  step="1"
                  min="0"
                  value={formBudget}
                  onChange={(e) => setFormBudget(e.target.value)}
                  className="w-20 px-2 py-2 text-sm font-mono rounded-md bg-surface border border-border-default"
                />
              </div>
              <button
                type="button"
                disabled={
                  !formTitle.trim() ||
                  !formQuestion.trim() ||
                  !formTargetId.trim() ||
                  createMut.isPending
                }
                onClick={() => {
                  const budget = parseFloat(formBudget);
                  createMut.mutate(
                    {
                      title: formTitle.trim(),
                      initial_question: formQuestion.trim(),
                      target_id: formTargetId.trim(),
                      kind: formKind,
                      cost_budget_usd: Number.isFinite(budget) ? budget : 50,
                    },
                    {
                      onSuccess: (result) => {
                        setShowForm(false);
                        setFormTitle("");
                        setFormQuestion("");
                        setFormTargetId("");
                        setFormKind("discovery");
                        setFormBudget("50");
                        navigate(`/vr/investigations/${result.data.id}`);
                      },
                    },
                  );
                }}
                className="ml-auto px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
              >
                {createMut.isPending ? "Creating…" : "Start investigation"}
              </button>
            </div>
          </div>
        </AilaCard>
      )}


      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load investigations.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && investigations.length === 0 && (
        <AilaCard>
          <div className="text-center py-8">
            <p className="text-text-muted">No investigations yet.</p>
            <p className="text-text-muted text-xs mt-2">
              Click <strong>New Investigation</strong> above to start one.
              Workflow auto-fires on create.
            </p>
          </div>
        </AilaCard>
      )}

      {!isLoading && !isError && investigations.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Title / Verdict</th>
                <th className="px-4 py-2 font-semibold">Kind</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold">Target</th>
                <th className="px-4 py-2 font-semibold text-right" title="Findings linked to this investigation">Find</th>
                <th className="px-4 py-2 font-semibold text-right">Br</th>
                <th className="px-4 py-2 font-semibold text-right">Msg</th>
                <th className="px-4 py-2 font-semibold text-right">Out</th>
                <th className="px-4 py-2 font-semibold text-right">Cost</th>
                <th className="px-4 py-2 font-semibold">Created</th>
                <th className="px-2 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {investigations.map((inv) => (
                <tr
                  key={inv.id}
                  onClick={() => navigate(`/vr/investigations/${inv.id}`)}
                  className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
                >
                  <td className="px-4 py-2 align-top min-w-0 max-w-[380px]">
                    <div className="font-semibold text-foreground break-words">
                      {inv.title}
                    </div>
                    {inv.primary_outcome_kind && (
                      <div className="mt-1 flex items-center gap-1 flex-wrap">
                        <AilaBadge
                          severity={
                            inv.primary_outcome_kind === "direct_finding"
                              ? "high"
                              : inv.primary_outcome_kind === "patch_assessment_report"
                                ? "info"
                                : inv.primary_outcome_kind === "variant_hunt_order"
                                  ? "medium"
                                  : "low"
                          }
                          size="sm"
                        >
                          {inv.primary_outcome_kind}
                        </AilaBadge>
                        {inv.primary_outcome_confidence && (
                          <span className="text-[10px] font-mono text-text-muted">
                            conf:{inv.primary_outcome_confidence}
                          </span>
                        )}
                      </div>
                    )}
                    {inv.primary_outcome_verdict_head && (
                      <div className="mt-1 text-xs text-text-muted line-clamp-2 break-words">
                        {inv.primary_outcome_verdict_head}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
                    {inv.kind}
                  </td>
                  <td className="px-4 py-2">
                    <AilaBadge
                      severity={statusColor[inv.status] ?? "info"}
                      size="sm"
                    >
                      {inv.pause_reason
                        ? `${inv.status}:${inv.pause_reason}`
                        : inv.status}
                    </AilaBadge>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
                    {targetMap.get(inv.target_id)?.display_name ?? "loading…"}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-foreground">
                    {inv.linked_finding_ids.length > 0 ? (
                      <span className="text-emerald-400 font-semibold">
                        {inv.linked_finding_ids.length}
                      </span>
                    ) : (
                      <span className="text-text-muted">0</span>
                    )}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-foreground">
                    {inv.branch_count}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-foreground">
                    {inv.message_count}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-foreground">
                    {inv.outcome_count}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-text-muted">
                    {fmtUsd(inv.cost_actual_usd)} / {fmtUsd(inv.cost_budget_usd)}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
                    {formatDate(inv.created_at)}
                  </td>
                  <td className="px-2 py-2 text-right">
                    <DeleteButton
                      id={inv.id}
                      label={`investigation "${inv.title}"`}
                      mutation={deleteMut}
                      compact
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}
