import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

import { AnalystDirectivesPanel } from "../components/AnalystDirectivesPanel";
import { RetrieveFilePanel } from "../components/RetrieveFilePanel";
import {
  useCancelInvestigation,
  useRerunInvestigation,
  useTagInvestigation,
} from "../mutations";
import { useInvestigationAnswers, useInvestigationDetail, useInvestigationEventFeed } from "../queries";
import type { AgentStep, AnswerCandidate, TagVerdict } from "../types";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

type TabId = "steps" | "answers" | "live";

const STATUS_SEVERITY: Record<string, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  queued: "info",
  running: "medium",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
  exhausted: "high",
  cancelled: "high",
};

const CONFIDENCE_SEVERITY: Record<string, "info" | "low" | "medium" | "high" | "critical"> = {
  high: "low",
  medium: "medium",
  low: "high",
  unknown: "info",
};

// ----- Case-model panel (contract / hypotheses / observables / provenance) -----
function CaseModelPanel({ step }: { step: AgentStep }) {
  const contract = step.contract;
  const hypotheses = step.hypotheses ?? [];
  const rejected = step.rejected ?? [];
  const observables = step.observables ?? null;
  const provenance = step.provenance ?? null;

  const hasAnything =
    (contract && Object.values(contract).some((v) => v && (Array.isArray(v) ? v.length > 0 : true))) ||
    hypotheses.length > 0 ||
    rejected.length > 0 ||
    (observables && Object.keys(observables).length > 0) ||
    (provenance && Object.values(provenance).some((v) => v && (Array.isArray(v) ? v.length > 0 : true))) ||
    step.expected_observation;

  if (!hasAnything) return null;

  return (
    <div className="border-t border-border px-4 py-2 space-y-2 bg-surface-secondary/40">
      {contract && (
        <div className="text-xs">
          <span className="font-mono text-text-muted">contract:</span>{" "}
          <span className="font-mono text-foreground">
            {contract.answer_type && `type=${contract.answer_type} `}
            {contract.answer_format && `format="${contract.answer_format}" `}
            {contract.evidence_domain && `evidence=${contract.evidence_domain}`}
          </span>
        </div>
      )}
      {step.expected_observation && (
        <div className="text-xs">
          <span className="font-mono text-text-muted">expected:</span>{" "}
          <span className="text-foreground">{step.expected_observation}</span>
        </div>
      )}
      {hypotheses.length > 0 && (
        <div className="text-xs">
          <div className="font-mono text-text-muted mb-1">hypotheses:</div>
          <ul className="pl-3 space-y-0.5">
            {hypotheses.map((h, i) => (
              <li key={i} className="text-foreground">
                <span className="font-mono text-text-muted">{h.id ?? `H${i + 1}`}:</span>{" "}
                {h.claim}
                {h.kill_criterion && (
                  <span className="text-text-muted italic"> — kill: {h.kill_criterion}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {rejected.length > 0 && (
        <div className="text-xs">
          <div className="font-mono text-text-muted mb-1">rejected ({rejected.length}):</div>
          <ul className="pl-3 space-y-0.5">
            {rejected.slice(0, 5).map((r, i) => (
              <li key={i} className="text-text-muted line-through">
                {r.id ?? "?"}: {r.claim}{" "}
                {r.reason && <span className="italic no-underline">({r.reason})</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {observables && Object.keys(observables).length > 0 && (
        <div className="text-xs">
          <div className="font-mono text-text-muted mb-1">observables:</div>
          <div className="flex flex-wrap gap-1 pl-3">
            {Object.entries(observables).slice(0, 24).map(([k, v]) => (
              <code
                key={k}
                className="px-1.5 py-0.5 bg-surface rounded text-text-muted font-mono"
              >
                {k}={String(v).slice(0, 120)}
              </code>
            ))}
          </div>
        </div>
      )}
      {provenance && (provenance.primary_artifact || (provenance.corroboration?.length ?? 0) > 0) && (
        <div className="text-xs">
          <div className="font-mono text-text-muted mb-1">provenance:</div>
          {provenance.primary_artifact && (
            <div className="pl-3 text-foreground">
              primary: <code className="font-mono">{provenance.primary_artifact}</code>
            </div>
          )}
          {(provenance.corroboration?.length ?? 0) > 0 && (
            <div className="pl-3 text-text-muted">
              corroboration:{" "}
              {(provenance.corroboration ?? []).map((c, i) => (
                <code key={i} className="ml-1 font-mono">{c}</code>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ----- Step card -----
function StepCard({ step }: { step: AgentStep }) {
  const [stdoutOpen, setStdoutOpen] = useState(false);
  const [stderrOpen, setStderrOpen] = useState(false);
  const [scriptOpen, setScriptOpen] = useState(false);

  const failed = step.exit_code !== null && step.exit_code !== 0;
  const hasStdout = !!step.stdout?.trim();
  const hasStderr = !!step.stderr?.trim();
  const hasScript = !!step.script_content?.trim();

  return (
    <div
      className={`rounded-md border bg-surface transition-colors ${
        failed ? "border-border-danger bg-red-950/10" : "border-border"
      }`}
    >
      {/* Header row */}
      <div className="flex items-start gap-3 px-4 py-3">
        <span
          className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold font-mono ${
            failed
              ? "bg-red-900/40 text-red-400"
              : "bg-surface-secondary text-text-muted"
          }`}
        >
          {step.step_number}
        </span>
        <div className="flex-1 min-w-0 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-foreground font-mono">
              {step.action}
            </span>
            {step.exit_code !== null && (
              <span
                className={`px-1.5 py-0.5 rounded text-xs font-mono ${
                  failed
                    ? "bg-red-900/40 text-red-400"
                    : "bg-green-900/30 text-green-400"
                }`}
              >
                exit {step.exit_code}
              </span>
            )}
          </div>
          {step.reasoning && (
            <p className="text-xs text-text-muted">{step.reasoning}</p>
          )}
          {step.command && (
            <code className="block text-xs font-mono text-text-muted bg-surface-secondary px-2 py-1 rounded truncate">
              {step.command}
            </code>
          )}
        </div>
      </div>

      <CaseModelPanel step={step} />

      {/* Expandable script */}
      {hasScript && (
        <div className="border-t border-border">
          <button
            type="button"
            onClick={() => setScriptOpen((v) => !v)}
            className="w-full flex items-center justify-between px-4 py-2 text-xs text-text-muted hover:text-foreground hover:bg-surface-secondary transition-colors"
          >
            <span className="font-mono">script content</span>
            <span>{scriptOpen ? "▲" : "▼"}</span>
          </button>
          {scriptOpen && (
            <pre className="px-4 pb-3 text-xs font-mono text-foreground bg-surface-secondary overflow-x-auto whitespace-pre-wrap">
              {step.script_content}
            </pre>
          )}
        </div>
      )}

      {/* Expandable stdout */}
      {hasStdout && (
        <div className="border-t border-border">
          <button
            type="button"
            onClick={() => setStdoutOpen((v) => !v)}
            className="w-full flex items-center justify-between px-4 py-2 text-xs text-text-muted hover:text-foreground hover:bg-surface-secondary transition-colors"
          >
            <span className="font-mono">stdout</span>
            <span>{stdoutOpen ? "▲" : "▼"}</span>
          </button>
          {stdoutOpen && (
            <pre className="px-4 pb-3 text-xs font-mono text-foreground bg-surface-secondary overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap">
              {step.stdout}
            </pre>
          )}
        </div>
      )}

      {/* Expandable stderr */}
      {hasStderr && (
        <div className={`border-t ${failed ? "border-border-danger" : "border-border"}`}>
          <button
            type="button"
            onClick={() => setStderrOpen((v) => !v)}
            className={`w-full flex items-center justify-between px-4 py-2 text-xs transition-colors hover:bg-surface-secondary ${
              failed ? "text-red-400 hover:text-red-300" : "text-text-muted hover:text-foreground"
            }`}
          >
            <span className="font-mono">stderr</span>
            <span>{stderrOpen ? "▲" : "▼"}</span>
          </button>
          {stderrOpen && (
            <pre
              className={`px-4 pb-3 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap bg-surface-secondary ${
                failed ? "text-red-300" : "text-foreground"
              }`}
            >
              {step.stderr}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ----- Answer candidate card -----
function AnswerCard({ answer }: { answer: AnswerCandidate }) {
  return (
    <AilaCard  techBorder glow><div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-foreground">{answer.question_text}</p>
        <AilaBadge
          severity={CONFIDENCE_SEVERITY[answer.confidence] ?? "info"}
          size="sm"
        >
          {answer.confidence}
        </AilaBadge>
      </div>
      <p className="text-sm text-text-muted">{answer.answer_text}</p>
      {answer.corroboration.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1">
          <span className="text-xs text-text-muted mr-1">Corroborated by:</span>
          {answer.corroboration.map((c, i) => (
            <span
              key={i}
              className="px-1.5 py-0.5 text-xs bg-surface-secondary rounded font-mono text-text-muted"
            >
              {c}
            </span>
          ))}
        </div>
      )}
      {answer.created_at && (
        <p className="text-xs text-text-muted">
          {new Date(answer.created_at).toLocaleString()}
        </p>
      )}
    </div></AilaCard>
  );
}

// "pending" is the status freshly-submitted investigations sit at until the
// freeflow agent flips them to "running". The earlier states (intake /
// collection / deep_analysis) emit progress while the row is still "pending",
// so we must treat it as running for SSE subscription purposes or the live
// feed silently never subscribes.
const RUNNING_STATUSES = new Set(["pending", "queued", "running", "analyzing"]);

interface InvestigationControlsProps {
  projectId: string;
  investigationId: string;
  status: string;
  isRunning: boolean;
  hasFinalAnswer: boolean;
  answerCandidates: AnswerCandidate[];
}

function InvestigationControls({
  projectId,
  investigationId,
  status,
  isRunning,
  hasFinalAnswer,
  answerCandidates,
}: InvestigationControlsProps) {
  const cancel = useCancelInvestigation(projectId);
  const rerun = useRerunInvestigation(projectId);
  const tag = useTagInvestigation(projectId);
  const [tagForm, setTagForm] = useState<TagVerdict | null>(null);
  const [selectedAnswerId, setSelectedAnswerId] = useState<string>("");
  const [notes, setNotes] = useState("");

  const canTag = !isRunning && (hasFinalAnswer || answerCandidates.length > 0);
  const isCompleted = status === "completed";
  const isDisabledTag = !isCompleted;

  const handleCancel = () => {
    if (!window.confirm("Stop this investigation immediately? The agent will exit between turns.")) return;
    cancel.mutate(investigationId);
  };

  const openTagForm = (verdict: TagVerdict) => {
    setTagForm(verdict);
    setSelectedAnswerId(answerCandidates.length === 1 ? answerCandidates[0].id : "");
    setNotes("");
  };

  const submitTag = () => {
    if (!tagForm) return;
    tag.mutate(
      {
        investigationId,
        body: {
          verdict: tagForm,
          answer_id: selectedAnswerId || null,
          notes,
        },
      },
      {
        onSuccess: () => {
          setTagForm(null);
          setSelectedAnswerId("");
          setNotes("");
        },
      },
    );
  };

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex gap-2 flex-wrap justify-end">
        {isRunning && (
          <Button
            variant="destructive"
            size="sm"
            onClick={handleCancel}
            disabled={cancel.isPending}
          >
            {cancel.isPending ? "Stopping…" : "Stop investigation"}
          </Button>
        )}
        {!isRunning && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => rerun.mutate({ investigationId })}
            disabled={rerun.isPending}
            title="Start a new investigation that carries this attempt's findings forward"
          >
            {rerun.isPending ? "Restarting…" : "Rerun (enriched)"}
          </Button>
        )}
        {canTag && (
          <>
            <Button
              size="sm"
              variant="default"
              className="bg-emerald-600 hover:bg-emerald-700 text-white"
              onClick={() => openTagForm("true")}
              disabled={isDisabledTag || tag.isPending}
              title={isDisabledTag ? "Only completed investigations can be tagged" : undefined}
            >
              Tag as TRUE finding
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="border-amber-600 text-amber-500 hover:bg-amber-950/20"
              onClick={() => openTagForm("false")}
              disabled={isDisabledTag || tag.isPending}
              title={isDisabledTag ? "Only completed investigations can be tagged" : undefined}
            >
              Tag as FALSE finding
            </Button>
          </>
        )}
      </div>
      {tagForm && (
        <AilaCard className="w-full max-w-md border-border" techBorder glow><div className="space-y-2">
          <p className="text-sm font-medium text-foreground">
            Tag as{" "}
            <span
              className={
                tagForm === "true" ? "text-emerald-400" : "text-amber-400"
              }
            >
              {tagForm === "true" ? "TRUE" : "FALSE"}
            </span>{" "}
            finding
          </p>
          <p className="text-xs text-text-muted">
            Saved to the Solid Evidence tab and injected into every future
            investigation's prompt as a{" "}
            {tagForm === "true" ? "confirmed fact" : "disproved hypothesis"}.
          </p>
          {answerCandidates.length > 1 && (
            <div className="space-y-1">
              <label className="text-xs font-mono text-text-muted">
                Which answer?
              </label>
              <select
                className="w-full bg-surface border border-border rounded px-2 py-1 text-sm text-foreground"
                value={selectedAnswerId}
                onChange={(e) => setSelectedAnswerId(e.target.value)}
              >
                <option value="">(use investigation's final_answer)</option>
                {answerCandidates.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.confidence}] {a.answer_text.slice(0, 80)}
                    {a.answer_text.length > 80 ? "…" : ""}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="space-y-1">
            <label className="text-xs font-mono text-text-muted">
              Notes (optional)
            </label>
            <Textarea
              rows={2}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Why? Any caveats?"
              className="text-sm"
            />
          </div>
          <div className="flex gap-2 justify-end pt-1">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setTagForm(null)}
              disabled={tag.isPending}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={submitTag}
              disabled={tag.isPending}
              className={
                tagForm === "true"
                  ? "bg-emerald-600 hover:bg-emerald-700 text-white"
                  : "bg-amber-600 hover:bg-amber-700 text-white"
              }
            >
              {tag.isPending ? "Saving…" : "Confirm"}
            </Button>
          </div>
        </div></AilaCard>
      )}
    </div>
  );
}

// ----- Main page -----
export function InvestigationDetailPage() {
  const { projectId, investigationId } = useParams<{
    projectId: string;
    investigationId: string;
  }>();
  const navigate = useNavigate();

  // hook moved below the useInvestigationDetail destructure so `investigation` is in scope
  // Default to "live" when the investigation is still running so the user sees
  // progress immediately instead of landing on an empty "Steps" tab.
  const [activeTab, setActiveTab] = useState<TabId>("live");

  const {
    data: investigation,
    isLoading,
    isError,
  } = useInvestigationDetail(projectId ?? "", investigationId ?? "");

  useUpdatePageHeader({
    title: investigation ? `Investigation ${investigationId?.slice(0, 8) ?? ''}` : 'Investigation',
    subtitle: investigation?.status ?? undefined,
    status: investigation?.status === 'running' ? 'live' : investigation?.status === 'failed' ? 'error' : investigation?.status === 'completed' ? 'ready' : null,
  });

  const {
    data: answers,
    isLoading: answersLoading,
  } = useInvestigationAnswers(projectId ?? "", investigationId ?? "");

  const isRunning = investigation ? RUNNING_STATUSES.has(investigation.status) : false;
  const { events: liveEvents, feedStatus } = useInvestigationEventFeed(
    isRunning ? (projectId ?? "") : "",
    isRunning ? (investigationId ?? "") : "",
  );

  if (!projectId || !investigationId) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Invalid investigation URL.</p></AilaCard>
    );
  }

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError || !investigation) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load investigation.</p></AilaCard>
    );
  }

  const TABS: { id: TabId; label: string; count?: number }[] = [
    ...(isRunning ? [{ id: "live" as TabId, label: "Live", count: liveEvents.length }] : []),
    { id: "steps", label: "Steps", count: investigation.steps.length },
    { id: "answers", label: "Answers", count: answers?.length },
  ];

  return (
    <div className="space-y-4">
      {/* Back link */}
      <button
        type="button"
        onClick={() => navigate(`/forensics/projects/${projectId}`)}
        className="flex items-center gap-1 text-xs text-text-muted hover:text-foreground transition-colors"
      >
        ← Back to project
      </button>

      {/* Previous-attempt banner (enriched rerun) */}
      {investigation.parent_investigation_id && (
        <AilaCard className="border-blue-700/40 bg-blue-950/20" techBorder glow><div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="space-y-0.5">
            <p className="text-xs font-mono text-blue-300">
              ENRICHED RERUN
            </p>
            <p className="text-sm text-foreground">
              This investigation carries findings forward from a prior
              attempt. Confirmed observables are pre-loaded into the
              agent's working memory; the prior answer is treated as a
              hypothesis to verify.
            </p>
          </div>
          <button
            type="button"
            onClick={() =>
              navigate(
                `/forensics/projects/${projectId}/investigations/${investigation.parent_investigation_id}`,
              )
            }
            className="text-xs px-2 py-1 rounded border border-blue-600 text-blue-300 hover:bg-blue-700 hover:text-white transition-colors shrink-0"
          >
            View parent ({investigation.parent_investigation_id.slice(0, 8)}) →
          </button>
        </div></AilaCard>
      )}

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="space-y-1 flex-1 min-w-[16rem]">
          <p className="text-sm text-text-muted font-mono">{investigation.question}</p>
          <div className="flex gap-4 text-xs text-text-muted">
            <span>
              {investigation.attempts_used}
              {investigation.max_attempts ? `/${investigation.max_attempts}` : ""} attempts
            </span>
            {investigation.confidence && (
              <span>Confidence: {investigation.confidence}</span>
            )}
          </div>
        </div>
        <InvestigationControls
          projectId={projectId}
          investigationId={investigationId}
          status={investigation.status}
          isRunning={isRunning}
          hasFinalAnswer={!!investigation.final_answer}
          answerCandidates={answers ?? []}
        />
      </div>

      {/* Final answer banner */}
      {investigation.final_answer && (
        <AilaCard className="border-border-accent bg-accent/5" techBorder glow><div className="space-y-1">
          <p className="text-xs font-medium text-text-muted uppercase tracking-wide">
            Final Answer
          </p>
          <p className="text-sm text-foreground">{investigation.final_answer}</p>
        </div></AilaCard>
      )}

      {/* Analyst directives — readable on every turn by AILA */}
      <AnalystDirectivesPanel
        projectId={projectId}
        investigationId={investigationId}
      />

      {/* Retrieve-File — pull any artefact out of the disk image */}
      <RetrieveFilePanel projectId={projectId} />

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
              activeTab === tab.id
                ? "bg-surface border border-b-0 border-border text-foreground"
                : "text-text-muted hover:text-foreground hover:bg-surface-secondary"
            }`}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className="ml-1.5 px-1.5 py-0.5 text-xs rounded-full bg-surface-secondary">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="pt-1">
        {activeTab === "live" && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-text-muted">
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  feedStatus === "live" ? "bg-amber-400 animate-pulse" :
                  feedStatus === "connecting" ? "bg-blue-400 animate-pulse" :
                  "bg-surface-secondary"
                }`}
              />
              <span className="font-mono">{feedStatus}</span>
            </div>
            <div className="rounded-md border border-border bg-surface font-mono text-xs overflow-y-auto max-h-[28rem] p-3 space-y-1">
              {liveEvents.length === 0 && (
                <p className="text-text-muted">Waiting for events…</p>
              )}
              {liveEvents.map((ev, i) => {
                const stage = ev.stage ?? "—";
                let payload: Record<string, unknown> = {};
                if (ev.data_json) {
                  try {
                    payload = JSON.parse(ev.data_json);
                  } catch {
                    // ignore — render raw message only
                  }
                }
                const color =
                  stage.includes("error") || stage.includes("failed") ? "text-red-400" :
                  stage.includes("done") || stage === "completed" || stage.includes("detected") ? "text-green-400" :
                  stage.includes("start") || stage.includes("begin") ? "text-amber-400" :
                  stage === "artifact_added" ? "text-blue-400" :
                  stage === "heartbeat" ? "text-text-muted" :
                  "text-accent";
                const lane = typeof payload.lane === "string" ? payload.lane : undefined;
                const path = typeof payload.path === "string" ? payload.path : undefined;
                const err = typeof payload.error === "string" ? payload.error : undefined;
                const inner = payload.query ?? payload.plugin ?? payload.tier;

                // Freeflow-specific payload fields: the actual script / shell
                // command being executed on the analyzer and the last chunk
                // of its output. Prefer full fields (script, reasoning) over
                // the legacy *_preview ones so the analyst sees the whole
                // thing instead of a clipped headline.
                const script =
                  typeof payload.script === "string" ? payload.script :
                  typeof payload.script_preview === "string" ? payload.script_preview :
                  undefined;
                const command = typeof payload.command === "string" ? payload.command : undefined;
                const stdout =
                  typeof payload.stdout === "string" ? payload.stdout :
                  typeof payload.stdout_tail === "string" ? payload.stdout_tail :
                  undefined;
                const stderr =
                  typeof payload.stderr === "string" ? payload.stderr :
                  typeof payload.stderr_tail === "string" ? payload.stderr_tail :
                  undefined;
                const stdoutBytes = typeof payload.stdout_bytes === "number" ? payload.stdout_bytes : undefined;
                const reasoning =
                  typeof payload.reasoning === "string" ? payload.reasoning :
                  typeof payload.reasoning_preview === "string" ? payload.reasoning_preview :
                  undefined;
                const exitCode = typeof payload.exit_code === "number" ? payload.exit_code : undefined;

                return (
                  <div key={i} className="py-0.5">
                    <div className="flex gap-2">
                      {ev.percent !== null && ev.percent !== undefined && ev.percent > 0 && (
                        <span className="shrink-0 text-text-muted w-9 text-right">{ev.percent}%</span>
                      )}
                      <span className={`shrink-0 font-semibold ${color}`}>[{stage}]</span>
                      {lane && <span className="shrink-0 text-text-muted">{lane}</span>}
                      {typeof inner === "string" && inner && (
                        <span className="shrink-0 text-text-muted">{inner as string}</span>
                      )}
                      <span className="text-foreground break-all">{ev.message ?? ""}</span>
                    </div>
                    {path && (
                      <div className="pl-14 text-[10px] text-text-muted break-all">↳ {path}</div>
                    )}
                    {err && (
                      <div className="pl-14 text-[10px] text-red-300/80 break-all whitespace-pre-wrap">✗ {err}</div>
                    )}
                    {reasoning && (
                      <details className="pl-14 mt-0.5" open>
                        <summary className="cursor-pointer text-[10px] text-text-muted/80 hover:text-foreground">
                          reasoning ({reasoning.length} chars)
                        </summary>
                        <div className="mt-1 text-[11px] text-text-muted whitespace-pre-wrap italic bg-black/20 border border-border rounded px-2 py-1">
                          {reasoning}
                        </div>
                      </details>
                    )}
                    {command && (
                      <details className="pl-14 mt-1">
                        <summary className="cursor-pointer text-[10px] text-amber-400/80 hover:text-amber-300">
                          shell command ({command.length} chars) — click to expand
                        </summary>
                        <pre className="mt-1 text-[11px] bg-black/40 border border-amber-900/30 rounded px-2 py-1 whitespace-pre-wrap break-all text-amber-200">
                          {command}
                        </pre>
                      </details>
                    )}
                    {script && (
                      <details className="pl-14 mt-1">
                        <summary className="cursor-pointer text-[10px] text-amber-400/80 hover:text-amber-300">
                          python script ({script.length} chars) — click to expand
                        </summary>
                        <pre className="mt-1 text-[11px] bg-black/40 border border-amber-900/30 rounded px-2 py-1 whitespace-pre-wrap break-all text-amber-200">
                          {script}
                        </pre>
                      </details>
                    )}
                    {(stdout || stderr) && (
                      <details className="pl-14 mt-1" open>
                        <summary className="cursor-pointer text-[10px] text-green-400/80 hover:text-green-300">
                          output {exitCode !== undefined ? `(exit=${exitCode})` : ""}
                          {stdoutBytes !== undefined && stdout && stdoutBytes > stdout.length
                            ? ` — showing last ${stdout.length.toLocaleString()} of ${stdoutBytes.toLocaleString()} bytes`
                            : stdout ? ` — ${stdout.length.toLocaleString()} bytes` : ""}
                        </summary>
                        {stdout && (
                          <pre className="mt-1 text-[11px] bg-black/40 border border-green-900/30 rounded px-2 py-1 whitespace-pre-wrap break-all text-green-200 max-h-[32rem] overflow-auto">
                            {stdout}
                          </pre>
                        )}
                        {stderr && (
                          <pre className="mt-1 text-[11px] bg-black/40 border border-red-900/30 rounded px-2 py-1 whitespace-pre-wrap break-all text-red-200 max-h-80 overflow-auto">
                            {stderr}
                          </pre>
                        )}
                      </details>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activeTab === "steps" && (
          <div className="space-y-3">
            {investigation.steps.length === 0 ? (
              <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-6">
                No steps recorded yet.
              </p></AilaCard>
            ) : (
              investigation.steps
                .slice()
                .sort((a, b) => a.step_number - b.step_number)
                .map((step) => <StepCard key={step.id} step={step} />)
            )}
          </div>
        )}

        {activeTab === "answers" && (
          <div className="space-y-3">
            {answersLoading && <LoadingSkeleton size="md" width="full" />}
            {!answersLoading && (answers ?? []).length === 0 && (
              <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-6">
                No answer candidates for this investigation yet.
              </p></AilaCard>
            )}
            {(answers ?? []).map((a) => (
              <AnswerCard key={a.id} answer={a} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
