import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { Detective } from "@phosphor-icons/react/dist/csr/Detective";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";

import { EmptyState } from "@/components/aila/EmptyState";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  MonoBadge,
  SectionHeader,
  Segmented,
  toneColor,
} from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import {
  InvestigationDetailSkeleton,
  InvestigationRowSkeletonList,
} from "../components/skeletons";
import { ActivityPanel } from "../components/ActivityPanel";
import { AnalystDirectivesPanel } from "../components/AnalystDirectivesPanel";
import { ConnectedPanel } from "../components/ConnectedPanel";
import { LiveRunPanel } from "../components/LiveRunPanel";
import { PanelBoundary } from "../components/PanelBoundary";
import { RetrieveFilePanel } from "../components/RetrieveFilePanel";
import { useForensicsInvestigationEvents } from "../hooks/useForensicsInvestigationEvents";
import {
  useCancelInvestigation,
  useReapInvestigation,
  useRerunInvestigation,
  useTagInvestigation,
} from "../mutations";
import { useInvestigationAnswers, useInvestigationDetail } from "../queries";
import type { AgentStep, AnswerCandidate, TagVerdict } from "../types";

// ---------------------------------------------------------------------------
// Type / tone tables (preserved verbatim from the prior presentation layer).
// ---------------------------------------------------------------------------

type TabId = "steps" | "answers" | "live" | "connected" | "activity";

// Status -> mock badge tone. Mirrors the STATUS_SEVERITY table one-for-one
// on the mock's semantic tone keys so `MonoBadge tone={STATUS_TONE[status]}`
// picks up the right --status-* token.
const STATUS_TONE: Record<string, string> = {
  created: "info",
  queued: "info",
  ready: "low",
  analyzing: "medium",
  running: "medium",
  pending: "info",
  completed: "low",
  failed: "critical",
  exhausted: "high",
  cancelled: "high",
  abandoned: "muted",
  stalled: "muted",
};

// Answer-confidence -> mock badge tone. Same policy as CONFIDENCE_SEVERITY
// (high confidence reads reassuring; low reads alarming).
const CONFIDENCE_TONE: Record<string, string> = {
  high: "low",
  medium: "medium",
  low: "high",
  unknown: "info",
};

// Confidence -> WindowPanel tone (a strict subset of the shared kit tones).
const CONFIDENCE_PANEL_TONE: Record<string, "ok" | "warn" | "info" | "accent" | "muted"> = {
  high: "ok",
  medium: "info",
  low: "warn",
  unknown: "muted",
};

// "pending" is the status freshly-submitted investigations sit at until the
// freeflow agent flips them to "running". The earlier states (intake /
// collection / deep_analysis) emit progress while the row is still "pending",
// so we must treat it as running for SSE subscription purposes or the live
// feed silently never subscribes.
const RUNNING_STATUSES: Record<string, true> = {
  pending: true,
  queued: true,
  running: true,
  analyzing: true,
};

// ---------------------------------------------------------------------------
// Shared raw-button primitives (no `@/components/ui/button` -- all mock).
// ---------------------------------------------------------------------------

type BtnTone = "accent" | "warn" | "critical" | "muted" | "ok";

function baseBtnStyle(
  tone: BtnTone,
  disabled?: boolean,
): React.CSSProperties {
  const c = toneColor(tone === "critical" ? "critical" : tone);
  const filled = tone === "critical" || tone === "accent" || tone === "ok";
  return {
    height: 28,
    padding: "0 12px",
    fontSize: 10,
    letterSpacing: "0.08em",
    borderRadius: 3,
    cursor: disabled ? "not-allowed" : "pointer",
    color: filled ? "var(--text-on-accent)" : c,
    background: filled ? c : "transparent",
    border: filled
      ? `1px solid ${c}`
      : `1px solid color-mix(in srgb, ${c} 55%, var(--border-soft))`,
    opacity: disabled ? 0.55 : 1,
  };
}

interface MockButtonProps {
  tone: BtnTone;
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  children: React.ReactNode;
}

function MockButton({ tone, onClick, disabled, title, children }: MockButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="font-mono uppercase"
      style={baseBtnStyle(tone, disabled)}
    >
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Case-model panel (contract / hypotheses / observables / provenance).
// Presentation only -- content-derivation logic is verbatim from the prior file.
// ---------------------------------------------------------------------------
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

  const label: React.CSSProperties = {
    fontSize: 9,
    letterSpacing: "0.08em",
    color: "var(--text-muted)",
    textTransform: "uppercase",
  };

  return (
    <div
      className="space-y-2"
      style={{
        borderTop: "1px solid var(--border-soft)",
        padding: "8px 14px",
        background: "var(--surface-sunk)",
      }}
    >
      {contract && (
        <div className="font-mono" style={{ fontSize: 11 }}>
          <span style={label}>contract</span>{" "}
          <span style={{ color: "var(--text-primary)" }}>
            {contract.answer_type && `type=${contract.answer_type} `}
            {contract.answer_format && `format="${contract.answer_format}" `}
            {contract.evidence_domain && `evidence=${contract.evidence_domain}`}
          </span>
        </div>
      )}
      {step.expected_observation && (
        <div className="font-mono" style={{ fontSize: 11 }}>
          <span style={label}>expected</span>{" "}
          <span style={{ color: "var(--text-primary)" }}>{step.expected_observation}</span>
        </div>
      )}
      {hypotheses.length > 0 && (
        <div className="font-mono" style={{ fontSize: 11 }}>
          <div style={label}>hypotheses</div>
          <ul className="pl-3" style={{ marginTop: 2 }}>
            {hypotheses.map((h, i) => (
              <li key={i} style={{ color: "var(--text-primary)" }}>
                <span style={{ color: "var(--text-muted)" }}>{h.id ?? `H${i + 1}`}:</span>{" "}
                {h.claim}
                {h.kill_criterion && (
                  <span style={{ color: "var(--text-faint)", fontStyle: "italic" }}>
                    {" "}
                    -- kill: {h.kill_criterion}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {rejected.length > 0 && (
        <div className="font-mono" style={{ fontSize: 11 }}>
          <div style={label}>rejected ({rejected.length})</div>
          <ul className="pl-3" style={{ marginTop: 2 }}>
            {rejected.slice(0, 5).map((r, i) => (
              <li
                key={i}
                style={{ color: "var(--text-faint)", textDecoration: "line-through" }}
              >
                {r.id ?? "?"}: {r.claim}
                {r.reason && (
                  <span style={{ fontStyle: "italic", textDecoration: "none" }}>
                    {" "}
                    ({r.reason})
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {observables && Object.keys(observables).length > 0 && (
        <div className="font-mono" style={{ fontSize: 11 }}>
          <div style={label}>observables</div>
          <div className="flex flex-wrap gap-1 pl-3" style={{ marginTop: 2 }}>
            {Object.entries(observables).slice(0, 24).map(([k, v]) => (
              <code
                key={k}
                style={{
                  padding: "1px 6px",
                  fontSize: 10,
                  background: "var(--surface-card)",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 2,
                  color: "var(--text-muted)",
                }}
              >
                {k}={String(v).slice(0, 120)}
              </code>
            ))}
          </div>
        </div>
      )}
      {provenance && (provenance.primary_artifact || (provenance.corroboration?.length ?? 0) > 0) && (
        <div className="font-mono" style={{ fontSize: 11 }}>
          <div style={label}>provenance</div>
          {provenance.primary_artifact && (
            <div className="pl-3" style={{ color: "var(--text-primary)" }}>
              primary:{" "}
              <code style={{ color: "var(--text-primary)" }}>{provenance.primary_artifact}</code>
            </div>
          )}
          {(provenance.corroboration?.length ?? 0) > 0 && (
            <div className="pl-3" style={{ color: "var(--text-muted)" }}>
              corroboration:{" "}
              {(provenance.corroboration ?? []).map((c, i) => (
                <code key={i} style={{ marginLeft: 4, color: "var(--text-muted)" }}>
                  {c}
                </code>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collapsible <details> block styled to the mock.
// ---------------------------------------------------------------------------
function CollapsibleBlock({
  label,
  tone,
  children,
  defaultOpen = false,
}: {
  label: React.ReactNode;
  tone: "ok" | "warn" | "critical" | "muted";
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const c = toneColor(tone);
  return (
    <details
      style={{
        borderTop: "1px solid var(--border-soft)",
      }}
      open={defaultOpen}
    >
      <summary
        className="font-mono uppercase"
        style={{
          cursor: "pointer",
          listStyle: "none",
          padding: "6px 14px",
          fontSize: 10,
          letterSpacing: "0.08em",
          color: c,
          display: "flex",
          alignItems: "center",
          gap: 6,
          userSelect: "none",
        }}
      >
        <span aria-hidden="true">{"\u25b8"}</span>
        <span>{label}</span>
      </summary>
      <div style={{ padding: "0 14px 10px" }}>{children}</div>
    </details>
  );
}

// ---------------------------------------------------------------------------
// StepCard -- bordered mono panel + step number square + action + exit badge.
// ---------------------------------------------------------------------------
function StepCard({ step }: { step: AgentStep }) {
  const failed = step.exit_code !== null && step.exit_code !== 0;
  const hasStdout = !!step.stdout?.trim();
  const hasStderr = !!step.stderr?.trim();
  const hasScript = !!step.script_content?.trim();
  const accent = failed ? "var(--accent)" : "var(--border-soft)";

  return (
    <div
      style={{
        background: "var(--surface-card)",
        border: `1px solid ${accent}`,
        borderRadius: 3,
      }}
    >
      <div className="flex items-start gap-3" style={{ padding: "10px 14px" }}>
        <span
          className="font-mono"
          aria-hidden="true"
          style={{
            flex: "0 0 auto",
            width: 26,
            height: 26,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 11,
            fontWeight: 700,
            background: failed
              ? "color-mix(in srgb, var(--accent) 18%, transparent)"
              : "var(--surface-sunk)",
            color: failed ? "var(--accent)" : "var(--text-muted)",
            border: `1px solid ${failed ? "color-mix(in srgb, var(--accent) 45%, transparent)" : "var(--border-soft)"}`,
            borderRadius: 3,
          }}
        >
          {step.step_number}
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="font-mono"
              style={{ fontSize: 12, color: "var(--text-primary)" }}
            >
              {step.action}
            </span>
            {step.exit_code !== null && (
              <MonoBadge tone={failed ? "critical" : "ok"}>
                exit {step.exit_code}
              </MonoBadge>
            )}
          </div>
          {step.reasoning && (
            <p style={{ fontSize: 11, color: "var(--text-muted)" }}>{step.reasoning}</p>
          )}
          {step.command && (
            <code
              className="block font-mono truncate"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                padding: "3px 8px",
                borderRadius: 2,
              }}
            >
              {step.command}
            </code>
          )}
        </div>
      </div>

      <CaseModelPanel step={step} />

      {hasScript && (
        <CollapsibleBlock label={`script content (${step.script_content!.length} chars)`} tone="warn">
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: "6px 8px",
              fontSize: 11,
              color: "var(--status-warn)",
              background: "var(--surface-sunk)",
              border: "1px solid color-mix(in srgb, var(--status-warn) 30%, transparent)",
              borderRadius: 2,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              overflowX: "auto",
            }}
          >
            {step.script_content}
          </pre>
        </CollapsibleBlock>
      )}

      {hasStdout && (
        <CollapsibleBlock label={`stdout (${step.stdout!.length.toLocaleString()} bytes)`} tone="ok">
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: "6px 8px",
              fontSize: 11,
              color: "var(--status-ok)",
              background: "var(--surface-sunk)",
              border: "1px solid color-mix(in srgb, var(--status-ok) 30%, transparent)",
              borderRadius: 2,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              maxHeight: 320,
              overflow: "auto",
            }}
          >
            {step.stdout}
          </pre>
        </CollapsibleBlock>
      )}

      {hasStderr && (
        <CollapsibleBlock label="stderr" tone={failed ? "critical" : "muted"}>
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: "6px 8px",
              fontSize: 11,
              color: failed ? "var(--accent)" : "var(--text-muted)",
              background: "var(--surface-sunk)",
              border: `1px solid ${failed ? "color-mix(in srgb, var(--accent) 40%, transparent)" : "var(--border-soft)"}`,
              borderRadius: 2,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              maxHeight: 320,
              overflow: "auto",
            }}
          >
            {step.stderr}
          </pre>
        </CollapsibleBlock>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AnswerCard -- one WindowPanel per candidate.
// ---------------------------------------------------------------------------
function AnswerCard({ answer }: { answer: AnswerCandidate }) {
  const tone = CONFIDENCE_PANEL_TONE[answer.confidence] ?? "muted";
  const truncatedQ =
    answer.question_text.length > 80
      ? `${answer.question_text.slice(0, 80)}\u2026`
      : answer.question_text;
  return (
    <WindowPanel
      title={truncatedQ}
      tone={tone}
      status={`confidence ; ${answer.confidence}`}
    >
      <div className="space-y-2">
        <p style={{ fontSize: 12, color: "var(--text-primary)" }}>{answer.answer_text}</p>
        {answer.corroboration.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
                marginRight: 4,
              }}
            >
              corroborated by
            </span>
            {answer.corroboration.map((c, i) => (
              <MonoBadge key={i} tone="muted">
                {c}
              </MonoBadge>
            ))}
          </div>
        )}
        {answer.created_at && (
          <p
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.08em",
              color: "var(--text-faint)",
            }}
          >
            {new Date(answer.created_at).toLocaleString()}
          </p>
        )}
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Investigation controls -- Stop / Rerun / Tag row + tag form panel.
// ---------------------------------------------------------------------------
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

  const inputStyle: React.CSSProperties = {
    height: 28,
    padding: "0 10px",
    fontSize: 11,
    background: "var(--surface-sunk)",
    border: "1px solid var(--border-soft)",
    color: "var(--text-primary)",
    borderRadius: 3,
    width: "100%",
  };
  const textareaStyle: React.CSSProperties = {
    ...inputStyle,
    height: "auto",
    padding: "6px 10px",
    minHeight: 56,
    resize: "vertical",
  };
  const labelStyle: React.CSSProperties = {
    fontSize: 9,
    letterSpacing: "0.08em",
    color: "var(--text-muted)",
    textTransform: "uppercase",
  };

  return (
    <div className="flex flex-col items-stretch gap-2" style={{ minWidth: 240 }}>
      <div className="flex flex-wrap justify-end gap-2">
        {isRunning && (
          <MockButton
            tone="critical"
            onClick={handleCancel}
            disabled={cancel.isPending}
          >
            {cancel.isPending ? "stopping\u2026" : "stop"}
          </MockButton>
        )}
        {!isRunning && (
          <MockButton
            tone="muted"
            onClick={() => rerun.mutate({ investigationId })}
            disabled={rerun.isPending}
            title="Start a new investigation that carries this attempt's findings forward"
          >
            {rerun.isPending ? "restarting\u2026" : "rerun (enriched)"}
          </MockButton>
        )}
        {canTag && (
          <>
            <MockButton
              tone="ok"
              onClick={() => openTagForm("true")}
              disabled={isDisabledTag || tag.isPending}
              title={isDisabledTag ? "Only completed investigations can be tagged" : undefined}
            >
              tag as true finding
            </MockButton>
            <MockButton
              tone="warn"
              onClick={() => openTagForm("false")}
              disabled={isDisabledTag || tag.isPending}
              title={isDisabledTag ? "Only completed investigations can be tagged" : undefined}
            >
              tag as false finding
            </MockButton>
          </>
        )}
      </div>
      {tagForm && (
        <WindowPanel
          title="tag finding"
          tone={tagForm === "true" ? "ok" : "warn"}
          status={`verdict ; ${tagForm}`}
        >
          <div className="space-y-3">
            <p style={{ fontSize: 12, color: "var(--text-primary)" }}>
              Tag as{" "}
              <span
                className="font-mono uppercase"
                style={{
                  color: tagForm === "true" ? "var(--status-ok)" : "var(--status-warn)",
                  letterSpacing: "0.08em",
                }}
              >
                {tagForm}
              </span>{" "}
              finding.
            </p>
            <p style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Saved to the Solid Evidence tab and injected into every future
              investigation's prompt as a{" "}
              {tagForm === "true" ? "confirmed fact" : "disproved hypothesis"}.
            </p>
            {answerCandidates.length > 1 && (
              <div className="space-y-1">
                <label htmlFor="tag-answer-select" className="font-mono" style={labelStyle}>
                  which answer?
                </label>
                <select
                  id="tag-answer-select"
                  className="font-mono"
                  style={inputStyle}
                  value={selectedAnswerId}
                  onChange={(e) => setSelectedAnswerId(e.target.value)}
                >
                  <option value="">(use investigation's final_answer)</option>
                  {answerCandidates.map((a) => (
                    <option key={a.id} value={a.id}>
                      [{a.confidence}] {a.answer_text.slice(0, 80)}
                      {a.answer_text.length > 80 ? "\u2026" : ""}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div className="space-y-1">
              <label htmlFor="tag-notes" className="font-mono" style={labelStyle}>
                notes (optional)
              </label>
              <textarea
                id="tag-notes"
                rows={2}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Why? Any caveats?"
                className="font-mono"
                style={textareaStyle}
              />
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <MockButton
                tone="muted"
                onClick={() => setTagForm(null)}
                disabled={tag.isPending}
              >
                cancel
              </MockButton>
              <MockButton
                tone={tagForm === "true" ? "ok" : "warn"}
                onClick={submitTag}
                disabled={tag.isPending}
              >
                {tag.isPending ? "saving\u2026" : "confirm"}
              </MockButton>
            </div>
          </div>
        </WindowPanel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Zombie-reap banner (§49). Presentation swap only; behavior identical.
// ---------------------------------------------------------------------------
interface ZombieReapBannerProps {
  projectId: string;
  investigationId: string;
  reason: string | null;
}

/**
 * Operator affordance for §49 zombie reap. The backend's GET handlers
 * mark a row ``needs_reap=true`` when the task is dead but the row's
 * ``status`` never got flipped; the POST re-checks the same predicate
 * and only then transitions to ``failed``. 409 means the row is no
 * longer stuck (someone else reaped, or the task recovered) -- the
 * mutation handles that as a benign refetch.
 */
function ZombieReapBanner({ projectId, investigationId, reason }: ZombieReapBannerProps) {
  const reap = useReapInvestigation(projectId);
  const handleReap = () => {
    const ok = window.confirm(
      "Force-fail this zombie investigation? This flips its status to `failed` and writes an audit note. Use only when the task is confirmed dead.",
    );
    if (!ok) return;
    reap.mutate(investigationId);
  };
  return (
    <WindowPanel title="zombie investigation detected" tone="warn" status="investigation ; needs reap">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1 flex-1" style={{ minWidth: "16rem" }}>
          <p style={{ fontSize: 12, color: "var(--text-primary)" }}>
            The backing task has settled but this row was never flipped to a
            terminal status. Reaping records an audit-friendly failure so
            downstream views stop treating it as live.
          </p>
          {reason && (
            <p className="font-mono break-all" style={{ fontSize: 11, color: "var(--text-muted)" }}>
              reason: {reason}
            </p>
          )}
        </div>
        <MockButton
          tone="critical"
          onClick={handleReap}
          disabled={reap.isPending}
        >
          {reap.isPending ? "reaping\u2026" : "reap (force-fail zombie)"}
        </MockButton>
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Live-event row -- streamed frame rendering, colour rules swapped to mock.
// ---------------------------------------------------------------------------
interface LiveEventRowProps {
  stage: string;
  message: string;
  percent: number | null | undefined;
  payload: Record<string, unknown>;
}

function stageColor(stage: string): string {
  if (stage.includes("error") || stage.includes("failed")) return "var(--accent)";
  if (stage.includes("done") || stage === "completed" || stage.includes("detected"))
    return "var(--status-ok)";
  if (stage.includes("start") || stage.includes("begin")) return "var(--status-warn)";
  if (stage === "artifact_added") return "var(--status-info)";
  if (stage === "heartbeat") return "var(--text-muted)";
  return "var(--accent)";
}

function LiveEventRow({ stage, message, percent, payload }: LiveEventRowProps) {
  const color = stageColor(stage);
  const lane = typeof payload.lane === "string" ? payload.lane : undefined;
  const path = typeof payload.path === "string" ? payload.path : undefined;
  const err = typeof payload.error === "string" ? payload.error : undefined;
  const inner = payload.query ?? payload.plugin ?? payload.tier;

  // Freeflow-specific payload fields: the actual script / shell command
  // being executed on the analyzer and the last chunk of its output.
  // Prefer full fields (script, reasoning) over the legacy *_preview ones
  // so the analyst sees the whole thing instead of a clipped headline.
  const script =
    typeof payload.script === "string"
      ? payload.script
      : typeof payload.script_preview === "string"
        ? payload.script_preview
        : undefined;
  const command = typeof payload.command === "string" ? payload.command : undefined;
  const stdout =
    typeof payload.stdout === "string"
      ? payload.stdout
      : typeof payload.stdout_tail === "string"
        ? payload.stdout_tail
        : undefined;
  const stderr =
    typeof payload.stderr === "string"
      ? payload.stderr
      : typeof payload.stderr_tail === "string"
        ? payload.stderr_tail
        : undefined;
  const stdoutBytes =
    typeof payload.stdout_bytes === "number" ? payload.stdout_bytes : undefined;
  const reasoning =
    typeof payload.reasoning === "string"
      ? payload.reasoning
      : typeof payload.reasoning_preview === "string"
        ? payload.reasoning_preview
        : undefined;
  const exitCode = typeof payload.exit_code === "number" ? payload.exit_code : undefined;

  const detailsSummary: React.CSSProperties = {
    cursor: "pointer",
    listStyle: "none",
    fontSize: 10,
    letterSpacing: "0.06em",
    color: "var(--status-warn)",
    userSelect: "none",
  };

  return (
    <div style={{ padding: "2px 0" }}>
      <div className="flex gap-2">
        {percent !== null && percent !== undefined && percent > 0 && (
          <span
            className="font-mono shrink-0 text-right"
            style={{ width: 36, color: "var(--text-muted)" }}
          >
            {percent}%
          </span>
        )}
        <span
          className="font-mono shrink-0"
          style={{ color, fontWeight: 600 }}
        >
          [{stage}]
        </span>
        {lane && (
          <span className="font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
            {lane}
          </span>
        )}
        {typeof inner === "string" && inner && (
          <span className="font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
            {inner}
          </span>
        )}
        <span className="break-all" style={{ color: "var(--text-primary)" }}>
          {message}
        </span>
      </div>
      {path && (
        <div
          className="font-mono break-all"
          style={{ paddingLeft: 56, fontSize: 10, color: "var(--text-muted)" }}
        >
          {"\u21b3 "}
          {path}
        </div>
      )}
      {err && (
        <div
          className="flex gap-1 break-all"
          style={{
            paddingLeft: 56,
            fontSize: 10,
            color: "var(--accent)",
            whiteSpace: "pre-wrap",
          }}
        >
          <PixelIcon name="close" size={11} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{err}</span>
        </div>
      )}
      {reasoning && (
        <details style={{ paddingLeft: 56, marginTop: 2 }} open>
          <summary
            style={{
              ...detailsSummary,
              color: "var(--text-muted)",
            }}
          >
            reasoning ({reasoning.length} chars)
          </summary>
          <div
            className="font-mono"
            style={{
              marginTop: 4,
              padding: "3px 8px",
              fontSize: 10,
              color: "var(--text-muted)",
              fontStyle: "italic",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              whiteSpace: "pre-wrap",
            }}
          >
            {reasoning}
          </div>
        </details>
      )}
      {command && (
        <details style={{ paddingLeft: 56, marginTop: 4 }}>
          <summary style={detailsSummary}>
            shell command ({command.length} chars) -- click to expand
          </summary>
          <pre
            className="font-mono"
            style={{
              marginTop: 4,
              padding: "3px 8px",
              fontSize: 10,
              color: "var(--status-warn)",
              background: "var(--surface-sunk)",
              border: "1px solid color-mix(in srgb, var(--status-warn) 30%, transparent)",
              borderRadius: 2,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {command}
          </pre>
        </details>
      )}
      {script && (
        <details style={{ paddingLeft: 56, marginTop: 4 }}>
          <summary style={detailsSummary}>
            python script ({script.length} chars) -- click to expand
          </summary>
          <pre
            className="font-mono"
            style={{
              marginTop: 4,
              padding: "3px 8px",
              fontSize: 10,
              color: "var(--status-warn)",
              background: "var(--surface-sunk)",
              border: "1px solid color-mix(in srgb, var(--status-warn) 30%, transparent)",
              borderRadius: 2,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {script}
          </pre>
        </details>
      )}
      {(stdout || stderr) && (
        <details style={{ paddingLeft: 56, marginTop: 4 }} open>
          <summary
            style={{
              ...detailsSummary,
              color: "var(--status-ok)",
            }}
          >
            output {exitCode !== undefined ? `(exit=${exitCode})` : ""}
            {stdoutBytes !== undefined && stdout && stdoutBytes > stdout.length
              ? ` -- showing last ${stdout.length.toLocaleString()} of ${stdoutBytes.toLocaleString()} bytes`
              : stdout
                ? ` -- ${stdout.length.toLocaleString()} bytes`
                : ""}
          </summary>
          {stdout && (
            <pre
              className="font-mono"
              style={{
                marginTop: 4,
                padding: "3px 8px",
                fontSize: 10,
                color: "var(--status-ok)",
                background: "var(--surface-sunk)",
                border: "1px solid color-mix(in srgb, var(--status-ok) 30%, transparent)",
                borderRadius: 2,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                maxHeight: 512,
                overflow: "auto",
              }}
            >
              {stdout}
            </pre>
          )}
          {stderr && (
            <pre
              className="font-mono"
              style={{
                marginTop: 4,
                padding: "3px 8px",
                fontSize: 10,
                color: "var(--accent)",
                background: "var(--surface-sunk)",
                border: "1px solid color-mix(in srgb, var(--accent) 30%, transparent)",
                borderRadius: 2,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                maxHeight: 320,
                overflow: "auto",
              }}
            >
              {stderr}
            </pre>
          )}
        </details>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page.
// ---------------------------------------------------------------------------
export function InvestigationDetailPage() {
  const { projectId, investigationId } = useParams<{
    projectId: string;
    investigationId: string;
  }>();
  const navigate = useNavigate();

  // Default to "live" when the investigation is still running so the user
  // sees progress immediately instead of landing on an empty "Steps" tab.
  const [activeTab, setActiveTab] = useState<TabId>("live");

  const {
    data: investigation,
    isLoading,
    isError,
  } = useInvestigationDetail(projectId ?? "", investigationId ?? "");

  useUpdatePageHeader({
    title: investigation
      ? `Investigation ${investigationId?.slice(0, 8) ?? ""}`
      : "Investigation",
    subtitle: investigation?.status ?? undefined,
    status:
      investigation?.status === "running"
        ? "live"
        : investigation?.status === "failed"
          ? "error"
          : investigation?.status === "completed"
            ? "ready"
            : null,
  });

  const { data: answers, isLoading: answersLoading } = useInvestigationAnswers(
    projectId ?? "",
    investigationId ?? "",
  );

  const isRunning = investigation ? RUNNING_STATUSES[investigation.status] === true : false;
  const {
    events: liveEvents,
    feedStatus,
    latestStage,
  } = useForensicsInvestigationEvents({
    projectId: projectId ?? "",
    investigationId: investigationId ?? "",
    isRunning,
  });

  if (!projectId || !investigationId) {
    return (
      <WindowPanel title="investigation" tone="warn" status="forensics ; invalid investigation url">
        <p style={{ fontSize: 12, color: "var(--accent)" }}>Invalid investigation URL.</p>
      </WindowPanel>
    );
  }

  if (isLoading) return <InvestigationDetailSkeleton />;

  if (isError || !investigation) {
    return (
      <WindowPanel title="investigation" tone="warn" status="forensics ; investigation unavailable">
        <p style={{ fontSize: 12, color: "var(--accent)" }}>Failed to load investigation.</p>
      </WindowPanel>
    );
  }

  const TABS: { id: TabId; label: string; count?: number }[] = [
    ...(isRunning ? [{ id: "live" as TabId, label: "Live", count: liveEvents.length }] : []),
    { id: "steps", label: "Steps", count: investigation.steps.length },
    { id: "answers", label: "Answers", count: answers?.length },
    { id: "connected", label: "Connected" },
    { id: "activity", label: "Activity" },
  ];

  // Right-rail engine-vitals tone: mirrors the row's terminal / running
  // state so the panel light square colour reads at a glance.
  const vitalsTone: "ok" | "warn" | "info" | "accent" =
    investigation.status === "completed"
      ? "ok"
      : investigation.status === "failed" ||
          investigation.status === "exhausted" ||
          investigation.status === "cancelled"
        ? "warn"
        : isRunning
          ? "info"
          : "accent";

  const vitalsRows: Array<{ k: string; v: string | number }> = [
    { k: "status", v: investigation.status },
    {
      k: "attempts",
      v: `${investigation.attempts_used}${investigation.max_attempts ? `/${investigation.max_attempts}` : ""}`,
    },
    ...(investigation.confidence ? [{ k: "confidence", v: investigation.confidence }] : []),
    ...(isRunning ? [{ k: "feed", v: feedStatus }] : []),
    ...(isRunning && latestStage ? [{ k: "stage", v: latestStage }] : []),
    { k: "steps", v: investigation.steps.length },
    { k: "answers", v: answers?.length ?? 0 },
    { k: "resolved", v: investigation.final_answer ? "yes" : "no" },
  ];

  // Aggregate hypotheses across every recorded step; a later `rejected`
  // entry supersedes a live one carrying the same id/claim.
  const railHypotheses: Array<{ key: string; claim: string; state: "live" | "rejected" }> = (() => {
    const m = new Map<string, { key: string; claim: string; state: "live" | "rejected" }>();
    for (const step of investigation.steps) {
      for (const h of step.hypotheses ?? []) {
        const key = h.id || h.claim || "";
        if (!key) continue;
        m.set(key, { key, claim: h.claim || h.id || key, state: "live" });
      }
      for (const r of step.rejected ?? []) {
        const key = r.id || r.claim || "";
        if (!key) continue;
        m.set(key, { key, claim: r.claim || r.id || key, state: "rejected" });
      }
    }
    return [...m.values()];
  })();

  // Append-only activity ticker: the live stream while running, else the
  // durable reasoning-step ledger.
  const railLedger: Array<{ key: string; kind: string; payload: string; color: string }> =
    isRunning && liveEvents.length > 0
      ? liveEvents.map((ev, i) => {
          const s = ev.stage ?? "";
          return {
            key: `ev-${i}`,
            kind: ev.stage ?? "event",
            payload: ev.message ?? "",
            color:
              s.includes("error") || s.includes("failed")
                ? "var(--accent)"
                : s.includes("done") || s === "completed"
                  ? "var(--status-ok)"
                  : "var(--status-info)",
          };
        })
      : investigation.steps
          .slice()
          .sort((a, b) => a.step_number - b.step_number)
          .map((s) => ({
            key: s.id,
            kind: s.action || `#${s.step_number}`,
            payload: s.reasoning || s.command || "",
            color:
              s.exit_code !== null && s.exit_code !== 0
                ? "var(--accent)"
                : "var(--status-ok)",
          }));

  const metaRow: React.CSSProperties = {
    fontSize: 10,
    letterSpacing: "0.08em",
    color: "var(--text-muted)",
    textTransform: "uppercase",
  };

  const parentInvestigationId = investigation.parent_investigation_id ?? null;

  const feedDotColor =
    feedStatus === "live"
      ? "var(--status-warn)"
      : feedStatus === "connecting"
        ? "var(--status-info)"
        : "var(--surface-hover)";

  return (
    <div className="space-y-4">
      {/* Case header row with icon badge + Apoc title + right-aligned controls. */}
      <SectionHeader
        icon={<PixelIcon name="terminal" />}
        title={`case ${investigationId.slice(0, 8)}`}
        actions={
          <InvestigationControls
            projectId={projectId}
            investigationId={investigationId}
            status={investigation.status}
            isRunning={isRunning}
            hasFinalAnswer={!!investigation.final_answer}
            answerCandidates={answers ?? []}
          />
        }
      />

      {/* Metadata strip -- mono uppercase key ; value pairs + back link. */}
      <div className="flex flex-wrap items-center gap-4 font-mono" style={metaRow}>
        <span>
          case <span style={{ color: "var(--text-faint)" }}>;</span>{" "}
          <span style={{ color: "var(--text-primary)" }}>{investigationId.slice(0, 8)}</span>
        </span>
        <span>
          attempts <span style={{ color: "var(--text-faint)" }}>;</span>{" "}
          <span style={{ color: "var(--text-primary)" }}>
            {investigation.attempts_used}
            {investigation.max_attempts ? `/${investigation.max_attempts}` : ""}
          </span>
        </span>
        {investigation.confidence && (
          <span>
            confidence <span style={{ color: "var(--text-faint)" }}>;</span>{" "}
            <span style={{ color: "var(--text-primary)" }}>{investigation.confidence}</span>
          </span>
        )}
        <MonoBadge tone={STATUS_TONE[investigation.status] ?? "muted"}>
          {investigation.status}
        </MonoBadge>
        <span style={{ flex: 1 }} />
        <button
          type="button"
          onClick={() => navigate(`/forensics/projects/${projectId}`)}
          className="font-mono uppercase"
          style={{
            ...metaRow,
            cursor: "pointer",
            background: "transparent",
            border: "1px solid var(--border-soft)",
            padding: "4px 8px",
            borderRadius: 2,
            color: "var(--text-muted)",
          }}
        >
          {"\u2039 back to project"}
        </button>
        <button
          type="button"
          onClick={() =>
            navigate(
              `/forensics/projects/${projectId}/investigations/${investigationId}/reasoning-replay`,
            )
          }
          className="font-mono uppercase"
          style={{
            ...metaRow,
            cursor: "pointer",
            background: "transparent",
            border: "1px solid var(--border-soft)",
            padding: "4px 8px",
            borderRadius: 2,
            color: "var(--text-muted)",
          }}
          title="Step through the reasoning-graph snapshots this investigation recorded"
        >
          reasoning replay
        </button>
      </div>

      {/* Investigation question -- displayed as a mono body block. */}
      <p
        className="font-mono"
        style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}
      >
        {investigation.question}
      </p>

      {/* Enriched-rerun banner -- prior-attempt lineage. */}
      {parentInvestigationId && (
        <WindowPanel title="enriched rerun" tone="info" status="lineage ; carries findings forward">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p style={{ fontSize: 12, color: "var(--text-primary)" }}>
              This investigation carries findings forward from a prior attempt.
              Confirmed observables are pre-loaded into the agent's working
              memory; the prior answer is treated as a hypothesis to verify.
            </p>
            <MockButton
              tone="accent"
              onClick={() =>
                navigate(
                  `/forensics/projects/${projectId}/investigations/${parentInvestigationId}`,
                )
              }
            >
              view parent ({parentInvestigationId.slice(0, 8)})
            </MockButton>
          </div>
        </WindowPanel>
      )}

      {/* Zombie-reap banner (§49) -- POST /reap flips status to failed. */}
      {investigation.needs_reap && (
        <ZombieReapBanner
          projectId={projectId}
          investigationId={investigationId}
          reason={investigation.needs_reap_reason ?? null}
        />
      )}

      {/* Final answer banner. */}
      {investigation.final_answer && (
        <WindowPanel title="final answer" tone="accent" status="investigation ; resolved">
          <p style={{ fontSize: 12, color: "var(--text-primary)" }}>
            {investigation.final_answer}
          </p>
        </WindowPanel>
      )}

      {/* Tiled workbench -- main reasoning column + right rail overview. */}
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start">
        <div className="min-w-0 flex-1 space-y-4">
          {/* Live run panel -- mounted only while running. */}
          {isRunning && (
            <PanelBoundary label="Live run panel">
              <LiveRunPanel
                status={investigation.status}
                attemptsUsed={investigation.attempts_used}
                maxAttempts={investigation.max_attempts}
                events={liveEvents}
                feedStatus={feedStatus}
                latestStage={latestStage}
              />
            </PanelBoundary>
          )}

          {/* Analyst directives -- readable on every turn by AILA. */}
          <AnalystDirectivesPanel
            projectId={projectId}
            investigationId={investigationId}
          />

          {/* Retrieve-File -- pull any artefact out of the disk image. */}
          <RetrieveFilePanel projectId={projectId} />

          {/* Tab bar -- Segmented with inline [N] counts. */}
          <Segmented<TabId>
            options={TABS.map((tab) => ({
              value: tab.id,
              label: (
                <span>
                  {tab.label.toUpperCase()}
                  {tab.count !== undefined && (
                    <span style={{ marginLeft: 6, color: "var(--text-faint)" }}>
                      [{tab.count}]
                    </span>
                  )}
                </span>
              ),
            }))}
            value={activeTab}
            onChange={setActiveTab}
          />

          {/* Tab content -- one WindowPanel per active tab. */}
          {activeTab === "live" && (
            <WindowPanel
              title="live"
              tone="info"
              status={`feed ; ${feedStatus}${latestStage ? ` :: ${latestStage}` : ""}`}
              flush
            >
              <div className="space-y-2" style={{ padding: 12 }}>
                <div className="flex items-center gap-2 font-mono uppercase" style={metaRow}>
                  <span
                    aria-hidden="true"
                    className={
                      feedStatus === "live" || feedStatus === "connecting"
                        ? "motion-safe:animate-pulse"
                        : ""
                    }
                    style={{
                      display: "inline-block",
                      width: 8,
                      height: 8,
                      borderRadius: 999,
                      background: feedDotColor,
                    }}
                  />
                  <span>{feedStatus}</span>
                  {latestStage && (
                    <>
                      <span style={{ color: "var(--text-faint)" }}>;</span>
                      <span style={{ color: "var(--text-primary)" }}>{latestStage}</span>
                    </>
                  )}
                </div>
                <div
                  className="font-mono space-y-1 overflow-y-auto"
                  style={{
                    background: "var(--surface-sunk)",
                    border: "1px solid var(--border-soft)",
                    borderRadius: 3,
                    padding: 10,
                    fontSize: 11,
                    maxHeight: 448,
                  }}
                >
                  {liveEvents.length === 0 && (
                    <p style={{ color: "var(--text-muted)" }}>{"Waiting for events\u2026"}</p>
                  )}
                  {liveEvents.map((ev, i) => {
                    const stage = ev.stage ?? "--";
                    let payload: Record<string, unknown> = {};
                    if (ev.data_json) {
                      try {
                        payload = JSON.parse(ev.data_json);
                      } catch {
                        // ignore -- render raw message only
                      }
                    }
                    return (
                      <LiveEventRow
                        key={i}
                        stage={stage}
                        message={ev.message ?? ""}
                        percent={ev.percent}
                        payload={payload}
                      />
                    );
                  })}
                </div>
              </div>
            </WindowPanel>
          )}

          {activeTab === "steps" && (
            <WindowPanel title="steps" tone="accent" status={`recorded ; ${investigation.steps.length}`}>
              <PanelBoundary label="Reasoning steps">
                <div className="space-y-3">
                  {investigation.steps.length === 0 ? (
                    <EmptyState
                      icon={<GitBranch className="h-10 w-10" />}
                      title="No steps recorded yet."
                      description={
                        isRunning
                          ? "The reasoning engine will emit step frames as soon as it lands the first turn -- watch the Live tab meanwhile."
                          : "Rerun (enriched) will re-drive the investigation and record fresh reasoning steps."
                      }
                    />
                  ) : (
                    investigation.steps
                      .slice()
                      .sort((a, b) => a.step_number - b.step_number)
                      .map((step) => <StepCard key={step.id} step={step} />)
                  )}
                </div>
              </PanelBoundary>
            </WindowPanel>
          )}

          {activeTab === "answers" && (
            <div className="space-y-3">
              {answersLoading && <InvestigationRowSkeletonList count={2} />}
              {!answersLoading && (answers ?? []).length === 0 && (
                <WindowPanel title="answers" tone="muted" status="candidates ; 0">
                  <EmptyState
                    icon={<Detective className="h-10 w-10" />}
                    title="No answer candidates yet."
                    description={
                      isRunning
                        ? "AILA is still collecting evidence. Candidates surface as soon as the first hypothesis crosses a confidence threshold."
                        : "Rerun (enriched) will re-drive this question and record fresh answer candidates."
                    }
                  />
                </WindowPanel>
              )}
              {(answers ?? []).map((a) => (
                <AnswerCard key={a.id} answer={a} />
              ))}
            </div>
          )}

          {activeTab === "connected" && (
            <WindowPanel title="connected" tone="info" status="entity graph">
              <PanelBoundary label="Connected panel">
                <ConnectedPanel projectId={projectId} investigation={investigation} />
              </PanelBoundary>
            </WindowPanel>
          )}

          {activeTab === "activity" && (
            <WindowPanel title="activity" tone="muted" status={`run ; ${(investigation.task_id ?? investigationId).slice(0, 8)}`}>
              <PanelBoundary label="Activity panel">
                <ActivityPanel runId={investigation.task_id ?? investigationId} />
              </PanelBoundary>
            </WindowPanel>
          )}
        </div>

        <aside
          className="w-full space-y-4 xl:w-80 xl:flex-none"
          aria-label="Investigation overview"
        >
          <WindowPanel
            title="engine vitals"
            tone={vitalsTone}
            status={`investigation ; ${investigation.status}`}
          >
            <dl className="flex flex-col">
              {vitalsRows.map((r) => (
                <div
                  key={r.k}
                  className="flex items-baseline justify-between gap-3"
                  style={{
                    padding: "6px 0",
                    borderBottom: "1px solid var(--border-soft)",
                  }}
                >
                  <dt
                    className="font-mono uppercase shrink-0"
                    style={{
                      fontSize: 10,
                      letterSpacing: "0.08em",
                      color: "var(--text-muted)",
                    }}
                  >
                    {r.k}
                  </dt>
                  <dd
                    className="font-mono truncate min-w-0 flex-1 text-right"
                    style={{ fontSize: 11, color: "var(--text-primary)" }}
                    title={String(r.v)}
                  >
                    {r.v}
                  </dd>
                </div>
              ))}
            </dl>
          </WindowPanel>

          <WindowPanel
            title="hypotheses"
            tone="info"
            status={`${railHypotheses.length} tracked`}
            flush
          >
            {railHypotheses.length === 0 ? (
              <p
                style={{
                  padding: 14,
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                No hypotheses recorded yet.
              </p>
            ) : (
              <ul style={{ maxHeight: 320, overflowY: "auto", margin: 0, padding: 0 }}>
                {railHypotheses.map((h) => (
                  <li
                    key={h.key}
                    className="flex items-center gap-2"
                    style={{
                      padding: "6px 12px",
                      borderBottom: "1px solid var(--border-soft)",
                      listStyle: "none",
                    }}
                  >
                    <MonoBadge tone={h.state === "rejected" ? "muted" : "info"}>
                      {h.state}
                    </MonoBadge>
                    <span
                      className="min-w-0 flex-1 truncate"
                      style={{
                        fontSize: 11,
                        color:
                          h.state === "rejected"
                            ? "var(--text-faint)"
                            : "var(--text-primary)",
                        textDecoration: h.state === "rejected" ? "line-through" : "none",
                      }}
                      title={h.claim}
                    >
                      {h.claim}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </WindowPanel>

          <WindowPanel title="ledger" tone="muted" status="append-only" flush>
            {railLedger.length === 0 ? (
              <p
                style={{
                  padding: 14,
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                {isRunning
                  ? "Waiting for the first activity frame\u2026"
                  : "No reasoning steps recorded yet."}
              </p>
            ) : (
              <ol
                className="font-mono"
                style={{ maxHeight: 384, overflowY: "auto", margin: 0, padding: 0 }}
              >
                {railLedger.map((e) => (
                  <li
                    key={e.key}
                    style={{
                      padding: "6px 12px",
                      fontSize: 10,
                      borderBottom: "1px solid var(--border-soft)",
                      listStyle: "none",
                    }}
                  >
                    <span style={{ color: e.color, fontWeight: 600 }}>[{e.kind}]</span>
                    {e.payload && (
                      <span
                        className="break-all"
                        style={{ marginLeft: 8, color: "var(--text-muted)" }}
                      >
                        {e.payload}
                      </span>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </WindowPanel>
        </aside>
      </div>
    </div>
  );
}
