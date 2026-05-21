import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { ExportReportButton } from "../components/ExportReportButton";
import { ReenqueuePicker } from "../components/ReenqueuePicker";
import { LiveDot, type LiveStatus } from "../components/LiveDot";
import { SteeringDrawer } from "../components/SteeringDrawer";
import { TurnCard } from "../components/TurnCard";
import { WorkflowStepper } from "../components/WorkflowStepper";
import { HypothesisDetailRail } from "../components/HypothesisDetailRail";
import { FuzzProposalsPanel } from "../components/FuzzProposalCard";
import { useInvestigationMessagesStream } from "../hooks/useInvestigationMessagesStream";
import { useVRKeyboardShortcuts } from "../hooks/useVRKeyboardShortcuts";
import {
  useDeleteInvestigation,
  usePauseInvestigation,
  useReenqueueInvestigation,
  useResumeInvestigation,
  useReverifyInvestigation,
  usePromoteOutcomeToFinding,
  useSendOperatorMessage,
} from "../mutations";
import {
  useInvestigation,
  useInvestigationBranches,
  useInvestigationMessages,
  useInvestigationOutcomes,
  useTargetName,
} from "../queries";
import type {
  BranchStatus,
  InvestigationStatus,
  OperatorIntent,
  OutcomeDispatchStatus,
  VRMessageSummary,
} from "../types";

const investigationStatusColor: Record<
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

const branchStatusColor: Record<
  BranchStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  active: "medium",
  paused: "info",
  merged: "low",
  promoted: "low",
  abandoned: "high",
};

const dispatchColor: Record<
  OutcomeDispatchStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  pending: "info",
  dispatched: "low",
  failed: "critical",
  skipped: "medium",
};

function fmtUsd(n: number): string {
  return `$${n.toFixed(2)}`;
}

function PayloadPreview({ payload }: { payload: Record<string, unknown> }) {
  const [expanded, setExpanded] = useState(false);
  // Outcome payloads carry the agent prose under one of these fields,
  // in priority order. assessment_report and patch_assessment_report
  // use `answer`; older shapes used `text`. Fall through to JSON for
  // structured payloads with no prose.
  const proseCandidate =
    (payload?.answer as string) ||
    (payload?.text as string) ||
    (payload?.summary as string) ||
    (payload?.description as string) ||
    "";
  if (proseCandidate) {
    const truncated = proseCandidate.length > 600;
    const shown = expanded || !truncated
      ? proseCandidate
      : proseCandidate.slice(0, 600) + "…";
    return (
      <div className="text-xs text-foreground whitespace-pre-wrap leading-relaxed break-words">
        {shown}
        {truncated && (
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            className="block mt-1 text-text-muted hover:text-foreground underline text-[10px]"
          >
            {expanded ? "Collapse" : `Show full (${proseCandidate.length} chars)`}
          </button>
        )}
      </div>
    );
  }
  const json = JSON.stringify(payload, null, 2);
  return (
    <pre className="text-[10px] text-text-muted font-mono whitespace-pre-wrap break-words">
      {json.slice(0, 240)}
      {json.length > 240 ? "…" : ""}
    </pre>
  );
}

/** Investigation Timeline — designed per 08_FRONTEND_UX.md §1.10.
 *
 *  Single-column TurnCard stream with sticky filter bar. Live-tails via
 *  the existing useInvestigationMessagesStream SSE hook; the LiveDot
 *  reflects connection state. URL state for filters lets operators
 *  deep-link a teammate to "look at this view of the timeline." */
export function InvestigationDetailPage() {
  const { investigationId } = useParams<{ investigationId: string }>();
  const invId = investigationId ?? "";
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: inv, isLoading } = useInvestigation(invId);
  const { data: branchesResult } = useInvestigationBranches(invId);
  const { data: messagesResult } = useInvestigationMessages(invId);
  useInvestigationMessagesStream(invId);
  const { data: outcomesResult } = useInvestigationOutcomes(invId);
  const targetName = useTargetName(inv?.target_id);

  const pauseMut = usePauseInvestigation(invId);
  const resumeMut = useResumeInvestigation(invId);
  const reenqueueMut = useReenqueueInvestigation(invId);
  const sendMut = useSendOperatorMessage(invId);
  const deleteMut = useDeleteInvestigation();
  const reverifyMut = useReverifyInvestigation();
  const promoteMut = usePromoteOutcomeToFinding(invId);

  const [messageText, setMessageText] = useState("");
  const [messageIntent, setMessageIntent] = useState<OperatorIntent | "">("");
  const [steeringOpen, setSteeringOpen] = useState(false);
  useVRKeyboardShortcuts({ onOpenSteering: () => setSteeringOpen(true) });
  const [liveTail, setLiveTail] = useState(true);


  // Live-tail: auto-scroll the newest turn into view when liveTail is on.
  // We watch the message count rather than ids so we don't re-fire on
  // every refetch.
  const lastSeenCount = useRef(0);
  useEffect(() => {
    if (!liveTail) return;
    const list = messagesResult?.data ?? [];
    if (list.length > lastSeenCount.current) {
      const id = `turn-${list.length - 1}`;
      requestAnimationFrame(() => {
        const el = document.getElementById(id);
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "end" });
          // Amber border flash — applied via a temporary class. Honours
          // prefers-reduced-motion (CSS keyframe respects the media query;
          // we just toggle the class).
          el.classList.add("animate-amber-flash");
          window.setTimeout(() => el.classList.remove("animate-amber-flash"), 1200);
        }
      });
    }
    lastSeenCount.current = list.length;
  }, [liveTail, messagesResult?.data]);
  // All hooks before any early return — keep React's hook ordering stable.
  const branches = branchesResult?.data ?? [];
  const messages = messagesResult?.data ?? [];
  const outcomes = outcomesResult?.data ?? [];

  const senderFilter = searchParams.get("sender") ?? "";
  const payloadFilter = searchParams.get("kind") ?? "";
  const branchFilter = searchParams.get("branch") ?? "";

  const senderKinds = useMemo(() => {
    const s = new Set<string>();
    for (const m of messages) if (m.sender_kind) s.add(m.sender_kind);
    return Array.from(s).sort();
  }, [messages]);
  const payloadKinds = useMemo(() => {
    const s = new Set<string>();
    for (const m of messages) if (m.payload_kind) s.add(m.payload_kind);
    return Array.from(s).sort();
  }, [messages]);

  const filtered: VRMessageSummary[] = useMemo(() => {
    return messages.filter((m) => {
      if (senderFilter && m.sender_kind !== senderFilter) return false;
      if (payloadFilter && m.payload_kind !== payloadFilter) return false;
      if (branchFilter && m.branch_id !== branchFilter) return false;
      return true;
    });
  }, [messages, senderFilter, payloadFilter, branchFilter]);

  if (isLoading || !inv) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  function updateParam(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next, { replace: true });
  }

  // Live-tail status. The SSE hook doesn't expose its readyState yet —
  // best-effort: green when investigation is running, amber when paused,
  // muted when terminal.
  const liveStatus: LiveStatus =
    inv.status === "running"
      ? "connected"
      : inv.status === "paused"
        ? "reconnecting"
        : "disconnected";

  const operatorComposerOpen =
    inv.status === "running" || inv.status === "paused" || inv.status === "created";

  return (
    <div className="space-y-4 max-w-full min-w-0 overflow-x-hidden break-words">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-bold font-mono text-foreground truncate">
            {inv.title}
          </h1>
          <p className="text-sm text-text-muted mt-1 font-mono">
            {inv.kind} · target: {targetName}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <LiveDot status={liveStatus} />
          <Link
            to={`/vr/investigations/${invId}/tree`}
            className="text-xs px-3 py-1.5 rounded-md bg-surface border border-border-default hover:bg-surface-hover text-foreground"
          >
            Branch tree →
          </Link>
          <Link
            to={`/vr/investigations/${invId}/graph`}
            className="text-xs px-3 py-1.5 rounded-md bg-surface border border-border-default hover:bg-surface-hover text-foreground"
          >
            Evidence graph →
          </Link>
          <button
            type="button"
            onClick={() => setSteeringOpen(true)}
            className="text-xs px-3 py-1.5 rounded-md bg-accent text-white hover:bg-accent/90"
          >
            Steering ⚙
          </button>
          <ExportReportButton invId={invId} title={inv.title} />
          <DeleteButton
            id={invId}
            label={`investigation "${inv.title}"`}
            mutation={deleteMut}
            onDeleted={() => navigate("/vr/investigations")}
          />
        </div>
      </div>

      {/* Workflow stepper */}
      <AilaCard>
        <WorkflowStepper
          flow="investigate"
          currentState={
            inv.status === "running"
              ? "investigation_loop"
              : inv.status === "completed"
                ? "investigation_emit"
                : inv.status === "failed"
                  ? "investigation_loop"
                  : "investigation_setup"
          }
          failedAt={inv.status === "failed" ? "investigation_loop" : null}
        />
      </AilaCard>

      {/* Status + cost ribbon */}
      <AilaCard>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <AilaBadge
              severity={investigationStatusColor[inv.status] ?? "info"}
              size="sm"
            >
              {inv.pause_reason
                ? `${inv.status}:${inv.pause_reason}`
                : inv.status}
            </AilaBadge>
            <AilaBadge severity="info" size="sm">
              {inv.strategy_family}
            </AilaBadge>
            <AilaBadge severity="info" size="sm">
              branches: {inv.branch_count}
            </AilaBadge>
            <AilaBadge severity="info" size="sm">
              messages: {inv.message_count}
            </AilaBadge>
            <AilaBadge severity="info" size="sm">
              outcomes: {inv.outcome_count}
            </AilaBadge>
          </div>
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            {inv.status === "running" && (
              <button
                type="button"
                onClick={() => pauseMut.mutate()}
                disabled={pauseMut.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50"
              >
                {pauseMut.isPending ? "Pausing…" : "Pause"}
              </button>
            )}
            {inv.status === "paused" && (
              <button
                type="button"
                onClick={() => resumeMut.mutate()}
                disabled={resumeMut.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
              >
                {resumeMut.isPending ? "Resuming…" : "Resume"}
              </button>
            )}
            {inv.status === "created" && (
              <button
                type="button"
                onClick={() => reenqueueMut.mutate(undefined)}
                disabled={reenqueueMut.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50 whitespace-nowrap"
                title="Start this investigation (enqueue run_vr_investigate task)"
              >
                {reenqueueMut.isPending ? "Starting…" : "Start ▶"}
              </button>
            )}
            {(inv.status === "completed" || inv.status === "failed") && (
              <ReenqueuePicker
                currentKind={inv.kind}
                mutation={reenqueueMut}
              />
            )}
          </div>
        </div>
        <dl className="grid grid-cols-4 gap-3 text-sm mt-3 pt-3 border-t border-border-default">
          <div>
            <dt className="text-text-muted text-xs">Budget</dt>
            <dd className="font-mono text-foreground">
              {fmtUsd(inv.cost_budget_usd)}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Actual</dt>
            <dd className="font-mono text-foreground">
              {fmtUsd(inv.cost_actual_usd)}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">LLM tokens</dt>
            <dd className="font-mono text-foreground">
              {fmtUsd(inv.llm_tokens_cost_usd)}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">MCP calls</dt>
            <dd className="font-mono text-foreground">
              {fmtUsd(inv.mcp_calls_cost_usd)}
            </dd>
          </div>
        </dl>
      </AilaCard>

      {/* Main grid: timeline left, side panels right */}
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_320px] gap-4">
        {/* Timeline column */}
        <div className="space-y-3 min-w-0">
          {/* Filter bar */}
          <AilaCard>
            <div className="flex items-center gap-2 flex-wrap text-xs">
              <span className="text-text-muted">Filter:</span>
              <select
                value={senderFilter}
                onChange={(e) => updateParam("sender", e.target.value)}
                className="px-2 py-1 rounded-md bg-surface border border-border-default font-mono"
                aria-label="Filter by sender kind"
              >
                <option value="">all senders</option>
                {senderKinds.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              <select
                value={payloadFilter}
                onChange={(e) => updateParam("kind", e.target.value)}
                className="px-2 py-1 rounded-md bg-surface border border-border-default font-mono"
                aria-label="Filter by payload kind"
              >
                <option value="">all kinds</option>
                {payloadKinds.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
              {branches.length > 1 && (
                <select
                  value={branchFilter}
                  onChange={(e) => updateParam("branch", e.target.value)}
                  className="px-2 py-1 rounded-md bg-surface border border-border-default font-mono"
                  aria-label="Filter by branch"
                >
                  <option value="">all branches</option>
                  {branches.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.persona_voice ?? "branch"}
                      {b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}
                    </option>
                  ))}
                </select>
              )}
              <span className="text-text-muted ml-auto">
                {filtered.length} of {messages.length} turn
                {messages.length === 1 ? "" : "s"}
              </span>
              <label className="flex items-center gap-1 text-text-muted">
                <input
                  type="checkbox"
                  checked={liveTail}
                  onChange={(e) => setLiveTail(e.target.checked)}
                  className="w-3 h-3"
                />
                live tail
              </label>
              <input
                type="number"
                placeholder="jump to turn #"
                min={1}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    const n = Number(e.currentTarget.value);
                    if (Number.isFinite(n) && n > 0) {
                      const el = document.getElementById(`turn-${n - 1}`);
                      if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
                    }
                  }
                }}
                className="w-20 px-2 py-0.5 rounded bg-surface border border-border-default font-mono"
                aria-label="Jump to turn number"
              />
            </div>
          </AilaCard>

          {/* Turn stream */}
          {filtered.length === 0 ? (
            <AilaCard>
              <p className="text-sm text-text-muted text-center py-6">
                {messages.length === 0
                  ? "No turns yet — engine hasn't started reasoning."
                  : "Filters hide every turn. Clear filters above to see them."}
              </p>
            </AilaCard>
          ) : (
            <div className="space-y-2">
              {filtered.map((m, i) => (
                <TurnCard key={m.id} message={m} index={i} />
              ))}
            </div>
          )}

          {/* Operator composer (bottom of stream, like a chat input) */}
          {operatorComposerOpen && (
            <AilaCard>
              <h2 className="text-sm font-semibold text-foreground mb-2">
                Inject context for next turn
              </h2>
              <p className="text-xs text-text-muted mb-2">
                The engine sees this verbatim as an operator note on its next
                turn. Use{" "}
                <span className="font-mono">steering</span> to redirect,{" "}
                <span className="font-mono">correction</span> to contradict a
                hypothesis,{" "}
                <span className="font-mono">dismissal</span> to drop a thread.
              </p>
              <textarea
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="e.g. 'try the JSPI base address path' or 'that hypothesis is wrong because…'"
                rows={3}
                className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
              />
              <div className="flex gap-2 items-center mt-2">
                <select
                  value={messageIntent}
                  onChange={(e) =>
                    setMessageIntent(e.target.value as OperatorIntent | "")
                  }
                  className="px-2 py-1.5 text-xs font-mono rounded-md bg-surface border border-border-default"
                  aria-label="Operator intent"
                >
                  <option value="">auto-classify</option>
                  <option value="steering">steering</option>
                  <option value="question">question</option>
                  <option value="correction">correction</option>
                  <option value="dismissal">dismissal</option>
                  <option value="outcome_selection">outcome_selection</option>
                  <option value="branch_command">branch_command</option>
                </select>
                <button
                  type="button"
                  disabled={!messageText.trim() || sendMut.isPending}
                  onClick={() => {
                    sendMut.mutate(
                      {
                        text: messageText.trim(),
                        explicit_intent: messageIntent || undefined,
                      },
                      {
                        onSuccess: () => {
                          setMessageText("");
                          setMessageIntent("");
                        },
                      },
                    );
                  }}
                  className="px-4 py-1.5 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
                >
                  {sendMut.isPending ? "Sending…" : "Send"}
                </button>
              </div>
            </AilaCard>
          )}
        </div>

        {/* Side rail */}
        <aside className="space-y-3 min-w-0">
          {/* Hypothesis projection (08_FRONTEND_UX.md §2.3) */}
          <HypothesisDetailRail investigationId={invId} />
          {/* Fuzz proposals queue (operator-in-the-loop) */}
          <FuzzProposalsPanel investigationId={invId} />


          {/* Branches summary */}
          <AilaCard>
            <h3 className="text-xs font-semibold text-foreground uppercase tracking-wide mb-2">
              Branches ({branches.length})
            </h3>
            {branches.length === 0 ? (
              <p className="text-xs text-text-muted">No forks yet.</p>
            ) : (
              <ul className="space-y-1.5">
                {branches.map((b) => (
                  <li
                    key={b.id}
                    className="text-xs border border-border-default rounded p-1.5"
                  >
                    <div className="flex items-center gap-1 flex-wrap">
                      <AilaBadge
                        severity={branchStatusColor[b.status] ?? "info"}
                        size="sm"
                      >
                        {b.status}
                      </AilaBadge>
                      {b.persona_voice && (
                        <AilaBadge severity="info" size="sm">
                          {b.persona_voice}
                        </AilaBadge>
                      )}
                      {b.promoted && (
                        <AilaBadge severity="low" size="sm">
                          promoted
                        </AilaBadge>
                      )}
                    </div>
                    <p className="text-text-muted font-mono mt-1">
                      turns: {b.turn_count} · {fmtUsd(b.branch_cost_usd)}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </AilaCard>

          {/* Outcomes summary */}
          <AilaCard>
            <h3 className="text-xs font-semibold text-foreground uppercase tracking-wide mb-2">
              Outcomes ({outcomes.length})
            </h3>
            {outcomes.length === 0 ? (
              <p className="text-xs text-text-muted">
                No outcomes yet — engine hasn't submitted.
              </p>
            ) : (
              <ul className="space-y-2">
                {[...outcomes]
                  .sort((a, b) => {
                    // synthesis / primary first
                    const aPrim = a.id === inv.primary_outcome_id ? -1 : 0;
                    const bPrim = b.id === inv.primary_outcome_id ? -1 : 0;
                    if (aPrim !== bPrim) return aPrim - bPrim;
                    // then newest first
                    return (b.created_at ?? "").localeCompare(a.created_at ?? "");
                  })
                  .map((o) => {
                    const persona = branches.find((b) => b.id === o.branch_id)?.persona_voice ?? null;
                    const isPrimary = o.id === inv.primary_outcome_id;
                    return (
                      <li
                        key={o.id}
                        className={`text-xs border rounded p-2 ${
                          isPrimary
                            ? "border-accent-default bg-surface-emphasised"
                            : "border-border-default"
                        }`}
                      >
                        <div className="flex items-center gap-1 flex-wrap mb-1">
                          {isPrimary && (
                            <AilaBadge severity="critical" size="sm">
                              SYNTHESIS · PRIMARY
                            </AilaBadge>
                          )}
                          {persona && !isPrimary && (
                            <AilaBadge severity="info" size="sm">
                              {persona}
                            </AilaBadge>
                          )}
                          <span className="font-mono text-foreground">
                            {o.outcome_kind}
                          </span>
                          <AilaBadge severity="info" size="sm">
                            conf:{o.confidence}
                          </AilaBadge>
                          <AilaBadge
                            severity={dispatchColor[o.dispatch_status] ?? "info"}
                            size="sm"
                          >
                            {o.dispatch_status}
                          </AilaBadge>
                          {(() => {
                            const vr = (o.payload as Record<string, unknown> | undefined)
                              ?.verifier_report as
                              | { verdict?: string; confidence?: number; summary?: string; counter_evidence?: string }
                              | undefined;
                            const sev =
                              vr?.verdict === "refuted"
                                ? "critical"
                                : vr?.verdict === "confirmed"
                                  ? "low"
                                  : "medium";
                            return (
                              <>
                                {vr?.verdict && (
                                  <AilaBadge severity={sev} size="sm" title={vr.summary || vr.verdict}>
                                    verifier: {vr.verdict}
                                    {typeof vr.confidence === "number"
                                      ? ` (${vr.confidence.toFixed(2)})`
                                      : ""}
                                  </AilaBadge>
                                )}
                                {isPrimary && (
                                  <button
                                    type="button"
                                    disabled={reverifyMut.isPending}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      reverifyMut.mutate(invId);
                                    }}
                                    className="px-2 py-0.5 text-[10px] rounded border border-border-default text-text-muted hover:text-foreground hover:border-accent disabled:opacity-50"
                                    title={
                                      vr?.verdict
                                        ? "Clear current verifier_report and re-run the verifier on this finding"
                                        : "Manually trigger the claim verifier on this finding"
                                    }
                                  >
                                    {reverifyMut.isPending ? "…" : (vr?.verdict ? "↻ re-verify" : "▶ verify")}
                                  </button>
                                )}
                                {o.outcome_kind === "assessment_report" &&
                                  o.dispatch_status === "skipped" && (
                                  <button
                                    type="button"
                                    disabled={promoteMut.isPending}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      const verdict = vr?.verdict;
                                      const conf =
                                        typeof vr?.confidence === "number"
                                          ? vr.confidence.toFixed(2)
                                          : "?";
                                      const note =
                                        verdict === "confirmed"
                                          ? `operator promote — verifier confirmed conf=${conf}`
                                          : verdict
                                            ? `operator promote — verifier ${verdict} conf=${conf}`
                                            : "operator promote — no verifier verdict";
                                      promoteMut.mutate({
                                        outcomeId: o.id,
                                        reason: note,
                                      });
                                    }}
                                    className={
                                      vr?.verdict === "confirmed"
                                        ? "px-2 py-0.5 text-[10px] rounded border border-emerald-500/60 text-emerald-300 hover:border-emerald-400 hover:bg-emerald-500/10 disabled:opacity-50"
                                        : "px-2 py-0.5 text-[10px] rounded border border-border-default text-text-muted hover:text-foreground hover:border-accent disabled:opacity-50"
                                    }
                                    title={
                                      vr?.verdict === "confirmed"
                                        ? `Verifier CONFIRMED this assessment — promote to direct_finding to create a vr_finding row and (on variant-child investigations) auto-enqueue the PoC writer.`
                                        : vr?.verdict === "refuted"
                                          ? `Verifier REFUTED — promoting will still create a finding row, but the PoC writer will skip itself per the verifier-gate.`
                                          : "Promote this assessment_report to direct_finding (creates vr_finding row + dispatches downstream)."
                                    }
                                  >
                                    {promoteMut.isPending ? "…" : "↗ promote to finding"}
                                  </button>
                                )}
                              </>
                            );
                          })()}
                        </div>
                        {(() => {
                          const vr = (o.payload as Record<string, unknown> | undefined)
                            ?.verifier_report as
                            | { verdict?: string; counter_evidence?: string; summary?: string }
                            | undefined;
                          if (!vr || vr.verdict !== "refuted" || !vr.counter_evidence) return null;
                          return (
                            <div className="mt-1 mb-2 text-[11px] border border-red-500/50 bg-red-500/10 rounded p-2 text-red-300">
                              <div className="font-semibold mb-1">verifier refuted this finding:</div>
                              <div className="break-words whitespace-pre-wrap">{vr.counter_evidence}</div>
                            </div>
                          );
                        })()}
                        <PayloadPreview payload={o.payload} />
                      </li>
                    );
                  })}
              </ul>
            )}
          </AilaCard>
        </aside>
      </div>
      <SteeringDrawer
        open={steeringOpen}
        onClose={() => setSteeringOpen(false)}
        investigationId={invId}
        status={inv.status}
      />
    </div>
  );
}
