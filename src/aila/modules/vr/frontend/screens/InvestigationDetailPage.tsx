import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import {
  useInvestigation,
  useInvestigationBranches,
  useInvestigationMessages,
  useInvestigationOutcomes,
} from "../queries";
import type {
  BranchStatus,
  InvestigationStatus,
  OutcomeDispatchStatus,
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
  skipped: "info",
};

function fmtTime(value?: string | null): string {
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

function PayloadPreview({
  payload,
}: {
  payload: Record<string, unknown>;
}) {
  const text = (payload?.text as string) || "";
  const command = (payload?.command as string) || "";
  if (text) {
    return (
      <p className="text-sm text-foreground whitespace-pre-wrap font-mono">
        {text.slice(0, 600)}
        {text.length > 600 ? "…" : ""}
      </p>
    );
  }
  if (command) {
    return (
      <p className="text-xs text-foreground font-mono">
        <span className="text-text-muted">command:</span> {command.slice(0, 400)}
      </p>
    );
  }
  // Fallback: compact JSON
  const json = JSON.stringify(payload, null, 2);
  return (
    <pre className="text-xs text-text-muted font-mono whitespace-pre-wrap">
      {json.slice(0, 600)}
      {json.length > 600 ? "…" : ""}
    </pre>
  );
}

export function InvestigationDetailPage() {
  const { investigationId } = useParams<{ investigationId: string }>();
  const invId = investigationId ?? "";

  const { data: inv, isLoading } = useInvestigation(invId);
  const { data: branchesResult } = useInvestigationBranches(invId);
  const { data: messagesResult } = useInvestigationMessages(invId);
  const { data: outcomesResult } = useInvestigationOutcomes(invId);

  if (isLoading || !inv) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  const branches = branchesResult?.data ?? [];
  const messages = messagesResult?.data ?? [];
  const outcomes = outcomesResult?.data ?? [];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          {inv.title}
        </h1>
        <p className="text-sm text-text-muted mt-1 font-mono">
          {inv.kind} · target:{inv.target_id.slice(0, 12)}…
        </p>
      </div>

      <div className="flex gap-2 items-center">
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
        {inv.auto_pilot && (
          <AilaBadge severity="info" size="sm">
            auto-pilot
          </AilaBadge>
        )}
      </div>

      {/* Cost panel */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">Cost</h2>
        <dl className="grid grid-cols-4 gap-3 text-sm">
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
            <dt className="text-text-muted text-xs">MCP + fuzz</dt>
            <dd className="font-mono text-foreground">
              {fmtUsd(inv.mcp_calls_cost_usd + inv.fuzz_infra_cost_usd)}
            </dd>
          </div>
        </dl>
      </AilaCard>

      {/* Branches */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Branches ({branches.length})
        </h2>
        {branches.length === 0 ? (
          <p className="text-sm text-text-muted">No branches yet.</p>
        ) : (
          <ul className="space-y-2">
            {branches.map((b) => (
              <li
                key={b.id}
                className="border border-border-default rounded-md p-2 text-sm"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-text-muted">
                    {b.id.slice(0, 12)}…
                  </span>
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
                <p className="text-xs text-text-muted">
                  turns: {b.turn_count} · cost: {fmtUsd(b.branch_cost_usd)}
                  {b.fork_reason && ` · reason: ${b.fork_reason}`}
                </p>
              </li>
            ))}
          </ul>
        )}
      </AilaCard>

      {/* Outcomes */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Outcomes ({outcomes.length})
        </h2>
        {outcomes.length === 0 ? (
          <p className="text-sm text-text-muted">
            No outcomes yet — engine hasn't submitted.
          </p>
        ) : (
          <ul className="space-y-2">
            {outcomes.map((o) => (
              <li
                key={o.id}
                className="border border-border-default rounded-md p-2"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-foreground">
                    {o.outcome_kind}
                  </span>
                  <AilaBadge severity="info" size="sm">
                    confidence:{o.confidence}
                  </AilaBadge>
                  <AilaBadge
                    severity={dispatchColor[o.dispatch_status] ?? "info"}
                    size="sm"
                  >
                    dispatch:{o.dispatch_status}
                  </AilaBadge>
                </div>
                <PayloadPreview payload={o.payload} />
                {o.dispatch_target && (
                  <p className="text-xs text-text-muted mt-2 font-mono">
                    → {o.dispatch_target}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </AilaCard>

      {/* Messages (turn log) */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Messages ({messages.length})
        </h2>
        {messages.length === 0 ? (
          <p className="text-sm text-text-muted">No messages yet.</p>
        ) : (
          <ul className="space-y-2">
            {messages.map((m) => (
              <li
                key={m.id}
                className="border border-border-default rounded-md p-2"
              >
                <div className="flex items-center gap-2 mb-1 text-xs">
                  <span className="font-mono text-text-muted">
                    {fmtTime(m.created_at)}
                  </span>
                  <AilaBadge
                    severity={m.sender_kind === "engine" ? "info" : "medium"}
                    size="sm"
                  >
                    {m.sender_kind}
                  </AilaBadge>
                  <AilaBadge severity="info" size="sm">
                    {m.payload_kind}
                  </AilaBadge>
                  {m.at_turn != null && (
                    <span className="text-text-muted font-mono">
                      turn {m.at_turn}
                    </span>
                  )}
                  {m.operator_intent && (
                    <span className="text-text-muted font-mono">
                      intent:{m.operator_intent}
                    </span>
                  )}
                </div>
                <PayloadPreview payload={m.payload} />
              </li>
            ))}
          </ul>
        )}
      </AilaCard>
    </div>
  );
}
