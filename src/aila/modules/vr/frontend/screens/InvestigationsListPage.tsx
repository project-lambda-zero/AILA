import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useInvestigations } from "../queries";
import type { InvestigationStatus } from "../types";

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
      </div>

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
              POST /api/vr/investigations with target_id + initial_question
              to start one. Workflow auto-fires.
            </p>
          </div>
        </AilaCard>
      )}

      {!isLoading && !isError && investigations.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Title</th>
                <th className="px-4 py-2 font-semibold">Kind</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold">Target</th>
                <th className="px-4 py-2 font-semibold text-right">Branches</th>
                <th className="px-4 py-2 font-semibold text-right">Msgs</th>
                <th className="px-4 py-2 font-semibold text-right">Outcomes</th>
                <th className="px-4 py-2 font-semibold text-right">Cost</th>
                <th className="px-4 py-2 font-semibold">Created</th>
              </tr>
            </thead>
            <tbody>
              {investigations.map((inv) => (
                <tr
                  key={inv.id}
                  onClick={() => navigate(`/vr/investigations/${inv.id}`)}
                  className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
                >
                  <td className="px-4 py-2 font-semibold text-foreground">
                    {inv.title}
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
                    {inv.target_id.slice(0, 8)}…
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
                </tr>
              ))}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}
