import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";

import { useInvestigationHypotheses } from "../queries";
import type { HypothesisProjection } from "../queries";

/**
 * Right-rail panel that surfaces live + rejected hypotheses for the
 * investigation (08_FRONTEND_UX.md §2.3).
 *
 * Reads from `/vr/investigations/:id/hypotheses` — an aggregate
 * projection across branches. Each row shows the hypothesis claim,
 * its lifecycle state (live / rejected / mixed across branches), the
 * kill criterion, why it was plausible, and per-branch attribution.
 */
export function HypothesisDetailRail({
  investigationId,
}: {
  investigationId: string;
}) {
  const { data, isLoading } = useInvestigationHypotheses(investigationId);
  const items: HypothesisProjection[] = data?.data ?? [];

  return (
    <AilaCard>
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-sm font-semibold text-foreground">
          Hypotheses
        </h2>
        <span className="text-[10px] text-text-muted font-mono">
          {items.length} tracked
        </span>
      </div>
      {isLoading ? (
        <p className="text-xs text-text-muted">Loading…</p>
      ) : items.length === 0 ? (
        <EmptyState
          title="No hypotheses yet"
          description="The reasoning engine populates hypotheses as it observes evidence on each branch."
        />
      ) : (
        <ul className="space-y-2">
          {items.map((h) => (
            <HypothesisRow key={h.id} h={h} />
          ))}
        </ul>
      )}
    </AilaCard>
  );
}

function HypothesisRow({ h }: { h: HypothesisProjection }) {
  const sev =
    h.state === "live" ? "info" : h.state === "rejected" ? "low" : "medium";
  return (
    <li className="border border-border-default rounded p-2 bg-surface/40 break-words">
      <div className="flex items-start justify-between gap-2 min-w-0">
        <p className="text-sm text-foreground flex-1">{h.claim || h.id}</p>
        <AilaBadge severity={sev} size="sm">
          {h.state}
        </AilaBadge>
      </div>
      {h.why_plausible && (
        <p className="text-xs text-text-muted mt-1">
          <span className="font-mono">why_plausible:</span> {h.why_plausible}
        </p>
      )}
      {h.kill_criterion && (
        <p className="text-xs text-text-muted mt-1">
          <span className="font-mono">kill_criterion:</span> {h.kill_criterion}
        </p>
      )}
      {h.rejection_reason && (
        <p className="text-xs text-text-danger mt-1">
          <span className="font-mono">rejected:</span> {h.rejection_reason}
        </p>
      )}
      <div className="flex flex-wrap gap-1 mt-1 text-[10px] text-text-muted font-mono">
        {h.live_in_branches.length > 0 && (
          <span>live on {h.live_in_branches.length} branch(es)</span>
        )}
        {h.rejected_in_branches.length > 0 && (
          <span>rejected on {h.rejected_in_branches.length} branch(es)</span>
        )}
      </div>
    </li>
  );
}
