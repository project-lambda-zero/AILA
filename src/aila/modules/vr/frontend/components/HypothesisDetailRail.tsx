import { useCallback, useEffect, useMemo, useState } from "react";

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
 *
 * Collapse model (added 2026-05-28 after operator reported the rail
 * gets heavy on long-running investigations — up to 53 hypotheses
 * per branch observed live):
 *
 *   * Whole-rail collapse — chevron in card header hides every row.
 *     Default: open.
 *   * Per-row collapse — chevron on each row toggles between compact
 *     (claim + state badge + branch-count tail) and full (current
 *     why_plausible / kill_criterion / rejection_reason rendering).
 *     Default: collapsed when the rail holds more than
 *     ``AUTO_COLLAPSE_THRESHOLD`` rows; otherwise expanded.
 *   * Expand-all / Collapse-all — bulk toggles all rows at once.
 *   * Persistence — state lives in localStorage keyed by
 *     ``vr-hypothesis-rail:<investigation_id>`` so navigating away
 *     + back preserves what the operator opened/closed.
 *
 * The persisted shape is deliberately minimal:
 *   { railOpen: boolean, openIds: string[] }
 * "openIds" is the exception set; the default for any unseen id is
 * derived from AUTO_COLLAPSE_THRESHOLD vs. the current row count.
 * That keeps the localStorage payload small even on investigations
 * with hundreds of hypotheses while still surviving page reloads.
 */

const AUTO_COLLAPSE_THRESHOLD = 5;

type RailState = {
  railOpen: boolean;
  openIds: string[];
};

function storageKey(investigationId: string): string {
  return `vr-hypothesis-rail:${investigationId}`;
}

function loadState(investigationId: string): RailState {
  if (typeof window === "undefined") return { railOpen: true, openIds: [] };
  try {
    const raw = window.localStorage.getItem(storageKey(investigationId));
    if (!raw) return { railOpen: true, openIds: [] };
    const parsed = JSON.parse(raw) as Partial<RailState>;
    return {
      railOpen: typeof parsed.railOpen === "boolean" ? parsed.railOpen : true,
      openIds: Array.isArray(parsed.openIds) ? parsed.openIds.filter((s) => typeof s === "string") : [],
    };
  } catch {
    return { railOpen: true, openIds: [] };
  }
}

function saveState(investigationId: string, next: RailState): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(storageKey(investigationId), JSON.stringify(next));
  } catch {
    // localStorage can throw (quota / private mode) — non-fatal; UI just
    // loses persistence for this session.
  }
}

export function HypothesisDetailRail({
  investigationId,
}: {
  investigationId: string;
}) {
  const { data, isLoading } = useInvestigationHypotheses(investigationId);
  const items: HypothesisProjection[] = data?.data ?? [];

  const [state, setStateRaw] = useState<RailState>(() => loadState(investigationId));

  // Reload state when the investigation id changes (e.g. router nav).
  useEffect(() => {
    setStateRaw(loadState(investigationId));
  }, [investigationId]);

  const setState = useCallback(
    (mut: (prev: RailState) => RailState) => {
      setStateRaw((prev) => {
        const next = mut(prev);
        saveState(investigationId, next);
        return next;
      });
    },
    [investigationId],
  );

  const defaultExpanded = items.length <= AUTO_COLLAPSE_THRESHOLD;

  const isRowExpanded = useCallback(
    (id: string): boolean => {
      // The persisted openIds list is the EXCEPTION set: when default is
      // expanded, openIds means "collapsed"; when default is collapsed,
      // openIds means "expanded". Encoding via a single set keeps the
      // localStorage payload small.
      const inExceptionSet = state.openIds.includes(id);
      return defaultExpanded ? !inExceptionSet : inExceptionSet;
    },
    [state.openIds, defaultExpanded],
  );

  const toggleRow = useCallback(
    (id: string) => {
      setState((prev) => {
        const idx = prev.openIds.indexOf(id);
        if (idx >= 0) {
          const nextIds = prev.openIds.slice();
          nextIds.splice(idx, 1);
          return { ...prev, openIds: nextIds };
        }
        return { ...prev, openIds: [...prev.openIds, id] };
      });
    },
    [setState],
  );

  const expandAll = useCallback(() => {
    setState((prev) => ({
      ...prev,
      // When default=expanded, openIds=[] means everything expanded.
      // When default=collapsed, openIds must contain every visible id.
      openIds: defaultExpanded ? [] : items.map((h) => h.id),
    }));
  }, [setState, defaultExpanded, items]);

  const collapseAll = useCallback(() => {
    setState((prev) => ({
      ...prev,
      // Mirror image of expandAll.
      openIds: defaultExpanded ? items.map((h) => h.id) : [],
    }));
  }, [setState, defaultExpanded, items]);

  const toggleRail = useCallback(() => {
    setState((prev) => ({ ...prev, railOpen: !prev.railOpen }));
  }, [setState]);

  const counts = useMemo(() => {
    let live = 0;
    let rejected = 0;
    let mixed = 0;
    for (const h of items) {
      if (h.state === "live") live++;
      else if (h.state === "rejected") rejected++;
      else mixed++;
    }
    return { live, rejected, mixed };
  }, [items]);

  // Are all currently-visible rows expanded? Used to choose between
  // showing the "Expand all" or the "Collapse all" affordance only —
  // saves clicks on the common case.
  const allExpanded = useMemo(() => {
    if (items.length === 0) return false;
    return items.every((h) => isRowExpanded(h.id));
  }, [items, isRowExpanded]);

  return (
    <AilaCard techBorder glow>
      <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
        <button
          type="button"
          onClick={toggleRail}
          className="flex items-center gap-1.5 text-sm font-semibold text-foreground hover:text-text-accent transition-colors"
          aria-expanded={state.railOpen}
          aria-controls={`hypotheses-list-${investigationId}`}
          title={state.railOpen ? "Hide hypotheses list" : "Show hypotheses list"}
        >
          <Chevron open={state.railOpen} />
          <span>Hypotheses</span>
          <span className="text-[10px] text-text-muted font-mono font-normal">
            ({items.length}
            {items.length > 0 ? (
              <>
                {counts.live > 0 ? `, ${counts.live} live` : ""}
                {counts.rejected > 0 ? `, ${counts.rejected} rej` : ""}
                {counts.mixed > 0 ? `, ${counts.mixed} mixed` : ""}
              </>
            ) : null}
            )
          </span>
        </button>
        {state.railOpen && items.length > 1 ? (
          <button
            type="button"
            onClick={allExpanded ? collapseAll : expandAll}
            className="text-[10px] text-text-muted hover:text-text-accent font-mono transition-colors"
            title={allExpanded ? "Collapse every hypothesis row" : "Expand every hypothesis row"}
          >
            {allExpanded ? "collapse all" : "expand all"}
          </button>
        ) : null}
      </div>
      {state.railOpen ? (
        isLoading ? (
          <p className="text-xs text-text-muted">Loading…</p>
        ) : items.length === 0 ? (
          <EmptyState
            title="No hypotheses yet"
            description="The reasoning engine populates hypotheses as it observes evidence on each branch."
          />
        ) : (
          <ul
            id={`hypotheses-list-${investigationId}`}
            className="space-y-2"
          >
            {items.map((h) => (
              <HypothesisRow
                key={h.id}
                h={h}
                expanded={isRowExpanded(h.id)}
                onToggle={() => toggleRow(h.id)}
              />
            ))}
          </ul>
        )
      ) : null}
    </AilaCard>
  );
}

function Chevron({ open }: { open: boolean }) {
  return (
    <span
      aria-hidden="true"
      className="inline-block w-3 text-text-muted font-mono text-[10px] leading-none transition-transform"
      style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)" }}
    >
      ▶
    </span>
  );
}

function HypothesisRow({
  h,
  expanded,
  onToggle,
}: {
  h: HypothesisProjection;
  expanded: boolean;
  onToggle: () => void;
}) {
  const sev =
    h.state === "live" ? "info" : h.state === "rejected" ? "low" : "medium";

  const hasDetail =
    Boolean(h.why_plausible) ||
    Boolean(h.kill_criterion) ||
    Boolean(h.rejection_reason) ||
    h.live_in_branches.length > 0 ||
    h.rejected_in_branches.length > 0;

  return (
    <li className="border border-border-default rounded bg-surface/40 break-words">
      <button
        type="button"
        onClick={onToggle}
        disabled={!hasDetail}
        className={`w-full flex items-start gap-2 p-2 text-left ${
          hasDetail ? "hover:bg-surface/60 cursor-pointer" : "cursor-default"
        }`}
        aria-expanded={expanded}
        title={hasDetail ? (expanded ? "Collapse" : "Expand") : "No additional detail"}
      >
        <span className="pt-0.5 shrink-0">
          {hasDetail ? <Chevron open={expanded} /> : (
            <span className="inline-block w-3" aria-hidden="true" />
          )}
        </span>
        <p className="text-sm text-foreground flex-1 min-w-0">
          {h.claim || h.id}
        </p>
        <AilaBadge severity={sev} size="sm">
          {h.state}
        </AilaBadge>
      </button>
      {expanded && hasDetail ? (
        <div className="px-2 pb-2 pl-7">
          {h.why_plausible ? (
            <p className="text-xs text-text-muted mt-1">
              <span className="font-mono">why_plausible:</span> {h.why_plausible}
            </p>
          ) : null}
          {h.kill_criterion ? (
            <p className="text-xs text-text-muted mt-1">
              <span className="font-mono">kill_criterion:</span> {h.kill_criterion}
            </p>
          ) : null}
          {h.rejection_reason ? (
            <p className="text-xs text-text-danger mt-1">
              <span className="font-mono">rejected:</span> {h.rejection_reason}
            </p>
          ) : null}
          {(h.live_in_branches.length > 0 || h.rejected_in_branches.length > 0) ? (
            <div className="flex flex-wrap gap-2 mt-1 text-[10px] text-text-muted font-mono">
              {h.live_in_branches.length > 0 ? (
                <span>live on {h.live_in_branches.length} branch(es)</span>
              ) : null}
              {h.rejected_in_branches.length > 0 ? (
                <span>rejected on {h.rejected_in_branches.length} branch(es)</span>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
