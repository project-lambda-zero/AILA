import { useCallback, useEffect, useMemo, useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";

import { useInvestigationHypotheses } from "../queries";
import type { HypothesisProjection } from "../queries";

/**
 * Right-rail panel that surfaces live + rejected hypotheses for the
 * investigation (08_FRONTEND_UX.md §2.3).
 *
 * Reads from `/vr/investigations/:id/hypotheses` -- an aggregate
 * projection across branches. Each row shows the hypothesis claim,
 * its lifecycle state (live / rejected / mixed across branches), the
 * kill criterion, why it was plausible, and per-branch attribution.
 *
 * Collapse model (added 2026-05-28 after the rail was observed
 * getting heavy on long-running investigations -- up to 53
 * hypotheses per branch observed live):
 *
 *   * Whole-rail collapse -- chevron in card header hides every row.
 *     Default: open.
 *   * Per-row collapse -- chevron on each row toggles between compact
 *     (claim + state badge + branch-count tail) and full (current
 *     why_plausible / kill_criterion / rejection_reason rendering).
 *     Default: collapsed when the rail holds more than
 *     ``AUTO_COLLAPSE_THRESHOLD`` rows; otherwise expanded.
 *   * Expand-all / Collapse-all -- bulk toggles all rows at once.
 *   * Persistence -- state lives in localStorage keyed by
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
    // localStorage can throw (quota / private mode) -- non-fatal; UI just
    // loses persistence for this session.
  }
}

// ─── Shared mock-language style constants ────────────────────────────────
const META_TEXT: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9.5,
  letterSpacing: "0.06em",
  color: "var(--text-muted)",
  textTransform: "uppercase",
};

const LINK_BTN: React.CSSProperties = {
  ...META_TEXT,
  background: "transparent",
  border: "none",
  padding: 0,
  cursor: "pointer",
};

export function HypothesisDetailRail({
  investigationId,
  live = true,
}: {
  investigationId: string;
  /** Forwarded to `useInvestigationHypotheses` -- false stops the 8s
   *  polling on paused / completed / failed investigations. The
   *  parent page derives this from `isInvestigationLive(inv?.status)`. */
  live?: boolean;
}) {
  const { data, isLoading } = useInvestigationHypotheses(investigationId, { live });
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
    let liveCount = 0;
    let rejected = 0;
    let mixed = 0;
    for (const h of items) {
      if (h.state === "live") liveCount++;
      else if (h.state === "rejected") rejected++;
      else mixed++;
    }
    return { live: liveCount, rejected, mixed };
  }, [items]);

  // Are all currently-visible rows expanded? Used to choose between
  // showing the "Expand all" or the "Collapse all" affordance only --
  // saves clicks on the common case.
  const allExpanded = useMemo(() => {
    if (items.length === 0) return false;
    return items.every((h) => isRowExpanded(h.id));
  }, [items, isRowExpanded]);

  return (
    <WindowPanel
      title="hypotheses"
      tone={counts.live > 0 ? "accent" : "muted"}
      actions={
        <div className="flex items-center" style={{ gap: 10 }}>
          <span style={{ ...META_TEXT, fontVariantNumeric: "tabular-nums" }}>
            ({items.length}
            {items.length > 0 ? (
              <>
                {counts.live > 0 ? (
                  <>
                    {", "}
                    <span style={{ color: "var(--accent)" }}>{counts.live} live</span>
                  </>
                ) : ""}
                {counts.rejected > 0 ? (
                  <>
                    {", "}
                    <span style={{ color: "var(--text-faint)" }}>{counts.rejected} rej</span>
                  </>
                ) : ""}
                {counts.mixed > 0 ? (
                  <>
                    {", "}
                    <span style={{ color: "var(--text-primary)" }}>{counts.mixed} mixed</span>
                  </>
                ) : ""}
              </>
            ) : null}
            )
          </span>
          {state.railOpen && items.length > 1 ? (
            <button
              type="button"
              onClick={allExpanded ? collapseAll : expandAll}
              style={LINK_BTN}
              title={allExpanded ? "Collapse every hypothesis row" : "Expand every hypothesis row"}
            >
              {allExpanded ? "collapse all" : "expand all"}
            </button>
          ) : null}
          <button
            type="button"
            onClick={toggleRail}
            className="flex items-center"
            style={{ ...LINK_BTN, color: "var(--text-muted)" }}
            aria-expanded={state.railOpen}
            aria-controls={`hypotheses-list-${investigationId}`}
            title={state.railOpen ? "Hide hypotheses list" : "Show hypotheses list"}
          >
            <Chevron open={state.railOpen} />
          </button>
        </div>
      }
    >
      <h2 className="sr-only">Hypotheses</h2>
      {state.railOpen ? (
        isLoading ? (
          // Content-shaped skeleton mirrors the hypothesis-row layout so
          // the rail keeps its height while the fetch resolves.
          <ul
            aria-busy="true"
            aria-label="Loading hypotheses"
            style={{ display: "flex", flexDirection: "column", gap: 8, listStyle: "none", margin: 0, padding: 0 }}
          >
            {[0, 1, 2].map((i) => (
              <li
                key={i}
                style={{
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  padding: "8px 10px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 6,
                }}
              >
                <LoadingSkeleton size="sm" width="half" />
                <LoadingSkeleton size="sm" width="full" />
              </li>
            ))}
          </ul>
        ) : items.length === 0 ? (
          <div
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no hypotheses yet -- the reasoning engine populates them as branches observe evidence.
          </div>
        ) : (
          <ul
            id={`hypotheses-list-${investigationId}`}
            style={{ display: "flex", flexDirection: "column", gap: 8, listStyle: "none", margin: 0, padding: 0 }}
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
    </WindowPanel>
  );
}

function Chevron({ open }: { open: boolean }) {
  return (
    <span
      aria-hidden="true"
      className="inline-block font-mono"
      style={{
        width: 12,
        fontSize: 9,
        lineHeight: 1,
        color: "var(--text-muted)",
        transform: open ? "rotate(90deg)" : "rotate(0deg)",
        transition: "transform 120ms ease",
      }}
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
  // Preserve the historic severity mapping so downstream visual weight
  // stays intact; route it through the mock badge tone (info/low/medium
  // are all valid MonoBadge tone keys).
  const sev: "info" | "low" | "medium" =
    h.state === "live" ? "info" : h.state === "rejected" ? "low" : "medium";

  // Presentational state accent for the row's left stripe -- live reads
  // hot-pink (the "watch this" cue), rejected recedes to the border
  // tone, everything else settles on primary text.
  const stateAccent =
    h.state === "live"
      ? "var(--accent)"
      : h.state === "rejected"
        ? "var(--border)"
        : "var(--text-primary)";

  const hasDetail =
    Boolean(h.why_plausible) ||
    Boolean(h.kill_criterion) ||
    Boolean(h.rejection_reason) ||
    h.live_in_branches.length > 0 ||
    h.rejected_in_branches.length > 0;

  return (
    <li
      style={{
        border: "1px solid var(--border-soft)",
        borderLeft: `3px solid ${stateAccent}`,
        borderRadius: 3,
        background: "var(--surface-card)",
        wordBreak: "break-word",
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        disabled={!hasDetail}
        className="w-full flex items-start text-left"
        style={{
          gap: 8,
          padding: 8,
          background: "transparent",
          border: "none",
          color: "inherit",
          cursor: hasDetail ? "pointer" : "default",
        }}
        aria-expanded={expanded}
        title={hasDetail ? (expanded ? "Collapse" : "Expand") : "No additional detail"}
      >
        <span className="shrink-0" style={{ paddingTop: 2 }}>
          {hasDetail ? <Chevron open={expanded} /> : (
            <span className="inline-block" style={{ width: 12 }} aria-hidden="true" />
          )}
        </span>
        <p
          className="flex-1 min-w-0"
          style={{
            fontSize: 12.5,
            lineHeight: 1.4,
            margin: 0,
            color: h.state === "rejected" ? "var(--text-muted)" : "var(--text-primary)",
          }}
        >
          {h.claim || h.id}
        </p>
        <MonoBadge tone={sev}>{h.state}</MonoBadge>
      </button>
      {expanded && hasDetail ? (
        <div style={{ padding: "0 8px 8px 28px", display: "flex", flexDirection: "column", gap: 4 }}>
          {h.why_plausible ? (
            <p style={{ fontSize: 11, margin: 0, color: "var(--text-muted)" }}>
              <span style={{ fontFamily: "var(--font-mono)" }}>why_plausible:</span> {h.why_plausible}
            </p>
          ) : null}
          {h.kill_criterion ? (
            <p style={{ fontSize: 11, margin: 0, color: "var(--text-muted)" }}>
              <span style={{ fontFamily: "var(--font-mono)" }}>kill_criterion:</span> {h.kill_criterion}
            </p>
          ) : null}
          {h.rejection_reason ? (
            <p style={{ fontSize: 11, margin: 0, color: "var(--accent)" }}>
              <span style={{ fontFamily: "var(--font-mono)" }}>rejected:</span> {h.rejection_reason}
            </p>
          ) : null}
          {(h.live_in_branches.length > 0 || h.rejected_in_branches.length > 0) ? (
            <div
              className="flex flex-wrap"
              style={{
                gap: 8,
                marginTop: 2,
                ...META_TEXT,
              }}
            >
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
