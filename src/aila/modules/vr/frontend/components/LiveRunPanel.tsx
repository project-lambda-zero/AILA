/** Live run-status panel for a still-active VR investigation.
 *
 *  Additive to InvestigationDetailPage -- rendered above the existing
 *  workflow/stepper card while the investigation is in a
 *  non-terminal state (created / running / paused / stalled). The
 *  panel consolidates four "am I still moving?" signals the operator
 *  otherwise has to eyeball across the page:
 *
 *    1. Current status + workflow stage (mirrors the stepper's own
 *       mapping so both cards agree on which phase is live).
 *    2. Wall-clock elapsed since started_at / created_at, with a
 *       1 s ticker gated on !prefers-reduced-motion. Reduced-motion
 *       users still see the current duration -- it just does not
 *       animate.
 *    3. Live cost accrual against the configured budget when the
 *       summary exposes one.
 *    4. A compact 5-turn activity ticker sourced from the EXISTING
 *       ["vr","investigation-messages",...] query cache. The parent
 *       page's useInvestigationMessagesStream hook already merges
 *       new turns into that cache, so this panel updates as new
 *       turns land without opening a second SSE socket.
 *
 *  Terminal states (completed / failed / abandoned) hide the panel
 *  entirely -- the existing outcome hero + final banners already
 *  cover that surface. The parent screen gates the render with a
 *  membership check on `LIVE_PANEL_STATUSES` (exported below). */

import { useEffect, useMemo, useState } from "react";
import { ChatCircleText } from "@phosphor-icons/react/dist/csr/ChatCircleText";
import { Clock } from "@phosphor-icons/react/dist/csr/Clock";
import { CurrencyDollar } from "@phosphor-icons/react/dist/csr/CurrencyDollar";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";

import { WindowPanel } from "@/components/aila/WindowPanel";

import { LiveDot, type LiveStatus } from "./LiveDot";
import { WorkflowStepper } from "./WorkflowStepper";
import { StatusIndicator } from "../screens/InvestigationDetailPage";
import type {
  InvestigationStatus,
  VRBranchSummary,
  VRInvestigationSummary,
  VRMessageSummary,
} from "../types";

/** Statuses at which the investigation is still operationally
 *  interesting -- either actively producing turns, waiting for a
 *  worker to pick it back up, or awaiting operator resume. Terminal
 *  states (completed / failed / abandoned) are absent because the
 *  existing outcome hero + final banners already cover that surface. */
export const LIVE_PANEL_STATUSES: Partial<Record<InvestigationStatus, true>> = {
  created: true,
  running: true,
  paused: true,
  stalled: true,
};

/** Hot-pink reserved for the ONE live indicator dot next to the
 *  elapsed counter (midnight-cloud-8 live/critical hue). Every other
 *  swatch on the panel is drawn from the shared status/cost palette
 *  so this one accent reads unambiguously as "this thing is ticking
 *  right now." */
const LIVE_INDICATOR = "#ff5f87";

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState<boolean>(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia(REDUCED_MOTION_QUERY).matches;
  });
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia(REDUCED_MOTION_QUERY);
    const handler = () => setReduced(mq.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);
  return reduced;
}

/** Wall-clock elapsed seconds since `anchorIso`. When `tick` is true
 *  the value updates every second so the render feels live; when
 *  false (reduced motion, or investigation not actively running) the
 *  value is computed once per mount + once per anchor change -- still
 *  accurate at page open, just not animated. */
function useElapsedSeconds(
  anchorIso: string | null | undefined,
  tick: boolean,
): number {
  const anchor = useMemo(() => {
    if (!anchorIso) return null;
    const t = Date.parse(anchorIso);
    return Number.isFinite(t) ? t : null;
  }, [anchorIso]);
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    if (!tick) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [tick]);
  if (anchor == null) return 0;
  return Math.max(0, Math.floor((now - anchor) / 1000));
}

/** Format `elapsed` seconds as H:MM:SS (or M:SS when <1h). Kept named
 *  because the two branch-and-pad path is unpleasant to inline in JSX. */
function formatElapsed(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const mm = m.toString().padStart(2, "0");
  const ss = s.toString().padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${m}:${ss}`;
}

/** Human "3s / 12m / 4h ago" phrasing for the activity ticker. Named
 *  because the four-branch cascade would obscure ticker rendering if
 *  inlined; the ticker calls it once per row per render. */
function timeAgo(iso: string | null | undefined, nowMs: number): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, Math.round((nowMs - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const mm = Math.floor(s / 60);
  if (mm < 60) return `${mm}m ago`;
  const hh = Math.floor(mm / 60);
  return `${hh}h ago`;
}

/** Domain-status -> workflow_state mapping copied from the page's own
 *  WorkflowStepper wiring so both cards highlight the same stage. Keep
 *  in sync with InvestigationDetailPage's inline mapping until the
 *  cursor SSOT lands and both can read the real current_state. */
function stepperStateFor(status: InvestigationStatus): string | null {
  switch (status) {
    case "paused":
      return null;
    case "running":
    case "failed":
      return "investigation_loop";
    case "completed":
      return "investigation_emit";
    case "created":
    case "stalled":
    case "abandoned":
    default:
      return "investigation_setup";
  }
}

const TICKER_ROWS = 5;

export interface LiveRunPanelProps {
  investigation: VRInvestigationSummary;
  /** Full message list from useInvestigationMessages (live-merged by
   *  useInvestigationMessagesStream). The panel slices the last
   *  TICKER_ROWS entries for the activity ticker. */
  messages: VRMessageSummary[];
  /** Branches, used ONLY for persona lookup on ticker rows -- messages
   *  carry branch_id but not persona_voice. */
  branches: VRBranchSummary[];
  /** SSE connection status from useInvestigationMessagesStream -- the
   *  same one the page header's LiveDot renders. Duplicated here so
   *  the panel is self-contained "am I connected?" evidence. */
  liveStatus: LiveStatus;
}

export function LiveRunPanel({
  investigation: inv,
  messages,
  branches,
  liveStatus,
}: LiveRunPanelProps) {
  const reduced = usePrefersReducedMotion();
  const anchorIso = inv.started_at ?? inv.created_at ?? null;
  // Only tick while the investigation is actually running -- paused /
  // stalled / created holds the elapsed value steady, matching the
  // wall-clock progress the backend perceives.
  const shouldTick = !reduced && inv.status === "running";
  const elapsedSec = useElapsedSeconds(anchorIso, shouldTick);
  // Captured once per render so every ticker row uses the same "now"
  // reference (no divergent time-ago strings within a single frame).
  const nowMs = Date.now();

  const branchPersonaMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const b of branches) if (b.persona_voice) map.set(b.id, b.persona_voice);
    return map;
  }, [branches]);

  const recent = useMemo(() => {
    if (messages.length === 0) return [] as VRMessageSummary[];
    return messages.slice(-TICKER_ROWS).reverse();
  }, [messages]);

  const budget = inv.cost_budget_usd;
  const actual = inv.cost_actual_usd;
  const costPct = budget > 0 ? Math.min(100, (actual / budget) * 100) : 0;
  const costTone = costPct >= 90 ? "#ff5f87" : costPct >= 60 ? "#ffb85f" : "#97dbbe";
  const showLivePulse = !reduced && inv.status === "running";

  return (
    <WindowPanel title="live run" tone="accent" aria-label="Live run status">
      {/* Row 1 -- status badge + SSE indicator + wall-clock ticker */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap min-w-0">
          <StatusIndicator status={inv.status} pauseReason={inv.pause_reason} />
          <LiveDot status={liveStatus} />
        </div>
        <div
          className="flex items-center gap-2 font-mono text-sm text-foreground tabular-nums"
          title={anchorIso ? `Started ${anchorIso}` : "No start timestamp"}
        >
          <span
            className={`inline-block w-2 h-2 rounded-full ${
              showLivePulse ? "animate-pulse motion-reduce:animate-none" : ""
            }`}
            style={{
              background: LIVE_INDICATOR,
              boxShadow: `0 0 6px ${LIVE_INDICATOR}`,
            }}
            aria-hidden
          />
          <Clock weight="fill" size={14} className="text-text-muted" />
          <span aria-live={reduced ? "off" : "polite"} aria-atomic="true">
            {formatElapsed(elapsedSec)}
          </span>
          <span className="text-2xs uppercase tracking-cyber-sm text-text-muted">
            elapsed
          </span>
        </div>
      </div>

      {/* Row 2 -- workflow stage (mirrors the primary stepper below) */}
      <div className="mt-3">
        <WorkflowStepper
          flow="investigate"
          currentState={stepperStateFor(inv.status)}
          failedAt={inv.status === "failed" ? "investigation_loop" : null}
        />
      </div>

      {/* Row 3 -- live counters (turns / branches / cost accrual) */}
      <div className="mt-3 pt-3 border-t border-border/60 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs font-mono text-text-muted">
        <span className="inline-flex items-center gap-1.5">
          <ChatCircleText weight="fill" size={13} className="text-text-muted" />
          <span className="text-foreground font-semibold tabular-nums">
            {inv.message_count.toLocaleString()}
          </span>
          turns
        </span>
        <span className="w-px h-3 bg-border" aria-hidden />
        <span className="inline-flex items-center gap-1.5">
          <TreeStructure weight="fill" size={13} className="text-text-muted" />
          <span className="text-foreground font-semibold tabular-nums">
            {inv.branch_count}
          </span>
          branches
        </span>
        {budget > 0 && (
          <>
            <span className="w-px h-3 bg-border" aria-hidden />
            <span
              className="inline-flex items-center gap-2 flex-1"
              style={{ minWidth: 220 }}
            >
              <CurrencyDollar weight="fill" size={13} className="text-text-muted" />
              <span className="tabular-nums text-foreground font-semibold">
                ${actual.toFixed(2)}
              </span>
              <span className="text-text-muted">/ ${budget.toFixed(2)}</span>
              <span
                className="relative flex-1 h-1 rounded-full overflow-hidden bg-elevated"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.round(costPct)}
                aria-label="Cost accrual against budget"
              >
                <span
                  className="block h-full"
                  style={{ width: `${costPct}%`, background: costTone }}
                />
              </span>
              <span className="tabular-nums text-text-muted">
                {costPct.toFixed(0)}%
              </span>
            </span>
          </>
        )}
      </div>

      {/* Row 4 -- compact activity ticker (last N turns, newest first) */}
      <div className="mt-3 pt-3 border-t border-border/60">
        <div className="flex items-center gap-2 mb-1.5 text-2xs font-mono uppercase tracking-cyber-sm text-text-muted">
          <span>Latest activity</span>
          {recent.length > 0 && (
            <span className="tabular-nums text-text-muted/70">
              last {recent.length}
            </span>
          )}
        </div>
        {recent.length === 0 ? (
          <p className="text-xs text-text-muted italic">
            Waiting for the first turn…
          </p>
        ) : (
          <ul
            className="space-y-1"
            aria-live={reduced ? "off" : "polite"}
            aria-relevant="additions"
          >
            {recent.map((m) => {
              const persona = branchPersonaMap.get(m.branch_id);
              const turnLabel = m.at_turn != null ? `#${m.at_turn}` : "#—";
              return (
                <li
                  key={m.id}
                  className="flex items-center gap-2 text-xs font-mono text-text-muted overflow-hidden"
                >
                  <span
                    className="tabular-nums text-foreground font-semibold shrink-0"
                    style={{ minWidth: 44 }}
                  >
                    {turnLabel}
                  </span>
                  <span
                    className="text-text-muted uppercase tracking-cyber-sm text-2xs shrink-0 truncate"
                    style={{ width: 72 }}
                  >
                    {m.sender_kind}
                  </span>
                  {persona ? (
                    <span
                      className="text-lavender text-2xs shrink-0 truncate"
                      style={{ width: 80 }}
                      title={persona}
                    >
                      {persona}
                    </span>
                  ) : (
                    <span style={{ width: 80 }} aria-hidden />
                  )}
                  <span className="text-foreground truncate flex-1 min-w-0">
                    {m.payload_kind}
                  </span>
                  <span className="text-text-muted text-2xs whitespace-nowrap shrink-0">
                    {timeAgo(m.created_at, nowMs)}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </WindowPanel>
  );
}
