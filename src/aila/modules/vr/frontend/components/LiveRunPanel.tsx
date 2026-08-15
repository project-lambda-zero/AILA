/** Live run-status panel for a still-active VR investigation.
 *
 *  Additive to InvestigationDetailPage -- rendered above the workflow
 *  stepper while the investigation is in a non-terminal state
 *  (created / running / paused / stalled). Three mock sub-panels:
 *
 *    1. Status header: status dot + label + wall-clock elapsed ticker
 *       (1 s tick gated on !prefers-reduced-motion + status==='running').
 *    2. Cost accrual: oversized $actual + / $budget + mock progress bar.
 *    3. Compact 5-turn activity ticker sourced from the parent's
 *       useInvestigationMessages cache (live-merged by
 *       useInvestigationMessagesStream) -- no second SSE socket.
 *
 *  Terminal states hide the panel; the parent gates render with a
 *  membership check on `LIVE_PANEL_STATUSES` (exported below). */

import { useEffect, useMemo, useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";

import { LiveDot, type LiveStatus } from "./LiveDot";
import { personaMeta } from "./personaMeta";
import type {
  InvestigationStatus,
  VRBranchSummary,
  VRInvestigationSummary,
  VRMessageSummary,
} from "../types";

export const LIVE_PANEL_STATUSES: Partial<Record<InvestigationStatus, true>> = {
  created: true,
  running: true,
  paused: true,
  stalled: true,
};

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";
const TICKER_ROWS = 5;

// ─── Local status meta (mock hues) — inlined to avoid a circular import
// with screens/InvestigationDetailPage.
const STATUS_META: Record<
  InvestigationStatus,
  { color: string; label: string; pulse: boolean }
> = {
  created: { color: "var(--text-faint)", label: "created", pulse: false },
  running: { color: "var(--status-ok)", label: "running", pulse: true },
  paused: { color: "var(--status-warn)", label: "paused", pulse: false },
  completed: { color: "var(--status-info)", label: "completed", pulse: false },
  failed: { color: "var(--accent)", label: "failed", pulse: false },
  abandoned: { color: "var(--text-faint)", label: "abandoned", pulse: false },
  stalled: { color: "var(--text-faint)", label: "stalled", pulse: false },
};

function LivePanelStatusDot({
  status,
  pauseReason,
}: {
  status: InvestigationStatus;
  pauseReason?: string | null;
}) {
  const meta = STATUS_META[status] ?? STATUS_META.created;
  return (
    <span
      className="inline-flex items-center font-mono uppercase"
      style={{
        gap: 6,
        color: meta.color,
        fontSize: 10.5,
        letterSpacing: "0.14em",
      }}
    >
      <span
        aria-hidden
        style={{
          width: 8,
          height: 8,
          background: meta.color,
          boxShadow: `0 0 6px ${meta.color}`,
          animation: meta.pulse
            ? "severity-pulse 1.6s ease-in-out infinite"
            : undefined,
        }}
      />
      <span>{meta.label}</span>
      {pauseReason && (
        <span style={{ color: "var(--text-faint)" }}>· {pauseReason.replace(/_/g, " ")}</span>
      )}
    </span>
  );
}

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

function formatElapsed(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const mm = m.toString().padStart(2, "0");
  const ss = s.toString().padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${m}:${ss}`;
}

function timeAgo(iso: string | null | undefined, nowMs: number): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, Math.round((nowMs - t) / 1000));
  if (s < 5) return "now";
  if (s < 60) return `${s}s`;
  const mm = Math.floor(s / 60);
  if (mm < 60) return `${mm}m`;
  const hh = Math.floor(mm / 60);
  return `${hh}h`;
}

export interface LiveRunPanelProps {
  investigation: VRInvestigationSummary;
  messages: VRMessageSummary[];
  branches: VRBranchSummary[];
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
  const shouldTick = !reduced && inv.status === "running";
  const elapsedSec = useElapsedSeconds(anchorIso, shouldTick);
  const nowMs = Date.now();

  const branchPersonaMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const b of branches) if (b.persona_voice) map[b.id] = b.persona_voice;
    return map;
  }, [branches]);

  const recent = useMemo(() => {
    if (messages.length === 0) return [] as VRMessageSummary[];
    return messages.slice(-TICKER_ROWS).reverse();
  }, [messages]);

  const budget = inv.cost_budget_usd;
  const actual = inv.cost_actual_usd;
  const costPct = budget > 0 ? Math.min(100, (actual / budget) * 100) : 0;
  const costTone =
    costPct >= 90
      ? "var(--accent)"
      : costPct >= 60
        ? "var(--status-warn)"
        : "var(--status-ok)";

  const panelTone: "ok" | "warn" | "info" =
    inv.status === "running" ? "ok" : inv.status === "paused" ? "warn" : "info";

  return (
    <WindowPanel
      title="live run"
      tone={panelTone}
      status={<LiveDot status={liveStatus} />}
      aria-label="Live run status"
    >
      <div className="flex flex-col" style={{ gap: 8 }}>
        {/* (a) Status header — status dot + wall-clock elapsed */}
        <div
          className="flex items-center justify-between font-mono"
          style={{
            gap: 12,
            padding: "6px 8px",
            border: "1px solid var(--border-faint)",
            background: "var(--surface-card)",
          }}
        >
          <LivePanelStatusDot status={inv.status} pauseReason={inv.pause_reason} />
          <span
            className="inline-flex items-center tabular-nums"
            style={{
              gap: 6,
              fontSize: 13,
              color: "var(--text-primary)",
            }}
            title={anchorIso ? `Started ${anchorIso}` : "No start timestamp"}
          >
            <span
              aria-live={reduced ? "off" : "polite"}
              aria-atomic="true"
            >
              {formatElapsed(elapsedSec)}
            </span>
            <span
              className="uppercase"
              style={{
                fontSize: 9,
                color: "var(--text-faint)",
                letterSpacing: "0.14em",
              }}
            >
              elapsed
            </span>
          </span>
        </div>

        {/* (b) Cost accrual — oversized number + progress bar */}
        <div
          className="font-mono"
          style={{
            padding: "8px 10px",
            border: "1px solid var(--border-faint)",
            background: "var(--surface-card)",
          }}
        >
          <div
            className="flex items-baseline"
            style={{ gap: 8, flexWrap: "wrap" }}
          >
            <span
              className="tabular-nums"
              style={{
                fontSize: 19,
                color: "var(--accent)",
                letterSpacing: "-0.01em",
                lineHeight: 1,
              }}
            >
              ${actual.toFixed(2)}
            </span>
            {budget > 0 && (
              <span
                className="tabular-nums"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                }}
              >
                / ${budget.toFixed(2)}
              </span>
            )}
            <span style={{ flex: 1 }} />
            <span
              className="uppercase tabular-nums"
              style={{
                fontSize: 9,
                letterSpacing: "0.14em",
                color: "var(--text-faint)",
              }}
            >
              {inv.message_count.toLocaleString()} turns · {inv.branch_count} branches
            </span>
          </div>
          {budget > 0 && (
            <div
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(costPct)}
              aria-label="Cost accrual against budget"
              style={{
                marginTop: 6,
                height: 5,
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-faint)",
                overflow: "hidden",
              }}
            >
              <span
                aria-hidden
                style={{
                  display: "block",
                  height: "100%",
                  width: `${costPct}%`,
                  background: costTone,
                }}
              />
            </div>
          )}
        </div>

        {/* (c) Activity ticker — last N turns, newest first */}
        <div
          style={{
            border: "1px solid var(--border-faint)",
            background: "var(--surface-card)",
          }}
        >
          <div
            className="font-mono uppercase flex items-center"
            style={{
              padding: "4px 8px",
              gap: 6,
              borderBottom: "1px solid var(--border-faint)",
              background: "var(--surface-chrome)",
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-faint)",
            }}
          >
            <span>latest activity</span>
            {recent.length > 0 && (
              <span className="tabular-nums" style={{ color: "var(--text-muted)" }}>
                last {recent.length}
              </span>
            )}
          </div>
          {recent.length === 0 ? (
            <div
              className="font-mono"
              style={{
                padding: "10px 8px",
                fontSize: 10.5,
                color: "var(--text-faint)",
              }}
            >
              waiting for the first turn…
            </div>
          ) : (
            <ul
              className="flex flex-col"
              style={{ listStyle: "none", margin: 0, padding: 0 }}
              aria-live={reduced ? "off" : "polite"}
              aria-relevant="additions"
            >
              {recent.map((m, i) => {
                const persona = branchPersonaMap[m.branch_id] ?? null;
                const pm = personaMeta(persona);
                const turn = m.at_turn != null ? `t${m.at_turn}` : `t?`;
                return (
                  <li
                    key={m.id}
                    className="flex items-center font-mono"
                    style={{
                      gap: 8,
                      padding: "5px 8px",
                      borderTop: i === 0 ? "none" : "1px solid var(--border-faint)",
                      fontSize: 10.5,
                      color: "var(--text-muted)",
                      overflow: "hidden",
                    }}
                  >
                    <span
                      aria-hidden
                      className="inline-flex items-center justify-center font-mono uppercase shrink-0"
                      style={{
                        width: 18,
                        height: 18,
                        fontSize: 9.5,
                        background: `color-mix(in srgb, ${pm.hue} 18%, transparent)`,
                        border: `1px solid color-mix(in srgb, ${pm.hue} 40%, transparent)`,
                        color: pm.hue,
                      }}
                    >
                      {pm.initial}
                    </span>
                    <span
                      className="tabular-nums shrink-0"
                      style={{ color: "var(--text-primary)", minWidth: 28 }}
                    >
                      {turn}
                    </span>
                    <span
                      className="uppercase shrink-0"
                      style={{
                        fontSize: 9,
                        letterSpacing: "0.14em",
                        color: "var(--text-faint)",
                        width: 60,
                      }}
                    >
                      {m.payload_kind.replace(/_/g, " ")}
                    </span>
                    <span
                      className="truncate"
                      style={{ color: "var(--text-primary)", flex: 1, minWidth: 0 }}
                      title={pm.label}
                    >
                      {pm.label}
                    </span>
                    <span
                      className="tabular-nums shrink-0"
                      style={{ color: "var(--text-faint)", fontSize: 9.5 }}
                    >
                      {timeAgo(m.created_at, nowMs)}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </WindowPanel>
  );
}
