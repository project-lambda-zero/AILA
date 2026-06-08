import { useEffect, useRef, useState } from "react";

import { useQueryClient } from "@tanstack/react-query";

import { useWizardResolution, useWizardSchema } from "../queries";
import type { ComponentClassificationResponse, SubtaskComponentResponse } from "../types";
import { useSessionEvents } from "./hooks/useSessionEvents";

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

type IconState = "inactive" | "triggered" | "uncertain" | "not_triggered";

interface IconEntry {
  component: SubtaskComponentResponse;
  state: IconState;
  confidence: number | null;
}

// ──────────────────────────────────────────────────────────────────────────────
// Icon hint → two-character abbreviation
// Maps the known icon_hint values from seed_subtasks.json to short display text.
// Unknown hints fall back to the first two characters of the key.
// ──────────────────────────────────────────────────────────────────────────────

const ICON_HINT_ABBREV: Record<string, string> = {
  wifi: "Wi",
  "file-text": "FL",
  database: "DB",
  bell: "AL",
  shield: "FW",
  search: "SC",
  lock: "LK",
  bug: "DA",
  "file-check": "FI",
  network: "NW",
  "clipboard-check": "OT",
  terminal: "OS",
  monitor: "WN",
  crosshair: "PT",
  key: "KY",
  layers: "PX",
  "alert-triangle": "RA",
  code: "SA",
  "shield-check": "SCS",
  settings: "SBD",
  package: "SCA",
  scan: "VS",
  filter: "WA",
  certificate: "TLS",
};

function iconAbbrev(component: SubtaskComponentResponse): string {
  const hint = ICON_HINT_ABBREV[component.icon_hint];
  if (hint) return hint.slice(0, 3);
  return component.key.slice(0, 2).toUpperCase();
}

// ──────────────────────────────────────────────────────────────────────────────
// Classification mapping (T-137-10: unknown values fall back to "inactive")
// ──────────────────────────────────────────────────────────────────────────────

function classificationToState(classification: string): IconState {
  if (classification === "triggered") return "triggered";
  if (classification === "uncertain") return "uncertain";
  if (classification === "not_triggered") return "not_triggered";
  return "inactive";
}

function stateLabel(state: IconState): string {
  switch (state) {
    case "triggered":
      return "Triggered";
    case "uncertain":
      return "Uncertain";
    case "not_triggered":
      return "Not Applicable";
    case "inactive":
      return "Inactive";
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Style maps for icon cells
// ──────────────────────────────────────────────────────────────────────────────

const CELL_BASE =
  "flex flex-col items-center gap-1 p-2 rounded-md cursor-pointer transition-colors hover:bg-elevated";

const CELL_BORDER: Record<IconState, string> = {
  triggered: "border border-[color:var(--color-accent)]/30",
  uncertain: "border border-[color:var(--color-medium)]/30",
  not_triggered: "border border-[color:var(--color-critical)]/30",
  inactive: "border border-transparent",
};

const ABBREV_BASE =
  "w-8 h-8 rounded-sm flex items-center justify-center font-mono text-xs font-bold";

const ABBREV_VARIANT: Record<IconState, string> = {
  triggered: "bg-accent text-badge-text",
  uncertain: "bg-medium text-badge-text",
  not_triggered: "bg-critical text-badge-text",
  inactive: "bg-surface text-text-muted",
};

// ──────────────────────────────────────────────────────────────────────────────
// Narrow-viewport hook
// ──────────────────────────────────────────────────────────────────────────────

function useIsNarrow(): boolean {
  const [isNarrow, setIsNarrow] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia("(max-width: 1023px)").matches : false,
  );

  useEffect(() => {
    const mq = window.matchMedia("(max-width: 1023px)");
    const handler = (e: MediaQueryListEvent) => setIsNarrow(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  return isNarrow;
}

// ──────────────────────────────────────────────────────────────────────────────
// IconCell
// ──────────────────────────────────────────────────────────────────────────────

interface IconCellProps {
  entry: IconEntry;
  isAnimating: boolean;
}

function IconCell({ entry, isAnimating }: IconCellProps) {
  const { component, state } = entry;
  const abbrev = iconAbbrev(component);
  const label = stateLabel(state);

  const animatingClass = isAnimating ? "animate-pulse" : "";

  return (
    <button
      className={`${CELL_BASE} ${CELL_BORDER[state]} ${animatingClass}`}
      aria-label={`${component.label}: ${label}`}
      tabIndex={0}
      type="button"
    >
      <span className={`${ABBREV_BASE} ${ABBREV_VARIANT[state]}`}>{abbrev}</span>
      <span className="text-3xs text-text truncate text-center" style={{ maxWidth: 60 }}>
        {component.label}
      </span>
      <span className="text-4xs text-text-muted">{label}</span>
    </button>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Icon grid
// ──────────────────────────────────────────────────────────────────────────────

interface IconGridProps {
  entries: IconEntry[];
  animatingKeys: Set<string>;
}

function IconGrid({ entries, animatingKeys }: IconGridProps) {
  return (
    <div className="grid grid-cols-5 gap-1.5" role="list" aria-label="Sub-task component grid">
      {entries.map((entry) => (
        <IconCell
          key={entry.component.key}
          entry={entry}
          isAnimating={animatingKeys.has(entry.component.key)}
        />
      ))}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Resolution progress banner
// ──────────────────────────────────────────────────────────────────────────────

function ResolvingBanner() {
  return (
    <div className="flex items-center gap-3 p-4 text-sm text-text-muted" aria-live="polite">
      <span
        className="w-4 h-4 rounded-full border-2 border-accent border-t-transparent animate-spin"
        aria-hidden="true"
      />
      Analyzing responses...
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Panel summary line
// ──────────────────────────────────────────────────────────────────────────────

const SUMMARY_CLASS = "text-xs font-mono text-text-muted mb-3";

function PanelSummary({
  entries,
  sessionStatus,
}: {
  entries: IconEntry[];
  sessionStatus: string;
}) {
  const total = entries.length || 25;
  const triggeredCount = entries.filter((e) => e.state === "triggered").length;
  const uncertainCount = entries.filter((e) => e.state === "uncertain").length;

  // During in-progress, show live counts from client-side triggering
  if (sessionStatus !== "resolved") {
    if (triggeredCount === 0 && uncertainCount === 0) {
      return <p className={SUMMARY_CLASS}>{total} security components</p>;
    }
    const parts: string[] = [`${triggeredCount} / ${total} triggered`];
    if (uncertainCount > 0) parts.push(`${uncertainCount} uncertain`);
    return <p className={SUMMARY_CLASS}>{parts.join(", ")}</p>;
  }

  if (triggeredCount === 0 && uncertainCount === 0) {
    return <p className={SUMMARY_CLASS}>0 / {total} triggered</p>;
  }

  const parts: string[] = [`${triggeredCount} / ${total} triggered`];
  if (uncertainCount > 0) parts.push(`${uncertainCount} uncertain`);

  return <p className={SUMMARY_CLASS}>{parts.join(", ")}</p>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Floating badge (narrow viewport)
// ──────────────────────────────────────────────────────────────────────────────

interface FloatingBadgeProps {
  triggeredCount: number;
  onOpen: () => void;
}

function FloatingBadge({ triggeredCount, onOpen }: FloatingBadgeProps) {
  return (
    <button
      className="fixed bottom-4 right-4 z-40 w-10 h-10 rounded-full bg-accent text-badge-text font-mono text-sm font-bold flex items-center justify-center shadow-lg"
      onClick={onOpen}
      aria-label={`${triggeredCount} components triggered. Tap to view all.`}
      type="button"
    >
      {triggeredCount}
    </button>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Overlay (narrow viewport)
// ──────────────────────────────────────────────────────────────────────────────

interface IconOverlayProps {
  entries: IconEntry[];
  animatingKeys: Set<string>;
  sessionStatus: string;
  onClose: () => void;
}

function IconOverlay({ entries, animatingKeys, sessionStatus, onClose }: IconOverlayProps) {
  return (
    <div
      className="fixed inset-x-0 bottom-0 z-50 bg-elevated border-t border-border p-4 overflow-y-auto"
      style={{ maxHeight: "60vh" }}
      role="dialog"
      aria-modal="true"
      aria-label="Sub-task components"
    >
      <div className="flex items-center justify-between pb-3 border-b border-border mb-3">
        <h3 className="font-mono text-sm text-text">Sub-task Components</h3>
        <button
          className="text-text-muted hover:text-text cursor-pointer"
          onClick={onClose}
          aria-label="Close"
          type="button"
        >
          ×
        </button>
      </div>
      <div>
        <PanelSummary entries={entries} sessionStatus={sessionStatus} />
        <IconGrid entries={entries} animatingKeys={animatingKeys} />
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// WizardSubtaskPanel — public component
// ──────────────────────────────────────────────────────────────────────────────

export interface WizardSubtaskPanelProps {
  sessionId: string;
  sessionStatus: string;
  /** Current answers map for live client-side subtask triggering. */
  answersMap?: Record<string, string>;
}

export function WizardSubtaskPanel({ sessionId, sessionStatus, answersMap }: WizardSubtaskPanelProps) {
  const queryClient = useQueryClient();
  const isNarrow = useIsNarrow();
  const [overlayOpen, setOverlayOpen] = useState(false);

  // ── Data sources ────────────────────────────────────────────────────────────

  const schemaQuery = useWizardSchema();

  const isResolving = sessionStatus === "resolving";
  const isResolved = sessionStatus === "resolved";
  const isFailed = sessionStatus === "resolution_failed";

  // SSE — active only while resolving (T-137-11)
  const { resolutionStatus } = useSessionEvents(sessionId, isResolving);

  // Resolution result — fetched only when resolved or failed
  const resolutionQuery = useWizardResolution(sessionId);
  // Override enabled state: only show data when appropriate
  const resolutionData = isResolved || isFailed ? resolutionQuery.data : undefined;

  // ── Invalidate queries on SSE resolution_completed ──────────────────────────
  const prevResolutionStatus = useRef<string>("idle");
  useEffect(() => {
    if (
      resolutionStatus === "completed" &&
      prevResolutionStatus.current !== "completed"
    ) {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "resolution", sessionId] });
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "session", sessionId] });
    }
    prevResolutionStatus.current = resolutionStatus;
  }, [resolutionStatus, sessionId, queryClient]);

  // ── Build icon entries ───────────────────────────────────────────────────────

  const subtaskComponents: SubtaskComponentResponse[] = schemaQuery.data?.subtask_components ?? [];
  const sorted = [...subtaskComponents].sort((a, b) => a.display_order - b.display_order);

  // ── Live client-side triggering from answers + subtask_mappings ──────────────
  // Walk every question in the schema; if the question is answered with a
  // triggering value (yes/partial), mark its mapped subtask_keys as triggered.
  const liveTriggeredKeys = new Set<string>();
  if (answersMap && schemaQuery.data && !resolutionData) {
    for (const section of schemaQuery.data.sections) {
      for (const subgroup of section.subgroups) {
        for (const question of subgroup.questions) {
          if (question.subtask_mappings.length === 0) continue;
          const answerVal = answersMap[question.id];
          if (!answerVal) continue;
          const lower = answerVal.toLowerCase();
          if (lower === "yes" || lower === "partial") {
            for (const mapping of question.subtask_mappings) {
              liveTriggeredKeys.add(mapping.subtask_key);
            }
          }
        }
      }
    }
  }

  // Build a classification lookup by key (from resolution data, if available)
  const classificationMap = new Map<string, ComponentClassificationResponse>();
  if (resolutionData?.components) {
    for (const comp of resolutionData.components) {
      classificationMap.set(comp.subtask_key, comp);
    }
  }

  const entries: IconEntry[] = sorted.map((component) => {
    // If resolution data exists, use server-side classification
    const classification = classificationMap.get(component.key);
    if (classification) {
      return {
        component,
        state: classificationToState(classification.classification),
        confidence: classification.confidence,
      };
    }
    // Otherwise, use live client-side triggering from answers
    if (liveTriggeredKeys.has(component.key)) {
      return { component, state: "triggered" as IconState, confidence: null };
    }
    return { component, state: "inactive" as IconState, confidence: null };
  });

  // ── Pulse animation on first resolution load (D-07) ─────────────────────────
  const [animatingKeys, setAnimatingKeys] = useState<Set<string>>(new Set());
  const prevResolutionId = useRef<string | null>(null);

  useEffect(() => {
    if (!resolutionData) return;
    const currentId = resolutionData.session_id + "_" + (resolutionData.resolved_at ?? "");
    if (prevResolutionId.current === currentId) return;
    prevResolutionId.current = currentId;

    const keysToAnimate = new Set(
      entries
        .filter((e) => e.state === "triggered" || e.state === "uncertain")
        .map((e) => e.component.key),
    );
    setAnimatingKeys(keysToAnimate);
    const timer = setTimeout(() => setAnimatingKeys(new Set()), 300);
    return () => clearTimeout(timer);
    // entries is derived from resolutionData — safe to omit from deps
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolutionData]);

  // ── Counts for badge ─────────────────────────────────────────────────────────
  const triggeredCount = entries.filter((e) => e.state === "triggered").length;

  // ── Render ───────────────────────────────────────────────────────────────────

  const panelContent = (
    <>
      {isResolving && <ResolvingBanner />}
      {isFailed && (
        <div
          className="text-sm text-critical p-3 rounded-md bg-critical/10 border border-critical/30"
          role="alert"
        >
          Resolution failed. Please try again.
        </div>
      )}
      <div className="flex items-center justify-between mb-3">
        <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Sub-task Components
        </span>
        <PanelSummary entries={entries} sessionStatus={sessionStatus} />
      </div>
      <IconGrid entries={entries} animatingKeys={animatingKeys} />
    </>
  );

  if (isNarrow) {
    return (
      <>
        <FloatingBadge triggeredCount={triggeredCount} onOpen={() => setOverlayOpen(true)} />
        {overlayOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/50"
            role="presentation"
            onClick={() => setOverlayOpen(false)}
          >
            <IconOverlay
              entries={entries}
              animatingKeys={animatingKeys}
              sessionStatus={sessionStatus}
              onClose={() => setOverlayOpen(false)}
            />
          </div>
        )}
      </>
    );
  }

  return <div>{panelContent}</div>;
}
