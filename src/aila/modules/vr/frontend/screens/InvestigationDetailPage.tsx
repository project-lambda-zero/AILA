import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";
import { Graph } from "@phosphor-icons/react/dist/csr/Graph";
import { GearSix } from "@phosphor-icons/react/dist/csr/GearSix";
import { ArrowCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowCounterClockwise";
import { Funnel } from "@phosphor-icons/react/dist/csr/Funnel";
import { PaperPlaneRight } from "@phosphor-icons/react/dist/csr/PaperPlaneRight";
import { Pause } from "@phosphor-icons/react/dist/csr/Pause";
import { Play } from "@phosphor-icons/react/dist/csr/Play";
import { Lightning } from "@phosphor-icons/react/dist/csr/Lightning";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { Hash } from "@phosphor-icons/react/dist/csr/Hash";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { XCircle } from "@phosphor-icons/react/dist/csr/XCircle";
import { WarningCircle } from "@phosphor-icons/react/dist/csr/WarningCircle";
import { Crown } from "@phosphor-icons/react/dist/csr/Crown";
import { ChatCircleText } from "@phosphor-icons/react/dist/csr/ChatCircleText";
import { Target } from "@phosphor-icons/react/dist/csr/Target";
import { CurrencyDollar } from "@phosphor-icons/react/dist/csr/CurrencyDollar";
import { ShieldCheck } from "@phosphor-icons/react/dist/csr/ShieldCheck";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { KpiTile } from "@/components/aila/KpiTile";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { OutcomeKindBadge, outcomeKindSeverity, outcomeKindLabel } from "../components/OutcomeKindBadge";
import { DeleteButton } from "../components/DeleteButton";
import { ExportReportButton } from "../components/ExportReportButton";
import { ReenqueuePicker } from "../components/ReenqueuePicker";
import { LiveDot } from "../components/LiveDot";
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
  useResetInvestigation,
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
  PersonaVoice,
  VRMessageSummary,
} from "../types";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

// (status / branch palette were inlined into STATUS_META / BRANCH_STATUS_META
// below — kept here only to document the per-status severity hue we use for
// any consumer that still needs an AilaBadge severity instead of a hex swatch.)

const dispatchColor: Record<
  OutcomeDispatchStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  pending: "info",
  dispatched: "low",
  failed: "critical",
  skipped: "medium",
};

// ── Status visual metadata ──────────────────────────────────────────
// Each investigation status maps to a swatch + label + whether the dot
// should pulse. Tones echo the dashboard's success/warn/crit/info hues
// rather than the generic AilaBadge severity ramp so the dot reads as
// "lifecycle phase", not "danger level".
const _STATUS_FALLBACK = { color: "#9aa0a6", label: "Unknown", pulse: false };
const STATUS_META: Record<
  string,
  { color: string; label: string; pulse: boolean }
> = {
  created:   { color: "#9aa0a6", label: "Created",   pulse: false },
  running:   { color: "#97dbbe", label: "Running",   pulse: true  },
  paused:    { color: "#f0c97a", label: "Paused",    pulse: false },
  completed: { color: "#8ec5ff", label: "Completed", pulse: false },
  failed:    { color: "#f0a8c7", label: "Failed",    pulse: false },
  abandoned: { color: "#9aa0a6", label: "Abandoned", pulse: false },
};

const _BRANCH_STATUS_FALLBACK = { color: "#9aa0a6", label: "Unknown" };
const BRANCH_STATUS_META: Record<
  string,
  { color: string; label: string }
> = {
  active:    { color: "#97dbbe", label: "Active"    },
  paused:    { color: "#f0c97a", label: "Paused"    },
  merged:    { color: "#8ec5ff", label: "Merged"    },
  promoted:  { color: "#97dbbe", label: "Promoted"  },
  completed: { color: "#8ec5ff", label: "Completed" },
  abandoned: { color: "#9aa0a6", label: "Abandoned" },
};

// Persona visual identity — each researcher persona gets a stable
// colored initial circle so operators can scan a branch list and read
// "who" before they read "what." Mirror this scheme in TurnCard later
// for full visual consistency across the page.
const PERSONA_META: Record<
  PersonaVoice | "default",
  { color: string; bg: string; initial: string; label: string }
> = {
  halvar:  { color: "#f0a8c7", bg: "color-mix(in srgb, #f0a8c7 16%, transparent)", initial: "H", label: "Halvar" },
  maddie:  { color: "#af87d7", bg: "color-mix(in srgb, #af87d7 16%, transparent)", initial: "M", label: "Maddie" },
  renzo:   { color: "#97dbbe", bg: "color-mix(in srgb, #97dbbe 16%, transparent)", initial: "R", label: "Renzo"  },
  yuki:    { color: "#8ec5ff", bg: "color-mix(in srgb, #8ec5ff 16%, transparent)", initial: "Y", label: "Yuki"   },
  noor:    { color: "#f0c97a", bg: "color-mix(in srgb, #f0c97a 16%, transparent)", initial: "N", label: "Noor"   },
  wei:     { color: "#7bdfd3", bg: "color-mix(in srgb, #7bdfd3 16%, transparent)", initial: "W", label: "Wei"    },
  default: { color: "#9aa0a6", bg: "color-mix(in srgb, #9aa0a6 16%, transparent)", initial: "?", label: "Branch" },
};

function personaMeta(voice?: PersonaVoice | string | null) {
  if (!voice) return PERSONA_META.default;
  return PERSONA_META[voice as PersonaVoice] ?? PERSONA_META.default;
}

function humanize(s: string | null | undefined): string {
  if (!s) return "";
  // Strip module prefix (e.g. "vulnerability_research.discovery_research" → "Discovery Research")
  const last = s.includes(".") ? s.split(".").pop()! : s;
  return last
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Map wire confidence strings to human labels. */
function humanConfidence(c: string | null | undefined): string {
  if (!c) return "";
  const map: Record<string, string> = {
    exact: "Exact",
    strong: "High",
    medium: "Medium",
    caveated: "Low",
    unknown: "Unknown",
  };
  return map[c] ?? c;
}

/** Strip LLM role prefixes like "DIRECT_FINDING:", "RESEARCHER (Halvar):" from prose. */
function stripRolePrefixes(text: string): string {
  return text
    .replace(/^DIRECT_FINDING:\s*/i, "")
    .replace(/^ASSESSMENT_REPORT:\s*/i, "")
    .replace(/^PATCH_ASSESSMENT_REPORT:\s*/i, "")
    .replace(/^(?:[\u{1F300}-\u{1FAD6}\u{2694}\u{1F52C}\u{2699}\u{1F6E0}]\s*)?(?:RESEARCHER|CRITIC|IMPLEMENTER)\s*\([^)]+\)\s*:\s*/gmu, "");
}

const OPERATOR_INTENTS: { value: OperatorIntent | ""; label: string }[] = [
  { value: "",                  label: "Auto"       },
  { value: "steering",          label: "Steering"   },
  { value: "question",          label: "Question"   },
  { value: "correction",        label: "Correction" },
  { value: "dismissal",         label: "Dismissal"  },
  { value: "outcome_selection", label: "Outcome"    },
  { value: "branch_command",    label: "Branch Cmd" },
];

function fmtUsd(n: number): string {
  return `$${n.toFixed(2)}`;
}

/** Render a payload's prose field (answer/text/summary/description) with
 *  optional collapse. Falls back to a compact JSON preview if no prose
 *  field is present. `defaultExpanded` controls initial state — true for
 *  the hero/primary outcome, false for the compact list. */
function PayloadPreview({
  payload,
  defaultExpanded = false,
  fullByDefault = false,
}: {
  payload: Record<string, unknown>;
  defaultExpanded?: boolean;
  fullByDefault?: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const proseCandidate =
    (payload?.answer as string) ||
    (payload?.text as string) ||
    (payload?.summary as string) ||
    (payload?.description as string) ||
    "";
  if (proseCandidate) {
    const cleaned = stripRolePrefixes(proseCandidate);
    const truncated = !fullByDefault && cleaned.length > 600;
    const shown = expanded || !truncated
      ? cleaned
      : cleaned.slice(0, 600) + "…";
    return (
      <div className="text-xs text-foreground whitespace-pre-wrap leading-relaxed break-words">
        {shown}
        {truncated && (
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            className="block mt-2 text-text-muted hover:text-foreground underline text-3xs"
          >
            {expanded ? "Collapse" : `Show full (${proseCandidate.length} chars)`}
          </button>
        )}
      </div>
    );
  }
  const json = JSON.stringify(payload, null, 2);
  const truncated = !fullByDefault && json.length > 320;
  const shown = expanded || !truncated ? json : json.slice(0, 320) + "…";
  return (
    <div className="text-3xs text-text-muted font-mono">
      <pre className="whitespace-pre-wrap break-words bg-elevated/40 rounded px-2 py-1.5 border border-border-default/60">
        {shown}
      </pre>
      {truncated && (
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="block mt-1 text-text-muted hover:text-foreground underline"
        >
          {expanded ? "Collapse" : `Show full (${json.length} chars)`}
        </button>
      )}
    </div>
  );
}

/** Cost progress bar — green/yellow/red based on actual-vs-budget %.
 *  Inline-styled width because Tailwind v4 strips arbitrary numeric
 *  width classes when the percent isn't statically detectable. */
function CostProgressBar({ actual, budget }: { actual: number; budget: number }) {
  if (budget <= 0) {
    return (
      <div className="h-1.5 rounded-sharp bg-elevated border border-border-default/60">
        <span className="sr-only">No budget set</span>
      </div>
    );
  }
  const pct = Math.max(0, Math.min(100, (actual / budget) * 100));
  const color = pct >= 80 ? "#f0a8c7" : pct >= 50 ? "#f0c97a" : "#97dbbe";
  return (
    <div
      role="progressbar"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Cost ${fmtUsd(actual)} of ${fmtUsd(budget)} (${pct.toFixed(0)}%)`}
      className="relative h-1.5 rounded-sharp overflow-hidden border border-border-default/60 bg-elevated"
    >
      <div
        className="h-full"
        style={{
          width: `${pct}%`,
          transition: "width 300ms ease-out",
          background: `linear-gradient(to right, color-mix(in srgb, ${color} 60%, transparent), ${color})`,
        }}
      />
    </div>
  );
}

/** Animated status dot + label. Pulses for live `running` state. */
function StatusIndicator({ status, pauseReason }: {
  status: InvestigationStatus;
  pauseReason?: string | null;
}) {
  const meta = STATUS_META[status] ?? _STATUS_FALLBACK;
  return (
    <div className="flex items-center gap-2.5">
      <span className="relative inline-flex items-center justify-center w-3 h-3">
        {meta.pulse && (
          <span
            className="absolute inset-0 rounded-full animate-ping"
            style={{ background: meta.color, opacity: 0.4 }}
          />
        )}
        <span
          className="relative inline-block w-2.5 h-2.5 rounded-full"
          style={{
            background: meta.color,
            boxShadow: `0 0 8px ${meta.color}`,
          }}
        />
      </span>
      <span className="font-display text-base font-semibold text-foreground leading-none">
        {meta.label}
      </span>
      {pauseReason && (
        <span className="text-3xs font-mono uppercase tracking-wide text-text-muted">
          · {humanize(pauseReason)}
        </span>
      )}
    </div>
  );
}

/** Colored persona avatar — initial circle. */
function PersonaAvatar({
  voice,
  size = 32,
}: {
  voice?: PersonaVoice | string | null;
  size?: number;
}) {
  const meta = personaMeta(voice);
  return (
    <span
      className="inline-flex items-center justify-center rounded-full font-display font-semibold flex-shrink-0"
      style={{
        width: size,
        height: size,
        background: meta.bg,
        color: meta.color,
        border: `1px solid ${meta.color}`,
        fontSize: Math.max(10, Math.round(size * 0.4)),
      }}
      title={meta.label}
      aria-label={meta.label}
    >
      {meta.initial}
    </span>
  );
}

/** Header-toolbar icon button: consistent look across Link, button. */
function ToolbarButton({
  icon,
  label,
  variant = "default",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: React.ReactNode;
  label: string;
  variant?: "default" | "primary" | "danger";
}) {
  const tone =
    variant === "primary"
      ? "bg-accent text-white border-accent hover:bg-accent/90"
      : variant === "danger"
        ? "bg-surface border-orange-500/60 text-orange-300 hover:border-orange-400 hover:bg-orange-500/10"
        : "bg-surface border-border-default text-foreground hover:bg-surface/80 hover:border-accent/60";
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors disabled:opacity-50 ${tone} ${props.className ?? ""}`}
    >
      <span className="[&_svg]:h-4 [&_svg]:w-4">{icon}</span>
      <span>{label}</span>
    </button>
  );
}

function ToolbarLink({
  to,
  icon,
  label,
}: {
  to: string;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default text-foreground hover:bg-surface/80 hover:border-accent/60 transition-colors"
    >
      <span className="[&_svg]:h-4 [&_svg]:w-4">{icon}</span>
      <span>{label}</span>
    </Link>
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
  const { status: liveStatus } = useInvestigationMessagesStream(invId);
  const { data: outcomesResult } = useInvestigationOutcomes(invId);
  const targetName = useTargetName(inv?.target_id);

  const pauseMut = usePauseInvestigation(invId);
  const resetMut = useResetInvestigation(invId);
  const resumeMut = useResumeInvestigation(invId);
  const reenqueueMut = useReenqueueInvestigation(invId);
  const sendMut = useSendOperatorMessage(invId);
  const deleteMut = useDeleteInvestigation();
  const reverifyMut = useReverifyInvestigation();
  const promoteMut = usePromoteOutcomeToFinding(invId);

  const [messageText, setMessageText] = useState("");

  useUpdatePageHeader({
    title: inv?.title,
    subtitle: inv ? `${inv.kind} · target: ${targetName}` : undefined,
    status: inv?.status === 'running' ? 'live' : inv?.status === 'paused' ? 'paused' : inv?.status === 'failed' ? 'error' : 'ready',
  });
  const [messageIntent, setMessageIntent] = useState<OperatorIntent | "">("");
  const [steeringOpen, setSteeringOpen] = useState(false);
  useVRKeyboardShortcuts({ onOpenSteering: () => setSteeringOpen(true) });
  const [liveTail, setLiveTail] = useState(true);


  // ── Default-land at the latest turn ──────────────────────────────
  //
  // When the page first loads with a populated investigation, scroll
  // straight to the bottom. Operator opening a 1000-turn
  // investigation expects to see "current state", not message #1.
  //
  // Implementation note: we deliberately scroll the WINDOW to
  // document.scrollHeight instead of doing scrollIntoView on the
  // last turn element, because at mount time the turn elements may
  // not be in the DOM yet (React hasn't committed) — element lookup
  // races and silently fails. Window-scroll has no such race.
  //
  // Retried 8 times over ~800ms via rAF so it tolerates: late
  // React commits, late image / font loads that grow the page
  // height, and slow streaming SSE that adds turns right after
  // mount. The retry is cheap (just a few scrollTo calls) and
  // stops at the first one that lands within 32px of the bottom.
  const initialScrolledRef = useRef(false);
  useEffect(() => {
    if (initialScrolledRef.current) return;
    const list = messagesResult?.data ?? [];
    if (list.length === 0) return;  // wait for data
    initialScrolledRef.current = true;

    let attempts = 0;
    const maxAttempts = 8;
    const tick = () => {
      window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "auto" });
      attempts++;
      const distFromBottom =
        document.documentElement.scrollHeight -
        window.scrollY -
        window.innerHeight;
      if (distFromBottom > 32 && attempts < maxAttempts) {
        // Page grew or didn't render yet — try again on next frame.
        requestAnimationFrame(tick);
      }
    };
    requestAnimationFrame(tick);
  }, [messagesResult?.data?.length]);

  // Live-tail: auto-scroll the newest turn into view when liveTail is on
  // AND new messages arrive AFTER the initial landing. We watch the
  // message count rather than ids so we don't re-fire on every refetch.
  const lastSeenCount = useRef(0);
  useEffect(() => {
    if (!liveTail) return;
    const list = messagesResult?.data ?? [];
    if (list.length > lastSeenCount.current && lastSeenCount.current > 0) {
      // Skip the initial 0 → N transition (handled by initial-scroll
      // effect above with instant scroll). Only smooth-scroll on
      // genuine streaming growth.
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

  // ── Scroll-to-end UX —————————————————————————————————————————————
  //
  // Long investigations (50+ turns) make it painful to scroll to the
  // newest turn manually. We add:
  //   - A floating "Jump to latest" button (bottom-right) that appears
  //     whenever the user has scrolled UP from the bottom of the page.
  //   - A floating "Turn N / M" position indicator (top-right) that
  //     reflects the most-recently-visible turn under the viewport.
  //   - Keyboard shortcuts handled in useVRKeyboardShortcuts (G+G top,
  //     Shift+G bottom — already wired).
  //
  // Operator-reported friction (75af3d8e-...): "I can't roll down to
  // the end smoothly because of the call history". Auto-scroll
  // (liveTail) handles the streaming case; this handles the manual
  // catch-up case after pausing or jumping around.
  const [scrollNearBottom, setScrollNearBottom] = useState(true);
  const [visibleTurn, setVisibleTurn] = useState<number | null>(null);
  // Refs hold the "last committed" state so the scroll handler can
  // skip setState calls when nothing actually changed. Without these,
  // every scroll event (or every refetch tick from
  // useInvestigationMessagesStream) re-fired setState on equal
  // values — React 18's Object.is short-circuit catches that on most
  // primitives, but the combination with an effect that re-runs on
  // messages-length changes hit "Maximum update depth exceeded" once
  // the page had 1000+ turns and streaming was active.
  const scrollNearBottomRef = useRef(true);
  const visibleTurnRef = useRef<number | null>(null);
  useEffect(() => {
    const onScroll = () => {
      const distFromBottom =
        document.documentElement.scrollHeight -
        window.scrollY -
        window.innerHeight;
      const nearBottom = distFromBottom < 240;
      if (nearBottom !== scrollNearBottomRef.current) {
        scrollNearBottomRef.current = nearBottom;
        setScrollNearBottom(nearBottom);
      }
      // Pick the visible turn by walking back from the latest until we
      // find one whose top is above viewport-mid.
      const cards = document.querySelectorAll<HTMLElement>('[id^="turn-"]');
      const viewportMid = window.scrollY + window.innerHeight / 2;
      let bestIdx: number | null = null;
      for (let i = cards.length - 1; i >= 0; i--) {
        const r = cards[i].getBoundingClientRect();
        const top = r.top + window.scrollY;
        if (top <= viewportMid) {
          bestIdx = i;
          break;
        }
      }
      if (bestIdx !== visibleTurnRef.current) {
        visibleTurnRef.current = bestIdx;
        setVisibleTurn(bestIdx);
      }
    };
    // Defer initial computation past the current commit so we don't
    // setState synchronously inside the effect body (the symptom path
    // that React reports as "Maximum update depth exceeded").
    const raf = requestAnimationFrame(onScroll);
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, []);  // empty deps — handler reads live DOM state, no stale-closure risk

  const jumpToLatest = () => {
    const cards = document.querySelectorAll<HTMLElement>('[id^="turn-"]');
    const last = cards[cards.length - 1];
    if (last) {
      last.scrollIntoView({ behavior: "smooth", block: "end" });
    } else {
      window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" });
    }
  };
  // All hooks before any early return — keep React's hook ordering stable.
  const branches = branchesResult?.data ?? [];
  const messages = messagesResult?.data ?? [];
  const outcomes = outcomesResult?.data ?? [];


  // branch_id → persona_voice lookup for TurnCard. Messages carry branch_id
  // but NOT persona name (sender_id is always 'engine' or 'tool_executor').
  const branchPersonaMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const b of branches) {
      if (b.persona_voice) m.set(b.id, b.persona_voice);
    }
    return m;
  }, [branches]);
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

  // LiveDot now reflects the real SSE fetch lifecycle reported by
  // useInvestigationMessagesStream (reconnecting → connected on first
  // bytes; disconnected when the stream ends or errors). No more
  // inferring from inv.status — that was misleading for `created` /
  // `completed` investigations where no stream is active.

  const operatorComposerOpen =
    inv.status === "running" || inv.status === "paused" || inv.status === "created";

  // Sort outcomes: primary first, then newest. Pre-compute so both
  // hero card and compact list see the same ordering.
  const sortedOutcomes = [...outcomes].sort((a, b) => {
    const aPrim = a.id === inv.primary_outcome_id ? -1 : 0;
    const bPrim = b.id === inv.primary_outcome_id ? -1 : 0;
    if (aPrim !== bPrim) return aPrim - bPrim;
    return (b.created_at ?? "").localeCompare(a.created_at ?? "");
  });
  const primaryOutcome = sortedOutcomes.find((o) => o.id === inv.primary_outcome_id) ?? null;
  const otherOutcomes = sortedOutcomes.filter((o) => o.id !== inv.primary_outcome_id);

  return (
    <div className="space-y-4 max-w-full min-w-0 overflow-x-hidden break-words">
      {/* Header toolbar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <LiveDot status={liveStatus} />
          <span className="w-px h-5 bg-border-default mx-1" aria-hidden />
          <ToolbarLink
            to={`/vr/investigations/${invId}/tree`}
            icon={<TreeStructure weight="regular" />}
            label="Branch tree"
          />
          <ToolbarLink
            to={`/vr/investigations/${invId}/graph`}
            icon={<Graph weight="regular" />}
            label="Evidence graph"
          />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <ToolbarButton
            icon={<GearSix weight="fill" />}
            label="Steering"
            variant="primary"
            onClick={() => setSteeringOpen(true)}
          />
          <ExportReportButton invId={invId} title={inv.title} />
          <span className="w-px h-5 bg-border-default mx-1" aria-hidden />
          <ToolbarButton
            icon={<ArrowCounterClockwise weight="regular" />}
            label={resetMut.isPending ? "Resetting…" : "Reset"}
            variant="danger"
            onClick={() => {
              const confirmed = window.confirm(
                `Reset "${inv.title}" to its initial state?\n\n` +
                `Deletes ALL messages (${inv.message_count}) + ALL outcomes ` +
                `(${inv.outcome_count}) + forked branches. Root branches reset ` +
                `to turn 0 with empty case state. Investigation flips back to ` +
                `CREATED so you can re-enqueue with a fresh history.\n\n` +
                `THIS CANNOT BE UNDONE.`,
              );
              if (!confirmed) return;
              resetMut.mutate();
            }}
            disabled={resetMut.isPending || inv.status === "running"}
            title={
              inv.status === "running"
                ? "Pause the investigation first, then reset."
                : "Wipe history + reset to start. Re-enqueue afterwards to run again."
            }
          />
          <DeleteButton
            id={invId}
            label={`investigation "${inv.title}"`}
            mutation={deleteMut}
            onDeleted={() => navigate("/vr/investigations")}
          />
        </div>
      </div>

      {/* Workflow stepper */}
      <AilaCard techBorder glow><WorkflowStepper
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
      /></AilaCard>

      {/* Status + cost ribbon */}
      <AilaCard techBorder glow>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex flex-col gap-1 min-w-0">
            <StatusIndicator status={inv.status} pauseReason={inv.pause_reason} />
            <p className="text-xs text-text-muted font-mono">
              {humanize(inv.strategy_family)} strategy
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            {inv.status === "running" && (
              <ToolbarButton
                icon={<Pause weight="fill" />}
                label={pauseMut.isPending ? "Pausing…" : "Pause"}
                onClick={() => pauseMut.mutate()}
                disabled={pauseMut.isPending}
              />
            )}
            {inv.status === "paused" && (
              <ToolbarButton
                icon={<Play weight="fill" />}
                label={resumeMut.isPending ? "Resuming…" : "Resume"}
                variant="primary"
                onClick={() => resumeMut.mutate()}
                disabled={resumeMut.isPending}
              />
            )}
            {inv.status === "created" && (
              <ToolbarButton
                icon={<Play weight="fill" />}
                label={reenqueueMut.isPending ? "Starting…" : "Start"}
                variant="primary"
                onClick={() => reenqueueMut.mutate(undefined)}
                disabled={reenqueueMut.isPending}
                title="Start this investigation (enqueue run_vr_investigate task)"
              />
            )}
            {(inv.status === "completed" || inv.status === "failed") && (
              <ReenqueuePicker
                currentKind={inv.kind}
                mutation={reenqueueMut}
              />
            )}
          </div>
        </div>

        {/* Compact stats row — no giant KPI boxes, no duplication */}
        <div className="mt-3 flex items-center gap-4 flex-wrap text-xs font-mono text-text-muted">
          <span className="inline-flex items-center gap-1.5">
            <TreeStructure weight="fill" size={13} className="text-accent" />
            <span className="text-foreground font-semibold">{inv.branch_count}</span> branches
          </span>
          <span className="w-px h-3 bg-border-default" />
          <span className="inline-flex items-center gap-1.5">
            <ChatCircleText weight="fill" size={13} className="text-text-muted" />
            <span className="text-foreground font-semibold">{inv.message_count.toLocaleString()}</span> turns
          </span>
          <span className="w-px h-3 bg-border-default" />
          <span className="inline-flex items-center gap-1.5">
            <Lightning weight="fill" size={13} className="text-text-muted" />
            ~<span className="text-foreground font-semibold">{((inv.message_count * 28000) / 1_000_000).toFixed(1)}M</span> tokens
          </span>
          <span className="w-px h-3 bg-border-default" />
          <span className="inline-flex items-center gap-1.5">
            <Target weight="fill" size={13} className={inv.outcome_count > 0 ? "text-emerald-400" : "text-text-muted"} />
            <span className="text-foreground font-semibold">{inv.outcome_count}</span> outcomes
          </span>
        </div>
      </AilaCard>

      {/* ── Outcomes (hero position — first content after status) ─── */}
      {outcomes.length > 0 && (
        <AilaCard techBorder glow>
          <div className="flex items-center gap-2 mb-3">
            <Target weight="fill" size={16} className="text-accent" />
            <h3 className="text-sm font-semibold text-foreground">
              Outcomes
            </h3>
            <span className="text-xs font-mono text-text-muted tabular-nums">
              {outcomes.length}
            </span>
          </div>
          <div className="space-y-3">
            {primaryOutcome && (
              <PrimaryOutcomeCard
                outcome={primaryOutcome}
                persona={branches.find((b) => b.id === primaryOutcome.branch_id)?.persona_voice ?? null}
                invId={invId}
                reverifyMut={reverifyMut}
                promoteMut={promoteMut}
              />
            )}
            {otherOutcomes.length > 0 && (
              <ul className="space-y-1.5">
                {otherOutcomes.map((o) => {
                  const oPers = branches.find((b) => b.id === o.branch_id)?.persona_voice ?? null;
                  return (
                    <CompactOutcomeRow
                      key={o.id}
                      outcome={o}
                      persona={oPers}
                      invId={invId}
                      reverifyMut={reverifyMut}
                      promoteMut={promoteMut}
                    />
                  );
                })}
              </ul>
            )}
          </div>
        </AilaCard>
      )}

      {/* Main layout — aside (order-1 = above) + timeline (order-2 = below) */}
      <div className="grid grid-cols-1 gap-4">
        {/* Timeline column — order-2 so it renders BELOW the aside.
            Default scroll-to-bottom lands operator at the latest turn
            (page bottom = last turn in timeline). To see hypotheses /
            branches / outcomes / fuzz proposals, operator scrolls up
            past the timeline to the aside section. */}
        <div className="space-y-3 min-w-0 order-2">
          {/* Filter bar */}
          <AilaCard padding="sm" techBorder glow>
            <div className="flex items-center gap-2 flex-wrap text-xs">
              <span className="inline-flex items-center gap-1.5 text-text-muted px-1">
                <Funnel weight="fill" size={14} />
                <span className="font-mono uppercase tracking-wide text-3xs">Filter</span>
              </span>
              <select
                value={senderFilter}
                onChange={(e) => updateParam("sender", e.target.value)}
                className="px-2 py-1 rounded-md bg-elevated border border-border-default font-mono text-foreground hover:border-accent/50 focus:border-accent focus:outline-none"
                aria-label="Filter by sender kind"
              >
                <option value="">all senders</option>
                {senderKinds.map((s) => (
                  <option key={s} value={s}>
                    {humanize(s)}
                  </option>
                ))}
              </select>
              <select
                value={payloadFilter}
                onChange={(e) => updateParam("kind", e.target.value)}
                className="px-2 py-1 rounded-md bg-elevated border border-border-default font-mono text-foreground hover:border-accent/50 focus:border-accent focus:outline-none"
                aria-label="Filter by payload kind"
              >
                <option value="">all kinds</option>
                {payloadKinds.map((k) => (
                  <option key={k} value={k}>
                    {humanize(k)}
                  </option>
                ))}
              </select>
              {branches.length > 1 && (
                <select
                  value={branchFilter}
                  onChange={(e) => updateParam("branch", e.target.value)}
                  className="px-2 py-1 rounded-md bg-elevated border border-border-default font-mono text-foreground hover:border-accent/50 focus:border-accent focus:outline-none"
                  aria-label="Filter by branch"
                >
                  <option value="">all branches</option>
                  {branches.map((b) => (
                    <option key={b.id} value={b.id}>
                      {personaMeta(b.persona_voice).label}
                      {b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}
                    </option>
                  ))}
                </select>
              )}
              <span className="ml-auto inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-elevated/60 border border-border-default/60 text-text-muted font-mono">
                <Hash weight="bold" size={12} />
                <span className="text-foreground tabular-nums">{filtered.length}</span>
                <span>/ {messages.length}</span>
                {visibleTurn != null && (
                  <span className="ml-1 text-3xs">· at #{visibleTurn + 1}</span>
                )}
              </span>
              <label
                className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md border cursor-pointer transition-colors focus-within:outline focus-within:outline-2 focus-within:outline-accent focus-within:outline-offset-2 ${
                  liveTail
                    ? "bg-accent/15 border-accent/50 text-foreground"
                    : "bg-elevated/60 border-border-default/60 text-text-muted hover:border-accent/40"
                }`}
                title={liveTail ? "Auto-scroll new turns into view" : "Frozen — won't auto-scroll"}
              >
                <input
                  type="checkbox"
                  checked={liveTail}
                  onChange={(e) => setLiveTail(e.target.checked)}
                  className="sr-only"
                />
                <Lightning weight={liveTail ? "fill" : "regular"} size={12} />
                <span className="font-mono uppercase tracking-wide text-3xs">
                  Live tail
                </span>
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{
                    background: liveTail ? "#97dbbe" : "#9aa0a6",
                    boxShadow: liveTail ? "0 0 6px #97dbbe" : "none",
                  }}
                />
              </label>
              <div className="inline-flex items-center gap-1">
                <span className="text-3xs font-mono text-text-muted uppercase tracking-wide">
                  Jump
                </span>
                <input
                  type="number"
                  placeholder="#"
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
                  className="w-16 px-2 py-1 rounded-md bg-elevated border border-border-default font-mono text-foreground focus:border-accent focus:outline-none"
                  aria-label="Jump to turn number"
                />
              </div>
            </div>
          </AilaCard>

          {/* Turn stream */}
          {filtered.length === 0 ? (
            <AilaCard techBorder glow>
              <p className="text-sm text-text-muted text-center py-6">
                {messages.length === 0
                  ? "No turns yet — engine hasn't started reasoning."
                  : "Filters hide every turn. Clear filters above to see them."}
              </p>
            </AilaCard>
          ) : (
            <div className="space-y-2">
              {filtered.map((m, i) => (
                <TurnCard key={m.id} message={m} index={i} persona={branchPersonaMap.get(m.branch_id) ?? null} />
              ))}
            </div>
          )}

          {/* Operator composer (bottom of stream, like a chat input) */}
          {operatorComposerOpen && (
            <AilaCard techBorder glow>
              <div className="flex items-center gap-2 mb-3">
                <PaperPlaneRight weight="fill" size={14} className="text-accent" />
                <h2 className="text-3xs font-mono uppercase tracking-cyber-sm text-text-muted">
                  Operator Input · Inject context for next turn
                </h2>
              </div>
              <p className="text-xs text-text-muted mb-3 leading-relaxed">
                The engine sees this verbatim as an operator note on its next turn.
                Pick an <span className="font-mono text-foreground">intent</span>{" "}
                below or let it auto-classify.
              </p>

              {/* Intent toggle row */}
              <div className="flex items-center gap-1.5 flex-wrap mb-3">
                {OPERATOR_INTENTS.map((it) => {
                  const active = messageIntent === it.value;
                  return (
                    <button
                      key={it.value || "auto"}
                      type="button"
                      onClick={() => setMessageIntent(it.value)}
                      className={`px-2.5 py-1 text-2xs font-mono rounded-full border transition-colors ${
                        active
                          ? "bg-accent/20 border-accent text-foreground"
                          : "bg-elevated/60 border-border-default/60 text-text-muted hover:border-accent/40 hover:text-foreground"
                      }`}
                      aria-pressed={active}
                    >
                      {it.label}
                    </button>
                  );
                })}
              </div>

              {/* Chat-style input with embedded send button */}
              <div className="relative flex items-end gap-0 rounded-lg border border-border-default bg-elevated focus-within:border-accent transition-colors">
                <textarea
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  onKeyDown={(e) => {
                    // Cmd/Ctrl+Enter → send
                    if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && messageText.trim()) {
                      e.preventDefault();
                      sendMut.mutate(
                        { text: messageText.trim(), explicit_intent: messageIntent || undefined },
                        { onSuccess: () => { setMessageText(""); setMessageIntent(""); } },
                      );
                    }
                  }}
                  placeholder="e.g. 'try the JSPI base address path' or 'that hypothesis is wrong because…'  (⌘↵ to send)"
                  rows={3}
                  aria-label="Operator message composer"
                  className="flex-1 px-3 py-2.5 text-sm font-mono bg-transparent text-foreground placeholder-text-muted/60 focus:outline-none resize-none rounded-lg"
                />
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
                  className="m-2 inline-flex items-center justify-center gap-1.5 h-9 px-3 rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-xs font-medium flex-shrink-0"
                  aria-label="Send operator message"
                >
                  {sendMut.isPending ? (
                    <>Sending…</>
                  ) : (
                    <>
                      <PaperPlaneRight weight="fill" size={14} />
                      Send
                    </>
                  )}
                </button>
              </div>
            </AilaCard>
          )}
        </div>

        {/* Side rail — order-1 so it renders ABOVE the timeline.
            Operator default-scrolls to page bottom (latest turn in
            timeline below); to see hypotheses / branches / outcomes,
            scroll up past the timeline to here. */}
        <aside className="space-y-3 min-w-0 order-1">
          {/* Hypothesis projection (08_FRONTEND_UX.md §2.3) */}
          <HypothesisDetailRail investigationId={invId} />
          {/* Fuzz proposals queue (operator-in-the-loop) */}
          <FuzzProposalsPanel investigationId={invId} />


          {/* Branches summary */}
          <AilaCard techBorder glow>
            <div className="flex items-center gap-2 mb-3">
              <TreeStructure weight="fill" size={14} className="text-accent" />
              <h3 className="text-3xs font-mono uppercase tracking-cyber-sm text-text-muted">
                Branches
              </h3>
              <span className="text-xs font-mono text-foreground tabular-nums">
                {branches.length}
              </span>
            </div>
            {(() => {
              const activeBranches = branches.filter((b) => b.turn_count > 0);
              const queuedBranches = branches.filter((b) => b.turn_count === 0);
              if (activeBranches.length === 0 && queuedBranches.length === 0) {
                return <p className="text-xs text-text-muted">No forks yet.</p>;
              }
              return (
                <>
                  <ul className="space-y-1.5">
                    {activeBranches.map((b) => {
                      const statusMeta = BRANCH_STATUS_META[b.status] ?? _BRANCH_STATUS_FALLBACK;
                      const pm = personaMeta(b.persona_voice);
                      const isActive = b.status === "active";
                      return (
                        <li
                          key={b.id}
                          className="flex items-center gap-3 rounded-md border border-border-default/60 bg-elevated/40 p-2 hover:border-accent/40 transition-colors"
                        >
                          <PersonaAvatar voice={b.persona_voice} size={32} />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-medium text-foreground">
                                {pm.label}
                              </span>
                              <span className="inline-flex items-center gap-1 text-3xs font-mono uppercase tracking-wide text-text-muted">
                                <span
                                  className="w-1.5 h-1.5 rounded-full"
                                  style={{
                                    background: statusMeta.color,
                                    boxShadow: isActive ? `0 0 6px ${statusMeta.color}` : "none",
                                  }}
                                />
                                {statusMeta.label}
                              </span>
                              {b.promoted && (
                                <AilaBadge severity="low" size="sm">
                                  Promoted
                                </AilaBadge>
                              )}
                            </div>
                            <p className="mt-0.5 text-2xs font-mono text-text-muted">
                              {b.turn_count} turn{b.turn_count === 1 ? "" : "s"} · {fmtUsd(b.branch_cost_usd)}
                              {b.fork_at_turn != null && (
                                <span> · forked @t{b.fork_at_turn}</span>
                              )}
                            </p>
                            {isActive && b.turn_count > 0 && (
                              <div className="mt-1.5 h-0.5 rounded-full bg-elevated overflow-hidden">
                                <div
                                  className="h-full animate-pulse"
                                  style={{
                                    width: "60%",
                                    background: `linear-gradient(to right, transparent, ${pm.color}, transparent)`,
                                  }}
                                />
                              </div>
                            )}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                  {queuedBranches.length > 0 && (
                    <div className="mt-2 flex items-center gap-2 text-2xs text-text-muted font-mono">
                      <span className="w-1.5 h-1.5 rounded-full bg-text-muted/40" />
                      {queuedBranches.length} branch{queuedBranches.length === 1 ? "" : "es"} queued
                      <span className="text-text-muted/60">
                        ({queuedBranches.map((b) => personaMeta(b.persona_voice).label).join(", ")})
                      </span>
                    </div>
                  )}
                </>
              );
            })()}
          </AilaCard>

          {/* Outcomes moved to hero position above — see line ~818 */}
        </aside>
      </div>
      <SteeringDrawer
        open={steeringOpen}
        onClose={() => setSteeringOpen(false)}
        investigationId={invId}
        status={inv.status}
      />

      {/* Floating turn position + scroll buttons. PORTAL'd to document.body
          because an ancestor sets transform/filter which would otherwise
          capture position:fixed elements (CSS spec). */}
      {messages.length > 1 && createPortal(
        <>
          {/* Top-right: jump-to-latest pill, only when not near bottom */}
          {!scrollNearBottom && (
            <div className="fixed top-20 right-6" style={{ zIndex: 60 }}>
              <button
                type="button"
                onClick={jumpToLatest}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-accent/95 text-white shadow-lg hover:bg-accent text-xs font-medium transition-colors"
                title="Jump to latest turn"
              >
                <Lightning weight="fill" size={12} />
                Jump to latest
                {visibleTurn != null && (
                  <span className="font-mono text-3xs opacity-80">
                    #{visibleTurn + 1} / {messages.length}
                  </span>
                )}
              </button>
            </div>
          )}

          {/* Bottom-right: scroll up / down */}
          <div className="fixed bottom-6 right-6 flex flex-col gap-2" style={{ zIndex: 60 }}>
            <button
              type="button"
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              className="w-10 h-10 rounded-full bg-surface/95 border border-border-default text-foreground shadow-lg hover:bg-surface hover:border-accent transition-colors flex items-center justify-center text-base"
              aria-label="Scroll to top"
              title="Scroll to top"
            >
              ↑
            </button>
            <button
              type="button"
              onClick={() => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" })}
              className="w-10 h-10 rounded-full bg-surface/95 border border-border-default text-foreground shadow-lg hover:bg-surface hover:border-accent transition-colors flex items-center justify-center text-base"
              aria-label="Scroll to bottom"
              title="Scroll to bottom"
            >
              ↓
            </button>
          </div>
        </>,
        document.body,
      )}
    </div>
  );
}

// ─── Outcome sub-components ─────────────────────────────────────────

type OutcomeRowProps = {
  outcome: import("../types").VROutcomeSummary;
  persona: PersonaVoice | null;
  invId: string;
  reverifyMut: ReturnType<typeof useReverifyInvestigation>;
  promoteMut: ReturnType<typeof usePromoteOutcomeToFinding>;
};

function readVerifier(payload: Record<string, unknown> | undefined) {
  return (payload?.verifier_report as
    | { verdict?: string; confidence?: number; summary?: string; counter_evidence?: string }
    | undefined) ?? undefined;
}

function VerifierBanner({ vr }: { vr: ReturnType<typeof readVerifier> }) {
  if (!vr?.verdict) return null;
  const isConfirmed = vr.verdict === "confirmed";
  const isRefuted = vr.verdict === "refuted";
  const color = isConfirmed ? "#97dbbe" : isRefuted ? "#f0a8c7" : "#f0c97a";
  const Icon = isConfirmed ? CheckCircle : isRefuted ? XCircle : WarningCircle;
  const conf = typeof vr.confidence === "number" ? ` (${vr.confidence.toFixed(2)})` : "";
  return (
    <div
      className="flex items-start gap-2 px-3 py-2 rounded-md text-xs border"
      style={{
        background: `color-mix(in srgb, ${color} 10%, transparent)`,
        borderColor: `color-mix(in srgb, ${color} 40%, transparent)`,
        color,
      }}
    >
      <Icon weight="fill" size={16} className="flex-shrink-0 mt-0.5" />
      <div className="min-w-0 flex-1">
        <div className="font-semibold uppercase tracking-wide text-3xs">
          Verifier: {vr.verdict}{conf}
        </div>
        {(vr.summary || vr.counter_evidence) && (
          <div className="mt-1 text-foreground/90 whitespace-pre-wrap break-words leading-relaxed">
            {isRefuted ? vr.counter_evidence : vr.summary}
          </div>
        )}
      </div>
    </div>
  );
}

function PrimaryOutcomeCard({
  outcome: o,
  persona,
  invId,
  reverifyMut,
  promoteMut,
}: OutcomeRowProps) {
  const vr = readVerifier(o.payload);
  const persMeta = personaMeta(persona);
  const verdictColor =
    vr?.verdict === "confirmed"
      ? "#97dbbe"
      : vr?.verdict === "refuted"
        ? "#f0a8c7"
        : "#f0c97a";
  return (
    <div
      className="relative rounded-lg border bg-elevated/30 p-4 overflow-hidden"
      style={{
        borderColor: vr?.verdict ? `color-mix(in srgb, ${verdictColor} 40%, var(--color-border))` : "var(--color-accent)",
      }}
    >
      {/* Crown ribbon at the top */}
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="inline-flex items-center gap-2">
          <Crown weight="fill" size={14} className="text-accent" />
          <span className="text-3xs font-mono uppercase tracking-cyber-sm text-accent">
            Primary · Synthesis
          </span>
        </div>
        <AilaBadge
          severity={dispatchColor[o.dispatch_status] ?? "info"}
          size="sm"
        >
          {humanize(o.dispatch_status)}
        </AilaBadge>
      </div>

      {/* Kind + persona + confidence */}
      <div className="flex items-center gap-2 flex-wrap mb-3">
        <div
          className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md border"
          style={{
            background: `color-mix(in srgb, var(--color-accent) 8%, transparent)`,
            borderColor: `color-mix(in srgb, var(--color-accent) 30%, transparent)`,
            color: "var(--color-accent)",
          }}
        >
          <OutcomeKindBadge kind={o.outcome_kind} showLabel={false} />
          <span className="text-xs font-medium">{outcomeKindLabel(o.outcome_kind)}</span>
        </div>
        {persona && (
          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-elevated/60 border border-border-default/60">
            <PersonaAvatar voice={persona} size={18} />
            <span className="text-2xs font-mono text-text-muted">{persMeta.label}</span>
          </span>
        )}
        <AilaBadge severity="info" size="sm">
          {humanConfidence(o.confidence)} Confidence
        </AilaBadge>
      </div>

      {/* Verifier banner */}
      {vr?.verdict && (
        <div className="mb-3">
          <VerifierBanner vr={vr} />
        </div>
      )}

      {/* Full answer text */}
      <div className="mb-3">
        <PayloadPreview payload={o.payload} fullByDefault defaultExpanded />
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 flex-wrap pt-3 border-t border-border-default/60">
        <button
          type="button"
          disabled={reverifyMut.isPending}
          onClick={(e) => {
            e.stopPropagation();
            reverifyMut.mutate(invId);
          }}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-2xs rounded-md border border-border-default text-text-muted hover:text-foreground hover:border-accent disabled:opacity-50 transition-colors"
          title={
            vr?.verdict
              ? "Clear current verifier_report and re-run the verifier on this finding"
              : "Manually trigger the claim verifier on this finding"
          }
        >
          <ShieldCheck weight="regular" size={12} />
          {reverifyMut.isPending ? "…" : vr?.verdict ? "Re-verify" : "Verify"}
        </button>
        {o.outcome_kind === "assessment_report" && o.dispatch_status === "skipped" && (
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
              promoteMut.mutate({ outcomeId: o.id, reason: note });
            }}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-2xs rounded-md border transition-colors disabled:opacity-50 ${
              vr?.verdict === "confirmed"
                ? "border-emerald-500/60 text-emerald-300 hover:border-emerald-400 hover:bg-emerald-500/10"
                : "border-border-default text-text-muted hover:text-foreground hover:border-accent"
            }`}
            title={
              vr?.verdict === "confirmed"
                ? `Verifier CONFIRMED this assessment — promote to direct_finding to create a vr_finding row and (on variant-child investigations) auto-enqueue the PoC writer.`
                : vr?.verdict === "refuted"
                  ? `Verifier REFUTED — promoting will still create a finding row, but the PoC writer will skip itself per the verifier-gate.`
                  : "Promote this assessment_report to direct_finding (creates vr_finding row + dispatches downstream)."
            }
          >
            {promoteMut.isPending ? "…" : "↗ Promote to finding"}
          </button>
        )}
      </div>
    </div>
  );
}

function CompactOutcomeRow({
  outcome: o,
  persona,
  invId,
  reverifyMut,
  promoteMut,
}: OutcomeRowProps) {
  const [expanded, setExpanded] = useState(false);
  const vr = readVerifier(o.payload);
  const persMeta = personaMeta(persona);
  return (
    <li className="rounded-md border border-border-default/60 bg-elevated/30 overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2 px-2.5 py-2 text-left hover:bg-elevated/60 transition-colors"
      >
        <span className="text-text-muted flex-shrink-0">
          {expanded ? <CaretDown weight="bold" size={12} /> : <CaretRight weight="bold" size={12} />}
        </span>
        <span
          className="inline-flex items-center gap-1 text-foreground"
          style={{ color: `color-mix(in srgb, var(--color-foreground) 80%, ${outcomeKindSeverityColor(o.outcome_kind)})` }}
        >
          <OutcomeKindBadge kind={o.outcome_kind} showLabel={false} />
        </span>
        <span className="text-xs font-medium text-foreground truncate flex-shrink min-w-0">
          {outcomeKindLabel(o.outcome_kind)}
        </span>
        {persona && (
          <PersonaAvatar voice={persona} size={18} />
        )}
        <span className="ml-auto inline-flex items-center gap-1.5 flex-shrink-0">
          <span className="text-3xs font-mono text-text-muted uppercase tracking-wide">
            {humanConfidence(o.confidence)}
          </span>
          {vr?.verdict && (
            <span
              className="inline-flex items-center gap-1 text-3xs font-mono uppercase tracking-wide"
              style={{
                color:
                  vr.verdict === "confirmed"
                    ? "#97dbbe"
                    : vr.verdict === "refuted"
                      ? "#f0a8c7"
                      : "#f0c97a",
              }}
            >
              {vr.verdict === "confirmed" && <CheckCircle weight="fill" size={10} />}
              {vr.verdict === "refuted" && <XCircle weight="fill" size={10} />}
              {vr.verdict !== "confirmed" && vr.verdict !== "refuted" && (
                <WarningCircle weight="fill" size={10} />
              )}
              {vr.verdict}
            </span>
          )}
          <AilaBadge
            severity={dispatchColor[o.dispatch_status] ?? "info"}
            size="sm"
          >
            {humanize(o.dispatch_status)}
          </AilaBadge>
        </span>
      </button>
      {expanded && (
        <div className="px-2.5 pb-2.5 pt-1 space-y-2 border-t border-border-default/40">
          {persona && (
            <p className="text-3xs font-mono text-text-muted">
              Voice: <span style={{ color: persMeta.color }}>{persMeta.label}</span>
            </p>
          )}
          {vr?.verdict && <VerifierBanner vr={vr} />}
          <PayloadPreview payload={o.payload} />
          {o.outcome_kind === "assessment_report" && o.dispatch_status === "skipped" && (
            <div className="flex gap-2 pt-1">
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
                  promoteMut.mutate({ outcomeId: o.id, reason: note });
                }}
                className={`px-2 py-0.5 text-3xs rounded border transition-colors disabled:opacity-50 ${
                  vr?.verdict === "confirmed"
                    ? "border-emerald-500/60 text-emerald-300 hover:border-emerald-400 hover:bg-emerald-500/10"
                    : "border-border-default text-text-muted hover:text-foreground hover:border-accent"
                }`}
              >
                {promoteMut.isPending ? "…" : "↗ Promote to finding"}
              </button>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

/** Map outcome kind severity to a hex color for inline icon tinting. */
function outcomeKindSeverityColor(kind: string): string {
  const sev = outcomeKindSeverity(kind);
  switch (sev) {
    case "critical": return "#f0a8c7";
    case "high":     return "#f0c97a";
    case "medium":   return "#af87d7";
    case "low":      return "#97dbbe";
    case "info":     return "#8ec5ff";
    default:         return "#9aa0a6";
  }
}
