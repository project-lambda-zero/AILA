import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { createPortal } from "react-dom";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";

import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";
import { Graph } from "@phosphor-icons/react/dist/csr/Graph";
import { GearSix } from "@phosphor-icons/react/dist/csr/GearSix";
import { ArrowCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowCounterClockwise";
import { PaperPlaneRight } from "@phosphor-icons/react/dist/csr/PaperPlaneRight";
import { Pause } from "@phosphor-icons/react/dist/csr/Pause";
import { Play } from "@phosphor-icons/react/dist/csr/Play";
import { ShieldCheck } from "@phosphor-icons/react/dist/csr/ShieldCheck";
import { ChatCircleText } from "@phosphor-icons/react/dist/csr/ChatCircleText";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { CaretUp } from "@phosphor-icons/react/dist/csr/CaretUp";
import { Lightning } from "@phosphor-icons/react/dist/csr/Lightning";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge, toneColor } from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { OutcomeKindBadge, outcomeKindSeverity, outcomeKindLabel } from "../components/OutcomeKindBadge";
import { OutcomePolarityBadge, outcomePolarity } from "../components/OutcomePolarityBadge";
import { DeleteButton } from "../components/DeleteButton";
import { ExportReportButton } from "../components/ExportReportButton";
import { ReenqueuePicker } from "../components/ReenqueuePicker";
import { LiveDot } from "../components/LiveDot";
import { SteeringDrawer } from "../components/SteeringDrawer";
import {
  VRNarrativeControls,
  type InvestigationNarrative,
} from "../components/VRNarrativeControls";
import { TurnCard } from "../components/TurnCard";
import { WorkflowStepper } from "../components/WorkflowStepper";
import { LiveRunPanel, LIVE_PANEL_STATUSES } from "../components/LiveRunPanel";
import { HypothesisDetailRail } from "../components/HypothesisDetailRail";
import { FuzzProposalsPanel } from "../components/FuzzProposalCard";
import { PanelBoundary } from "../components/PanelBoundary";
import { InvestigationLineagePanel } from "../components/InvestigationLineagePanel";
import { InvestigationConnectedCard } from "../components/InvestigationConnectedCard";
import { InvestigationActivityPanel } from "../components/InvestigationActivityPanel";
import { personaMeta } from "../components/personaMeta";
import { useInvestigationMessagesStream } from "../hooks/useInvestigationMessagesStream";
import { useVRKeyboardShortcuts } from "../hooks/useVRKeyboardShortcuts";
import {
  useCreateOutcomeReview,
  useDeleteInvestigation,
  usePauseInvestigation,
  useReenqueueInvestigation,
  useResetInvestigation,
  useReopenInvestigation,
  useResumeInvestigation,
  useReverifyInvestigation,
  usePromoteOutcomeToFinding,
  useSendOperatorMessage,
} from "../mutations";
import { formatBranchDisplayName } from "../branchDisplay";
import {
  isInvestigationLive,
  useInvestigation,
  useInvestigationBranches,
  useInvestigationMessages,
  useInvestigationOutcomes,
  useTargetName,
} from "../queries";
import type {
  InvestigationStatus,
  OperatorIntent,
  OutcomeDispatchStatus,
  OutcomeReviewVote,
  PersonaVoice,
  VRBranchSummary,
  VRMessageSummary,
  VROutcomeSummary,
} from "../types";

// ── Local const tables (mock tokens only) ───────────────────────────

const dispatchColor: Record<OutcomeDispatchStatus, string> = {
  pending: "info",
  claimed: "info",
  dispatched: "low",
  failed: "critical",
  skipped: "medium",
};

const STATUS_FALLBACK = { color: "var(--text-faint)", label: "unknown", pulse: false };
const STATUS_META: Record<string, { color: string; label: string; pulse: boolean }> = {
  created:   { color: "var(--text-faint)",   label: "created",   pulse: false },
  running:   { color: "var(--status-ok)",    label: "running",   pulse: true  },
  paused:    { color: "var(--status-warn)",  label: "paused",    pulse: false },
  completed: { color: "var(--status-info)",  label: "completed", pulse: false },
  failed:    { color: "var(--accent)",       label: "failed",    pulse: false },
  abandoned: { color: "var(--text-faint)",   label: "abandoned", pulse: false },
  stalled:   { color: "var(--text-faint)",   label: "stalled",   pulse: false },
};

const BRANCH_STATUS_FALLBACK = { color: "var(--text-faint)", label: "unknown" };
const BRANCH_STATUS_META: Record<string, { color: string; label: string }> = {
  active:    { color: "var(--status-ok)",   label: "active"    },
  paused:    { color: "var(--status-warn)", label: "paused"    },
  merged:    { color: "var(--status-info)", label: "merged"    },
  promoted:  { color: "var(--status-ok)",   label: "promoted"  },
  completed: { color: "var(--status-info)", label: "completed" },
  abandoned: { color: "var(--text-faint)",  label: "abandoned" },
};

const STATUS_TONE: Record<string, "accent" | "ok" | "info" | "warn" | "muted"> = {
  running: "ok",
  failed: "accent",
  paused: "warn",
  completed: "info",
};

const BRANCH_STATUS_TONE: Record<string, string> = {
  active: "ok",
  promoted: "ok",
  paused: "warn",
  merged: "info",
  completed: "info",
};

// ── Helpers ─────────────────────────────────────────────────────────

function humanize(s: string | null | undefined): string {
  if (!s) return "";
  const last = s.includes(".") ? s.split(".").pop()! : s;
  return last.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

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

// ── Mock-styled button primitives (inline) ──────────────────────────

const MONO_BTN_BASE: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
  height: 26,
  padding: "0 10px",
  fontSize: 10.5,
  fontFamily: "var(--font-mono)",
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  borderRadius: 3,
  cursor: "pointer",
  whiteSpace: "nowrap",
};

function monoBtnStyle(variant: "default" | "accent" | "danger" = "default"): CSSProperties {
  if (variant === "accent") {
    return {
      ...MONO_BTN_BASE,
      background: "var(--accent)",
      color: "var(--text-on-accent)",
      border: "1px solid var(--accent)",
    };
  }
  if (variant === "danger") {
    return {
      ...MONO_BTN_BASE,
      color: "var(--accent)",
      border: "1px solid color-mix(in srgb, var(--accent) 45%, transparent)",
    };
  }
  return MONO_BTN_BASE;
}

// ── PayloadPreview ──────────────────────────────────────────────────

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
    const shown = expanded || !truncated ? cleaned : cleaned.slice(0, 600) + "\u2026";
    return (
      <div
        style={{
          fontFamily: "var(--font-sans)",
          fontSize: 12.5,
          lineHeight: 1.55,
          color: "var(--text-primary)",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {shown}
        {truncated && (
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            className="font-mono uppercase"
            style={{
              display: "block",
              marginTop: 8,
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-muted)",
              background: "transparent",
              border: 0,
              textDecoration: "underline",
              cursor: "pointer",
              padding: 0,
            }}
          >
            {expanded ? "Collapse" : `Show full (${proseCandidate.length} chars)`}
          </button>
        )}
      </div>
    );
  }
  const json = JSON.stringify(payload, null, 2);
  const truncated = !fullByDefault && json.length > 320;
  const shown = expanded || !truncated ? json : json.slice(0, 320) + "\u2026";
  return (
    <div>
      <pre
        className="font-mono"
        style={{
          fontSize: 10.5,
          lineHeight: 1.5,
          color: "var(--text-muted)",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-faint)",
          borderRadius: 3,
          padding: "6px 8px",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          margin: 0,
        }}
      >
        {shown}
      </pre>
      {truncated && (
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="font-mono uppercase"
          style={{
            display: "block",
            marginTop: 6,
            fontSize: 9,
            letterSpacing: "0.14em",
            color: "var(--text-muted)",
            background: "transparent",
            border: 0,
            textDecoration: "underline",
            cursor: "pointer",
            padding: 0,
          }}
        >
          {expanded ? "Collapse" : `Show full (${json.length} chars)`}
        </button>
      )}
    </div>
  );
}

// ── CostProgressBar ─────────────────────────────────────────────────

function CostProgressBar({ actual, budget }: { actual: number; budget: number }) {
  if (budget <= 0) {
    return (
      <div
        style={{
          height: 5,
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderRadius: 2,
        }}
        aria-label="No budget set"
      />
    );
  }
  const pct = Math.max(0, Math.min(100, (actual / budget) * 100));
  const color = pct >= 80 ? "var(--accent)" : pct >= 50 ? "var(--status-warn)" : "var(--status-ok)";
  return (
    <div
      role="progressbar"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Cost ${fmtUsd(actual)} of ${fmtUsd(budget)} (${pct.toFixed(0)}%)`}
      style={{
        position: "relative",
        height: 5,
        background: "var(--surface-sunk)",
        border: "1px solid var(--border-soft)",
        borderRadius: 2,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          width: `${pct}%`,
          height: "100%",
          background: color,
          transition: "width 300ms ease-out",
        }}
      />
    </div>
  );
}

// ── StatusIndicator (exported for LiveRunPanel) ─────────────────────

export function StatusIndicator({
  status,
  pauseReason,
}: {
  status: InvestigationStatus;
  pauseReason?: string | null;
}) {
  const meta = STATUS_META[status] ?? STATUS_FALLBACK;
  return (
    <div className="flex items-center" style={{ gap: 10 }}>
      <span
        aria-hidden="true"
        style={{
          position: "relative",
          display: "inline-block",
          width: 10,
          height: 10,
          background: meta.color,
          boxShadow: `0 0 6px ${meta.color}`,
        }}
      >
        {meta.pulse && (
          <span
            style={{
              position: "absolute",
              inset: 0,
              background: meta.color,
              opacity: 0.35,
              animation: "aila-pulse 1.4s ease-in-out infinite",
            }}
            className="motion-reduce:hidden"
          />
        )}
      </span>
      <span
        style={{
          fontFamily: "var(--font-display)",
          fontSize: 16,
          fontWeight: 400,
          color: "var(--text-primary)",
          letterSpacing: "-0.01em",
          textTransform: "lowercase",
          lineHeight: 1,
        }}
      >
        {meta.label}
      </span>
      {pauseReason && (
        <span
          className="font-mono uppercase"
          style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-muted)" }}
        >
          {"\u00b7"} {humanize(pauseReason)}
        </span>
      )}
    </div>
  );
}

// ── PersonaAvatar (square logo tile per contract) ───────────────────

function PersonaAvatar({
  voice,
  size = 22,
}: {
  voice?: PersonaVoice | string | null;
  size?: number;
}) {
  const meta = personaMeta(voice ?? null);
  return (
    <span
      className="inline-flex items-center justify-center font-mono flex-shrink-0"
      style={{
        width: size,
        height: size,
        background: `color-mix(in srgb, ${meta.hue} 18%, transparent)`,
        border: `1px solid color-mix(in srgb, ${meta.hue} 40%, transparent)`,
        color: meta.hue,
        fontSize: Math.max(9, Math.round(size * 0.5)),
        borderRadius: 2,
        textTransform: "uppercase",
        letterSpacing: 0,
      }}
      title={meta.label}
      aria-label={meta.label}
    >
      {meta.initial}
    </span>
  );
}

// ── InvestigationDetailPage ─────────────────────────────────────────

export function InvestigationDetailPage() {
  const { investigationId } = useParams<{ investigationId: string }>();
  const invId = investigationId ?? "";
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: inv, isLoading } = useInvestigation(invId);
  const isLive = isInvestigationLive(inv?.status);
  const { data: branchesResult } = useInvestigationBranches(invId, { live: isLive });
  const { data: messagesResult } = useInvestigationMessages(invId);
  const { status: liveStatus } = useInvestigationMessagesStream(invId);
  const { data: outcomesResult } = useInvestigationOutcomes(invId, { live: isLive });
  const targetName = useTargetName(inv?.target_id);

  const pauseMut = usePauseInvestigation(invId);
  const resetMut = useResetInvestigation(invId);
  const reopenMut = useReopenInvestigation(invId);
  const resumeMut = useResumeInvestigation(invId);
  const reenqueueMut = useReenqueueInvestigation(invId);
  const sendMut = useSendOperatorMessage(invId);
  const deleteMut = useDeleteInvestigation();
  const reverifyMut = useReverifyInvestigation();
  const promoteMut = usePromoteOutcomeToFinding(invId);
  const reviewMut = useCreateOutcomeReview(invId);

  const [messageText, setMessageText] = useState("");
  const [messageIntent, setMessageIntent] = useState<OperatorIntent | "">("");
  const [steeringOpen, setSteeringOpen] = useState(false);
  const [liveTail, setLiveTail] = useState(true);

  useUpdatePageHeader({
    title: inv?.title,
    subtitle: inv ? `${inv.kind} \u00b7 target: ${targetName}` : undefined,
    status:
      inv?.status === "running"
        ? "live"
        : inv?.status === "paused"
          ? "paused"
          : inv?.status === "failed"
            ? "error"
            : "ready",
  });
  useVRKeyboardShortcuts({ onOpenSteering: () => setSteeringOpen(true) });

  // ── Default-land at latest turn ────────────────────────────────
  const initialScrolledRef = useRef(false);
  useEffect(() => {
    if (initialScrolledRef.current) return;
    const list = messagesResult?.data ?? [];
    if (list.length === 0) return;
    initialScrolledRef.current = true;
    let attempts = 0;
    const maxAttempts = 8;
    const tick = () => {
      window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "auto" });
      attempts++;
      const distFromBottom =
        document.documentElement.scrollHeight - window.scrollY - window.innerHeight;
      if (distFromBottom > 32 && attempts < maxAttempts) {
        requestAnimationFrame(tick);
      }
    };
    requestAnimationFrame(tick);
  }, [messagesResult?.data?.length]);

  // ── Live-tail auto-scroll ──────────────────────────────────────
  const lastSeenCount = useRef(0);
  useEffect(() => {
    if (!liveTail) return;
    const list = messagesResult?.data ?? [];
    if (list.length > lastSeenCount.current && lastSeenCount.current > 0) {
      const id = `turn-${list.length - 1}`;
      requestAnimationFrame(() => {
        const el = document.getElementById(id);
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "end" });
          el.classList.add("animate-amber-flash");
          window.setTimeout(() => el.classList.remove("animate-amber-flash"), 1200);
        }
      });
    }
    lastSeenCount.current = list.length;
  }, [liveTail, messagesResult?.data]);

  // ── Scroll-to-end UX ───────────────────────────────────────────
  const [scrollNearBottom, setScrollNearBottom] = useState(true);
  const [visibleTurn, setVisibleTurn] = useState<number | null>(null);
  const scrollNearBottomRef = useRef(true);
  const visibleTurnRef = useRef<number | null>(null);
  useEffect(() => {
    const onScroll = () => {
      const distFromBottom =
        document.documentElement.scrollHeight - window.scrollY - window.innerHeight;
      const nearBottom = distFromBottom < 240;
      if (nearBottom !== scrollNearBottomRef.current) {
        scrollNearBottomRef.current = nearBottom;
        setScrollNearBottom(nearBottom);
      }
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
    const raf = requestAnimationFrame(onScroll);
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, []);

  const jumpToLatest = () => {
    const cards = document.querySelectorAll<HTMLElement>('[id^="turn-"]');
    const last = cards[cards.length - 1];
    if (last) {
      last.scrollIntoView({ behavior: "smooth", block: "end" });
    } else {
      window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" });
    }
  };

  // All hooks before any early return.
  const branches = branchesResult?.data ?? [];
  const messages = messagesResult?.data ?? [];
  const outcomes = outcomesResult?.data ?? [];

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

  const operatorComposerOpen =
    inv.status === "running" || inv.status === "paused" || inv.status === "created";

  const sortedOutcomes = [...outcomes].sort((a, b) => {
    const aPrim = a.id === inv.primary_outcome_id ? -1 : 0;
    const bPrim = b.id === inv.primary_outcome_id ? -1 : 0;
    if (aPrim !== bPrim) return aPrim - bPrim;
    return (b.created_at ?? "").localeCompare(a.created_at ?? "");
  });
  const primaryOutcome = sortedOutcomes.find((o) => o.id === inv.primary_outcome_id) ?? null;
  const otherOutcomes = sortedOutcomes.filter((o) => o.id !== inv.primary_outcome_id);

  const activeBranches = branches.filter((b) => b.turn_count > 0);
  const queuedBranches = branches.filter((b) => b.turn_count === 0);

  // Mock-styled mono select
  const monoSelectStyle: CSSProperties = {
    height: 26,
    padding: "0 8px",
    fontFamily: "var(--font-mono)",
    fontSize: 10.5,
    letterSpacing: "0.06em",
    color: "var(--text-primary)",
    background: "var(--surface-sunk)",
    border: "1px solid var(--border-soft)",
    borderRadius: 3,
    minWidth: 0,
  };

  // Utility bar mono link style
  const utilityLinkStyle: CSSProperties = {
    ...MONO_BTN_BASE,
    textDecoration: "none",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>
      {/* ── Utility command bar ────────────────────────────────── */}
      <div
        className="flex items-center justify-between flex-wrap"
        style={{
          gap: 10,
          padding: "6px 10px",
          background: "var(--surface-chrome)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
        }}
      >
        <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
          <LiveDot status={liveStatus} />
          <span
            aria-hidden="true"
            style={{ width: 1, height: 16, background: "var(--border-soft)", margin: "0 2px" }}
          />
          <Link to={`/vr/investigations/${invId}/tree`} style={utilityLinkStyle}>
            <TreeStructure weight="regular" size={12} />
            Branch tree
          </Link>
          <Link to={`/vr/investigations/${invId}/graph`} style={utilityLinkStyle}>
            <Graph weight="regular" size={12} />
            Evidence graph
          </Link>
        </div>
        <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
          <button
            type="button"
            style={monoBtnStyle("accent")}
            onClick={() => setSteeringOpen(true)}
            data-testid="vr-open-steering"
            aria-label="Open steering drawer"
          >
            <GearSix weight="fill" size={12} />
            Steering
          </button>
          <ExportReportButton invId={invId} title={inv.title} />
          <span
            aria-hidden="true"
            style={{ width: 1, height: 16, background: "var(--border-soft)", margin: "0 2px" }}
          />
          <button
            type="button"
            style={monoBtnStyle("danger")}
            disabled={
              resetMut.isPending || inv.status === "running" || inv.status === "paused"
            }
            onClick={() => {
              const confirmed = window.confirm(
                `Reset "${inv.title}" to its initial state?\n\n` +
                  `Deletes ALL messages (${inv.message_count}) + ALL outcomes ` +
                  `(${inv.outcome_count}) + forked branches. Root branches reset ` +
                  `to turn 0 with empty case state. The workflow_state_cursor ` +
                  `archive is cleared so the next run starts from setup, not the ` +
                  `archived paused state. Investigation flips back to CREATED so ` +
                  `you can re-enqueue with a fresh history.\n\n` +
                  `THIS CANNOT BE UNDONE.`,
              );
              if (!confirmed) return;
              resetMut.mutate();
            }}
            title={
              inv.status === "running"
                ? "Pause the investigation first, then reset."
                : inv.status === "paused"
                  ? "Resume first, then reset -- pause-then-reset would lose the cursor archive."
                  : "Wipe history + reset to start. Re-enqueue afterwards to run again."
            }
            data-testid="vr-reset-investigation"
          >
            <ArrowCounterClockwise weight="regular" size={12} />
            {resetMut.isPending ? "Resetting\u2026" : "Reset"}
          </button>
          <DeleteButton
            id={invId}
            label={`investigation "${inv.title}"`}
            mutation={deleteMut}
            onDeleted={() => navigate("/vr/investigations")}
          />
        </div>
      </div>

      {/* ── Two-column workbench ────────────────────────────────── */}
      <div
        className="grid items-start"
        style={{
          gridTemplateColumns: "minmax(0, 1fr) 320px",
          gap: 12,
        }}
      >
        {/* LEFT column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>
          {LIVE_PANEL_STATUSES[inv.status] === true && (
            <PanelBoundary
              label="Live run"
              invalidateKeyPrefix={["vr", "investigation-messages", inv.id]}
            >
              <LiveRunPanel
                investigation={inv}
                messages={messages}
                branches={branches}
                liveStatus={liveStatus}
              />
            </PanelBoundary>
          )}

          {/* Run state ─────────────────────────────────────────── */}
          <WindowPanel title="run state" tone="muted">
            <h2 className="sr-only">Run state</h2>
            <WorkflowStepper
              flow="investigate"
              currentState={
                inv.status === "paused"
                  ? null
                  : inv.status === "running"
                    ? "investigation_loop"
                    : inv.status === "completed"
                      ? "investigation_emit"
                      : inv.status === "failed"
                        ? "investigation_loop"
                        : "investigation_setup"
              }
              failedAt={inv.status === "failed" ? "investigation_loop" : null}
            />

            <div
              className="flex items-start justify-between flex-wrap"
              style={{
                marginTop: 12,
                paddingTop: 12,
                borderTop: "1px solid var(--border-soft)",
                gap: 12,
              }}
            >
              <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
                <StatusIndicator status={inv.status} pauseReason={inv.pause_reason} />
                {inv.status === "failed" && inv.failure_reason && (
                  <p
                    className="font-mono"
                    style={{ fontSize: 10.5, color: "var(--accent)" }}
                  >
                    {inv.failure_reason}
                  </p>
                )}
                <p
                  className="font-mono uppercase"
                  style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-muted)" }}
                >
                  {humanize(inv.strategy_family)} strategy
                </p>
              </div>
              <div className="flex items-center flex-wrap" style={{ gap: 6, minWidth: 0 }}>
                {inv.status === "running" && (
                  <button
                    type="button"
                    style={monoBtnStyle("default")}
                    onClick={() => pauseMut.mutate()}
                    disabled={pauseMut.isPending}
                    data-testid="vr-pause-investigation"
                  >
                    <Pause weight="fill" size={12} />
                    {pauseMut.isPending ? "Pausing\u2026" : "Pause"}
                  </button>
                )}
                {(inv.status === "paused" || resumeMut.isResuming) && (
                  <button
                    type="button"
                    style={monoBtnStyle("accent")}
                    onClick={() => resumeMut.mutate()}
                    disabled={resumeMut.isResuming}
                    data-testid="vr-resume-investigation"
                  >
                    <Play weight="fill" size={12} />
                    {resumeMut.isResuming ? "Resuming\u2026" : "Resume"}
                  </button>
                )}
                {inv.status === "created" && (
                  <button
                    type="button"
                    style={monoBtnStyle("accent")}
                    onClick={() => reenqueueMut.mutate(undefined)}
                    disabled={reenqueueMut.isPending}
                    title="Start this investigation (enqueue run_vr_investigate task)"
                    data-testid="vr-start-investigation"
                  >
                    <Play weight="fill" size={12} />
                    {reenqueueMut.isPending ? "Starting\u2026" : "Start"}
                  </button>
                )}
                {(inv.status === "completed" ||
                  inv.status === "failed" ||
                  inv.status === "stalled") && (
                  <ReenqueuePicker currentKind={inv.kind} mutation={reenqueueMut} />
                )}
                {(inv.status === "completed" ||
                  inv.status === "failed" ||
                  inv.status === "abandoned") && (
                  <button
                    type="button"
                    style={monoBtnStyle("accent")}
                    onClick={() => reopenMut.mutate()}
                    disabled={reopenMut.isPending}
                    title={
                      "Push this terminal investigation back into the workflow. " +
                      "Spawns a fresh primary branch on top of the existing history."
                    }
                    data-testid="vr-reopen-investigation"
                  >
                    <Play weight="fill" size={12} />
                    {reopenMut.isPending ? "Reopening\u2026" : "Reopen"}
                  </button>
                )}
              </div>
            </div>

            {/* Compact stats strip ─ pipe-separated mono cells */}
            <div
              className="flex items-center flex-wrap font-mono"
              style={{
                marginTop: 12,
                paddingTop: 12,
                borderTop: "1px solid var(--border-soft)",
                fontSize: 10.5,
                color: "var(--text-muted)",
              }}
            >
              {[
                { k: "turns", v: inv.message_count.toLocaleString() },
                { k: "branches", v: String(inv.branch_count) },
                {
                  k: "tokens",
                  v: `~${((inv.message_count * 28000) / 1_000_000).toFixed(1)}M`,
                },
                { k: "outcomes", v: String(inv.outcome_count) },
              ].map((r, i, arr) => (
                <span
                  key={r.k}
                  className="inline-flex items-baseline"
                  style={{
                    gap: 6,
                    padding: "0 12px",
                    borderRight: i < arr.length - 1 ? "1px solid var(--border-faint)" : undefined,
                  }}
                >
                  <span
                    className="uppercase"
                    style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
                  >
                    {r.k}
                  </span>
                  <span
                    className="tabular-nums"
                    style={{ color: "var(--text-primary)" }}
                  >
                    {r.v}
                  </span>
                </span>
              ))}
            </div>
          </WindowPanel>

          {/* Outcomes ──────────────────────────────────────────── */}
          {outcomes.length > 0 && (
            <WindowPanel
              title="outcomes"
              tone="accent"
              actions={
                <span
                  className="font-mono tabular-nums"
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  {outcomes.length}
                </span>
              }
            >
              <h2 className="sr-only">Outcomes</h2>
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {primaryOutcome && (
                  <PrimaryOutcomeCard
                    outcome={primaryOutcome}
                    persona={
                      branches.find((b) => b.id === primaryOutcome.branch_id)?.persona_voice ?? null
                    }
                    invId={invId}
                    branches={branches}
                    reverifyMut={reverifyMut}
                    promoteMut={promoteMut}
                    reviewMut={reviewMut}
                  />
                )}
                {primaryOutcome && (
                  <VRNarrativeControls
                    investigationId={invId}
                    narrative={readNarrative(primaryOutcome.payload)}
                  />
                )}
                {otherOutcomes.length > 0 && (
                  <ul style={{ display: "flex", flexDirection: "column", gap: 6, listStyle: "none", padding: 0, margin: 0 }}>
                    {otherOutcomes.map((o) => {
                      const oPers =
                        branches.find((b) => b.id === o.branch_id)?.persona_voice ?? null;
                      return (
                        <CompactOutcomeRow
                          key={o.id}
                          outcome={o}
                          persona={oPers}
                          invId={invId}
                          branches={branches}
                          reverifyMut={reverifyMut}
                          promoteMut={promoteMut}
                          reviewMut={reviewMut}
                        />
                      );
                    })}
                  </ul>
                )}
              </div>
            </WindowPanel>
          )}

          {/* Lineage ───────────────────────────────────────────── */}
          <PanelBoundary label="Lineage" invalidateKeyPrefix={["vr", "investigations"]}>
            <InvestigationLineagePanel investigation={inv} />
          </PanelBoundary>

          {/* Filter bar ────────────────────────────────────────── */}
          <WindowPanel
            title="filters"
            tone="muted"
            flush
            actions={
              <span
                className="font-mono tabular-nums"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {filtered.length} / {messages.length}
              </span>
            }
          >
            <div
              className="flex items-center flex-wrap"
              style={{ gap: 8, padding: "10px 12px" }}
            >
              <select
                value={senderFilter}
                onChange={(e) => updateParam("sender", e.target.value)}
                style={monoSelectStyle}
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
                style={monoSelectStyle}
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
                  style={monoSelectStyle}
                  aria-label="Filter by branch"
                >
                  <option value="">all branches</option>
                  {branches.map((b) => (
                    <option key={b.id} value={b.id}>
                      {formatBranchDisplayName(b)}
                      {b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}
                    </option>
                  ))}
                </select>
              )}
              <button
                type="button"
                onClick={() => setLiveTail((v) => !v)}
                className="font-mono uppercase"
                style={{
                  height: 26,
                  padding: "0 10px",
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  borderRadius: 3,
                  cursor: "pointer",
                  color: liveTail ? "var(--status-ok)" : "var(--text-faint)",
                  border: `1px solid ${liveTail ? "var(--status-ok)" : "var(--border-soft)"}`,
                  background: liveTail
                    ? "color-mix(in srgb, var(--status-ok) 11%, transparent)"
                    : "transparent",
                }}
                aria-pressed={liveTail}
                data-testid="vr-live-tail-toggle"
                title={
                  liveTail
                    ? "Auto-scroll new turns into view"
                    : "Frozen -- won't auto-scroll"
                }
              >
                Live tail
              </button>
              <span style={{ flex: 1 }} />
              {visibleTurn != null && (
                <span
                  className="font-mono uppercase tabular-nums"
                  style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
                >
                  at #{visibleTurn + 1}
                </span>
              )}
              <span
                className="font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
              >
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
                      if (el)
                        el.scrollIntoView({ behavior: "smooth", block: "center" });
                    }
                  }
                }}
                style={{ ...monoSelectStyle, width: 60 }}
                aria-label="Jump to turn number"
              />
            </div>
          </WindowPanel>

          {/* Turn stream ───────────────────────────────────────── */}
          <WindowPanel
            title="turns"
            tone="muted"
            flush
            actions={
              <span
                className="font-mono tabular-nums"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {filtered.length}
              </span>
            }
          >
            {filtered.length === 0 ? (
              <div
                className="font-mono"
                style={{
                  padding: 34,
                  textAlign: "center",
                  fontSize: 12,
                  color: "var(--text-muted)",
                }}
              >
                {messages.length === 0
                  ? "no turns yet \u00b7 engine hasn't started reasoning."
                  : "filters hide every turn. clear filters to see them."}
              </div>
            ) : (
              <div
                className="scroll-virtual"
                style={{ display: "flex", flexDirection: "column", gap: 6, padding: 8 }}
              >
                {filtered.map((m, i) => (
                  <TurnCard
                    key={m.id}
                    message={m}
                    index={i}
                    persona={branchPersonaMap.get(m.branch_id) ?? null}
                  />
                ))}
              </div>
            )}
          </WindowPanel>

          {/* Operator composer ─────────────────────────────────── */}
          {operatorComposerOpen && (
            <WindowPanel title="steering" tone="accent">
              <h2 className="sr-only">Operator Input</h2>
              <p
                className="font-mono"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                  marginBottom: 10,
                  lineHeight: 1.55,
                }}
              >
                Engine sees this verbatim on its next turn. Pick an intent below
                or let it auto-classify.
              </p>
              <div
                className="flex items-center flex-wrap"
                style={{ gap: 6, marginBottom: 10 }}
              >
                {OPERATOR_INTENTS.map((it) => {
                  const active = messageIntent === it.value;
                  const color = "var(--accent)";
                  return (
                    <button
                      key={it.value || "auto"}
                      type="button"
                      onClick={() => setMessageIntent(it.value)}
                      className="font-mono uppercase"
                      style={{
                        height: 26,
                        padding: "0 10px",
                        fontSize: 9.5,
                        letterSpacing: "0.08em",
                        borderRadius: 3,
                        cursor: "pointer",
                        color: active ? color : "var(--text-faint)",
                        border: `1px solid ${active ? color : "var(--border-soft)"}`,
                        background: active
                          ? "color-mix(in srgb, var(--accent) 11%, transparent)"
                          : "transparent",
                      }}
                      aria-pressed={active}
                    >
                      {it.label}
                    </button>
                  );
                })}
              </div>
              <textarea
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                onKeyDown={(e) => {
                  if (
                    (e.metaKey || e.ctrlKey) &&
                    e.key === "Enter" &&
                    messageText.trim()
                  ) {
                    e.preventDefault();
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
                  }
                }}
                placeholder="e.g. 'try the JSPI base address path' or 'that hypothesis is wrong because\u2026'  (Ctrl/Cmd+Enter to send)"
                rows={3}
                aria-label="Operator message composer"
                className="font-mono"
                style={{
                  width: "100%",
                  padding: "8px 10px",
                  fontSize: 11,
                  lineHeight: 1.5,
                  color: "var(--text-primary)",
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  resize: "vertical",
                }}
              />
              <div
                className="flex items-center justify-end"
                style={{ gap: 8, marginTop: 10 }}
              >
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
                  style={{
                    ...monoBtnStyle("accent"),
                    opacity: !messageText.trim() || sendMut.isPending ? 0.4 : 1,
                    cursor:
                      !messageText.trim() || sendMut.isPending
                        ? "not-allowed"
                        : "pointer",
                  }}
                  aria-label="Send operator message"
                  data-testid="vr-send-operator-message"
                >
                  <PaperPlaneRight weight="fill" size={12} />
                  {sendMut.isPending ? "Sending\u2026" : "Send"}
                </button>
              </div>
            </WindowPanel>
          )}
        </div>

        {/* RIGHT rail ─────────────────────────────────────────── */}
        <aside style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>
          {/* Engine vitals */}
          <WindowPanel
            title="engine ; vitals"
            tone={STATUS_TONE[inv.status] ?? "muted"}
            status={`${humanize(inv.strategy_family)} strategy`}
          >
            <h3 className="sr-only">Engine vitals</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <StatusIndicator status={inv.status} pauseReason={inv.pause_reason} />
              {(inv.cost_actual_usd > 0 || inv.cost_budget_usd > 0) && (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <div
                    className="flex items-baseline justify-between"
                    style={{ gap: 8 }}
                  >
                    <span
                      className="font-mono tabular-nums"
                      style={{
                        fontSize: 30,
                        letterSpacing: "-0.02em",
                        color: "var(--accent)",
                        lineHeight: 1,
                      }}
                    >
                      {fmtUsd(inv.cost_actual_usd)}
                    </span>
                    {inv.cost_budget_usd > 0 && (
                      <span
                        className="font-mono"
                        style={{
                          fontSize: 10,
                          color: "var(--text-faint)",
                          whiteSpace: "nowrap",
                        }}
                      >
                        / {fmtUsd(inv.cost_budget_usd)}
                      </span>
                    )}
                  </div>
                  <CostProgressBar
                    actual={inv.cost_actual_usd}
                    budget={inv.cost_budget_usd}
                  />
                </div>
              )}
              <div style={{ display: "flex", flexDirection: "column" }}>
                {[
                  { k: "turns", v: inv.message_count.toLocaleString() },
                  { k: "branches", v: String(inv.branch_count) },
                  { k: "outcomes", v: String(inv.outcome_count) },
                  { k: "llm cost", v: fmtUsd(inv.llm_tokens_cost_usd) },
                  { k: "mcp cost", v: fmtUsd(inv.mcp_calls_cost_usd) },
                  { k: "fuzz cost", v: fmtUsd(inv.fuzz_infra_cost_usd) },
                  { k: "strategy", v: humanize(inv.strategy_family) },
                ].map((r) => (
                  <div
                    key={r.k}
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 2,
                      padding: "6px 0",
                      borderBottom: "1px solid var(--border-faint)",
                    }}
                  >
                    <span
                      className="font-mono uppercase"
                      style={{
                        fontSize: 9,
                        letterSpacing: "0.14em",
                        color: "var(--text-faint)",
                      }}
                    >
                      {r.k}
                    </span>
                    <span
                      className="font-mono tabular-nums"
                      style={{ fontSize: 10.5, color: "var(--text-primary)" }}
                    >
                      {r.v}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </WindowPanel>

          <HypothesisDetailRail investigationId={invId} live={isLive} />

          <WindowPanel title="activity" tone="muted">
            <PanelBoundary
              label="Activity"
              invalidateKeyPrefix={["vr", "investigation-audit", invId]}
            >
              <InvestigationActivityPanel investigationId={invId} />
            </PanelBoundary>
          </WindowPanel>

          <FuzzProposalsPanel investigationId={invId} live={isLive} />

          <InvestigationConnectedCard investigation={inv} />

          {/* Branches */}
          <WindowPanel
            title="branches"
            tone="info"
            actions={
              <span
                className="font-mono tabular-nums"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {branches.length}
              </span>
            }
          >
            <h3 className="sr-only">Branches</h3>
            {activeBranches.length === 0 && queuedBranches.length === 0 ? (
              <p
                className="font-mono"
                style={{ fontSize: 11, color: "var(--text-muted)" }}
              >
                no forks yet.
              </p>
            ) : (
              <>
                <ul
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 6,
                    listStyle: "none",
                    padding: 0,
                    margin: 0,
                  }}
                >
                  {activeBranches.map((b) => {
                    const sm = BRANCH_STATUS_META[b.status] ?? BRANCH_STATUS_FALLBACK;
                    return (
                      <li
                        key={b.id}
                        className="flex items-center"
                        style={{
                          gap: 10,
                          padding: "6px 8px",
                          background: "var(--surface-sunk)",
                          border: "1px solid var(--border-soft)",
                          borderLeft: `3px solid ${sm.color}`,
                          borderRadius: 3,
                          minWidth: 0,
                        }}
                      >
                        <PersonaAvatar voice={b.persona_voice} size={22} />
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <div className="flex items-center flex-wrap" style={{ gap: 6 }}>
                            <span
                              className="font-mono"
                              style={{
                                fontSize: 11,
                                color: "var(--text-primary)",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {formatBranchDisplayName(b)}
                            </span>
                            <MonoBadge tone={BRANCH_STATUS_TONE[b.status] ?? "muted"}>
                              {sm.label}
                            </MonoBadge>
                            {b.promoted && <MonoBadge tone="ok">promoted</MonoBadge>}
                          </div>
                          <div
                            className="font-mono"
                            style={{
                              marginTop: 2,
                              fontSize: 9.5,
                              letterSpacing: "0.06em",
                              color: "var(--text-faint)",
                            }}
                          >
                            {b.turn_count}t {"\u00b7"} {fmtUsd(b.branch_cost_usd)}
                            {b.fork_at_turn != null && ` \u00b7 fork@t${b.fork_at_turn}`}
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ul>
                {queuedBranches.length > 0 && (
                  <div
                    className="flex items-center font-mono"
                    style={{
                      marginTop: 8,
                      gap: 6,
                      fontSize: 9.5,
                      letterSpacing: "0.06em",
                      color: "var(--text-faint)",
                    }}
                  >
                    <span
                      aria-hidden="true"
                      style={{
                        display: "inline-block",
                        width: 6,
                        height: 6,
                        background: "var(--text-faint)",
                      }}
                    />
                    {queuedBranches.length} branch
                    {queuedBranches.length === 1 ? "" : "es"} queued
                    <span style={{ color: "var(--text-muted)" }}>
                      ({queuedBranches.map((b) => formatBranchDisplayName(b)).join(", ")})
                    </span>
                  </div>
                )}
              </>
            )}
          </WindowPanel>
        </aside>
      </div>

      {/* ── Footer keybind strip ────────────────────────────────── */}
      <div
        className="flex items-center font-mono uppercase"
        style={{
          height: "var(--statusbar-h)",
          padding: "0 12px",
          borderTop: "1px solid var(--border-soft)",
          background: "var(--surface-chrome)",
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
          gap: 12,
        }}
        aria-hidden="true"
      >
        <span>1-5 layout</span>
        <span>{"\u00b7"}</span>
        <span>hjkl focus</span>
        <span>{"\u00b7"}</span>
        <span>f zoom</span>
        <span>{"\u00b7"}</span>
        <span>/ find</span>
        <span>{"\u00b7"}</span>
        <span>p pause</span>
        <span>{"\u00b7"}</span>
        <span>? keys</span>
      </div>

      <SteeringDrawer
        open={steeringOpen}
        onClose={() => setSteeringOpen(false)}
        investigationId={invId}
        status={inv.status}
      />

      {/* Floating jump-to-latest + scroll buttons */}
      {messages.length > 1 &&
        createPortal(
          <>
            {!scrollNearBottom && (
              <div className="fixed top-20 right-6" style={{ zIndex: 60 }}>
                <button
                  type="button"
                  onClick={jumpToLatest}
                  style={monoBtnStyle("accent")}
                  title="Jump to latest turn"
                >
                  <Lightning weight="fill" size={11} />
                  Jump to latest
                  {visibleTurn != null && (
                    <span
                      className="tabular-nums"
                      style={{ fontSize: 9, opacity: 0.8, marginLeft: 4 }}
                    >
                      #{visibleTurn + 1} / {messages.length}
                    </span>
                  )}
                </button>
              </div>
            )}
            <div
              className="fixed bottom-6 right-6"
              style={{
                zIndex: 60,
                display: "flex",
                flexDirection: "column",
                gap: 6,
              }}
            >
              <button
                type="button"
                onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
                style={{
                  width: 26,
                  height: 26,
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "var(--text-primary)",
                  background: "var(--surface-card)",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  cursor: "pointer",
                }}
                aria-label="Scroll to top"
                title="Scroll to top"
              >
                <CaretUp weight="bold" size={14} />
              </button>
              <button
                type="button"
                onClick={() =>
                  window.scrollTo({
                    top: document.documentElement.scrollHeight,
                    behavior: "smooth",
                  })
                }
                style={{
                  width: 26,
                  height: 26,
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "var(--text-primary)",
                  background: "var(--surface-card)",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  cursor: "pointer",
                }}
                aria-label="Scroll to bottom"
                title="Scroll to bottom"
              >
                <CaretDown weight="bold" size={14} />
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
  outcome: VROutcomeSummary;
  persona: PersonaVoice | string | null;
  invId: string;
  branches: VRBranchSummary[];
  reverifyMut: ReturnType<typeof useReverifyInvestigation>;
  promoteMut: ReturnType<typeof usePromoteOutcomeToFinding>;
  reviewMut: ReturnType<typeof useCreateOutcomeReview>;
};

const REVIEW_VOTES: readonly OutcomeReviewVote[] = [
  "approve",
  "reject",
  "request_edit",
  "abstain",
  "not_ready",
];

function SiblingReviewForm({
  outcomeId,
  outcomeBranchId,
  branches,
  reviewMut,
}: {
  outcomeId: string;
  outcomeBranchId: string | null | undefined;
  branches: VRBranchSummary[];
  reviewMut: ReturnType<typeof useCreateOutcomeReview>;
}) {
  const defaultBranch =
    branches.find((b) => b.id !== outcomeBranchId)?.id ??
    branches[0]?.id ??
    "";
  const [reviewerBranchId, setReviewerBranchId] = useState<string>(defaultBranch);
  const [vote, setVote] = useState<OutcomeReviewVote>("approve");
  const [comment, setComment] = useState("");
  const [open, setOpen] = useState(false);

  if (branches.length === 0) return null;

  const monoSelect: CSSProperties = {
    height: 24,
    padding: "0 6px",
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-primary)",
    background: "var(--surface-sunk)",
    border: "1px solid var(--border-soft)",
    borderRadius: 2,
  };
  const labelStyle: CSSProperties = {
    display: "block",
    fontSize: 9,
    letterSpacing: "0.14em",
    color: "var(--text-faint)",
    marginBottom: 3,
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
        style={monoBtnStyle("default")}
        title="Cast a sibling review \u2014 approve quorum flips this outcome to APPROVED and fires the dispatcher."
      >
        <ChatCircleText weight="regular" size={11} />
        Review
      </button>
    );
  }

  const disabled = reviewMut.isPending || reviewerBranchId === "" || vote === undefined;

  return (
    <form
      style={{
        width: "100%",
        marginTop: 8,
        padding: 8,
        background: "var(--surface-sunk)",
        border: "1px solid var(--border-soft)",
        borderRadius: 3,
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        if (disabled) return;
        reviewMut.mutate(
          {
            outcomeId,
            body: {
              reviewer_branch_id: reviewerBranchId,
              vote,
              comment: comment.trim(),
            },
          },
          {
            onSuccess: () => {
              setComment("");
              setOpen(false);
            },
          },
        );
      }}
    >
      <div className="flex flex-wrap" style={{ gap: 10 }}>
        <label>
          <span className="font-mono uppercase" style={labelStyle}>
            Reviewer branch
          </span>
          <select
            value={reviewerBranchId}
            onChange={(e) => setReviewerBranchId(e.target.value)}
            onClick={(e) => e.stopPropagation()}
            style={monoSelect}
          >
            {branches.map((b) => (
              <option key={b.id} value={b.id}>
                {formatBranchDisplayName(b)}
                {b.id === outcomeBranchId ? " (self)" : ""}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="font-mono uppercase" style={labelStyle}>
            Vote
          </span>
          <select
            value={vote}
            onChange={(e) => setVote(e.target.value as OutcomeReviewVote)}
            onClick={(e) => e.stopPropagation()}
            style={monoSelect}
          >
            {REVIEW_VOTES.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
      </div>
      <textarea
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        onClick={(e) => e.stopPropagation()}
        placeholder="Comment (optional). For not_ready, state the blocker."
        rows={2}
        maxLength={4096}
        className="font-mono"
        style={{
          width: "100%",
          padding: 6,
          fontSize: 10.5,
          color: "var(--text-primary)",
          background: "var(--surface-card)",
          border: "1px solid var(--border-soft)",
          borderRadius: 2,
          resize: "vertical",
        }}
      />
      <div className="flex justify-end" style={{ gap: 6 }}>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setOpen(false);
          }}
          style={monoBtnStyle("default")}
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={disabled}
          style={{
            ...monoBtnStyle("accent"),
            opacity: disabled ? 0.5 : 1,
            cursor: disabled ? "not-allowed" : "pointer",
          }}
        >
          {reviewMut.isPending ? "\u2026" : "Submit review"}
        </button>
      </div>
    </form>
  );
}

function readVerifier(payload: Record<string, unknown> | undefined) {
  return (
    (payload?.verifier_report as
      | { verdict?: string; confidence?: number; summary?: string; counter_evidence?: string }
      | undefined) ?? undefined
  );
}

function readNarrative(
  payload: Record<string, unknown> | undefined,
): InvestigationNarrative | null {
  const n = payload?.investigation_narrative as
    | {
        title?: string;
        body?: string;
        chapter_outline?: string[];
        tone_used?: string;
        generated_at?: string;
        narrative_words?: number;
      }
    | undefined;
  if (!n || typeof n.body !== "string" || !n.body.trim()) return null;
  return {
    title: n.title ?? "(untitled writeup)",
    body: n.body,
    chapter_outline: Array.isArray(n.chapter_outline) ? n.chapter_outline : [],
    tone_used: n.tone_used ?? "blog",
    generated_at: n.generated_at ?? "",
    narrative_words: typeof n.narrative_words === "number" ? n.narrative_words : 0,
  };
}

function VerifierBanner({ vr }: { vr: ReturnType<typeof readVerifier> }) {
  if (!vr?.verdict) return null;
  const isConfirmed = vr.verdict === "confirmed";
  const isRefuted = vr.verdict === "refuted";
  const color = isConfirmed
    ? "var(--status-ok)"
    : isRefuted
      ? "var(--accent)"
      : "var(--status-warn)";
  const conf =
    typeof vr.confidence === "number" ? ` (${vr.confidence.toFixed(2)})` : "";
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        padding: "8px 10px",
        borderLeft: `2px solid ${color}`,
        border: "1px solid var(--border-soft)",
        borderLeftWidth: 2,
        borderLeftColor: color,
        background: `color-mix(in srgb, ${color} 8%, transparent)`,
        borderRadius: 3,
      }}
    >
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.14em",
            color,
          }}
        >
          Verifier: {vr.verdict}
          {conf}
        </div>
        {(vr.summary || vr.counter_evidence) && (
          <div
            style={{
              marginTop: 4,
              fontFamily: "var(--font-sans)",
              fontSize: 12,
              lineHeight: 1.55,
              color: "var(--text-primary)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
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
  branches,
  reverifyMut,
  promoteMut,
  reviewMut,
}: OutcomeRowProps) {
  const vr = readVerifier(o.payload);
  const persMeta = personaMeta(persona);
  const verdictColor = vr?.verdict === "confirmed"
    ? "var(--status-ok)"
    : vr?.verdict === "refuted"
      ? "var(--accent)"
      : vr?.verdict
        ? "var(--status-warn)"
        : "var(--accent)";
  return (
    <div
      style={{
        position: "relative",
        padding: 12,
        background: "var(--surface-sunk)",
        border: `1px solid ${verdictColor}`,
        borderLeftWidth: 2,
        borderRadius: 3,
        overflow: "hidden",
      }}
    >
      {/* Header row */}
      <div
        className="flex items-center flex-wrap"
        style={{ gap: 8, marginBottom: 10 }}
      >
        <PersonaAvatar voice={persona} size={22} />
        <span
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.14em",
            color: "var(--accent)",
          }}
        >
          Primary {"\u00b7"} Synthesis
        </span>
        <span
          className="inline-flex items-center"
          style={{ gap: 6 }}
        >
          <OutcomeKindBadge kind={o.outcome_kind} showLabel={false} />
          <MonoBadge tone={outcomeKindSeverity(o.outcome_kind)}>
            {outcomeKindLabel(o.outcome_kind)}
          </MonoBadge>
        </span>
        <OutcomePolarityBadge polarity={outcomePolarity(o.outcome_kind, o.payload)} />
        <MonoBadge tone={dispatchColor[o.dispatch_status] ?? "info"}>
          {humanize(o.dispatch_status)}
        </MonoBadge>
        {persona && (
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)" }}
          >
            {persMeta.label}
          </span>
        )}
        <MonoBadge tone="info">{humanConfidence(o.confidence)} confidence</MonoBadge>
        <span style={{ flex: 1 }} />
        <span
          className="font-mono"
          style={{ fontSize: 9, color: "var(--text-faint)" }}
        >
          {o.created_at ? o.created_at.replace("T", " ").slice(0, 19) : ""}
        </span>
      </div>

      {vr?.verdict && (
        <div style={{ marginBottom: 10 }}>
          <VerifierBanner vr={vr} />
        </div>
      )}

      <div style={{ marginBottom: 10 }}>
        <PayloadPreview payload={o.payload} fullByDefault defaultExpanded />
      </div>

      <div
        className="flex items-center flex-wrap"
        style={{
          gap: 6,
          paddingTop: 10,
          borderTop: "1px solid var(--border-soft)",
        }}
      >
        <button
          type="button"
          disabled={reverifyMut.isPending}
          onClick={(e) => {
            e.stopPropagation();
            reverifyMut.mutate(invId);
          }}
          style={{
            ...monoBtnStyle("default"),
            opacity: reverifyMut.isPending ? 0.5 : 1,
          }}
          title={
            vr?.verdict
              ? "Clear current verifier_report and re-run the verifier on this finding"
              : "Manually trigger the claim verifier on this finding"
          }
        >
          <ShieldCheck weight="regular" size={11} />
          {reverifyMut.isPending
            ? "\u2026"
            : vr?.verdict
              ? "Re-verify"
              : "Verify"}
        </button>
        <SiblingReviewForm
          outcomeId={o.id}
          outcomeBranchId={o.branch_id}
          branches={branches}
          reviewMut={reviewMut}
        />
        {o.outcome_kind === "assessment_report" && o.dispatch_status === "skipped" && (
          <button
            type="button"
            disabled={promoteMut.isPending}
            onClick={(e) => {
              e.stopPropagation();
              const verdict = vr?.verdict;
              const conf =
                typeof vr?.confidence === "number" ? vr.confidence.toFixed(2) : "?";
              const note =
                verdict === "confirmed"
                  ? `operator promote -- verifier confirmed conf=${conf}`
                  : verdict
                    ? `operator promote -- verifier ${verdict} conf=${conf}`
                    : "operator promote -- no verifier verdict";
              promoteMut.mutate({ outcomeId: o.id, reason: note });
            }}
            style={{
              ...monoBtnStyle(vr?.verdict === "confirmed" ? "accent" : "default"),
              opacity: promoteMut.isPending ? 0.5 : 1,
            }}
            title={
              vr?.verdict === "confirmed"
                ? "Verifier CONFIRMED this assessment \u2014 promote to direct_finding."
                : vr?.verdict === "refuted"
                  ? "Verifier REFUTED \u2014 promoting still creates a finding row but PoC writer skips."
                  : "Promote this assessment_report to direct_finding."
            }
          >
            {promoteMut.isPending ? (
              "\u2026"
            ) : (
              <>
                <PixelIcon name="emit" size={11} />
                Promote to finding
              </>
            )}
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
  branches,
  reverifyMut,
  promoteMut,
  reviewMut,
}: OutcomeRowProps) {
  const [expanded, setExpanded] = useState(false);
  const vr = readVerifier(o.payload);
  const persMeta = personaMeta(persona);
  const verdictStripe =
    vr?.verdict === "confirmed"
      ? "var(--status-ok)"
      : vr?.verdict === "refuted"
        ? "var(--accent)"
        : vr?.verdict
          ? "var(--status-warn)"
          : "var(--border-soft)";
  return (
    <li
      style={{
        background: "var(--surface-card)",
        border: "1px solid var(--border-soft)",
        borderLeft: `3px solid ${verdictStripe}`,
        borderRadius: 3,
        overflow: "hidden",
      }}
    >
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center"
        style={{
          width: "100%",
          gap: 8,
          padding: "6px 10px",
          background: "transparent",
          border: 0,
          textAlign: "left",
          cursor: "pointer",
          color: "var(--text-primary)",
          minWidth: 0,
        }}
      >
        <PersonaAvatar voice={persona} size={22} />
        <span
          className="inline-flex items-center"
          style={{
            color: `color-mix(in srgb, var(--text-primary) 80%, ${outcomeKindSeverityColor(o.outcome_kind)})`,
          }}
        >
          <OutcomeKindBadge kind={o.outcome_kind} showLabel={false} />
        </span>
        <span
          className="font-mono"
          style={{
            flex: 1,
            fontSize: 11,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            minWidth: 0,
          }}
        >
          {outcomeKindLabel(o.outcome_kind)}
        </span>
        <OutcomePolarityBadge polarity={outcomePolarity(o.outcome_kind, o.payload)} />
        <span
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.14em",
            color: "var(--text-faint)",
          }}
        >
          {humanConfidence(o.confidence)}
        </span>
        {vr?.verdict && (
          <MonoBadge
            tone={
              vr.verdict === "confirmed"
                ? "ok"
                : vr.verdict === "refuted"
                  ? "critical"
                  : "warn"
            }
          >
            {vr.verdict}
          </MonoBadge>
        )}
        <MonoBadge tone={dispatchColor[o.dispatch_status] ?? "info"}>
          {humanize(o.dispatch_status)}
        </MonoBadge>
      </button>
      {expanded && (
        <div
          style={{
            padding: "8px 10px",
            borderTop: "1px solid var(--border-faint)",
            display: "flex",
            flexDirection: "column",
            gap: 8,
          }}
        >
          {persona && (
            <p
              className="font-mono"
              style={{ fontSize: 9.5, color: "var(--text-faint)" }}
            >
              Voice:{" "}
              <span style={{ color: persMeta.hue }}>{persMeta.label}</span>
            </p>
          )}
          {vr?.verdict && <VerifierBanner vr={vr} />}
          <PayloadPreview payload={o.payload} />
          <div className="flex" style={{ gap: 6 }}>
            <SiblingReviewForm
              outcomeId={o.id}
              outcomeBranchId={o.branch_id}
              branches={branches}
              reviewMut={reviewMut}
            />
            <button
              type="button"
              disabled={reverifyMut.isPending}
              onClick={(e) => {
                e.stopPropagation();
                reverifyMut.mutate(invId);
              }}
              style={{ ...monoBtnStyle("default"), opacity: reverifyMut.isPending ? 0.5 : 1 }}
            >
              <ShieldCheck weight="regular" size={11} />
              {vr?.verdict ? "Re-verify" : "Verify"}
            </button>
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
                        ? `operator promote -- verifier confirmed conf=${conf}`
                        : verdict
                          ? `operator promote -- verifier ${verdict} conf=${conf}`
                          : "operator promote -- no verifier verdict";
                    promoteMut.mutate({ outcomeId: o.id, reason: note });
                  }}
                  style={{
                    ...monoBtnStyle(vr?.verdict === "confirmed" ? "accent" : "default"),
                    opacity: promoteMut.isPending ? 0.5 : 1,
                  }}
                >
                  <PixelIcon name="emit" size={11} />
                  Promote to finding
                </button>
              )}
          </div>
        </div>
      )}
    </li>
  );
}

/** Map outcome kind severity to a css color for inline icon tinting. */
function outcomeKindSeverityColor(kind: string): string {
  const sev = outcomeKindSeverity(kind);
  switch (sev) {
    case "critical":
      return "var(--accent)";
    case "high":
      return "var(--status-warn)";
    case "medium":
      return "var(--status-info)";
    case "low":
      return "var(--status-ok)";
    case "info":
      return "var(--status-info)";
    default:
      return "var(--text-muted)";
  }
}
