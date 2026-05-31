import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import {
  Plus,
  MagnifyingGlass,
  ArrowRight,
  Briefcase,
  Bug,
  Lightning,
  ShieldCheck,
  Star,
  X,
  CaretLeft,
  CaretRight,
  GitBranch,
  Funnel,
  Calendar,
  CaretDown,
  CaretRight as CaretRightSmall,
  type Icon,
} from "@phosphor-icons/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { OutcomeKindBadge, outcomeKindSeverity } from "../components/OutcomeKindBadge";
import { DeleteButton } from "../components/DeleteButton";
import {
  useCreateInvestigation,
  useDeleteInvestigation,
  useToggleInvestigationFavorite,
} from "../mutations";
import {
  useInvestigations,
  useTargetMap,
  useTargets,
  useWorkspaces,
} from "../queries";
import type {
  InvestigationKind,
  InvestigationStatus,
  VRInvestigationSummary,
} from "../types";

// ─────────────────────────────────────────────────────────────────────
// Status palette — matches the dots on the detail page.
// ─────────────────────────────────────────────────────────────────────

const STATUS_DOT: Record<InvestigationStatus, string> = {
  created: "#9aa0a6",
  running: "#97dbbe",
  paused: "#f0c97a",
  completed: "#8ec5ff",
  failed: "#f0a8c7",
  abandoned: "#9aa0a6",
};

// Priority for the default "Smart" sort: live and actionable first.
const STATUS_PRIORITY: Record<InvestigationStatus, number> = {
  running: 0,
  paused: 1,
  completed: 2,
  failed: 3,
  created: 4,
  abandoned: 5,
};

const KIND_ICON: Record<InvestigationKind, Icon> = {
  discovery: MagnifyingGlass,
  variant_hunt: GitBranch,
  triage: Funnel,
  n_day: Calendar,
  audit: ShieldCheck,
};

// ─────────────────────────────────────────────────────────────────────
// Pure helpers
// ─────────────────────────────────────────────────────────────────────

function relativeTime(value?: string | null): string {
  if (!value) return "—";
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return "—";
  const delta = Date.now() - t;
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

type VerifierTone = "low" | "medium" | "high" | "critical" | null;

function verifierBadgeTone(verdict?: string | null): VerifierTone {
  if (verdict === "confirmed") return "low";
  if (verdict === "refuted") return "critical";
  if (verdict === "inconclusive") return "medium";
  return null;
}

function verdictTextColor(verdict?: string | null): string {
  if (verdict === "confirmed") return "#97dbbe";
  if (verdict === "refuted") return "#f0a8c7";
  return "var(--color-text-muted)";
}

// ─────────────────────────────────────────────────────────────────────
// InvestigationCard — one investigation per row, ~80px tall.
//
// Replaces the old 14-column table. Status dot (pulses if live) + kind
// icon on the left, title/target/verdict in the middle, outcome /
// findings / time / actions on the right. CREATED investigations are
// dimmed; RUNNING ones get an accent left-border and a pulse ring.
// ─────────────────────────────────────────────────────────────────────

function InvestigationCard({
  inv,
  targetName,
  onOpen,
  onToggleFavorite,
  deleteMut,
}: {
  inv: VRInvestigationSummary;
  targetName: string;
  onOpen: () => void;
  onToggleFavorite: () => void;
  deleteMut: ReturnType<typeof useDeleteInvestigation>;
}) {
  const isRunning = inv.status === "running";
  const isCreated = inv.status === "created";
  const dotColor = STATUS_DOT[inv.status] ?? "#9aa0a6";
  const KindIcon = KIND_ICON[inv.kind] ?? MagnifyingGlass;

  const verifierTone = verifierBadgeTone(inv.verifier_verdict);
  const verdictColor = verdictTextColor(inv.verifier_verdict);
  const findingsCount = inv.linked_finding_ids.length;

  // Visual hierarchy: completed-with-findings pops, created fades back,
  // running gets a glow edge.
  const hasFindings = findingsCount > 0;
  const dim = isCreated && !inv.is_favorite;

  return (
    <li
      onClick={onOpen}
      className="group relative flex items-center gap-3 px-4 py-3 rounded-md border bg-surface hover:bg-elevated cursor-pointer transition-all"
      style={{
        opacity: dim ? 0.55 : 1,
        borderColor: isRunning
          ? "color-mix(in srgb, #97dbbe 45%, var(--color-border))"
          : hasFindings && inv.verifier_verdict === "confirmed"
            ? "color-mix(in srgb, #97dbbe 30%, var(--color-border))"
            : "var(--color-border)",
        boxShadow: isRunning
          ? "inset 3px 0 0 #97dbbe, 0 0 12px color-mix(in srgb, #97dbbe 18%, transparent)"
          : hasFindings && inv.verifier_verdict === "confirmed"
            ? "inset 3px 0 0 #97dbbe"
            : inv.verifier_verdict === "refuted"
              ? "inset 3px 0 0 #f0a8c7"
              : isCreated
                ? "inset 3px 0 0 transparent"
                : "inset 3px 0 0 color-mix(in srgb, var(--color-text-muted) 30%, transparent)",
      }}
    >
      {/* Status dot + kind icon column */}
      <div className="flex items-center gap-2.5 shrink-0">
        <span className="relative flex h-2.5 w-2.5 items-center justify-center">
          <span
            className="absolute inset-0 rounded-full"
            style={{ background: dotColor }}
          />
          {isRunning && (
            <span
              className="absolute inset-0 rounded-full animate-ping"
              style={{ background: dotColor, opacity: 0.6 }}
            />
          )}
        </span>
        <KindIcon
          className="h-5 w-5 text-text-muted shrink-0"
          weight="duotone"
          aria-label={inv.kind}
        />
      </div>

      {/* Title / target / verdict excerpt */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="text-[14px] font-medium text-foreground truncate"
            title={inv.title}
          >
            {inv.title}
          </span>
          {inv.is_favorite && (
            <Star
              className="h-3.5 w-3.5 shrink-0"
              weight="fill"
              style={{ color: "#fbbf24" }}
              aria-label="favorite"
            />
          )}
          <span
            className="hidden sm:inline shrink-0 px-1.5 py-0.5 rounded text-[9px] font-mono uppercase tracking-wider text-text-muted"
            style={{
              border:
                "1px solid color-mix(in srgb, var(--color-text-muted) 25%, transparent)",
            }}
          >
            {inv.kind}
          </span>
          <span
            className="hidden md:inline shrink-0 text-[10px] font-mono uppercase tracking-wider"
            style={{ color: dotColor }}
          >
            {inv.pause_reason ? `${inv.status}:${inv.pause_reason}` : inv.status}
            {isRunning && inv.message_count > 0 && (
              <span className="text-text-muted ml-1">
                · {inv.message_count} turns
                {inv.primary_outcome_kind ? " · has finding" : ""}
              </span>
            )}
          </span>
        </div>
        <div
          className="mt-0.5 text-[11px] font-mono text-text-muted truncate"
          title={targetName}
        >
          target: {targetName}
        </div>
        {inv.primary_outcome_verdict_head && (
          <div
            className="mt-0.5 text-[12px] truncate"
            style={{ color: verdictColor }}
            title={inv.primary_outcome_verdict_head}
          >
            {inv.primary_outcome_verdict_head}
          </div>
        )}
      </div>

      {/* Right cluster: findings · outcome · verifier · time · actions */}
      <div className="flex items-center gap-3 shrink-0">
        {hasFindings && (
          <span
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold"
            title={`${findingsCount} linked findings`}
            style={{
              background: "color-mix(in srgb, #97dbbe 14%, transparent)",
              color: "#97dbbe",
            }}
          >
            <Bug className="h-3 w-3" weight="bold" />
            {findingsCount}
          </span>
        )}
        {inv.primary_outcome_kind && (
          <AilaBadge
            severity={outcomeKindSeverity(inv.primary_outcome_kind)}
            size="sm"
          >
            <OutcomeKindBadge kind={inv.primary_outcome_kind} />
            {inv.primary_outcome_confidence
              ? ` · ${inv.primary_outcome_confidence}`
              : ""}
          </AilaBadge>
        )}
        {verifierTone && (
          <AilaBadge severity={verifierTone} size="sm">
            {inv.verifier_verdict}
            {typeof inv.verifier_confidence === "number"
              ? ` ${inv.verifier_confidence.toFixed(2)}`
              : ""}
          </AilaBadge>
        )}
        <span
          className="text-[11px] font-mono text-text-muted whitespace-nowrap w-16 text-right"
          title={inv.created_at ?? ""}
        >
          {relativeTime(inv.created_at)}
        </span>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onToggleFavorite();
          }}
          className="flex transition-colors"
          style={{
            color: inv.is_favorite ? "#fbbf24" : "var(--color-text-muted)",
          }}
          title={inv.is_favorite ? "Unfavorite" : "Favorite"}
          aria-label={inv.is_favorite ? "Unfavorite" : "Favorite"}
        >
          <Star
            className="h-4 w-4"
            weight={inv.is_favorite ? "fill" : "regular"}
          />
        </button>
        <div
          className="opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={(e) => e.stopPropagation()}
        >
          <DeleteButton
            id={inv.id}
            label={`investigation "${inv.title}"`}
            mutation={deleteMut}
            compact
          />
        </div>
        <ArrowRight
          className="h-4 w-4 text-text-muted/50 group-hover:text-accent group-hover:translate-x-0.5 transition-all"
          aria-hidden
        />
      </div>
    </li>
  );
}

// ─────────────────────────────────────────────────────────────────────
// StatusPill — single toggle button used by the status filter row.
// ─────────────────────────────────────────────────────────────────────

function StatusPill({
  id,
  label,
  active,
  count,
  onClick,
  accentColor,
}: {
  id: string;
  label: string;
  active: boolean;
  count?: number;
  onClick: () => void;
  accentColor?: string;
}) {
  const color = accentColor ?? "var(--color-accent)";
  return (
    <button
      key={id || "all"}
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono rounded-md border uppercase tracking-wider transition-colors"
      style={
        active
          ? {
              borderColor: color,
              background: `color-mix(in srgb, ${color} 14%, transparent)`,
              color,
            }
          : {
              borderColor: "var(--color-border)",
              background: "var(--color-surface)",
              color: "var(--color-text-muted)",
            }
      }
    >
      {accentColor && (
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: color }}
        />
      )}
      {label}
      {typeof count === "number" && (
        <span
          className="font-mono text-[10px]"
          style={{ color: active ? color : "var(--color-text-muted)" }}
        >
          {count}
        </span>
      )}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────
// InvestigationsListPage — card list with KPIs, status pills and
// optional target grouping. Replaces the old 14-column table.
// ─────────────────────────────────────────────────────────────────────

export function InvestigationsListPage() {
  const navigate = useNavigate();

  const [searchQ, setSearchQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [kindFilter, setKindFilter] = useState<string>("");
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [verifierFilter, setVerifierFilter] = useState<string>("");
  const [hideCreated, setHideCreated] = useState(true);
  const [groupByTarget, setGroupByTarget] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(
    () => new Set(),
  );
  const [pageSize, setPageSize] = useState(100);
  const [offset, setOffset] = useState(0);

  const { data: result, isLoading, isError } = useInvestigations({
    offset,
    limit: pageSize,
    status: statusFilter || undefined,
    kind: kindFilter || undefined,
    q: searchQ || undefined,
    favorites: favoritesOnly || undefined,
  });
  const targetMap = useTargetMap();
  const { data: targetsResult } = useTargets();
  const { data: workspacesResult } = useWorkspaces();
  const createMut = useCreateInvestigation();
  const deleteMut = useDeleteInvestigation();
  const favMut = useToggleInvestigationFavorite();

  const [showForm, setShowForm] = useState(false);
  const [formTitle, setFormTitle] = useState("");
  const [formQuestion, setFormQuestion] = useState("");
  const [formTargetId, setFormTargetId] = useState("");
  const [formKind, setFormKind] = useState<InvestigationKind>("discovery");
  const [formBudget, setFormBudget] = useState("50");

  // Inject the "New investigation" toggle into the global page header
  // so it sits at the top-right next to the page title, not buried in
  // the filter bar.
  const headerActions = useMemo(
    () => (
      <button
        type="button"
        onClick={() => setShowForm((v) => !v)}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-all hover:-translate-y-px"
        style={{
          background: showForm
            ? "color-mix(in srgb, var(--color-text-muted) 28%, transparent)"
            : "var(--color-accent)",
          color: showForm ? "var(--color-foreground)" : "var(--color-base)",
          boxShadow: showForm
            ? "none"
            : "0 0 0 1px color-mix(in srgb, var(--color-accent) 50%, transparent), 0 0 12px color-mix(in srgb, var(--color-accent) 28%, transparent)",
        }}
      >
        {showForm ? (
          <X className="h-3.5 w-3.5" />
        ) : (
          <Plus className="h-3.5 w-3.5" weight="bold" />
        )}
        {showForm ? "Cancel" : "New investigation"}
      </button>
    ),
    [showForm],
  );
  useUpdatePageHeader({ actions: headerActions });

  const totalRaw = (result?.meta as { total?: number } | undefined)?.total ?? 0;
  const investigationsRaw = result?.data ?? [];

  // Status-pill counts use the unfiltered server page so the operator
  // can see what is hidden by their current pill choice.
  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {
      "": investigationsRaw.length,
      running: 0,
      completed: 0,
      failed: 0,
      created: 0,
      paused: 0,
    };
    for (const i of investigationsRaw) {
      counts[i.status] = (counts[i.status] ?? 0) + 1;
    }
    return counts;
  }, [investigationsRaw]);

  // Apply client-side filters that don't round-trip through the server.
  let filtered: VRInvestigationSummary[] = investigationsRaw;
  if (findingsOnly) {
    filtered = filtered.filter((i) => i.linked_finding_ids.length > 0);
  }
  if (verifierFilter) {
    filtered = filtered.filter(
      (i) => (i.verifier_verdict ?? "") === verifierFilter,
    );
  }
  // Hide created unless the operator explicitly filters for that status
  // or unchecks the toggle.
  if (hideCreated && statusFilter !== "created") {
    filtered = filtered.filter((i) => i.status !== "created");
  }

  // Smart sort: running > paused > completed > failed > created >
  // abandoned. Within each bucket, newest first.
  const sorted = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      const ap = STATUS_PRIORITY[a.status] ?? 99;
      const bp = STATUS_PRIORITY[b.status] ?? 99;
      if (ap !== bp) return ap - bp;
      const at = a.created_at ? new Date(a.created_at).getTime() : 0;
      const bt = b.created_at ? new Date(b.created_at).getTime() : 0;
      return bt - at;
    });
    return copy;
  }, [filtered]);

  // Group by target — preserves the sorted order so the first group
  // shown is the target with the most "important" investigation.
  const grouped = useMemo(() => {
    const m = new Map<string, VRInvestigationSummary[]>();
    for (const inv of sorted) {
      const arr = m.get(inv.target_id) ?? [];
      arr.push(inv);
      m.set(inv.target_id, arr);
    }
    return m;
  }, [sorted]);

  function toggleGroup(targetId: string) {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(targetId)) next.delete(targetId);
      else next.add(targetId);
      return next;
    });
  }

  function resetToFirstPage() {
    setOffset(0);
  }

  function clearAllFilters() {
    setSearchQ("");
    setStatusFilter("");
    setKindFilter("");
    setFindingsOnly(false);
    setFavoritesOnly(false);
    setVerifierFilter("");
    setHideCreated(true);
    resetToFirstPage();
  }

  const hasActiveFilters =
    !!searchQ ||
    !!statusFilter ||
    !!kindFilter ||
    findingsOnly ||
    favoritesOnly ||
    !!verifierFilter ||
    !hideCreated ||
    groupByTarget;

  const kpis = useMemo(() => {
    const running = investigationsRaw.filter((i) => i.status === "running").length;
    const withFindings = investigationsRaw.filter((i) => i.linked_finding_ids.length > 0).length;
    const confirmed = investigationsRaw.filter((i) => i.verifier_verdict === "confirmed").length;
    const refuted = investigationsRaw.filter((i) => i.verifier_verdict === "refuted").length;
    const totalMessages = investigationsRaw.reduce((sum, i) => sum + (i.message_count ?? 0), 0);
    const estTokensM = ((totalMessages * 28000) / 1_000_000);
    return { running, withFindings, confirmed, refuted, totalMessages, estTokensM };
  }, [investigationsRaw]);

  return (
    <div className="flex flex-col gap-6">
      {/* Stats bar — compact inline, no boxes */}
      <AilaCard techBorder glow padding="sm">
        <div className="flex items-center justify-between gap-6 flex-wrap">
          <div className="flex items-center gap-5 flex-wrap">
            <span className="inline-flex items-center gap-2 text-sm">
              <Briefcase weight="fill" size={16} className="text-accent" />
              <span className="font-mono font-bold text-foreground text-lg">{totalRaw}</span>
              <span className="text-text-muted text-xs">investigations</span>
            </span>
            <span className="w-px h-5 bg-border-default" />
            <span className="inline-flex items-center gap-1.5 text-sm">
              <span
                className="w-2 h-2 rounded-full"
                style={{
                  background: kpis.running > 0 ? "#97dbbe" : "#9aa0a6",
                  boxShadow: kpis.running > 0 ? "0 0 6px #97dbbe" : "none",
                }}
              />
              <span className="font-mono font-semibold text-foreground">{kpis.running}</span>
              <span className="text-text-muted text-xs">running</span>
            </span>
            <span className="w-px h-5 bg-border-default" />
            <span className="inline-flex items-center gap-1.5 text-sm">
              <Bug weight="fill" size={14} className={kpis.withFindings > 0 ? "text-emerald-400" : "text-text-muted"} />
              <span className="font-mono font-semibold text-foreground">{kpis.withFindings}</span>
              <span className="text-text-muted text-xs">with findings</span>
            </span>
            <span className="w-px h-5 bg-border-default" />
            <span className="inline-flex items-center gap-1.5 text-sm">
              <Lightning weight="fill" size={14} className="text-text-muted" />
              <span className="font-mono font-semibold text-foreground">
                {kpis.estTokensM >= 1000 ? `${(kpis.estTokensM / 1000).toFixed(1)}B` : `${kpis.estTokensM.toFixed(0)}M`}
              </span>
              <span className="text-text-muted text-xs">tokens</span>
            </span>
            {(kpis.confirmed > 0 || kpis.refuted > 0) && (
              <>
                <span className="w-px h-5 bg-border-default" />
                <span className="inline-flex items-center gap-1.5 text-sm">
                  <ShieldCheck weight="fill" size={14} className="text-emerald-400" />
                  <span className="font-mono text-xs">
                    <span style={{ color: "#97dbbe" }}>{kpis.confirmed}</span>
                    <span className="text-text-muted/60"> / </span>
                    <span style={{ color: "#f0a8c7" }}>{kpis.refuted}</span>
                  </span>
                  <span className="text-text-muted text-xs">verdicts</span>
                </span>
              </>
            )}
          </div>
          <span className="text-[11px] font-mono text-text-muted">
            {kpis.totalMessages.toLocaleString()} total turns
          </span>
        </div>
      </AilaCard>

      {/* Create form */}
      {showForm && (
        <AilaCard padding="md" techBorder glow>
          <div className="flex items-center gap-2 mb-3">
            <Plus className="h-4 w-4 text-accent" />
            <h2 className="font-display text-base font-semibold text-foreground">
              Start a new investigation
            </h2>
          </div>
          <p className="text-xs text-text-muted mb-4 leading-relaxed">
            Pick a target you already onboarded under{" "}
            <strong>Workspaces → Targets</strong>. Workflow{" "}
            <code className="font-mono">VR_INVESTIGATE_V1</code> fires
            immediately on create.
          </p>
          <div className="space-y-3">
            <input
              type="text"
              value={formTitle}
              onChange={(e) => setFormTitle(e.target.value)}
              placeholder="Title (e.g. 'Audit V8 InferMaps for missing alias check')"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none transition-colors"
            />
            <textarea
              value={formQuestion}
              onChange={(e) => setFormQuestion(e.target.value)}
              placeholder="Initial question — what are you asking the engine to investigate?"
              rows={3}
              className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none transition-colors"
            />
            {(() => {
              const targets = targetsResult?.data ?? [];
              const workspaces = workspacesResult?.data ?? [];
              const byWs = new Map<string, typeof targets>();
              for (const t of targets) {
                const arr = byWs.get(t.workspace_id) ?? [];
                arr.push(t);
                byWs.set(t.workspace_id, arr);
              }
              const wsName = (id: string) =>
                workspaces.find((w) => w.id === id)?.name ??
                "(unknown workspace)";
              const orderedWsIds = Array.from(byWs.keys()).sort((a, b) =>
                wsName(a).localeCompare(wsName(b)),
              );
              if (targetsResult === undefined) {
                return (
                  <div className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border text-text-muted">
                    Loading targets…
                  </div>
                );
              }
              if (targets.length === 0) {
                return (
                  <div className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border-danger text-text-danger">
                    No targets exist yet. Create one under Workspaces → Targets
                    before starting an investigation.
                  </div>
                );
              }
              return (
                <select
                  value={formTargetId}
                  onChange={(e) => setFormTargetId(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none transition-colors"
                >
                  <option value="">— Pick a target —</option>
                  {orderedWsIds.map((wsId) => (
                    <optgroup key={wsId} label={wsName(wsId)}>
                      {(byWs.get(wsId) ?? [])
                        .slice()
                        .sort((a, b) =>
                          a.display_name.localeCompare(b.display_name),
                        )
                        .map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.display_name} · {t.kind} ·{" "}
                            {t.primary_language ?? "—"} · {t.analysis_state}
                          </option>
                        ))}
                    </optgroup>
                  ))}
                </select>
              );
            })()}
            <div className="flex items-center gap-3 flex-wrap">
              <select
                value={formKind}
                onChange={(e) =>
                  setFormKind(e.target.value as InvestigationKind)
                }
                className="px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
              >
                <option value="discovery">discovery</option>
                <option value="variant_hunt">variant_hunt</option>
                <option value="triage">triage</option>
                <option value="n_day">n_day</option>
                <option value="audit">audit</option>
              </select>
              <div className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-surface border border-border">
                <span className="text-xs font-mono text-text-muted">
                  budget $
                </span>
                <input
                  type="number"
                  step="1"
                  min="0"
                  value={formBudget}
                  onChange={(e) => setFormBudget(e.target.value)}
                  className="w-20 px-1 text-sm font-mono bg-transparent border-0 focus:outline-none"
                />
              </div>
              <button
                type="button"
                disabled={
                  !formTitle.trim() ||
                  !formQuestion.trim() ||
                  !formTargetId.trim() ||
                  createMut.isPending
                }
                onClick={() => {
                  const budget = parseFloat(formBudget);
                  createMut.mutate(
                    {
                      title: formTitle.trim(),
                      initial_question: formQuestion.trim(),
                      target_id: formTargetId.trim(),
                      kind: formKind,
                      cost_budget_usd: Number.isFinite(budget) ? budget : 50,
                    },
                    {
                      onSuccess: (created) => {
                        setShowForm(false);
                        setFormTitle("");
                        setFormQuestion("");
                        setFormTargetId("");
                        setFormKind("discovery");
                        setFormBudget("50");
                        navigate(`/vr/investigations/${created.data.id}`);
                      },
                    },
                  );
                }}
                className="ml-auto inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-md transition-all hover:-translate-y-px disabled:opacity-50 disabled:hover:translate-y-0"
                style={{
                  background: "var(--color-accent)",
                  color: "var(--color-base)",
                  boxShadow:
                    "0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)",
                }}
              >
                {createMut.isPending ? "Creating…" : "Start investigation"}
              </button>
            </div>
          </div>
        </AilaCard>
      )}

      {/* Status pills — primary axis the operator scans by */}
      <div className="flex flex-wrap items-center gap-1.5">
        <StatusPill
          id=""
          label="All"
          active={statusFilter === ""}
          count={statusCounts[""]}
          onClick={() => {
            setStatusFilter("");
            resetToFirstPage();
          }}
        />
        <StatusPill
          id="running"
          label="Running"
          active={statusFilter === "running"}
          count={statusCounts.running}
          accentColor={STATUS_DOT.running}
          onClick={() => {
            setStatusFilter("running");
            resetToFirstPage();
          }}
        />
        <StatusPill
          id="completed"
          label="Completed"
          active={statusFilter === "completed"}
          count={statusCounts.completed}
          accentColor={STATUS_DOT.completed}
          onClick={() => {
            setStatusFilter("completed");
            resetToFirstPage();
          }}
        />
        <StatusPill
          id="failed"
          label="Failed"
          active={statusFilter === "failed"}
          count={statusCounts.failed}
          accentColor={STATUS_DOT.failed}
          onClick={() => {
            setStatusFilter("failed");
            resetToFirstPage();
          }}
        />
        <StatusPill
          id="created"
          label="Created"
          active={statusFilter === "created"}
          count={statusCounts.created}
          accentColor={STATUS_DOT.created}
          onClick={() => {
            setStatusFilter("created");
            resetToFirstPage();
          }}
        />
        <StatusPill
          id="paused"
          label="Paused"
          active={statusFilter === "paused"}
          count={statusCounts.paused}
          accentColor={STATUS_DOT.paused}
          onClick={() => {
            setStatusFilter("paused");
            resetToFirstPage();
          }}
        />
      </div>

      {/* Secondary filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <MagnifyingGlass className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted pointer-events-none" />
          <input
            type="search"
            value={searchQ}
            onChange={(e) => {
              setSearchQ(e.target.value);
              resetToFirstPage();
            }}
            placeholder="Search title (ILIKE)…"
            className="w-full pl-9 pr-3 py-2 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none transition-colors"
          />
        </div>
        <select
          value={kindFilter}
          onChange={(e) => {
            setKindFilter(e.target.value);
            resetToFirstPage();
          }}
          className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none uppercase tracking-wider"
          aria-label="Filter by kind"
        >
          <option value="">all kind</option>
          <option value="discovery">discovery</option>
          <option value="variant_hunt">variant_hunt</option>
          <option value="triage">triage</option>
          <option value="n_day">n_day</option>
          <option value="audit">audit</option>
        </select>
        <select
          value={verifierFilter}
          onChange={(e) => {
            setVerifierFilter(e.target.value);
            resetToFirstPage();
          }}
          className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none uppercase tracking-wider"
          aria-label="Filter by verifier verdict"
        >
          <option value="">all verifier</option>
          <option value="confirmed">confirmed</option>
          <option value="refuted">refuted</option>
          <option value="inconclusive">inconclusive</option>
        </select>
        <label className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border uppercase tracking-wider cursor-pointer">
          <input
            type="checkbox"
            className="accent-accent"
            checked={findingsOnly}
            onChange={(e) => setFindingsOnly(e.target.checked)}
          />
          findings only
        </label>
        <label
          className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-md border uppercase tracking-wider cursor-pointer transition-colors"
          style={{
            borderColor: hideCreated
              ? "var(--color-accent)"
              : "var(--color-border)",
            background: hideCreated
              ? "color-mix(in srgb, var(--color-accent) 10%, transparent)"
              : "var(--color-surface)",
            color: hideCreated
              ? "var(--color-accent)"
              : "var(--color-text-muted)",
          }}
          title="Hide queued (created) investigations from the list"
        >
          <input
            type="checkbox"
            className="accent-accent"
            checked={hideCreated}
            onChange={(e) => setHideCreated(e.target.checked)}
          />
          hide created
        </label>
        <button
          type="button"
          onClick={() => {
            setFavoritesOnly((v) => !v);
            resetToFirstPage();
          }}
          className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-md border uppercase tracking-wider transition-colors"
          style={
            favoritesOnly
              ? {
                  borderColor: "#fbbf24",
                  background:
                    "color-mix(in srgb, #fbbf24 12%, transparent)",
                  color: "#fbbf24",
                }
              : {
                  borderColor: "var(--color-border)",
                  background: "var(--color-surface)",
                  color: "var(--color-text-muted)",
                }
          }
          title="Show only favorited investigations"
        >
          <Star
            className="h-3.5 w-3.5"
            weight={favoritesOnly ? "fill" : "regular"}
          />
          favorites
        </button>
        <button
          type="button"
          onClick={() => setGroupByTarget((v) => !v)}
          className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-md border uppercase tracking-wider transition-colors"
          style={
            groupByTarget
              ? {
                  borderColor: "var(--color-accent)",
                  background:
                    "color-mix(in srgb, var(--color-accent) 14%, transparent)",
                  color: "var(--color-accent)",
                }
              : {
                  borderColor: "var(--color-border)",
                  background: "var(--color-surface)",
                  color: "var(--color-text-muted)",
                }
          }
          title="Group investigations by target"
        >
          <GitBranch className="h-3.5 w-3.5" weight="duotone" />
          group by target
        </button>
        {hasActiveFilters && (
          <button
            type="button"
            onClick={clearAllFilters}
            className="inline-flex items-center gap-1 px-2 py-2 text-xs font-mono rounded-md text-text-muted hover:text-foreground transition-colors"
          >
            <X className="h-3.5 w-3.5" />
            clear
          </button>
        )}
        <span className="text-[11px] font-mono text-text-muted ml-auto">
          {sorted.length}
          <span className="text-text-muted/50"> / {totalRaw}</span>
        </span>
      </div>

      {/* Loading / error / empty */}
      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow>
          <p className="text-sm text-text-danger">
            Failed to load investigations.
          </p>
        </AilaCard>
      )}

      {!isLoading && !isError && sorted.length === 0 && !showForm && (
        <EmptyState
          icon={<MagnifyingGlass className="h-7 w-7" weight="duotone" />}
          title={
            hasActiveFilters
              ? "No investigations match the current filter"
              : "No investigations yet"
          }
          description={
            hasActiveFilters
              ? "Adjust filters above or clear them to see everything."
              : "Spin up a HonestVulnResearcher loop against any onboarded target."
          }
          action={
            hasActiveFilters
              ? { label: "Clear filters", onClick: clearAllFilters }
              : {
                  label: "Start your first investigation",
                  onClick: () => setShowForm(true),
                }
          }
        />
      )}

      {/* Card list — either flat or grouped by target */}
      {!isLoading && !isError && sorted.length > 0 && !groupByTarget && (
        <ul className="flex flex-col gap-2">
          {sorted.map((inv) => (
            <InvestigationCard
              key={inv.id}
              inv={inv}
              targetName={
                targetMap.get(inv.target_id)?.display_name ?? "loading…"
              }
              onOpen={() => navigate(`/vr/investigations/${inv.id}`)}
              onToggleFavorite={() => favMut.mutate(inv.id)}
              deleteMut={deleteMut}
            />
          ))}
        </ul>
      )}

      {!isLoading && !isError && sorted.length > 0 && groupByTarget && (
        <div className="flex flex-col gap-5">
          {Array.from(grouped.entries()).map(([targetId, items]) => {
            const target = targetMap.get(targetId);
            const targetName = target?.display_name ?? "loading…";
            const targetKind = target?.kind ?? "";
            const collapsed = collapsedGroups.has(targetId);
            return (
              <section key={targetId} className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => toggleGroup(targetId)}
                  className="flex items-center gap-2 text-left group/group"
                >
                  {collapsed ? (
                    <CaretRightSmall className="h-3.5 w-3.5 text-text-muted" />
                  ) : (
                    <CaretDown className="h-3.5 w-3.5 text-text-muted" />
                  )}
                  <span
                    className="font-mono text-[10px] uppercase tracking-[0.18em] text-text-muted shrink-0"
                  >
                    target
                  </span>
                  <span className="text-[13px] font-semibold text-foreground truncate">
                    {targetName}
                  </span>
                  {targetKind && (
                    <span className="text-[10px] font-mono uppercase tracking-wider text-text-muted">
                      · {targetKind}
                    </span>
                  )}
                  <span className="text-[10px] font-mono text-text-muted">
                    · {items.length} investigation
                    {items.length === 1 ? "" : "s"}
                  </span>
                  <span
                    className="flex-1 ml-2 h-px"
                    style={{
                      background:
                        "color-mix(in srgb, var(--color-text-muted) 18%, transparent)",
                    }}
                  />
                </button>
                {!collapsed && (
                  <ul className="flex flex-col gap-2">
                    {items.map((inv) => (
                      <InvestigationCard
                        key={inv.id}
                        inv={inv}
                        targetName={targetName}
                        onOpen={() =>
                          navigate(`/vr/investigations/${inv.id}`)
                        }
                        onToggleFavorite={() => favMut.mutate(inv.id)}
                        deleteMut={deleteMut}
                      />
                    ))}
                  </ul>
                )}
              </section>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {!isLoading && !isError && totalRaw > pageSize && (
        <div className="flex items-center justify-between gap-4 px-4 py-3 rounded-md border border-border bg-surface text-xs font-mono text-text-muted">
          <span>
            {sorted.length === investigationsRaw.length
              ? `${offset + 1}–${offset + sorted.length} of ${totalRaw}`
              : `${sorted.length} of ${investigationsRaw.length} (page) · ${totalRaw} total`}
          </span>
          <div className="flex items-center gap-2">
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(parseInt(e.target.value, 10));
                resetToFirstPage();
              }}
              className="px-2 py-1 rounded bg-base border border-border focus:border-accent focus:outline-none text-text-muted"
              title="Page size"
            >
              <option value="50">50 / page</option>
              <option value="100">100 / page</option>
              <option value="200">200 / page</option>
              <option value="500">500 / page</option>
            </select>
            <button
              type="button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-border disabled:opacity-40 hover:text-foreground hover:border-accent/40 transition-colors"
            >
              <CaretLeft className="h-3 w-3" />
              prev
            </button>
            <button
              type="button"
              disabled={offset + pageSize >= totalRaw}
              onClick={() => setOffset(offset + pageSize)}
              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-border disabled:opacity-40 hover:text-foreground hover:border-accent/40 transition-colors"
            >
              next
              <CaretRight className="h-3 w-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
