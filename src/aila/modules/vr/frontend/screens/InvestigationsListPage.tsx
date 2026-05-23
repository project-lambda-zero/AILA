import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import {
  Plus,
  MagnifyingGlass,
  ArrowRight,
  Pulse,
  Briefcase,
  Bug,
  ShieldCheck,
  ShieldWarning,
  Star,
  X,
  CaretLeft,
  CaretRight,
} from "@phosphor-icons/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { SeverityPulse } from "@/components/aila/SeverityPulse";
import { KpiTile } from "@/components/aila/KpiTile";

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

function fmtUsd(n: number): string {
  return `$${n.toFixed(2)}`;
}

// ─────────────────────────────────────────────────────────────────────
// InvestigationRow — single-line compact row, ~48-56px tall.
// All meta inline; no metric stacks; no cost bars; no multiline
// verdict heads. Designed so the operator scans 20-30 rows above the
// fold on a 1440x900 viewport without scrolling.
// ─────────────────────────────────────────────────────────────────────
function InvestigationRow({
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
  const sev = statusColor[inv.status] ?? "info";
  const isLive = inv.status === "running";
  const isFailed = inv.status === "failed";

  const verifierTone: "low" | "medium" | "high" | "critical" | null =
    inv.verifier_verdict === "confirmed"
      ? "low"
      : inv.verifier_verdict === "refuted"
        ? "critical"
        : inv.verifier_verdict === "inconclusive"
          ? "medium"
          : null;

  const edgeColor: Record<typeof sev, string> = {
    info: "var(--color-text-muted)",
    low: "#97dbbe",
    medium: "#f0a8c7",
    high: "var(--color-accent)",
    critical: "var(--color-accent)",
  };

  const costRatio = inv.cost_budget_usd > 0
    ? Math.min(1, inv.cost_actual_usd / inv.cost_budget_usd)
    : 0;

  return (
    <div className="group relative rounded-md border border-border bg-surface pl-3 pr-2 py-2 transition-all hover:border-accent/40 hover:bg-surface/70">
      {/* Severity edge */}
      <span
        aria-hidden
        className="absolute inset-y-1.5 left-0 w-[2px] rounded-r"
        style={{ background: edgeColor[sev] }}
      />

      {/* ── Line 1: favorite · title · trailing actions ─────────────── */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onToggleFavorite}
          className="flex-shrink-0 transition-colors"
          style={{ color: inv.is_favorite ? "#fbbf24" : "var(--color-text-muted)" }}
          title={inv.is_favorite ? "Unfavorite" : "Favorite"}
          aria-label={inv.is_favorite ? "Unfavorite" : "Favorite"}
        >
          <Star className="h-4 w-4" weight={inv.is_favorite ? "fill" : "regular"} />
        </button>
        <button
          type="button"
          onClick={onOpen}
          className="min-w-0 flex-1 text-left focus:outline-none truncate text-sm font-medium text-foreground"
          title={inv.title}
        >
          {inv.title}
        </button>
        <div className="flex-shrink-0 flex items-center gap-1">
          <div className="opacity-0 group-hover:opacity-100 transition-opacity">
            <DeleteButton
              id={inv.id}
              label={`investigation "${inv.title}"`}
              mutation={deleteMut}
              compact
            />
          </div>
          <button
            type="button"
            onClick={onOpen}
            aria-label="Open investigation"
            className="inline-flex items-center text-text-muted group-hover:text-accent group-hover:translate-x-0.5 transition-all px-1"
          >
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* ── Line 2: status pulse + kind + verifier + outcome + meta ── */}
      <div className="mt-1 ml-6 flex items-center gap-2 flex-wrap text-[11px] font-mono text-text-muted">
        <SeverityPulse active={isLive || isFailed}>
          <AilaBadge severity={sev} size="sm">
            {inv.pause_reason
              ? `${inv.status}:${inv.pause_reason}`
              : inv.status}
          </AilaBadge>
        </SeverityPulse>
        <span
          className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] tracking-wider uppercase"
          style={{
            border: "1px solid color-mix(in srgb, var(--color-text-muted) 25%, transparent)",
          }}
        >
          {inv.kind}
        </span>
        {verifierTone && (
          <AilaBadge severity={verifierTone} size="sm">
            {inv.verifier_verdict}
            {typeof inv.verifier_confidence === "number"
              ? ` ${inv.verifier_confidence.toFixed(2)}`
              : ""}
          </AilaBadge>
        )}
        {inv.primary_outcome_kind && (
          <AilaBadge
            severity={
              inv.primary_outcome_kind === "direct_finding"
                ? "high"
                : inv.primary_outcome_kind === "patch_assessment_report"
                  ? "info"
                  : inv.primary_outcome_kind === "variant_hunt_order"
                    ? "medium"
                    : "low"
            }
            size="sm"
          >
            {inv.primary_outcome_kind}
            {inv.primary_outcome_confidence
              ? ` · ${inv.primary_outcome_confidence}`
              : ""}
          </AilaBadge>
        )}
        <span className="text-text-muted/40">·</span>
        <span className="truncate max-w-[260px]">
          <span className="text-text-muted/50">→ </span>
          <span className="text-foreground/80">{targetName}</span>
        </span>
        {inv.primary_outcome_verdict_head && (
          <>
            <span className="text-text-muted/40">·</span>
            <span className="truncate max-w-[420px] text-text-muted/80">
              {inv.primary_outcome_verdict_head}
            </span>
          </>
        )}
        {/* Spacer + right-aligned metric block */}
        <span className="flex-1" />
        <span
          className="tabular-nums"
          title={`${inv.linked_finding_ids.length} findings`}
          style={{
            color: inv.linked_finding_ids.length > 0 ? "#97dbbe" : undefined,
          }}
        >
          <span className="text-text-muted/60">f</span>{inv.linked_finding_ids.length}
        </span>
        <span className="tabular-nums" title={`${inv.branch_count} branches`}>
          <span className="text-text-muted/60">b</span>{inv.branch_count}
        </span>
        <span className="tabular-nums" title={`${inv.message_count} messages`}>
          <span className="text-text-muted/60">m</span>{inv.message_count}
        </span>
        <span
          className="tabular-nums"
          title={`cost ${fmtUsd(inv.cost_actual_usd)} of ${fmtUsd(inv.cost_budget_usd)} budget (${Math.round(costRatio * 100)}%)`}
          style={{
            color:
              costRatio > 0.9
                ? "var(--color-accent)"
                : costRatio > 0.6
                  ? "#f0a8c7"
                  : undefined,
          }}
        >
          {fmtUsd(inv.cost_actual_usd)}
        </span>
        <span className="tabular-nums text-text-muted/70" title={inv.created_at ?? ""}>
          {relativeTime(inv.created_at)}
        </span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// InvestigationsListPage — KPI hero + filter bar + vertical row list.
// Rows over tiles because each investigation carries ~10 fields of
// meta the operator wants to scan; cramming that into a 380px tile
// requires line-clamping that hides exactly the information the page
// exists to surface.
// ─────────────────────────────────────────────────────────────────────
export function InvestigationsListPage() {
  const navigate = useNavigate();

  const [searchQ, setSearchQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [kindFilter, setKindFilter] = useState<string>("");
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [verifierFilter, setVerifierFilter] = useState<string>("");
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

  const totalRaw = (result?.meta as { total?: number } | undefined)?.total ?? 0;
  const investigationsRaw = result?.data ?? [];
  let investigations = findingsOnly
    ? investigationsRaw.filter((i) => i.linked_finding_ids.length > 0)
    : investigationsRaw;
  if (verifierFilter) {
    investigations = investigations.filter(
      (i) => (i.verifier_verdict ?? "") === verifierFilter,
    );
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
    resetToFirstPage();
  }

  const hasActiveFilters =
    !!searchQ ||
    !!statusFilter ||
    !!kindFilter ||
    findingsOnly ||
    favoritesOnly ||
    !!verifierFilter;

  const kpis = useMemo(() => {
    const running = investigationsRaw.filter((i) => i.status === "running").length;
    const withFindings = investigationsRaw.filter(
      (i) => i.linked_finding_ids.length > 0,
    ).length;
    const confirmed = investigationsRaw.filter(
      (i) => i.verifier_verdict === "confirmed",
    ).length;
    const refuted = investigationsRaw.filter(
      (i) => i.verifier_verdict === "refuted",
    ).length;
    return { running, withFindings, confirmed, refuted };
  }, [investigationsRaw]);

  return (
    <div className="flex flex-col gap-6">
      {/* KPI hero */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiTile
          label="Total"
          value={totalRaw}
          hint="across all targets"
          icon={<Briefcase weight="duotone" />}
          tone="accent"
        />
        <KpiTile
          label="Running"
          value={kpis.running}
          hint={kpis.running === 0 ? "all idle" : "engine active"}
          icon={<Pulse weight="duotone" />}
          tone={kpis.running > 0 ? "warn" : "neutral"}
        />
        <KpiTile
          label="With findings"
          value={kpis.withFindings}
          hint={
            kpis.confirmed
              ? `${kpis.confirmed} verifier-confirmed`
              : "none verified"
          }
          icon={<Bug weight="duotone" />}
          tone={kpis.withFindings > 0 ? "crit" : "neutral"}
        />
        <KpiTile
          label="Verifier verdicts"
          value={`${kpis.confirmed}/${kpis.refuted}`}
          hint="confirmed / refuted"
          icon={
            kpis.refuted > kpis.confirmed
              ? <ShieldWarning weight="duotone" />
              : <ShieldCheck weight="duotone" />
          }
          tone={kpis.refuted > kpis.confirmed ? "warn" : "ok"}
        />
      </div>

      {/* Action bar */}
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
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            resetToFirstPage();
          }}
          className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none uppercase tracking-wider"
          aria-label="Filter by status"
        >
          <option value="">all status</option>
          <option value="created">created</option>
          <option value="running">running</option>
          <option value="paused">paused</option>
          <option value="completed">completed</option>
          <option value="failed">failed</option>
        </select>
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
                  background: "color-mix(in srgb, #fbbf24 12%, transparent)",
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
          <Star className="h-3.5 w-3.5" weight={favoritesOnly ? "fill" : "regular"} />
          favorites
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
          {investigations.length}
          <span className="text-text-muted/50"> / {totalRaw}</span>
        </span>
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-md transition-all hover:-translate-y-px"
          style={{
            background: showForm
              ? "color-mix(in srgb, var(--color-text-muted) 30%, transparent)"
              : "var(--color-accent)",
            color: showForm ? "var(--color-foreground)" : "var(--color-base)",
            boxShadow: showForm
              ? "none"
              : "0 0 0 1px color-mix(in srgb, var(--color-accent) 50%, transparent), 0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)",
          }}
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" weight="bold" />}
          {showForm ? "Cancel" : "New investigation"}
        </button>
      </div>

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
            Pick a target you already onboarded under <strong>Workspaces → Targets</strong>.
            Workflow <code className="font-mono">VR_INVESTIGATE_V1</code> fires immediately on create.
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
                workspaces.find((w) => w.id === id)?.name ?? "(unknown workspace)";
              const orderedWsIds = Array.from(byWs.keys()).sort(
                (a, b) => wsName(a).localeCompare(wsName(b)),
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
                    No targets exist yet. Create one under Workspaces → Targets before starting an investigation.
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
                        .sort((a, b) => a.display_name.localeCompare(b.display_name))
                        .map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.display_name} · {t.kind} · {t.primary_language ?? "—"} · {t.analysis_state}
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
                onChange={(e) => setFormKind(e.target.value as InvestigationKind)}
                className="px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
              >
                <option value="discovery">discovery</option>
                <option value="variant_hunt">variant_hunt</option>
                <option value="triage">triage</option>
                <option value="n_day">n_day</option>
                <option value="audit">audit</option>
              </select>
              <div className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-surface border border-border">
                <span className="text-xs font-mono text-text-muted">budget $</span>
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
                  boxShadow: "0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)",
                }}
              >
                {createMut.isPending ? "Creating…" : "Start investigation"}
              </button>
            </div>
          </div>
        </AilaCard>
      )}

      {/* Loading / error / empty */}
      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow>
          <p className="text-sm text-text-danger">Failed to load investigations.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && investigations.length === 0 && !showForm && (
        <div
          className="rounded-md border border-dashed border-border px-8 py-16 text-center"
          style={{ background: "color-mix(in srgb, var(--color-accent) 3%, transparent)" }}
        >
          <div
            className="inline-flex h-14 w-14 items-center justify-center rounded-full mb-4"
            style={{
              background: "color-mix(in srgb, var(--color-accent) 12%, transparent)",
              color: "var(--color-accent)",
            }}
          >
            <MagnifyingGlass className="h-7 w-7" weight="duotone" />
          </div>
          <p className="font-display text-lg font-semibold text-foreground">
            {hasActiveFilters ? "No investigations match the current filter" : "No investigations yet"}
          </p>
          <p className="mt-1 text-sm text-text-muted">
            {hasActiveFilters
              ? "Adjust filters above or clear them to see everything."
              : "Spin up a HonestVulnResearcher loop against any onboarded target."}
          </p>
          <button
            type="button"
            onClick={() => (hasActiveFilters ? clearAllFilters() : setShowForm(true))}
            className="mt-5 inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-md transition-all hover:-translate-y-px"
            style={{
              background: "var(--color-accent)",
              color: "var(--color-base)",
              boxShadow: "0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)",
            }}
          >
            {hasActiveFilters ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" weight="bold" />}
            {hasActiveFilters ? "Clear filters" : "Start your first investigation"}
          </button>
        </div>
      )}

      {/* Row list — full-width rows, vertical stack */}
      {!isLoading && !isError && investigations.length > 0 && (
        <div className="flex flex-col gap-2">
          {investigations.map((inv) => (
            <InvestigationRow
              key={inv.id}
              inv={inv}
              targetName={targetMap.get(inv.target_id)?.display_name ?? "loading…"}
              onOpen={() => navigate(`/vr/investigations/${inv.id}`)}
              onToggleFavorite={() => favMut.mutate(inv.id)}
              deleteMut={deleteMut}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      {!isLoading && !isError && totalRaw > pageSize && (
        <div className="flex items-center justify-between gap-4 px-4 py-3 rounded-md border border-border bg-surface text-xs font-mono text-text-muted">
          <span>
            {investigations.length === investigationsRaw.length
              ? `${offset + 1}–${offset + investigations.length} of ${totalRaw}`
              : `${investigations.length} of ${investigationsRaw.length} (page) · ${totalRaw} total`}
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
