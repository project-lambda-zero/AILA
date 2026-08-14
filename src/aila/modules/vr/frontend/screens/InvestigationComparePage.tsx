import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQueries } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { ArrowSquareOut } from "@phosphor-icons/react/dist/csr/ArrowSquareOut";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { Rows } from "@phosphor-icons/react/dist/csr/Rows";
import { Scales } from "@phosphor-icons/react/dist/csr/Scales";
import { X } from "@phosphor-icons/react/dist/csr/X";

import { OutcomeKindBadge } from "../components/OutcomeKindBadge";
import { OutcomePolarityBadge } from "../components/OutcomePolarityBadge";
import {
  isInvestigationLive,
  useInvestigations,
  useTargetMap,
  type HypothesisProjection,
} from "../queries";
import type {
  Envelope,
  InvestigationStatus,
  VRInvestigationSummary,
  VROutcomeSummary,
} from "../types";

// ─────────────────────────────────────────────────────────────────────
// Constants + tiny formatters. Kept local so this screen is
// self-contained and doesn't force sibling files to export helpers.
// ─────────────────────────────────────────────────────────────────────

const MAX_COLUMNS = 4;
const IDS_PARAM = "ids";

const STATUS_DOT: Record<InvestigationStatus, string> = {
  created: "#9aa0a6",
  running: "#97dbbe",
  paused: "#f0c97a",
  completed: "#8ec5ff",
  failed: "#f0a8c7",
  abandoned: "#9aa0a6",
  stalled: "#9aa0a6",
};

function fmtUsd(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "$0.00";
  return `$${n.toFixed(2)}`;
}

function humanize(s: string | null | undefined): string {
  if (!s) return "";
  const last = s.includes(".") ? s.split(".").pop()! : s;
  return last.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─────────────────────────────────────────────────────────────────────
// Per-column read bundle. Uses EXISTING query keys shared with
// useInvestigation / useInvestigationOutcomes / useInvestigationHypotheses
// so TanStack cache hits are reused across pages -- opening this page
// after visiting InvestigationDetailPage renders instantly for the
// already-loaded investigation. No new backend endpoints are touched.
// ─────────────────────────────────────────────────────────────────────

interface Bundle {
  id: string | null;
  inv: VRInvestigationSummary | undefined;
  invLoading: boolean;
  invError: boolean;
  outcomes: VROutcomeSummary[];
  outcomesLoading: boolean;
  hyps: HypothesisProjection[];
  hypsLoading: boolean;
}

function useCompareBundles(ids: readonly (string | null)[]): Bundle[] {
  // Fetch investigation summary per selected id. Reuses the exact
  // ["vr", "investigation", id] key used by useInvestigation, so
  // TanStack Query caches are shared.
  const invQueries = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["vr", "investigation", id ?? ""],
      queryFn: async () =>
        (
          await authorizedRequestJson<Envelope<VRInvestigationSummary>>(
            `/vr/investigations/${encodeURIComponent(id ?? "")}`,
          )
        ).data,
      enabled: !!id,
      refetchInterval: (q: { state: { data?: VRInvestigationSummary } }) => {
        const status = q.state.data?.status;
        return isInvestigationLive(status) ? 5000 : false;
      },
    })),
  });

  const outcomesQueries = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["vr", "investigation-outcomes", id ?? ""],
      queryFn: async () =>
        await authorizedRequestJson<Envelope<VROutcomeSummary[]>>(
          `/vr/investigations/${encodeURIComponent(id ?? "")}/outcomes`,
        ),
      enabled: !!id,
      refetchInterval: false as const,
    })),
  });

  const hypsQueries = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["vr", "investigation-hypotheses", id ?? ""],
      queryFn: async () =>
        await authorizedRequestJson<Envelope<HypothesisProjection[]>>(
          `/vr/investigations/${encodeURIComponent(id ?? "")}/hypotheses`,
        ),
      enabled: !!id,
      refetchInterval: false as const,
    })),
  });

  return ids.map((id, i) => ({
    id,
    inv: invQueries[i]?.data,
    invLoading: !!id && invQueries[i]?.isLoading === true,
    invError: !!id && invQueries[i]?.isError === true,
    outcomes: outcomesQueries[i]?.data?.data ?? [],
    outcomesLoading: !!id && outcomesQueries[i]?.isLoading === true,
    hyps: hypsQueries[i]?.data?.data ?? [],
    hypsLoading: !!id && hypsQueries[i]?.isLoading === true,
  }));
}

// ─────────────────────────────────────────────────────────────────────
// Investigation picker -- lightweight typeahead over the workspace
// investigations list. No new dep; a plain input filters the same
// list this page's Compare rows are built from.
// ─────────────────────────────────────────────────────────────────────

interface InvestigationPickerProps {
  slotIndex: number;
  currentId: string | null;
  otherIds: readonly (string | null)[];
  investigations: VRInvestigationSummary[];
  targetLabel: (targetId: string) => string;
  onPick: (id: string) => void;
  onClear: () => void;
}

function InvestigationPicker({
  slotIndex,
  currentId,
  otherIds,
  investigations,
  targetLabel,
  onPick,
  onClear,
}: InvestigationPickerProps) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);

  const current = currentId
    ? investigations.find((i) => i.id === currentId)
    : undefined;

  const matches = useMemo(() => {
    const needle = q.trim().toLowerCase();
    // otherIds is at most MAX_COLUMNS - 1 items; a linear .includes is
    // cheaper and clearer than materialising a Set every render.
    const taken = otherIds.filter((s): s is string => !!s);
    const pool = investigations.filter(
      (inv) => inv.id !== currentId && !taken.includes(inv.id),
    );
    if (!needle) return pool.slice(0, 20);
    return pool
      .filter((inv) => {
        const hay = [
          inv.title,
          inv.id,
          humanize(inv.strategy_family),
          targetLabel(inv.target_id),
          inv.kind,
          inv.status,
        ]
          .join(" ")
          .toLowerCase();
        return hay.includes(needle);
      })
      .slice(0, 20);
  }, [q, investigations, currentId, otherIds, targetLabel]);

  return (
    <AilaCard techBorder padding="sm" className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs font-mono uppercase tracking-wide text-text-muted">
          Slot {slotIndex + 1}
        </span>
        {current && (
          <button
            type="button"
            onClick={onClear}
            className="text-2xs font-mono text-text-muted hover:text-text inline-flex items-center gap-1"
            aria-label="Clear selection"
          >
            <X className="h-3 w-3" /> Clear
          </button>
        )}
      </div>

      {current ? (
        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <span
              aria-hidden
              className="inline-block h-2 w-2 rounded-full shrink-0"
              style={{
                background: STATUS_DOT[current.status] ?? "#9aa0a6",
                boxShadow:
                  current.status === "running"
                    ? `0 0 6px ${STATUS_DOT.running}`
                    : "none",
              }}
            />
            <Link
              to={`/vr/investigations/${current.id}`}
              className="font-mono text-sm font-semibold text-foreground truncate hover:underline"
              title={current.title}
            >
              {current.title || current.id.slice(0, 8)}
            </Link>
          </div>
          <span className="font-mono text-2xs text-text-muted truncate">
            {targetLabel(current.target_id)} · {humanize(current.kind)}
          </span>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="mt-1 self-start text-2xs font-mono text-accent hover:underline"
          >
            {open ? "Hide picker" : "Replace…"}
          </button>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-2">
            <MagnifyingGlass className="h-3.5 w-3.5 text-text-muted" />
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onFocus={() => setOpen(true)}
              placeholder="Find investigation…"
              className="min-w-0 flex-1 bg-transparent border-b border-border-default focus:border-accent outline-none font-mono text-xs py-1"
              aria-label="Search investigations"
            />
          </div>
          {!open && (
            <button
              type="button"
              onClick={() => setOpen(true)}
              className="self-start text-2xs font-mono text-accent hover:underline"
            >
              Browse recent
            </button>
          )}
        </>
      )}

      {open && (
        <ul
          className="mt-1 max-h-64 overflow-y-auto flex flex-col gap-0.5 border-t border-border-default pt-2"
          role="listbox"
          aria-label={`Slot ${slotIndex + 1} candidates`}
        >
          {matches.length === 0 && (
            <li className="font-mono text-2xs text-text-muted px-1 py-1">
              No matches.
            </li>
          )}
          {matches.map((inv) => (
            <li key={inv.id}>
              <button
                type="button"
                onClick={() => {
                  onPick(inv.id);
                  setQ("");
                  setOpen(false);
                }}
                className="w-full text-left px-2 py-1 rounded-sm hover:bg-surface-elevated flex items-center gap-2 min-w-0"
              >
                <span
                  aria-hidden
                  className="inline-block h-1.5 w-1.5 rounded-full shrink-0"
                  style={{
                    background: STATUS_DOT[inv.status] ?? "#9aa0a6",
                  }}
                />
                <span className="flex-1 min-w-0 flex flex-col">
                  <span className="font-mono text-xs text-foreground truncate">
                    {inv.title || inv.id.slice(0, 8)}
                  </span>
                  <span className="font-mono text-2xs text-text-muted truncate">
                    {targetLabel(inv.target_id)} · {humanize(inv.kind)} ·{" "}
                    {inv.status}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </AilaCard>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Compare row -- one row = one facet, N cells = N selected columns.
// Divergence highlighting is driven by `key`: cells whose key differs
// between columns get a subtle left-accent border so the operator can
// scan a variant-hunt for signal without reading every cell.
// ─────────────────────────────────────────────────────────────────────

interface CellSpec {
  /** Value used to compute divergence. `null` means "empty / N/A" and
   *  is treated as its own bucket so a missing column is highlighted
   *  against a populated one. */
  key: string | null;
  render: React.ReactNode;
}

function CompareRow({
  label,
  help,
  cells,
  slots,
}: {
  label: string;
  help?: string;
  cells: (CellSpec | null)[];
  slots: number;
}) {
  // Divergence: only compute across non-empty slots (an empty slot is
  // the picker; comparing populated vs picker isn't useful signal).
  const populated = cells
    .map((c, i) => ({ c, i }))
    .filter((x) => x.c !== null);
  const uniq = new Set(populated.map((x) => x.c!.key));
  const divergent = uniq.size > 1;

  const gridStyle = { gridTemplateColumns: `160px repeat(${slots}, minmax(0, 1fr))` };

  return (
    <div
      className="grid items-start gap-3 border-b border-border-default/60 py-2 px-2"
      style={gridStyle}
    >
      <div className="flex flex-col gap-0.5 min-w-0">
        <span className="font-mono text-2xs uppercase tracking-wide text-text-muted">
          {label}
        </span>
        {help && (
          <span className="font-mono text-3xs text-text-muted opacity-70">
            {help}
          </span>
        )}
      </div>
      {cells.map((cell, i) => {
        if (cell === null) {
          return (
            <div
              key={i}
              className="min-w-0 font-mono text-2xs text-text-muted opacity-50 italic"
            >
              —
            </div>
          );
        }
        const isThisDivergent =
          divergent &&
          populated.length > 1 &&
          populated.some((p) => p.i === i);
        return (
          <div
            key={i}
            className={`min-w-0 rounded-sm pl-2 py-1 ${
              isThisDivergent ? "border-l-2 border-accent bg-accent/5" : ""
            }`}
          >
            {cell.render}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Cell builders. Each returns a CellSpec so CompareRow can compute
// divergence + render side-by-side.
// ─────────────────────────────────────────────────────────────────────

function statusCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (b.invLoading) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  if (b.invError || !b.inv)
    return { key: "__error__", render: <span className="text-2xs text-text-danger font-mono">failed</span> };
  const inv = b.inv;
  const live = isInvestigationLive(inv.status);
  return {
    key: inv.status,
    render: (
      <span className="inline-flex items-center gap-1.5">
        <span
          aria-hidden
          className="inline-block h-2 w-2 rounded-full"
          style={{
            background: STATUS_DOT[inv.status] ?? "#9aa0a6",
            boxShadow: live ? `0 0 6px ${STATUS_DOT[inv.status]}` : "none",
          }}
        />
        <span className="font-mono text-xs text-foreground">
          {humanize(inv.status)}
        </span>
      </span>
    ),
  };
}

function kindCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="quarter" /> };
  return {
    key: b.inv.kind,
    render: (
      <span className="font-mono text-xs text-foreground">
        {humanize(b.inv.kind)}
      </span>
    ),
  };
}

function strategyCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  return {
    key: b.inv.strategy_family || "",
    render: (
      <span className="font-mono text-xs text-foreground">
        {humanize(b.inv.strategy_family) || "—"}
      </span>
    ),
  };
}

function progressCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  const inv = b.inv;
  // Divergence bucket by scale of activity, not exact turn counts (a
  // 34-vs-35 turn split is not meaningful).
  const bucket = `${bucketize(inv.branch_count, [1, 3, 8])}/${bucketize(inv.message_count, [10, 50, 200, 800])}`;
  return {
    key: bucket,
    render: (
      <div className="flex flex-col gap-1 min-w-0">
        <div className="flex items-center gap-3 font-mono text-2xs text-text-muted">
          <span className="inline-flex items-center gap-1">
            <GitBranch className="h-3 w-3" />
            {inv.branch_count}
          </span>
          <span className="inline-flex items-center gap-1">
            <Rows className="h-3 w-3" />
            {inv.message_count}
          </span>
          <span className="text-text-muted opacity-60">
            {inv.outcome_count} outcome{inv.outcome_count === 1 ? "" : "s"}
          </span>
        </div>
      </div>
    ),
  };
}

function bucketize(n: number, edges: number[]): string {
  for (let i = 0; i < edges.length; i++) {
    if (n < edges[i]) return `<${edges[i]}`;
  }
  return `>=${edges[edges.length - 1]}`;
}

function primaryOutcomeCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="full" /> };
  const inv = b.inv;
  if (!inv.primary_outcome_id) {
    return {
      key: "__none__",
      render: (
        <span className="font-mono text-2xs text-text-muted italic">
          No primary outcome
        </span>
      ),
    };
  }
  const kind = inv.primary_outcome_kind ?? "";
  const polarity = inv.primary_outcome_polarity ?? "inconclusive";
  return {
    key: `${kind}:${polarity}`,
    render: (
      <div className="flex flex-col gap-1 min-w-0">
        <div className="flex items-center gap-1.5 flex-wrap">
          {kind && <OutcomeKindBadge kind={kind} />}
          <OutcomePolarityBadge polarity={polarity} showLabel size="sm" />
        </div>
        {inv.primary_outcome_verdict_head && (
          <p className="font-mono text-2xs text-text-muted line-clamp-3">
            {inv.primary_outcome_verdict_head}
          </p>
        )}
      </div>
    ),
  };
}

function verifierCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  const inv = b.inv;
  const verdict = inv.verifier_verdict ?? null;
  if (!verdict) {
    return {
      key: "__none__",
      render: (
        <span className="font-mono text-2xs text-text-muted italic">
          No verifier run
        </span>
      ),
    };
  }
  const badge =
    verdict === "confirmed" ? (
      <AilaBadge severity="critical" size="sm">
        Confirmed
      </AilaBadge>
    ) : verdict === "refuted" ? (
      <AilaBadge status="completed" size="sm">
        Refuted
      </AilaBadge>
    ) : (
      <AilaBadge severity="medium" size="sm">
        {humanize(verdict)}
      </AilaBadge>
    );
  return {
    key: verdict,
    render: (
      <div className="flex flex-col gap-1">
        {badge}
        {inv.verifier_confidence != null && (
          <span className="font-mono text-2xs text-text-muted">
            conf {inv.verifier_confidence.toFixed(2)}
          </span>
        )}
      </div>
    ),
  };
}

function costCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="full" /> };
  const inv = b.inv;
  const actual = inv.cost_actual_usd ?? 0;
  const budget = inv.cost_budget_usd ?? 0;
  const bar = budget > 0 ? Math.min(100, (actual / budget) * 100) : 0;
  // Divergence bucket by cost decile so $12.34 vs $12.90 doesn't lie
  // to the operator about "different".
  const bucket = `${Math.round(actual)}`;
  return {
    key: bucket,
    render: (
      <div className="flex flex-col gap-1 min-w-0">
        <div className="flex items-baseline gap-1.5">
          <span className="font-mono text-sm text-foreground font-semibold">
            {fmtUsd(actual)}
          </span>
          <span className="font-mono text-2xs text-text-muted">
            / {fmtUsd(budget)}
          </span>
        </div>
        <div
          className="h-1 rounded-full overflow-hidden"
          style={{ background: "color-mix(in srgb, var(--color-text-muted) 22%, transparent)" }}
        >
          <div
            style={{
              width: `${bar}%`,
              height: "100%",
              background:
                bar >= 90
                  ? "var(--color-accent)"
                  : "color-mix(in srgb, var(--color-accent) 60%, transparent)",
            }}
          />
        </div>
        <div className="flex items-center gap-2 font-mono text-3xs text-text-muted">
          <span title="LLM tokens">L {fmtUsd(inv.llm_tokens_cost_usd)}</span>
          <span title="MCP calls">M {fmtUsd(inv.mcp_calls_cost_usd)}</span>
          <span title="Fuzz infra">F {fmtUsd(inv.fuzz_infra_cost_usd)}</span>
        </div>
      </div>
    ),
  };
}

function findingsCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (!b.inv) return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  const ids = b.inv.linked_finding_ids ?? [];
  return {
    key: String(ids.length),
    render: (
      <div className="flex flex-col gap-1 min-w-0">
        <span className="font-mono text-sm text-foreground font-semibold">
          {ids.length}
        </span>
        {ids.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {ids.slice(0, 4).map((fid) => (
              <Link
                key={fid}
                to={`/vr/findings/${fid}`}
                className="font-mono text-3xs px-1.5 py-0.5 rounded-sm bg-surface-elevated text-text hover:text-accent inline-flex items-center gap-1"
                title={fid}
              >
                <ArrowSquareOut className="h-2.5 w-2.5" />
                {fid.slice(0, 8)}
              </Link>
            ))}
            {ids.length > 4 && (
              <span className="font-mono text-3xs text-text-muted px-1 py-0.5">
                +{ids.length - 4}
              </span>
            )}
          </div>
        )}
      </div>
    ),
  };
}

function hypothesesCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (b.hypsLoading && !b.hyps.length) {
    return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  }
  const counts = { live: 0, rejected: 0, resolved: 0, mixed: 0 };
  for (const h of b.hyps) counts[h.state]++;
  const total = b.hyps.length;
  return {
    key: `${counts.live}/${counts.rejected}/${counts.resolved}/${counts.mixed}`,
    render: (
      <div className="flex flex-col gap-1 min-w-0">
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-sm text-foreground font-semibold">
            {total}
          </span>
          <span className="font-mono text-2xs text-text-muted">total</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {counts.live > 0 && (
            <AilaBadge status="running" size="sm">
              {counts.live} live
            </AilaBadge>
          )}
          {counts.resolved > 0 && (
            <AilaBadge status="completed" size="sm">
              {counts.resolved} resolved
            </AilaBadge>
          )}
          {counts.rejected > 0 && (
            <AilaBadge severity="low" size="sm">
              {counts.rejected} rejected
            </AilaBadge>
          )}
          {counts.mixed > 0 && (
            <AilaBadge severity="medium" size="sm">
              {counts.mixed} mixed
            </AilaBadge>
          )}
        </div>
      </div>
    ),
  };
}

function outcomeMixCell(b: Bundle): CellSpec | null {
  if (!b.id) return null;
  if (b.outcomesLoading && b.outcomes.length === 0) {
    return { key: "__loading__", render: <LoadingSkeleton size="sm" width="half" /> };
  }
  const byKind = new Map<string, number>();
  for (const o of b.outcomes) byKind.set(o.outcome_kind, (byKind.get(o.outcome_kind) ?? 0) + 1);
  if (byKind.size === 0) {
    return {
      key: "__none__",
      render: (
        <span className="font-mono text-2xs text-text-muted italic">
          No outcomes yet
        </span>
      ),
    };
  }
  const entries = Array.from(byKind.entries()).sort((a, b) => b[1] - a[1]);
  const key = entries.map(([k, n]) => `${k}:${n}`).join("|");
  return {
    key,
    render: (
      <div className="flex flex-col gap-1">
        {entries.slice(0, 5).map(([kind, n]) => (
          <div key={kind} className="flex items-center gap-1.5 min-w-0">
            <OutcomeKindBadge kind={kind} />
            <span className="font-mono text-2xs text-text-muted">× {n}</span>
          </div>
        ))}
      </div>
    ),
  };
}

// ─────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────

export function InvestigationComparePage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Fixed-length slot array; a `null` slot renders as an empty picker.
  // Default: 2 slots. Grows/shrinks between 1 and MAX_COLUMNS on demand.
  const rawIds = searchParams.get(IDS_PARAM);
  const initialIds: string[] = rawIds
    ? rawIds
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
        .slice(0, MAX_COLUMNS)
    : [];
  const initialSlotCount = Math.max(2, Math.min(MAX_COLUMNS, initialIds.length || 2));

  const [slots, setSlots] = useState<(string | null)[]>(() => {
    const arr: (string | null)[] = Array(initialSlotCount).fill(null);
    for (let i = 0; i < Math.min(initialIds.length, initialSlotCount); i++) {
      arr[i] = initialIds[i];
    }
    return arr;
  });

  function commitSlots(next: (string | null)[]) {
    setSlots(next);
    const serialized = next
      .filter((s): s is string => !!s && s.length > 0)
      .join(",");
    const nextParams = new URLSearchParams(searchParams);
    if (serialized) {
      nextParams.set(IDS_PARAM, serialized);
    } else {
      nextParams.delete(IDS_PARAM);
    }
    setSearchParams(nextParams, { replace: true });
  }

  function setSlot(i: number, id: string | null) {
    const next = slots.slice();
    next[i] = id;
    commitSlots(next);
  }

  function addSlot() {
    if (slots.length >= MAX_COLUMNS) return;
    commitSlots([...slots, null]);
  }

  function removeSlot(i: number) {
    if (slots.length <= 1) return;
    const next = slots.slice();
    next.splice(i, 1);
    commitSlots(next);
  }

  // Investigation list is the source of the picker candidates. Same
  // filters as InvestigationsListPage default view: broad workspace
  // window, no server-side status/kind filter.
  const listQuery = useInvestigations({ offset: 0, limit: 200 });
  const investigations = listQuery.data?.data ?? [];

  const targetMap = useTargetMap();
  const targetLabel = (targetId: string) =>
    targetMap.get(targetId)?.display_name ?? targetId.slice(0, 8);

  const bundles = useCompareBundles(slots);
  const populatedCount = slots.filter((s): s is string => !!s).length;

  return (
    <div className="flex flex-col gap-6">
      {/* Intro strip -- states the point of the screen without cargo. */}
      <AilaCard techBorder padding="sm">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-start gap-3 min-w-0">
            <div
              aria-hidden
              className="rounded-sm p-2 shrink-0"
              style={{ background: "color-mix(in srgb, var(--color-accent) 14%, transparent)" }}
            >
              <Scales className="h-5 w-5 text-accent" weight="fill" />
            </div>
            <div className="flex flex-col gap-0.5 min-w-0">
              <p className="font-mono text-sm text-foreground font-semibold">
                Compare investigations side by side
              </p>
              <p className="font-mono text-2xs text-text-muted">
                Pick up to {MAX_COLUMNS} investigations. Cells that diverge
                across columns get a left accent so variant hunts are
                scannable.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {slots.length < MAX_COLUMNS && (
              <button
                type="button"
                onClick={addSlot}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-sm font-mono text-xs border border-border-default hover:border-accent hover:text-accent"
              >
                <Plus className="h-3.5 w-3.5" /> Add column
              </button>
            )}
            <span className="font-mono text-2xs text-text-muted">
              {populatedCount}/{slots.length} selected
            </span>
          </div>
        </div>
      </AilaCard>

      {/* Picker row -- one card per slot. */}
      <div
        className="grid gap-3"
        style={{
          gridTemplateColumns: `repeat(${slots.length}, minmax(0, 1fr))`,
        }}
      >
        {slots.map((id, i) => (
          <div key={i} className="flex flex-col gap-2 min-w-0">
            <InvestigationPicker
              slotIndex={i}
              currentId={id}
              otherIds={slots.filter((_, j) => j !== i)}
              investigations={investigations}
              targetLabel={targetLabel}
              onPick={(picked) => setSlot(i, picked)}
              onClear={() => setSlot(i, null)}
            />
            {slots.length > 1 && (
              <button
                type="button"
                onClick={() => removeSlot(i)}
                className="self-end text-2xs font-mono text-text-muted hover:text-text-danger inline-flex items-center gap-1"
                aria-label={`Remove slot ${i + 1}`}
              >
                <X className="h-3 w-3" /> Remove column
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Compare grid -- one row per facet, one cell per slot. */}
      {populatedCount === 0 ? (
        <EmptyState
          icon={<Scales className="h-7 w-7" weight="duotone" />}
          title="Pick at least one investigation to compare"
          description="Select investigations from the pickers above. Two or more populated columns unlock divergence highlighting."
          action={{ label: "Browse investigations", href: "/vr/investigations" }}
        />
      ) : listQuery.isError && populatedCount === 0 ? (
        <AilaCard className="border-border-danger" techBorder>
          <p className="text-sm text-text-danger font-mono">
            Failed to load the investigations list.
          </p>
        </AilaCard>
      ) : (
        <AilaCard techBorder padding="sm" className="overflow-x-auto">
          <div className="min-w-full flex flex-col">
            {/* Header row -- column titles for context. */}
            <div
              className="grid gap-3 border-b border-border-default pb-2 px-2 items-end"
              style={{
                gridTemplateColumns: `160px repeat(${slots.length}, minmax(0, 1fr))`,
              }}
            >
              <span className="font-mono text-2xs uppercase tracking-wide text-text-muted">
                Facet
              </span>
              {bundles.map((b, i) => (
                <div key={i} className="min-w-0 flex flex-col gap-0.5">
                  {b.inv ? (
                    <>
                      <Link
                        to={`/vr/investigations/${b.inv.id}`}
                        className="font-mono text-xs font-semibold text-foreground truncate hover:underline"
                        title={b.inv.title}
                      >
                        {b.inv.title || b.inv.id.slice(0, 8)}
                      </Link>
                      <span className="font-mono text-3xs text-text-muted truncate">
                        {targetLabel(b.inv.target_id)}
                      </span>
                    </>
                  ) : (
                    <span className="font-mono text-2xs text-text-muted italic">
                      No selection
                    </span>
                  )}
                </div>
              ))}
            </div>

            <CompareRow
              label="Status"
              slots={slots.length}
              cells={bundles.map(statusCell)}
            />
            <CompareRow
              label="Kind"
              slots={slots.length}
              cells={bundles.map(kindCell)}
            />
            <CompareRow
              label="Strategy"
              slots={slots.length}
              cells={bundles.map(strategyCell)}
            />
            <CompareRow
              label="Progress"
              help="branches · messages · outcomes"
              slots={slots.length}
              cells={bundles.map(progressCell)}
            />
            <CompareRow
              label="Primary outcome"
              slots={slots.length}
              cells={bundles.map(primaryOutcomeCell)}
            />
            <CompareRow
              label="Verifier"
              slots={slots.length}
              cells={bundles.map(verifierCell)}
            />
            <CompareRow
              label="Cost"
              help="actual / budget · L=llm M=mcp F=fuzz"
              slots={slots.length}
              cells={bundles.map(costCell)}
            />
            <CompareRow
              label="Findings"
              slots={slots.length}
              cells={bundles.map(findingsCell)}
            />
            <CompareRow
              label="Hypotheses"
              help="live / resolved / rejected / mixed"
              slots={slots.length}
              cells={bundles.map(hypothesesCell)}
            />
            <CompareRow
              label="Outcome mix"
              help="counts per outcome kind"
              slots={slots.length}
              cells={bundles.map(outcomeMixCell)}
            />
          </div>
        </AilaCard>
      )}
    </div>
  );
}
