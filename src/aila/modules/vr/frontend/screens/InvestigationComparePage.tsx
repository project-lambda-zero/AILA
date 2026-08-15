import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQueries } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { SectionHeader, MonoBadge, Segmented } from "@/components/aila/mock";

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
import { personaMeta } from "../components/personaMeta";

// ---------------------------------------------------------------------------
// Constants + tiny formatters.
// ---------------------------------------------------------------------------
const MAX_COLUMNS = 4;
const IDS_PARAM = "ids";

const STATUS_META: Record<
  InvestigationStatus,
  { tone: string; label: string }
> = {
  created: { tone: "muted", label: "created" },
  running: { tone: "ok", label: "running" },
  paused: { tone: "warn", label: "paused" },
  completed: { tone: "info", label: "completed" },
  failed: { tone: "critical", label: "failed" },
  abandoned: { tone: "muted", label: "abandoned" },
  stalled: { tone: "muted", label: "stalled" },
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

// ---------------------------------------------------------------------------
// Per-column data bundle -- reuses the EXACT query keys as
// useInvestigation / useInvestigationOutcomes / useInvestigationHypotheses so
// TanStack cache hits are shared across pages.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Column picker -- mono search over the workspace investigation list.
// ---------------------------------------------------------------------------
function InvestigationPicker({
  slotIndex,
  currentId,
  otherIds,
  investigations,
  targetLabel,
  onPick,
  onClear,
  onRemoveSlot,
  removable,
}: {
  slotIndex: number;
  currentId: string | null;
  otherIds: readonly (string | null)[];
  investigations: VRInvestigationSummary[];
  targetLabel: (targetId: string) => string;
  onPick: (id: string) => void;
  onClear: () => void;
  onRemoveSlot: () => void;
  removable: boolean;
}) {
  const [q, setQ] = useState("");
  const current = currentId
    ? investigations.find((i) => i.id === currentId)
    : undefined;

  const matches = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const taken = otherIds.filter((s): s is string => !!s);
    const pool = investigations.filter(
      (inv) => inv.id !== currentId && !taken.includes(inv.id),
    );
    if (!needle) return pool.slice(0, 12);
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
      .slice(0, 12);
  }, [q, investigations, currentId, otherIds, targetLabel]);

  return (
    <WindowPanel
      title={`slot ${slotIndex + 1}`}
      tone={current ? "info" : "muted"}
      actions={
        <div className="flex items-center" style={{ gap: 6 }}>
          {current && (
            <IconButton
              label="clear"
              onClick={onClear}
              ariaLabel={`Clear slot ${slotIndex + 1}`}
            />
          )}
          {removable && (
            <IconButton
              label="\u00d7"
              onClick={onRemoveSlot}
              ariaLabel={`Remove slot ${slotIndex + 1}`}
            />
          )}
        </div>
      }
    >
      {current ? (
        <div className="flex flex-col" style={{ gap: 6 }}>
          <div className="flex items-center" style={{ gap: 8, minWidth: 0 }}>
            <MonoBadge tone={STATUS_META[current.status].tone}>
              {STATUS_META[current.status].label}
            </MonoBadge>
            <Link
              to={`/vr/investigations/${current.id}`}
              className="font-mono"
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: "var(--text-primary)",
                textDecoration: "none",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                minWidth: 0,
              }}
              title={current.title}
            >
              {current.title || current.id.slice(0, 8)}
            </Link>
          </div>
          <span
            className="font-mono"
            style={{
              fontSize: 10,
              color: "var(--text-muted)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {targetLabel(current.target_id)} · {humanize(current.kind)}
          </span>
        </div>
      ) : (
        <div className="flex flex-col" style={{ gap: 8 }}>
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="find investigation…"
            aria-label={`Search investigations for slot ${slotIndex + 1}`}
            className="font-mono"
            style={{
              width: "100%",
              padding: "5px 8px",
              fontSize: 11,
              color: "var(--text-primary)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              outline: "none",
            }}
          />
          <ul
            role="listbox"
            aria-label={`Slot ${slotIndex + 1} candidates`}
            className="flex flex-col"
            style={{
              gap: 2,
              maxHeight: 220,
              overflowY: "auto",
              margin: 0,
              padding: 0,
              listStyle: "none",
            }}
          >
            {matches.length === 0 && (
              <li
                className="font-mono"
                style={{
                  fontSize: 10,
                  color: "var(--text-faint)",
                  padding: "6px 8px",
                }}
              >
                no matches.
              </li>
            )}
            {matches.map((inv) => (
              <li key={inv.id}>
                <button
                  type="button"
                  onClick={() => {
                    onPick(inv.id);
                    setQ("");
                  }}
                  className="font-mono"
                  style={{
                    display: "flex",
                    width: "100%",
                    padding: "5px 8px",
                    gap: 8,
                    alignItems: "center",
                    background: "transparent",
                    border: "1px solid transparent",
                    borderRadius: 2,
                    textAlign: "left",
                    cursor: "pointer",
                    color: "var(--text-primary)",
                    minWidth: 0,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "var(--surface-hover)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "transparent";
                  }}
                >
                  <MonoBadge tone={STATUS_META[inv.status].tone}>
                    {STATUS_META[inv.status].label}
                  </MonoBadge>
                  <span
                    className="flex flex-col"
                    style={{ minWidth: 0, flex: 1 }}
                  >
                    <span
                      style={{
                        fontSize: 11,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={inv.title || inv.id}
                    >
                      {inv.title || inv.id.slice(0, 8)}
                    </span>
                    <span
                      style={{
                        fontSize: 9.5,
                        color: "var(--text-faint)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {targetLabel(inv.target_id)} · {humanize(inv.kind)}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Column view -- header (persona tile + title + status) + brief-row mock
// list + outcome list.
// ---------------------------------------------------------------------------
function ColumnView({
  bundle,
  targetLabel,
  divergentFields,
  viewMode,
}: {
  bundle: Bundle;
  targetLabel: (targetId: string) => string;
  divergentFields: ReadonlySet<CompareFacet>;
  viewMode: "rows" | "scales";
}) {
  if (!bundle.id) {
    return (
      <WindowPanel title="empty" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-faint)" }}
        >
          pick an investigation via the slot above.
        </p>
      </WindowPanel>
    );
  }

  if (bundle.invLoading && !bundle.inv) {
    return (
      <WindowPanel title="loading" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          fetching investigation…
        </p>
      </WindowPanel>
    );
  }

  if (bundle.invError || !bundle.inv) {
    return (
      <WindowPanel title="load error" tone="warn">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          failed to load investigation {bundle.id?.slice(0, 8)}.
        </p>
      </WindowPanel>
    );
  }

  const inv = bundle.inv;
  const meta = STATUS_META[inv.status];
  // Investigations don't carry a single persona; seed the tile off
  // strategy_family so operators can eyeball same-strategy columns fast.
  // personaMeta() falls back to a neutral hue + "?" for unknown keys.
  const pm = personaMeta(inv.strategy_family);
  const tileInitial =
    (inv.title || inv.strategy_family || inv.id).trim().charAt(0).toUpperCase() ||
    pm.initial;
  const budget = inv.cost_budget_usd ?? 0;
  const actual = inv.cost_actual_usd ?? 0;
  const bar = budget > 0 ? Math.min(100, (actual / budget) * 100) : 0;

  const outcomeMix = new Map<string, number>();
  for (const o of bundle.outcomes)
    outcomeMix.set(o.outcome_kind, (outcomeMix.get(o.outcome_kind) ?? 0) + 1);
  const outcomeMixEntries = Array.from(outcomeMix.entries()).sort(
    (a, b) => b[1] - a[1],
  );

  const hypCounts = { live: 0, rejected: 0, resolved: 0, mixed: 0 };
  for (const h of bundle.hyps) hypCounts[h.state]++;

  const verdict = inv.verifier_verdict ?? null;
  const verdictTone =
    verdict === "confirmed"
      ? "critical"
      : verdict === "refuted"
        ? "ok"
        : verdict
          ? "medium"
          : "muted";

  const rows: {
    facet: CompareFacet;
    label: string;
    value: React.ReactNode;
  }[] = [
    {
      facet: "status",
      label: "status",
      value: <MonoBadge tone={meta.tone}>{meta.label}</MonoBadge>,
    },
    {
      facet: "kind",
      label: "kind",
      value: (
        <span style={{ color: "var(--text-primary)" }}>
          {humanize(inv.kind)}
        </span>
      ),
    },
    {
      facet: "strategy",
      label: "strategy",
      value: (
        <span style={{ color: "var(--text-primary)" }}>
          {humanize(inv.strategy_family) || "—"}
        </span>
      ),
    },
    {
      facet: "progress",
      label: "progress",
      value: (
        <span className="flex items-center flex-wrap" style={{ gap: 10 }}>
          <span>br {inv.branch_count}</span>
          <span>msg {inv.message_count}</span>
          <span style={{ color: "var(--text-faint)" }}>
            oc {inv.outcome_count}
          </span>
        </span>
      ),
    },
    {
      facet: "primary",
      label: "primary",
      value: inv.primary_outcome_id ? (
        <span className="flex items-center flex-wrap" style={{ gap: 6 }}>
          {inv.primary_outcome_kind && (
            <OutcomeKindBadge kind={inv.primary_outcome_kind} />
          )}
          <OutcomePolarityBadge
            polarity={inv.primary_outcome_polarity ?? "inconclusive"}
            showLabel
            size="sm"
          />
        </span>
      ) : (
        <span style={{ color: "var(--text-faint)", fontStyle: "italic" }}>
          none
        </span>
      ),
    },
    {
      facet: "verifier",
      label: "verifier",
      value: verdict ? (
        <span className="flex items-center" style={{ gap: 6 }}>
          <MonoBadge tone={verdictTone}>{humanize(verdict)}</MonoBadge>
          {inv.verifier_confidence != null && (
            <span style={{ color: "var(--text-faint)", fontSize: 10 }}>
              conf {inv.verifier_confidence.toFixed(2)}
            </span>
          )}
        </span>
      ) : (
        <span style={{ color: "var(--text-faint)", fontStyle: "italic" }}>
          no run
        </span>
      ),
    },
    {
      facet: "cost",
      label: "cost",
      value: (
        <div className="flex flex-col" style={{ gap: 4, minWidth: 0 }}>
          <span className="flex items-baseline" style={{ gap: 6 }}>
            <span style={{ fontWeight: 600 }}>{fmtUsd(actual)}</span>
            <span style={{ color: "var(--text-faint)", fontSize: 10 }}>
              / {fmtUsd(budget)}
            </span>
          </span>
          <span
            style={{
              display: "block",
              height: 4,
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              overflow: "hidden",
            }}
          >
            <span
              style={{
                display: "block",
                height: "100%",
                width: `${bar}%`,
                background:
                  bar >= 90 ? "var(--accent)" : "var(--status-info)",
              }}
            />
          </span>
        </div>
      ),
    },
    {
      facet: "findings",
      label: "findings",
      value: (
        <span className="flex items-center flex-wrap" style={{ gap: 6 }}>
          <span style={{ fontWeight: 600 }}>
            {(inv.linked_finding_ids ?? []).length}
          </span>
          {(inv.linked_finding_ids ?? []).slice(0, 3).map((fid) => (
            <Link
              key={fid}
              to={`/vr/findings/${fid}`}
              className="font-mono"
              style={{
                fontSize: 9,
                color: "var(--text-muted)",
                textDecoration: "none",
                border: "1px solid var(--border-soft)",
                padding: "1px 5px",
                borderRadius: 2,
              }}
              title={fid}
            >
              {fid.slice(0, 8)}
            </Link>
          ))}
        </span>
      ),
    },
    {
      facet: "hypotheses",
      label: "hypotheses",
      value: (
        <span className="flex items-center flex-wrap" style={{ gap: 6 }}>
          <span style={{ fontWeight: 600 }}>{bundle.hyps.length}</span>
          {hypCounts.live > 0 && (
            <MonoBadge tone="ok">{hypCounts.live} live</MonoBadge>
          )}
          {hypCounts.resolved > 0 && (
            <MonoBadge tone="info">{hypCounts.resolved} res</MonoBadge>
          )}
          {hypCounts.rejected > 0 && (
            <MonoBadge tone="muted">{hypCounts.rejected} rej</MonoBadge>
          )}
          {hypCounts.mixed > 0 && (
            <MonoBadge tone="medium">{hypCounts.mixed} mix</MonoBadge>
          )}
        </span>
      ),
    },
    {
      facet: "mix",
      label: "outcome mix",
      value:
        outcomeMixEntries.length === 0 ? (
          <span style={{ color: "var(--text-faint)", fontStyle: "italic" }}>
            no outcomes
          </span>
        ) : (
          <div className="flex flex-col" style={{ gap: 3 }}>
            {outcomeMixEntries.slice(0, 5).map(([kind, n]) => (
              <span
                key={kind}
                className="flex items-center"
                style={{ gap: 6 }}
              >
                <OutcomeKindBadge kind={kind} />
                <span style={{ color: "var(--text-faint)", fontSize: 10 }}>
                  × {n}
                </span>
              </span>
            ))}
          </div>
        ),
    },
  ];

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <WindowPanel title="brief" tone="accent">
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div className="flex items-center" style={{ gap: 10 }}>
            <span
              aria-hidden
              className="flex items-center justify-center font-mono uppercase"
              style={{
                width: 22,
                height: 22,
                flex: "0 0 auto",
                fontSize: 11,
                color: pm.hue,
                background: `color-mix(in srgb, ${pm.hue} 18%, transparent)`,
                border: `1px solid color-mix(in srgb, ${pm.hue} 40%, transparent)`,
                borderRadius: 3,
              }}
            >
              {tileInitial}
            </span>
            <div
              className="flex flex-col"
              style={{ minWidth: 0, gap: 2, flex: 1 }}
            >
              <Link
                to={`/vr/investigations/${inv.id}`}
                className="font-mono"
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  textDecoration: "none",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={inv.title}
              >
                {inv.title || inv.id.slice(0, 8)}
              </Link>
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  color: "var(--text-faint)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {targetLabel(inv.target_id)}
              </span>
            </div>
            <MonoBadge tone={meta.tone}>{meta.label}</MonoBadge>
          </div>
          <div className="flex flex-col">
            {rows.map((r, i) => {
              const divergent = divergentFields.has(r.facet);
              return (
                <div
                  key={r.label}
                  className="grid items-start"
                  style={{
                    gridTemplateColumns: "84px 1fr",
                    gap: 10,
                    padding: "6px 0",
                    borderTop:
                      i === 0 ? "none" : "1px solid var(--border-faint)",
                    borderLeft: divergent
                      ? "2px solid var(--accent)"
                      : undefined,
                    paddingLeft: divergent ? 8 : undefined,
                    marginLeft: divergent ? -10 : undefined,
                    background: divergent
                      ? "color-mix(in srgb, var(--accent) 5%, transparent)"
                      : undefined,
                  }}
                >
                  <span
                    className="font-mono uppercase"
                    style={{
                      fontSize: 9,
                      letterSpacing: "0.12em",
                      color: "var(--text-faint)",
                      paddingTop: 2,
                    }}
                  >
                    {r.label}
                  </span>
                  <span
                    className="font-mono"
                    style={{
                      fontSize: 11,
                      color: "var(--text-primary)",
                      minWidth: 0,
                    }}
                  >
                    {r.value}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </WindowPanel>

      {viewMode === "rows" && (
        <WindowPanel
          title={`outcomes (${bundle.outcomes.length})`}
          tone="muted"
          flush
        >
          {bundle.outcomes.length === 0 ? (
            <p
              className="font-mono"
              style={{
                fontSize: 11,
                padding: 12,
                color: "var(--text-faint)",
                fontStyle: "italic",
              }}
            >
              no outcomes yet.
            </p>
          ) : (
            <div className="flex flex-col">
              {bundle.outcomes.slice(0, 8).map((o, i) => (
                <div
                  key={o.id}
                  className="flex items-center"
                  style={{
                    gap: 8,
                    padding: "8px 12px",
                    borderTop:
                      i === 0 ? "none" : "1px solid var(--border-faint)",
                    minWidth: 0,
                  }}
                >
                  <OutcomeKindBadge kind={o.outcome_kind} />
                  <span
                    className="font-mono"
                    style={{
                      flex: 1,
                      fontSize: 10.5,
                      color: "var(--text-muted)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      minWidth: 0,
                    }}
                    title={o.id}
                  >
                    {o.id.slice(0, 8)} · {o.confidence}
                  </span>
                  <MonoBadge
                    tone={
                      o.dispatch_status === "dispatched"
                        ? "low"
                        : o.dispatch_status === "failed"
                          ? "critical"
                          : o.dispatch_status === "skipped"
                            ? "medium"
                            : "info"
                    }
                  >
                    {o.dispatch_status}
                  </MonoBadge>
                </div>
              ))}
              {bundle.outcomes.length > 8 && (
                <div
                  className="font-mono"
                  style={{
                    padding: "6px 12px",
                    fontSize: 9.5,
                    color: "var(--text-faint)",
                    borderTop: "1px solid var(--border-faint)",
                  }}
                >
                  + {bundle.outcomes.length - 8} more
                </div>
              )}
            </div>
          )}
        </WindowPanel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Divergence detector -- returns a set of facet names that differ across
// populated columns. Used to accent-stripe the corresponding rows.
// ---------------------------------------------------------------------------
type CompareFacet =
  | "status"
  | "kind"
  | "strategy"
  | "progress"
  | "primary"
  | "verifier"
  | "cost"
  | "findings"
  | "hypotheses"
  | "mix";

function bucketize(n: number, edges: number[]): string {
  for (let i = 0; i < edges.length; i++) {
    if (n < edges[i]) return `<${edges[i]}`;
  }
  return `>=${edges[edges.length - 1]}`;
}

function facetKeys(bundle: Bundle): Record<CompareFacet, string> | null {
  const inv = bundle.inv;
  if (!inv) return null;
  const hypCounts = { live: 0, rejected: 0, resolved: 0, mixed: 0 };
  for (const h of bundle.hyps) hypCounts[h.state]++;
  const mix = new Map<string, number>();
  for (const o of bundle.outcomes)
    mix.set(o.outcome_kind, (mix.get(o.outcome_kind) ?? 0) + 1);
  const mixKey = Array.from(mix.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${k}:${n}`)
    .join("|");
  return {
    status: inv.status,
    kind: inv.kind,
    strategy: inv.strategy_family || "",
    progress: `${bucketize(inv.branch_count, [1, 3, 8])}/${bucketize(inv.message_count, [10, 50, 200, 800])}`,
    primary: inv.primary_outcome_id
      ? `${inv.primary_outcome_kind ?? ""}:${inv.primary_outcome_polarity ?? "inconclusive"}`
      : "__none__",
    verifier: inv.verifier_verdict ?? "__none__",
    cost: String(Math.round(inv.cost_actual_usd ?? 0)),
    findings: String((inv.linked_finding_ids ?? []).length),
    hypotheses: `${hypCounts.live}/${hypCounts.rejected}/${hypCounts.resolved}/${hypCounts.mixed}`,
    mix: mixKey || "__none__",
  };
}

function computeDivergence(bundles: Bundle[]): ReadonlySet<CompareFacet> {
  const populated = bundles
    .map(facetKeys)
    .filter((k): k is Record<CompareFacet, string> => k !== null);
  if (populated.length < 2) return new Set();
  const facets: CompareFacet[] = [
    "status",
    "kind",
    "strategy",
    "progress",
    "primary",
    "verifier",
    "cost",
    "findings",
    "hypotheses",
    "mix",
  ];
  const divergent = new Set<CompareFacet>();
  for (const f of facets) {
    const first = populated[0][f];
    if (populated.some((p) => p[f] !== first)) divergent.add(f);
  }
  return divergent;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export function InvestigationComparePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [viewMode, setViewMode] = useState<"rows" | "scales">("rows");

  const rawIds = searchParams.get(IDS_PARAM);
  const initialIds: string[] = rawIds
    ? rawIds
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
        .slice(0, MAX_COLUMNS)
    : [];
  const initialSlotCount = Math.max(
    2,
    Math.min(MAX_COLUMNS, initialIds.length || 2),
  );

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

  const listQuery = useInvestigations({ offset: 0, limit: 200 });
  const investigations = listQuery.data?.data ?? [];

  const targetMap = useTargetMap();
  const targetLabel = (targetId: string) =>
    targetMap.get(targetId)?.display_name ?? targetId.slice(0, 8);

  const bundles = useCompareBundles(slots);
  const populatedCount = slots.filter((s): s is string => !!s).length;
  const divergent = useMemo(() => computeDivergence(bundles), [bundles]);

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="⚖"
        title="Compare Investigations"
        actions={
          <div className="flex items-center" style={{ gap: 10 }}>
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.12em",
                color: "var(--text-faint)",
              }}
            >
              {populatedCount}/{slots.length} selected
            </span>
            <Segmented
              options={[
                { value: "rows", label: "rows" },
                { value: "scales", label: "scales" },
              ]}
              value={viewMode}
              onChange={setViewMode}
            />
            {slots.length < MAX_COLUMNS && (
              <button
                type="button"
                onClick={addSlot}
                className="font-mono uppercase"
                style={{
                  height: 26,
                  padding: "0 11px",
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  borderRadius: 3,
                  border: "1px solid var(--border-soft)",
                  background: "transparent",
                  color: "var(--text-primary)",
                  cursor: "pointer",
                }}
              >
                + add column
              </button>
            )}
          </div>
        }
      />

      {/* Picker strip */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: `repeat(${slots.length}, minmax(220px, 1fr))`,
          gap: 12,
          overflowX: "auto",
        }}
      >
        {slots.map((id, i) => (
          <InvestigationPicker
            key={i}
            slotIndex={i}
            currentId={id}
            otherIds={slots.filter((_, j) => j !== i)}
            investigations={investigations}
            targetLabel={targetLabel}
            onPick={(picked) => setSlot(i, picked)}
            onClear={() => setSlot(i, null)}
            onRemoveSlot={() => removeSlot(i)}
            removable={slots.length > 1}
          />
        ))}
      </div>

      {/* Comparison grid */}
      {populatedCount === 0 ? (
        <WindowPanel title="no columns" tone="muted">
          <div
            className="flex flex-col items-start"
            style={{ gap: 8, padding: "12px 0" }}
          >
            <p
              className="font-mono"
              style={{
                fontSize: 12,
                color: "var(--text-primary)",
              }}
            >
              pick at least one investigation to compare.
            </p>
            <p
              className="font-mono"
              style={{
                fontSize: 10,
                color: "var(--text-muted)",
                lineHeight: 1.5,
              }}
            >
              select investigations from the pickers above. two or more
              populated columns unlock divergence highlighting on facets that
              differ.
            </p>
            <Link
              to="/vr/investigations"
              className="font-mono uppercase"
              style={{
                marginTop: 4,
                height: 26,
                padding: "0 11px",
                fontSize: 9.5,
                letterSpacing: "0.08em",
                borderRadius: 3,
                border: "1px solid var(--accent)",
                background: "var(--accent)",
                color: "var(--text-on-accent)",
                display: "inline-flex",
                alignItems: "center",
                textDecoration: "none",
              }}
            >
              browse investigations
            </Link>
          </div>
        </WindowPanel>
      ) : listQuery.isError && populatedCount === 0 ? (
        <WindowPanel title="load error" tone="warn">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--accent)" }}
          >
            failed to load the investigations list.
          </p>
        </WindowPanel>
      ) : (
        <div
          className="grid"
          style={{
            gridTemplateColumns: `repeat(${slots.length}, minmax(300px, 1fr))`,
            gap: 12,
            overflowX: "auto",
          }}
        >
          {bundles.map((b, i) => (
            <ColumnView
              key={i}
              bundle={b}
              targetLabel={targetLabel}
              divergentFields={divergent}
              viewMode={viewMode}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Icon-only mini button used in slot title bars.
// ---------------------------------------------------------------------------
function IconButton({
  label,
  onClick,
  ariaLabel,
}: {
  label: React.ReactNode;
  onClick: () => void;
  ariaLabel: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={ariaLabel}
      className="font-mono uppercase"
      style={{
        height: 20,
        padding: "0 6px",
        fontSize: 9,
        letterSpacing: "0.08em",
        borderRadius: 2,
        border: "1px solid var(--border-soft)",
        background: "transparent",
        color: "var(--text-muted)",
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  );
}
