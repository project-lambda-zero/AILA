/**
 * MlOpsPage -- god-tier admin console wiring the three model-lifecycle,
 * eval-harness, and prompt-version endpoint families.
 *
 * Routes:
 *   Lifecycle (`aila/api/routers/admin_lifecycle.py`)
 *     per-version metrics table, transitions timeline, route preview,
 *     shadow run + report, row actions (evaluate/approve/promote/rollback/
 *     shadow/canary). promote + rollback are confirm-gated.
 *   Evals (`aila/api/routers/admin_eval.py`)
 *     eval runs table with expandable report JSON, "score version" modal,
 *     "new benchmark" modal, calibrators card with train + promote.
 *   Prompts (`aila/api/routers/admin_prompts.py`)
 *     versions timeline, two-version body diff, "new version" modal,
 *     alias bar with "deploy to alias" -- amber badge when production
 *     lags the latest registered version.
 *
 * Rebuilt to the AILA mock: SectionHeader top with a Segmented switcher for
 * the three concerns, WindowPanels + DataGrid + MonoBadge for content,
 * ModalShell replaces shadcn Dialog. Every data hook is preserved verbatim.
 *
 * All endpoints take a ``key`` (a model / prompt registry key). There is
 * no list-keys endpoint by contract: the operator types the key and the
 * page keeps a rolling list of the ten most-recent keys in localStorage.
 */
import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { Brain } from "@phosphor-icons/react/dist/csr/Brain";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { Play } from "@phosphor-icons/react/dist/csr/Play";
import { Eye } from "@phosphor-icons/react/dist/csr/Eye";
import { GitCommit } from "@phosphor-icons/react/dist/csr/GitCommit";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { Sparkle } from "@phosphor-icons/react/dist/csr/Sparkle";
import { X } from "@phosphor-icons/react/dist/csr/X";

import {
  SectionHeader,
  Segmented,
  MonoBadge,
  DataGrid,
  FilterChip,
  toneColor,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { FeatureBoundary } from "@app/FeatureBoundary";
import { toast } from "@/components/ui/sonner";
import { ApiHttpError } from "@platform/api/http";

import {
  useCalibrators,
  useEvalRuns,
  useLifecycleApprove,
  useLifecycleCanary,
  useLifecycleEvaluate,
  useLifecyclePromote,
  useLifecycleRollback,
  useLifecycleShadow,
  useLifecycleTransitions,
  useLifecycleRoutePreview,
  useLifecycleVersionMetrics,
  usePromoteCalibrator,
  usePromptAliases,
  usePromptVersions,
  useRegisterBenchmark,
  useRegisterPromptVersion,
  useRunEval,
  useSetPromptAlias,
  useShadowReport,
  useShadowRun,
  useTrainCalibrator,
  type BenchmarkCaseSpec,
  type CalibratorVersionInfo,
  type EvalRunInfo,
  type PromptAliasInfo,
  type PromptVersionInfo,
  type ShadowReportInfo,
  type TransitionInfo,
  type VersionMetricsRow,
} from "./mlOpsQueries";

// ---------------------------------------------------------------------------
// Shared inline styles
// ---------------------------------------------------------------------------

const BUTTON_STYLE: CSSProperties = {
  height: 24, padding: "0 9px", fontSize: 9, fontFamily: "var(--font-mono)",
  letterSpacing: "0.08em", textTransform: "uppercase",
  background: "var(--surface-sunk)", border: "1px solid var(--border-soft)",
  color: "var(--text-primary)", borderRadius: 3, cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: 5,
};

const PRIMARY_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "var(--accent)", border: "1px solid var(--accent)",
  color: "var(--text-on-accent)",
};

const WARN_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "color-mix(in srgb, var(--status-warn) 14%, transparent)",
  border: "1px solid var(--status-warn)", color: "var(--status-warn)",
};

const GHOST_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "transparent", border: "1px solid var(--border-faint)",
  color: "var(--text-muted)",
};

const INPUT_STYLE: CSSProperties = {
  height: 26, padding: "0 8px", fontSize: 11, fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)", border: "1px solid var(--border-soft)",
  color: "var(--text-primary)", borderRadius: 3, width: "100%",
};

const TEXTAREA_STYLE: CSSProperties = {
  padding: "6px 8px", fontSize: 11, fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)", border: "1px solid var(--border-soft)",
  color: "var(--text-primary)", borderRadius: 3, resize: "vertical", width: "100%",
};

const LABEL_STYLE: CSSProperties = {
  fontFamily: "var(--font-mono)", fontSize: 9, letterSpacing: "0.14em",
  color: "var(--text-faint)", textTransform: "uppercase",
};

const ERROR_TEXT_STYLE: CSSProperties = {
  fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--status-warn)",
};

const ERROR_BOX_STYLE: CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "6px 10px", fontSize: 11, borderRadius: 3, fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Recent-keys memory -- localStorage-backed rolling list.
// ---------------------------------------------------------------------------

const RECENT_KEYS_STORAGE = "aila.ml-ops.recent-keys.v1";
const RECENT_KEYS_LIMIT = 10;

function loadRecentKeys(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_KEYS_STORAGE);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string").slice(0, RECENT_KEYS_LIMIT);
  } catch {
    return [];
  }
}

function saveRecentKeys(keys: string[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(RECENT_KEYS_STORAGE, JSON.stringify(keys));
  } catch {
    // ignore quota / access errors -- recall degrades to empty on next load
  }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiHttpError) {
    return err.envelope?.message ?? err.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

function stageTone(stage: string | null | undefined): string {
  if (!stage) return "muted";
  const s = stage.toLowerCase();
  if (s === "production") return "info";
  if (s === "rolled_back" || s === "failed") return "critical";
  if (s === "canary") return "medium";
  if (s === "shadow") return "low";
  if (s === "evaluated" || s === "approved") return "info";
  return "muted";
}

function verdictTone(verdict: string | null | undefined): string {
  if (!verdict) return "muted";
  const v = verdict.toLowerCase();
  if (v === "pass" || v === "passed") return "info";
  if (v === "fail" || v === "failed") return "critical";
  if (v === "regression") return "high";
  return "muted";
}

function StageBadge({ stage }: { stage: string | null }) {
  if (!stage) return <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>--</span>;
  return <MonoBadge tone={stageTone(stage)}>{stage}</MonoBadge>;
}

function VerdictBadge({ verdict }: { verdict: string | null }) {
  if (!verdict) return <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>--</span>;
  return <MonoBadge tone={verdictTone(verdict)}>{verdict}</MonoBadge>;
}

// ---------------------------------------------------------------------------
// Modal shell (replaces shadcn Dialog)
// ---------------------------------------------------------------------------

interface ModalShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  tone?: "accent" | "warn" | "muted" | "ok" | "info";
  width?: number;
  children: ReactNode;
}

function ModalShell({ open, onClose, title, tone = "accent", width = 480, children }: ModalShellProps) {
  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, zIndex: 60, padding: 16,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width: "100%", maxWidth: width }}>
        <WindowPanel
          title={title}
          tone={tone}
          actions={
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              style={{
                width: 20, height: 20, background: "transparent", border: 0,
                color: "var(--text-muted)", cursor: "pointer",
                display: "inline-flex", alignItems: "center", justifyContent: "center",
              }}
            >
              <X size={12} aria-hidden />
            </button>
          }
        >
          {children}
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Key picker -- text input + recent-keys chip row.
// ---------------------------------------------------------------------------

interface KeyPickerProps {
  activeKey: string;
  onCommit: (key: string) => void;
}

function KeyPicker({ activeKey, onCommit }: KeyPickerProps) {
  const [draft, setDraft] = useState(activeKey);
  const [recent, setRecent] = useState<string[]>(() => loadRecentKeys());

  useEffect(() => { setDraft(activeKey); }, [activeKey]);

  function commit(next: string) {
    const trimmed = next.trim();
    if (trimmed.length === 0) return;
    const nextRecent = [trimmed, ...recent.filter((k) => k !== trimmed)].slice(0, RECENT_KEYS_LIMIT);
    setRecent(nextRecent);
    saveRecentKeys(nextRecent);
    onCommit(trimmed);
  }

  return (
    <WindowPanel title="registry key">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label htmlFor="ml-ops-key" style={LABEL_STYLE}>MODEL / PROMPT REGISTRY KEY</label>
          <div className="flex" style={{ gap: 8 }}>
            <input
              id="ml-ops-key"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commit(draft);
                }
              }}
              placeholder="e.g. vuln.researcher.system_prompt"
              spellCheck={false}
              style={{ ...INPUT_STYLE, flex: 1 }}
            />
            <button
              type="button"
              onClick={() => commit(draft)}
              disabled={draft.trim().length === 0 || draft.trim() === activeKey}
              style={PRIMARY_BUTTON_STYLE}
            >
              LOAD
            </button>
          </div>
          <p className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.5 }}>
            There is no list-keys endpoint; type the exact registry key or pick a recent one.
            The ten most-recent keys are remembered per-browser.
          </p>
        </div>
        {recent.length > 0 && (
          <div className="flex flex-wrap" style={{ gap: 6 }}>
            {recent.map((k) => (
              <FilterChip
                key={k}
                active={k === activeKey}
                onClick={() => { setDraft(k); commit(k); }}
              >
                {k}
              </FilterChip>
            ))}
          </div>
        )}
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Confirm dialog helper
// ---------------------------------------------------------------------------

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  pending?: boolean;
}

function ConfirmDialog({ open, title, description, confirmLabel, onConfirm, onCancel, pending }: ConfirmDialogProps) {
  return (
    <ModalShell open={open} onClose={onCancel} title={title} tone="warn">
      <div className="flex flex-col" style={{ gap: 12 }}>
        <div
          className="font-mono"
          style={{
            padding: 10, fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55,
            border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            borderRadius: 3,
          }}
        >
          {description}
        </div>
        <div className="flex" style={{ gap: 8 }}>
          <button
            type="button"
            style={{ ...WARN_BUTTON_STYLE, flex: 1 }}
            onClick={onConfirm}
            disabled={pending}
          >
            {pending ? "WORKING\u2026" : confirmLabel.toUpperCase()}
          </button>
          <button
            type="button"
            style={BUTTON_STYLE}
            onClick={onCancel}
            disabled={pending}
          >
            CANCEL
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Tab 1 -- Lifecycle
// ---------------------------------------------------------------------------

type PendingAction =
  | { kind: "promote"; row: VersionMetricsRow }
  | { kind: "rollback"; row: VersionMetricsRow; targetVersion: string };

interface LifecycleTabProps { activeKey: string }

function LifecycleTab({ activeKey }: LifecycleTabProps) {
  const metricsQuery = useLifecycleVersionMetrics(activeKey);
  const transitionsQuery = useLifecycleTransitions(activeKey);

  const evaluateMutation = useLifecycleEvaluate();
  const approveMutation = useLifecycleApprove();
  const promoteMutation = useLifecyclePromote();
  const rollbackMutation = useLifecycleRollback();
  const shadowMutation = useLifecycleShadow();
  const canaryMutation = useLifecycleCanary();
  const shadowRunMutation = useShadowRun();

  const [pending, setPending] = useState<PendingAction | null>(null);
  const [evalOpen, setEvalOpen] = useState<{ row: VersionMetricsRow } | null>(null);
  const [evalBenchmarkId, setEvalBenchmarkId] = useState("");
  const [canaryOpen, setCanaryOpen] = useState<{ row: VersionMetricsRow } | null>(null);
  const [canaryPercent, setCanaryPercent] = useState(10);
  const [shadowSampleN, setShadowSampleN] = useState(5);
  const [routeOpen, setRouteOpen] = useState(false);
  const [routeInvestigationId, setRouteInvestigationId] = useState("");
  const [routeInvestigationCommitted, setRouteInvestigationCommitted] = useState("");

  const routeQuery = useLifecycleRoutePreview(
    activeKey, routeInvestigationCommitted, routeOpen && routeInvestigationCommitted.length > 0,
  );

  async function handleEvaluate(row: VersionMetricsRow) {
    if (evalBenchmarkId.trim().length === 0) {
      toast.error("benchmark_id is required.");
      return;
    }
    try {
      await evaluateMutation.mutateAsync({
        key: activeKey, version: row.version, benchmark_id: evalBenchmarkId.trim(),
      });
      toast.success(`Evaluated ${row.version} against ${evalBenchmarkId.trim()}.`);
      setEvalOpen(null);
      setEvalBenchmarkId("");
    } catch (err) {
      toast.error(extractErrorMessage(err, "Evaluate failed."));
    }
  }

  async function handleApprove(row: VersionMetricsRow) {
    try {
      await approveMutation.mutateAsync({ key: activeKey, version: row.version, reason: "operator approval" });
      toast.success(`Approver recorded on ${row.version}.`);
    } catch (err) {
      toast.error(extractErrorMessage(err, "Approve failed."));
    }
  }

  async function handleShadow(row: VersionMetricsRow) {
    try {
      await shadowMutation.mutateAsync({ key: activeKey, version: row.version, reason: "operator shadow" });
      toast.success(`${row.version} registered as shadow.`);
    } catch (err) {
      toast.error(extractErrorMessage(err, "Shadow assignment failed."));
    }
  }

  async function handleCanary(row: VersionMetricsRow) {
    try {
      await canaryMutation.mutateAsync({
        key: activeKey, version: row.version, cohort_percent: canaryPercent, reason: "operator canary",
      });
      toast.success(`${row.version} on canary at ${canaryPercent}%.`);
      setCanaryOpen(null);
    } catch (err) {
      toast.error(extractErrorMessage(err, "Canary assignment failed."));
    }
  }

  async function handleConfirmPending() {
    if (!pending) return;
    try {
      if (pending.kind === "promote") {
        await promoteMutation.mutateAsync({
          key: activeKey, version: pending.row.version, reason: "operator promote",
        });
        toast.success(`Promoted ${pending.row.version} to production.`);
      } else {
        await rollbackMutation.mutateAsync({
          key: activeKey,
          version: pending.row.version,
          target_version: pending.targetVersion.length > 0 ? pending.targetVersion : null,
          reason: "operator rollback",
        });
        toast.success(`Rolled back to ${pending.targetVersion || "prior production"}.`);
      }
      setPending(null);
    } catch (err) {
      toast.error(extractErrorMessage(err, "Action failed."));
    }
  }

  async function handleShadowRun(row: VersionMetricsRow) {
    try {
      await shadowRunMutation.mutateAsync({
        key: activeKey, version: row.version, sample_n: shadowSampleN,
      });
      toast.success(`Shadow report generated for ${row.version} (n=${shadowSampleN}).`);
    } catch (err) {
      toast.error(extractErrorMessage(err, "Shadow run failed."));
    }
  }

  const rows = metricsQuery.data?.rows ?? [];
  const transitions = transitionsQuery.data ?? [];

  return (
    <div
      className="grid"
      style={{ gridTemplateColumns: "minmax(0, 3fr) minmax(0, 1fr)", gap: 16 }}
    >
      {/* Left column: metrics + shadow */}
      <div className="flex flex-col" style={{ gap: 16 }}>
        <WindowPanel
          title="per-version metrics"
          actions={
            <button
              type="button"
              onClick={() => setRouteOpen((v) => !v)}
              style={BUTTON_STYLE}
            >
              <Eye size={11} aria-hidden />
              ROUTE PREVIEW
            </button>
          }
          flush
        >
          {routeOpen && (
            <div
              style={{
                padding: 12,
                background: "var(--surface-sunk)",
                borderBottom: "1px solid var(--border-faint)",
              }}
            >
              <div className="flex flex-col sm:flex-row" style={{ gap: 8 }}>
                <input
                  value={routeInvestigationId}
                  onChange={(e) => setRouteInvestigationId(e.target.value)}
                  placeholder="investigation_id"
                  style={{ ...INPUT_STYLE, flex: 1 }}
                />
                <button
                  type="button"
                  onClick={() => setRouteInvestigationCommitted(routeInvestigationId.trim())}
                  disabled={routeInvestigationId.trim().length === 0}
                  style={PRIMARY_BUTTON_STYLE}
                >
                  RESOLVE
                </button>
              </div>
              {routeQuery.isLoading && (
                <p className="font-mono" style={{ marginTop: 8, fontSize: 10.5, color: "var(--text-muted)" }}>
                  Resolving\u2026
                </p>
              )}
              {routeQuery.isError && (
                <p style={{ ...ERROR_TEXT_STYLE, marginTop: 8 }}>
                  {extractErrorMessage(routeQuery.error, "Route resolve failed.")}
                </p>
              )}
              {routeQuery.data && (
                <dl
                  className="grid font-mono"
                  style={{ marginTop: 10, gridTemplateColumns: "max-content 1fr", gap: "4px 16px", fontSize: 10.5 }}
                >
                  <dt style={{ color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 9 }}>RESOLVED VERSION</dt>
                  <dd style={{ color: "var(--text-primary)" }}>{routeQuery.data.version ?? "--"}</dd>
                  <dt style={{ color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 9 }}>BUCKET</dt>
                  <dd style={{ color: "var(--text-primary)" }}>{routeQuery.data.bucket}</dd>
                  <dt style={{ color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 9 }}>ON CANARY</dt>
                  <dd style={{ color: "var(--text-primary)" }}>{routeQuery.data.on_canary ? "yes" : "no"}</dd>
                  <dt style={{ color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 9 }}>CANARY_VERSION</dt>
                  <dd style={{ color: "var(--text-primary)" }}>{routeQuery.data.canary_version ?? "--"}</dd>
                  <dt style={{ color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 9 }}>PRODUCTION_VERSION</dt>
                  <dd style={{ color: "var(--text-primary)" }}>{routeQuery.data.production_version ?? "--"}</dd>
                  <dt style={{ color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 9 }}>COHORT_PERCENT</dt>
                  <dd style={{ color: "var(--text-primary)" }}>{routeQuery.data.cohort_percent ?? "--"}</dd>
                </dl>
              )}
            </div>
          )}

          {metricsQuery.isLoading && <div style={{ padding: 14 }}><LoadingSkeletonGroup lines={5} /></div>}
          {metricsQuery.isError && (
            <p style={{ ...ERROR_TEXT_STYLE, padding: 14 }}>
              {extractErrorMessage(metricsQuery.error, "Failed to load metrics.")}
            </p>
          )}
          {metricsQuery.data && rows.length === 0 && (
            <div
              className="font-mono"
              style={{ padding: 32, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
            >
              No versions found.
              <br />
              No lifecycle rows exist for this key yet.
            </div>
          )}

          {rows.length > 0 && (
            <DataGrid<VersionMetricsRow>
              columns={[
                { label: "VERSION", width: "120px" },
                { label: "STAGE", width: "110px" },
                { label: "EVAL", width: "90px" },
                { label: "APPROVERS", width: "100px" },
                { label: "QUORUM", width: "70px", align: "right" },
                { label: "COST", width: "120px", align: "right" },
                { label: "DRIFT", width: "130px" },
                { label: "ACTIONS", width: "300px" },
              ]}
              rows={rows}
              getKey={(row) => row.version}
              renderCells={(row) => [
                <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.version}</span>,
                <StageBadge stage={row.latest_stage} />,
                <VerdictBadge verdict={row.eval_verdict} />,
                <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
                  {row.approver_count}
                  <span style={{ color: "var(--text-muted)" }}> / {row.evaluated_count}</span>
                </span>,
                <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
                  {(row.quorum_accept_rate * 100).toFixed(0)}%
                </span>,
                <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
                  {`$${row.cost_usd_total.toFixed(4)}`}
                  <span style={{ color: "var(--text-muted)" }}> ({row.cost_call_count})</span>
                </span>,
                <div className="flex flex-col" style={{ gap: 2 }}>
                  <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)" }}>
                    {row.drift_status ?? "--"}
                  </span>
                  <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)" }}>
                    {formatTimestamp(row.drift_last_recorded)}
                  </span>
                </div>,
                <div className="flex flex-wrap justify-end" style={{ gap: 4 }}>
                  <button type="button" style={GHOST_BUTTON_STYLE} onClick={() => setEvalOpen({ row })}>evaluate</button>
                  <button type="button" style={GHOST_BUTTON_STYLE} onClick={() => void handleApprove(row)}>approve</button>
                  <button type="button" style={GHOST_BUTTON_STYLE} onClick={() => setPending({ kind: "promote", row })}>promote</button>
                  <button type="button" style={GHOST_BUTTON_STYLE} onClick={() => setPending({ kind: "rollback", row, targetVersion: "" })}>rollback</button>
                  <button type="button" style={GHOST_BUTTON_STYLE} onClick={() => void handleShadow(row)}>shadow</button>
                  <button type="button" style={GHOST_BUTTON_STYLE} onClick={() => setCanaryOpen({ row })}>canary</button>
                </div>,
              ]}
            />
          )}
        </WindowPanel>

        <ShadowPanel
          activeKey={activeKey}
          rows={rows}
          sampleN={shadowSampleN}
          setSampleN={setShadowSampleN}
          runPending={shadowRunMutation.isPending}
          onRun={handleShadowRun}
        />
      </div>

      {/* Right column: transitions timeline */}
      <WindowPanel title="transitions">
        {transitionsQuery.isLoading && <LoadingSkeletonGroup lines={6} />}
        {transitionsQuery.isError && (
          <p style={ERROR_TEXT_STYLE}>
            {extractErrorMessage(transitionsQuery.error, "Failed to load transitions.")}
          </p>
        )}
        {transitionsQuery.data && transitions.length === 0 && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
            No transitions journaled for this key.
          </p>
        )}
        {transitions.length > 0 && (
          <ol className="flex flex-col" style={{ gap: 10, padding: 0, margin: 0, listStyle: "none" }}>
            {transitions.map((t) => (
              <TransitionEntry key={t.id} transition={t} />
            ))}
          </ol>
        )}
      </WindowPanel>

      {/* Evaluate modal */}
      <ModalShell
        open={evalOpen !== null}
        onClose={() => { setEvalOpen(null); setEvalBenchmarkId(""); }}
        title={`evaluate ${evalOpen?.row.version ?? ""}`}
      >
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>BENCHMARK_ID</label>
            <input
              value={evalBenchmarkId}
              onChange={(e) => setEvalBenchmarkId(e.target.value)}
              placeholder="e.g. vuln-classify-2025q4"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }}
              onClick={() => evalOpen && void handleEvaluate(evalOpen.row)}
              disabled={evaluateMutation.isPending}
            >
              {evaluateMutation.isPending ? "RUNNING\u2026" : "EVALUATE"}
            </button>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => { setEvalOpen(null); setEvalBenchmarkId(""); }}
            >
              CANCEL
            </button>
          </div>
        </div>
      </ModalShell>

      {/* Canary modal */}
      <ModalShell
        open={canaryOpen !== null}
        onClose={() => setCanaryOpen(null)}
        title={`canary ${canaryOpen?.row.version ?? ""}`}
      >
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>COHORT_PERCENT (1-100)</label>
            <input
              type="number"
              min={1}
              max={100}
              value={canaryPercent}
              onChange={(e) => {
                const v = Number.parseInt(e.target.value, 10);
                if (Number.isFinite(v)) setCanaryPercent(Math.min(100, Math.max(1, v)));
              }}
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }}
              onClick={() => canaryOpen && void handleCanary(canaryOpen.row)}
              disabled={canaryMutation.isPending}
            >
              {canaryMutation.isPending ? "ASSIGNING\u2026" : "ASSIGN CANARY"}
            </button>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => setCanaryOpen(null)}
            >
              CANCEL
            </button>
          </div>
        </div>
      </ModalShell>

      {/* Rollback dialog (target version input + confirm) */}
      <ModalShell
        open={pending?.kind === "rollback"}
        onClose={() => setPending(null)}
        title={`rollback ${pending?.kind === "rollback" ? pending.row.version : ""}`}
        tone="warn"
      >
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div
            className="font-mono"
            style={{
              padding: 10, fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55,
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              borderRadius: 3,
            }}
          >
            Flips the production alias for <code>{activeKey}</code> back to the target version.
            Every team's investigations resolve through this alias.
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>TARGET_VERSION (OPTIONAL)</label>
            <input
              value={pending?.kind === "rollback" ? pending.targetVersion : ""}
              onChange={(e) => setPending((prev) =>
                prev?.kind === "rollback" ? { ...prev, targetVersion: e.target.value } : prev,
              )}
              placeholder="leave empty for prior production"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{ ...WARN_BUTTON_STYLE, flex: 1 }}
              onClick={() => void handleConfirmPending()}
              disabled={rollbackMutation.isPending}
            >
              {rollbackMutation.isPending ? "ROLLING BACK\u2026" : "CONFIRM ROLLBACK"}
            </button>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => setPending(null)}
            >
              CANCEL
            </button>
          </div>
        </div>
      </ModalShell>

      {/* Promote confirm */}
      <ConfirmDialog
        open={pending?.kind === "promote"}
        title={`promote ${pending?.kind === "promote" ? pending.row.version : ""} to production?`}
        description={(
          <>
            Flips the production alias for <code>{activeKey}</code>.
            Requires a passing eval and a distinct-approver quorum -- the controller will
            reject the transition if either gate is unmet.
          </>
        )}
        confirmLabel="Confirm promote"
        pending={promoteMutation.isPending}
        onConfirm={() => void handleConfirmPending()}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}

interface ShadowPanelProps {
  activeKey: string;
  rows: VersionMetricsRow[];
  sampleN: number;
  setSampleN: (n: number) => void;
  runPending: boolean;
  onRun: (row: VersionMetricsRow) => Promise<void>;
}

function ShadowPanel({ activeKey, rows, sampleN, setSampleN, runPending, onRun }: ShadowPanelProps) {
  const shadowRows = useMemo(
    () => rows.filter((r) => (r.latest_stage ?? "").toLowerCase() === "shadow"),
    [rows],
  );
  const [selectedVersion, setSelectedVersion] = useState<string>("");

  useEffect(() => {
    if (shadowRows.length > 0 && !shadowRows.some((r) => r.version === selectedVersion)) {
      setSelectedVersion(shadowRows[0]!.version);
    }
    if (shadowRows.length === 0 && selectedVersion !== "") setSelectedVersion("");
  }, [shadowRows, selectedVersion]);

  const reportQuery = useShadowReport(activeKey, selectedVersion, selectedVersion.length > 0);
  const selectedRow = shadowRows.find((r) => r.version === selectedVersion);

  return (
    <WindowPanel title="shadow run + report">
      {shadowRows.length === 0 ? (
        <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
          No version currently sits in the shadow stage. Assign one from the row actions above.
        </p>
      ) : (
        <div className="flex flex-col" style={{ gap: 12 }}>
          <div className="flex flex-wrap items-end" style={{ gap: 10 }}>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label style={LABEL_STYLE}>SHADOW VERSION</label>
              <select
                value={selectedVersion}
                onChange={(e) => setSelectedVersion(e.target.value)}
                style={{ ...INPUT_STYLE, width: 220 }}
              >
                {shadowRows.map((r) => (
                  <option key={r.version} value={r.version}>{r.version}</option>
                ))}
              </select>
            </div>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label style={LABEL_STYLE}>SAMPLE_N</label>
              <input
                type="number"
                min={1}
                max={100}
                value={sampleN}
                onChange={(e) => {
                  const v = Number.parseInt(e.target.value, 10);
                  if (Number.isFinite(v)) setSampleN(Math.min(100, Math.max(1, v)));
                }}
                style={{ ...INPUT_STYLE, width: 96 }}
              />
            </div>
            <button
              type="button"
              onClick={() => selectedRow && void onRun(selectedRow)}
              disabled={runPending || !selectedRow}
              style={PRIMARY_BUTTON_STYLE}
            >
              <Play size={11} aria-hidden />
              {runPending ? "RUNNING\u2026" : "RUN SHADOW"}
            </button>
          </div>

          {reportQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
          {reportQuery.isError && (
            <p style={ERROR_TEXT_STYLE}>
              {extractErrorMessage(reportQuery.error, "Failed to load report.")}
            </p>
          )}
          {reportQuery.data === null && (
            <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
              No report persisted yet -- click Run shadow.
            </p>
          )}
          {reportQuery.data && <ShadowReportView report={reportQuery.data} />}
        </div>
      )}
    </WindowPanel>
  );
}

function ShadowReportView({ report }: { report: ShadowReportInfo }) {
  return (
    <div
      className="flex flex-col"
      style={{
        gap: 10, padding: 12,
        border: "1px solid var(--border-faint)", borderRadius: 3,
        background: "var(--surface-sunk)",
      }}
    >
      <div className="grid" style={{ gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10 }}>
        <ReportMetric label="mean faithfulness" value={report.mean_faithfulness.toFixed(3)} />
        <ReportMetric label="mean determinism" value={report.mean_determinism.toFixed(3)} />
        <ReportMetric
          label="regressions"
          value={String(report.regressions)}
          tone={report.regressions > 0 ? "critical" : "info"}
        />
        <ReportMetric label="samples" value={`${report.sample_succeeded}/${report.sample_attempted}`} />
      </div>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <span style={LABEL_STYLE}>DIFF_SUMMARY</span>
        <pre
          style={{
            maxHeight: 220, overflow: "auto",
            padding: 8, fontSize: 10.5, fontFamily: "var(--font-mono)",
            color: "var(--text-primary)", background: "var(--surface-card)",
            border: "1px solid var(--border-faint)", borderRadius: 3,
            whiteSpace: "pre-wrap", margin: 0,
          }}
        >
          {JSON.stringify(report.diff_summary, null, 2)}
        </pre>
      </div>
      <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)" }}>
        recorded {formatTimestamp(report.created_at)} by {report.actor}
      </span>
    </div>
  );
}

function ReportMetric({ label, value, tone = "muted" }: { label: string; value: string; tone?: string }) {
  const color = tone === "critical" ? toneColor("critical") : tone === "info" ? toneColor("info") : "var(--text-primary)";
  return (
    <div className="flex flex-col" style={{ gap: 4 }}>
      <span style={LABEL_STYLE}>{label.toUpperCase()}</span>
      <span className="font-mono" style={{ fontSize: 14, color }}>{value}</span>
    </div>
  );
}

function TransitionEntry({ transition }: { transition: TransitionInfo }) {
  return (
    <li className="flex" style={{ gap: 8 }}>
      <GitCommit size={12} aria-hidden style={{ marginTop: 2, flex: "0 0 auto", color: "var(--text-muted)" }} />
      <div className="flex flex-col" style={{ gap: 3, minWidth: 0 }}>
        <div className="flex flex-wrap items-center" style={{ gap: 5 }}>
          <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            {transition.version}
          </span>
          <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)" }}>
            {transition.from_stage}
          </span>
          <CaretRight size={10} aria-hidden style={{ color: "var(--text-faint)" }} />
          <StageBadge stage={transition.to_stage} />
        </div>
        {transition.reason && (
          <span className="font-mono" style={{ fontSize: 10, color: "var(--text-muted)", wordBreak: "break-word" }}>
            {transition.reason}
          </span>
        )}
        <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)" }}>
          {formatTimestamp(transition.created_at)} {"\u00b7"} {transition.actor}
        </span>
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Tab 2 -- Evals
// ---------------------------------------------------------------------------

function EvalsTab({ activeKey }: { activeKey: string }) {
  const runsQuery = useEvalRuns(activeKey);
  const scoreMutation = useRunEval();
  const benchMutation = useRegisterBenchmark();

  const [scoreOpen, setScoreOpen] = useState(false);
  const [scoreCandidate, setScoreCandidate] = useState("");
  const [scoreBenchmark, setScoreBenchmark] = useState("");

  const [benchOpen, setBenchOpen] = useState(false);
  const [benchName, setBenchName] = useState("");
  const [benchCasesJson, setBenchCasesJson] = useState("");

  const [taskType, setTaskType] = useState<string>("");
  const [taskTypeDraft, setTaskTypeDraft] = useState<string>("");
  const calibratorsQuery = useCalibrators(taskType.length > 0 ? taskType : null);
  const trainMutation = useTrainCalibrator();
  const promoteCalibratorMutation = usePromoteCalibrator();
  const [approversDraft, setApproversDraft] = useState("");

  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  async function handleScore() {
    if (scoreCandidate.trim().length === 0 || scoreBenchmark.trim().length === 0) {
      toast.error("candidate_version and benchmark_id are required.");
      return;
    }
    try {
      const env = await scoreMutation.mutateAsync({
        key: activeKey,
        candidate_version: scoreCandidate.trim(),
        benchmark_id: scoreBenchmark.trim(),
      });
      toast.success(`Scored ${env.data.candidate_version} \u2192 ${env.data.verdict}.`);
      setScoreOpen(false);
      setScoreCandidate("");
      setScoreBenchmark("");
    } catch (err) {
      toast.error(extractErrorMessage(err, "Eval failed."));
    }
  }

  async function handleRegisterBenchmark() {
    let cases: BenchmarkCaseSpec[];
    try {
      const parsed = JSON.parse(benchCasesJson);
      if (!Array.isArray(parsed)) throw new Error("cases must be an array");
      cases = parsed as BenchmarkCaseSpec[];
    } catch (err) {
      toast.error(`cases must be a JSON array of BenchmarkCaseSpec: ${(err as Error).message}`);
      return;
    }
    if (cases.length === 0) { toast.error("At least one case is required."); return; }
    if (benchName.trim().length === 0) { toast.error("name is required."); return; }
    try {
      const env = await benchMutation.mutateAsync({ key: activeKey, name: benchName.trim(), cases });
      toast.success(`Registered benchmark ${env.data.id} (${env.data.case_count} cases).`);
      setBenchOpen(false);
      setBenchName("");
      setBenchCasesJson("");
    } catch (err) {
      toast.error(extractErrorMessage(err, "Benchmark registration failed."));
    }
  }

  async function handleTrain() {
    if (taskTypeDraft.trim().length === 0) {
      toast.error("task_type is required to train a calibrator.");
      return;
    }
    try {
      const env = await trainMutation.mutateAsync({ task_type: taskTypeDraft.trim() });
      toast.success(`Trained ${env.data.method} for ${env.data.task_type}: ECE ${env.data.ece_before.toFixed(3)} \u2192 ${env.data.ece_after.toFixed(3)}.`);
      setTaskType(taskTypeDraft.trim());
    } catch (err) {
      toast.error(extractErrorMessage(err, "Calibrator training failed."));
    }
  }

  async function handlePromoteCalibrator(row: CalibratorVersionInfo) {
    const approver_ids = approversDraft.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    if (approver_ids.length === 0) {
      toast.error("At least one approver_id is required (comma-separated).");
      return;
    }
    try {
      await promoteCalibratorMutation.mutateAsync({ id: row.id, approver_ids });
      toast.success(`Promoted calibrator ${row.id.slice(0, 8)}\u2026`);
    } catch (err) {
      toast.error(extractErrorMessage(err, "Calibrator promotion failed."));
    }
  }

  const runs = runsQuery.data ?? [];
  const calibrators = calibratorsQuery.data ?? [];

  return (
    <div className="flex flex-col" style={{ gap: 16 }}>
      {/* Eval runs */}
      <WindowPanel
        title="eval runs"
        actions={
          <button
            type="button"
            onClick={() => setScoreOpen(true)}
            style={PRIMARY_BUTTON_STYLE}
          >
            <Sparkle size={11} aria-hidden />
            SCORE VERSION
          </button>
        }
        flush
      >
        {runsQuery.isLoading && <div style={{ padding: 14 }}><LoadingSkeletonGroup lines={4} /></div>}
        {runsQuery.isError && (
          <p style={{ ...ERROR_TEXT_STYLE, padding: 14 }}>
            {extractErrorMessage(runsQuery.error, "Failed to load eval runs.")}
          </p>
        )}
        {runsQuery.data && runs.length === 0 && (
          <div
            className="font-mono"
            style={{ padding: 32, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
          >
            No eval runs recorded.
            <br />
            Click SCORE VERSION to run a candidate against a registered benchmark.
          </div>
        )}
        {runs.length > 0 && (
          <div>
            <div
              className="grid font-mono uppercase"
              style={{
                gridTemplateColumns: "24px 160px 130px 130px 1fr 110px 130px",
                gap: 10, padding: "8px 12px",
                background: "var(--surface-sunk)", borderBottom: "1px solid var(--border-soft)",
                fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)",
              }}
            >
              <span />
              <span>WHEN</span>
              <span>CANDIDATE</span>
              <span>BASELINE</span>
              <span>BENCHMARK</span>
              <span>VERDICT</span>
              <span>ACTOR</span>
            </div>
            {runs.map((run) => (
              <EvalRunRow
                key={run.id}
                run={run}
                expanded={expandedRunId === run.id}
                onToggle={() => setExpandedRunId((prev) => (prev === run.id ? null : run.id))}
              />
            ))}
          </div>
        )}
      </WindowPanel>

      {/* Calibrators */}
      <WindowPanel
        title="calibrators"
        actions={
          <div className="flex items-center" style={{ gap: 6 }}>
            <input
              placeholder="task_type filter (blank = all)"
              value={taskTypeDraft}
              onChange={(e) => setTaskTypeDraft(e.target.value)}
              style={{ ...INPUT_STYLE, width: 220 }}
            />
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => setTaskType(taskTypeDraft.trim())}
            >
              FILTER
            </button>
            <button
              type="button"
              style={PRIMARY_BUTTON_STYLE}
              onClick={() => void handleTrain()}
              disabled={trainMutation.isPending || taskTypeDraft.trim().length === 0}
            >
              <Play size={11} aria-hidden />
              {trainMutation.isPending ? "TRAINING\u2026" : "TRAIN"}
            </button>
          </div>
        }
        flush
      >
        <div style={{ padding: 12, background: "var(--surface-sunk)", borderBottom: "1px solid var(--border-faint)" }}>
          <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
            <label style={LABEL_STYLE}>APPROVER_IDS (COMMA-SEPARATED)</label>
            <input
              value={approversDraft}
              onChange={(e) => setApproversDraft(e.target.value)}
              placeholder="user-a, user-b"
              style={{ ...INPUT_STYLE, width: 280 }}
            />
          </div>
        </div>
        {calibratorsQuery.isLoading && <div style={{ padding: 14 }}><LoadingSkeletonGroup lines={3} /></div>}
        {calibratorsQuery.isError && (
          <p style={{ ...ERROR_TEXT_STYLE, padding: 14 }}>
            {extractErrorMessage(calibratorsQuery.error, "Failed to load calibrators.")}
          </p>
        )}
        {calibratorsQuery.data && calibrators.length === 0 && (
          <div
            className="font-mono"
            style={{ padding: 24, textAlign: "center", fontSize: 11, color: "var(--text-muted)" }}
          >
            No calibrator versions match {taskType.length > 0 ? `task_type=${taskType}` : "any filter"}.
          </div>
        )}
        {calibrators.length > 0 && (
          <DataGrid<CalibratorVersionInfo>
            columns={[
              { label: "TASK TYPE", width: "150px" },
              { label: "METHOD", width: "120px" },
              { label: "ECE BEFORE", width: "110px", align: "right" },
              { label: "ECE AFTER", width: "110px", align: "right" },
              { label: "SAMPLES", width: "90px", align: "right" },
              { label: "STATUS", width: "110px" },
              { label: "", width: "100px", align: "right" },
            ]}
            rows={calibrators}
            getKey={(row) => row.id}
            renderCells={(row) => [
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.task_type}</span>,
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.method}</span>,
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.ece_before.toFixed(3)}</span>,
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.ece_after.toFixed(3)}</span>,
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.sample_count}</span>,
              <MonoBadge tone={row.status === "active" ? "info" : "muted"}>{row.status}</MonoBadge>,
              <button
                type="button"
                style={GHOST_BUTTON_STYLE}
                onClick={() => void handlePromoteCalibrator(row)}
                disabled={promoteCalibratorMutation.isPending || row.status === "active"}
              >
                promote
              </button>,
            ]}
          />
        )}
      </WindowPanel>

      {/* Bottom action row -- new benchmark */}
      <div className="flex justify-end">
        <button
          type="button"
          style={BUTTON_STYLE}
          onClick={() => setBenchOpen(true)}
        >
          <ArrowClockwise size={11} aria-hidden />
          NEW BENCHMARK
        </button>
      </div>

      {/* Score version modal */}
      <ModalShell open={scoreOpen} onClose={() => setScoreOpen(false)} title="score a candidate version">
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>CANDIDATE_VERSION</label>
            <input value={scoreCandidate} onChange={(e) => setScoreCandidate(e.target.value)} placeholder="v42" style={INPUT_STYLE} />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>BENCHMARK_ID</label>
            <input value={scoreBenchmark} onChange={(e) => setScoreBenchmark(e.target.value)} placeholder="bench-uuid-or-slug" style={INPUT_STYLE} />
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button type="button" style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }} onClick={() => void handleScore()} disabled={scoreMutation.isPending}>
              {scoreMutation.isPending ? "SCORING\u2026" : "SCORE"}
            </button>
            <button type="button" style={BUTTON_STYLE} onClick={() => setScoreOpen(false)}>CANCEL</button>
          </div>
        </div>
      </ModalShell>

      {/* New benchmark modal */}
      <ModalShell open={benchOpen} onClose={() => setBenchOpen(false)} title="register new benchmark" width={560}>
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>NAME</label>
            <input value={benchName} onChange={(e) => setBenchName(e.target.value)} placeholder="human-readable name" style={INPUT_STYLE} />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>CASES (JSON ARRAY OF BENCHMARKCASESPEC)</label>
            <textarea
              value={benchCasesJson}
              onChange={(e) => setBenchCasesJson(e.target.value)}
              rows={10}
              spellCheck={false}
              placeholder={'[\n  {\n    "outcome_kind": "vuln_classify",\n    "predicted_verdict": "true_positive",\n    "verified_verdict": "true_positive",\n    "confidence": 0.92,\n    "version": "v41"\n  }\n]'}
              style={TEXTAREA_STYLE}
            />
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button type="button" style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }} onClick={() => void handleRegisterBenchmark()} disabled={benchMutation.isPending}>
              {benchMutation.isPending ? "REGISTERING\u2026" : "REGISTER"}
            </button>
            <button type="button" style={BUTTON_STYLE} onClick={() => setBenchOpen(false)}>CANCEL</button>
          </div>
        </div>
      </ModalShell>
    </div>
  );
}

interface EvalRunRowProps {
  run: EvalRunInfo;
  expanded: boolean;
  onToggle: () => void;
}

function EvalRunRow({ run, expanded, onToggle }: EvalRunRowProps) {
  return (
    <>
      <div
        className="grid font-mono"
        style={{
          gridTemplateColumns: "24px 160px 130px 130px 1fr 110px 130px",
          gap: 10, padding: "8px 12px",
          borderBottom: "1px solid var(--border-faint)",
          background: "var(--surface-card)",
          alignItems: "center", fontSize: 11,
        }}
      >
        <button
          type="button"
          onClick={onToggle}
          aria-label={expanded ? "Collapse" : "Expand"}
          style={{
            width: 20, height: 20, background: "transparent", border: 0,
            color: "var(--text-muted)", cursor: "pointer",
            display: "inline-flex", alignItems: "center", justifyContent: "center",
          }}
        >
          {expanded ? <CaretDown size={11} /> : <CaretRight size={11} />}
        </button>
        <span style={{ color: "var(--text-primary)" }}>{formatTimestamp(run.created_at)}</span>
        <span style={{ color: "var(--text-primary)" }}>{run.candidate_version}</span>
        <span style={{ color: "var(--text-muted)" }}>{run.baseline_version ?? "--"}</span>
        <span className="truncate" style={{ color: "var(--text-muted)", wordBreak: "break-all" }}>{run.benchmark_id}</span>
        <VerdictBadge verdict={run.verdict} />
        <span style={{ color: "var(--text-muted)" }}>{run.actor}</span>
      </div>
      {expanded && (
        <div
          style={{
            padding: 12, background: "var(--surface-sunk)",
            borderBottom: "1px solid var(--border-faint)",
          }}
        >
          <pre
            style={{
              maxHeight: 380, overflow: "auto",
              padding: 10, fontSize: 10.5, fontFamily: "var(--font-mono)",
              color: "var(--text-primary)", background: "var(--surface-card)",
              border: "1px solid var(--border-faint)", borderRadius: 3,
              whiteSpace: "pre-wrap", margin: 0,
            }}
          >
            {JSON.stringify(run.report, null, 2)}
          </pre>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Tab 3 -- Prompts
// ---------------------------------------------------------------------------

function PromptsTab({ activeKey }: { activeKey: string }) {
  const versionsQuery = usePromptVersions(activeKey);
  const aliasesQuery = usePromptAliases(activeKey);
  const registerMutation = useRegisterPromptVersion();
  const setAliasMutation = useSetPromptAlias();

  const [selectedLeft, setSelectedLeft] = useState<string>("");
  const [selectedRight, setSelectedRight] = useState<string>("");
  const [bodyCache, setBodyCache] = useState<Record<string, string>>({});

  const [newOpen, setNewOpen] = useState(false);
  const [newBody, setNewBody] = useState("");
  const [newAuthor, setNewAuthor] = useState("");
  const [newNotes, setNewNotes] = useState("");

  const [aliasOpen, setAliasOpen] = useState(false);
  const [aliasName, setAliasName] = useState("production");
  const [aliasVersion, setAliasVersion] = useState("");
  const [aliasReason, setAliasReason] = useState("");

  const versions = useMemo(
    () => [...(versionsQuery.data ?? [])].sort((a, b) => (a.created_at < b.created_at ? 1 : -1)),
    [versionsQuery.data],
  );
  const aliases = aliasesQuery.data ?? [];

  const productionAlias = aliases.find((a) => a.alias === "production");
  const latestVersion = versions[0]?.version ?? null;
  const productionLagging =
    productionAlias !== undefined
    && latestVersion !== null
    && productionAlias.version !== latestVersion;

  useEffect(() => {
    if (versions.length >= 2) {
      if (!selectedLeft || !versions.some((v) => v.version === selectedLeft)) {
        setSelectedLeft(versions[1]!.version);
      }
      if (!selectedRight || !versions.some((v) => v.version === selectedRight)) {
        setSelectedRight(versions[0]!.version);
      }
    } else if (versions.length === 1) {
      setSelectedLeft(versions[0]!.version);
      setSelectedRight(versions[0]!.version);
    }
  }, [versions, selectedLeft, selectedRight]);

  async function handleRegisterNew() {
    if (newBody.length === 0) { toast.error("body is required."); return; }
    try {
      const env = await registerMutation.mutateAsync({
        key: activeKey,
        body: newBody,
        author: newAuthor.length > 0 ? newAuthor : undefined,
        notes: newNotes.length > 0 ? newNotes : undefined,
      });
      setBodyCache((prev) => ({ ...prev, [env.data.version]: newBody }));
      toast.success(`Registered ${env.data.version} (${env.data.content_hash.slice(0, 12)}\u2026).`);
      setNewOpen(false);
      setNewBody("");
      setNewNotes("");
    } catch (err) {
      toast.error(extractErrorMessage(err, "Version registration failed."));
    }
  }

  async function handleSetAlias() {
    if (aliasVersion.trim().length === 0) { toast.error("version is required."); return; }
    try {
      await setAliasMutation.mutateAsync({
        key: activeKey,
        alias: aliasName.trim(),
        version: aliasVersion.trim(),
        reason: aliasReason,
      });
      toast.success(`${aliasName} \u2192 ${aliasVersion}`);
      setAliasOpen(false);
      setAliasVersion("");
      setAliasReason("");
    } catch (err) {
      toast.error(extractErrorMessage(err, "Alias update failed."));
    }
  }

  return (
    <div className="flex flex-col" style={{ gap: 16 }}>
      {/* Aliases */}
      <WindowPanel
        title="aliases"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            {productionLagging && (
              <MonoBadge
                tone="medium"
                title={`production is at ${productionAlias?.version} but the latest registered version is ${latestVersion}`}
              >
                <Warning size={9} aria-hidden style={{ marginRight: 4, verticalAlign: "-1px" }} />
                production lags latest
              </MonoBadge>
            )}
            <button
              type="button"
              onClick={() => setAliasOpen(true)}
              style={PRIMARY_BUTTON_STYLE}
            >
              DEPLOY TO ALIAS
            </button>
          </div>
        }
      >
        {aliasesQuery.isLoading && <LoadingSkeletonGroup lines={2} />}
        {aliasesQuery.isError && (
          <p style={ERROR_TEXT_STYLE}>
            {extractErrorMessage(aliasesQuery.error, "Failed to load aliases.")}
          </p>
        )}
        {aliasesQuery.data && aliases.length === 0 && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
            No alias pointers for this key.
          </p>
        )}
        {aliases.length > 0 && (
          <div className="flex flex-wrap" style={{ gap: 10 }}>
            {aliases.map((a) => (
              <AliasChip key={a.alias} alias={a} lagging={a.alias === "production" && productionLagging} />
            ))}
          </div>
        )}
      </WindowPanel>

      {/* Split pane: timeline + diff */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(0, 2fr)", gap: 16 }}
      >
        <WindowPanel
          title="versions"
          actions={
            <button
              type="button"
              onClick={() => setNewOpen(true)}
              style={PRIMARY_BUTTON_STYLE}
            >
              NEW VERSION
            </button>
          }
        >
          {versionsQuery.isLoading && <LoadingSkeletonGroup lines={5} />}
          {versionsQuery.isError && (
            <p style={ERROR_TEXT_STYLE}>
              {extractErrorMessage(versionsQuery.error, "Failed to load versions.")}
            </p>
          )}
          {versionsQuery.data && versions.length === 0 && (
            <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
              No versions registered for this key. Click New version to write the first.
            </p>
          )}
          {versions.length > 0 && (
            <ol
              className="flex flex-col"
              style={{ gap: 8, padding: 0, margin: 0, listStyle: "none" }}
            >
              {versions.map((v) => (
                <PromptVersionEntry
                  key={v.version}
                  version={v}
                  isLeft={selectedLeft === v.version}
                  isRight={selectedRight === v.version}
                  onSelectLeft={() => setSelectedLeft(v.version)}
                  onSelectRight={() => setSelectedRight(v.version)}
                  aliasBadges={aliases.filter((a) => a.version === v.version).map((a) => a.alias)}
                />
              ))}
            </ol>
          )}
        </WindowPanel>

        <WindowPanel title="body diff">
          <BodyDiffView
            leftVersion={selectedLeft}
            rightVersion={selectedRight}
            bodyCache={bodyCache}
            setBody={(v, b) => setBodyCache((prev) => ({ ...prev, [v]: b }))}
          />
        </WindowPanel>
      </div>

      {/* New version modal */}
      <ModalShell open={newOpen} onClose={() => setNewOpen(false)} title="register new prompt version" width={640}>
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>BODY</label>
            <textarea
              value={newBody}
              onChange={(e) => setNewBody(e.target.value)}
              rows={12}
              spellCheck={false}
              style={TEXTAREA_STYLE}
            />
          </div>
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label style={LABEL_STYLE}>AUTHOR (OPTIONAL)</label>
              <input value={newAuthor} onChange={(e) => setNewAuthor(e.target.value)} style={INPUT_STYLE} />
            </div>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label style={LABEL_STYLE}>NOTES (OPTIONAL)</label>
              <input value={newNotes} onChange={(e) => setNewNotes(e.target.value)} style={INPUT_STYLE} />
            </div>
          </div>
          <p className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.55 }}>
            Registration is content-hash-deduplicated: identical bodies return the existing version.
            The body is cached in-page against its assigned version so the diff view renders immediately.
          </p>
          <div className="flex" style={{ gap: 8 }}>
            <button type="button" style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }} onClick={() => void handleRegisterNew()} disabled={registerMutation.isPending}>
              {registerMutation.isPending ? "REGISTERING\u2026" : "REGISTER"}
            </button>
            <button type="button" style={BUTTON_STYLE} onClick={() => setNewOpen(false)}>CANCEL</button>
          </div>
        </div>
      </ModalShell>

      {/* Alias modal */}
      <ModalShell open={aliasOpen} onClose={() => setAliasOpen(false)} title="deploy version to alias" tone="warn">
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div
            className="font-mono"
            style={{
              padding: 10, fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55,
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              borderRadius: 3,
            }}
          >
            Pointing <code>production</code> flips the live prompt for every team resolving <code>{activeKey}</code>.
            Use <code>staging</code> or <code>candidate</code> for out-of-line rollouts.
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>ALIAS</label>
            <input aria-label="Alias name" value={aliasName} onChange={(e) => setAliasName(e.target.value)} style={INPUT_STYLE} />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>VERSION</label>
            <input aria-label="Version identifier" value={aliasVersion} onChange={(e) => setAliasVersion(e.target.value)} style={INPUT_STYLE} />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE}>REASON</label>
            <textarea value={aliasReason} onChange={(e) => setAliasReason(e.target.value)} rows={3} style={TEXTAREA_STYLE} />
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={aliasName.trim() === "production" ? { ...WARN_BUTTON_STYLE, flex: 1 } : { ...PRIMARY_BUTTON_STYLE, flex: 1 }}
              onClick={() => void handleSetAlias()}
              disabled={setAliasMutation.isPending}
            >
              {setAliasMutation.isPending ? "DEPLOYING\u2026" : "DEPLOY"}
            </button>
            <button type="button" style={BUTTON_STYLE} onClick={() => setAliasOpen(false)}>CANCEL</button>
          </div>
        </div>
      </ModalShell>
    </div>
  );
}

function AliasChip({ alias, lagging }: { alias: PromptAliasInfo; lagging: boolean }) {
  const tone =
    alias.alias === "production" ? (lagging ? "medium" : "info")
    : alias.alias === "staging" ? "low"
    : "muted";
  return (
    <div
      className="flex flex-col"
      style={{
        gap: 4, padding: "8px 10px",
        border: "1px solid var(--border-soft)", borderRadius: 3,
        background: "var(--surface-sunk)",
      }}
    >
      <div className="flex items-center" style={{ gap: 6 }}>
        <MonoBadge tone={tone}>{alias.alias}</MonoBadge>
        <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{alias.version}</span>
      </div>
      <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)" }}>
        updated {formatTimestamp(alias.updated_at)}
      </span>
    </div>
  );
}

interface PromptVersionEntryProps {
  version: PromptVersionInfo;
  isLeft: boolean;
  isRight: boolean;
  onSelectLeft: () => void;
  onSelectRight: () => void;
  aliasBadges: string[];
}

function PromptVersionEntry({
  version, isLeft, isRight, onSelectLeft, onSelectRight, aliasBadges,
}: PromptVersionEntryProps) {
  return (
    <li
      className="flex flex-col"
      style={{
        gap: 4, padding: "8px 10px",
        border: "1px solid var(--border-soft)", borderRadius: 3,
        background: "var(--surface-card)",
      }}
    >
      <div className="flex items-center justify-between" style={{ gap: 6 }}>
        <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{version.version}</span>
        <div className="flex flex-wrap" style={{ gap: 4 }}>
          {aliasBadges.map((a) => (
            <MonoBadge key={a} tone={a === "production" ? "info" : "muted"}>{a}</MonoBadge>
          ))}
        </div>
      </div>
      <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)", wordBreak: "break-all" }}>
        {version.content_hash.slice(0, 16)}{"\u2026 \u00b7 "}{formatTimestamp(version.created_at)}
      </span>
      {version.author && (
        <span className="font-mono" style={{ fontSize: 10, color: "var(--text-muted)" }}>by {version.author}</span>
      )}
      {version.notes && (
        <span className="font-mono" style={{ fontSize: 10, color: "var(--text-primary)", wordBreak: "break-word" }}>
          {version.notes}
        </span>
      )}
      <div className="flex" style={{ gap: 4, marginTop: 4 }}>
        <button
          type="button"
          style={isLeft ? PRIMARY_BUTTON_STYLE : GHOST_BUTTON_STYLE}
          onClick={onSelectLeft}
        >
          A
        </button>
        <button
          type="button"
          style={isRight ? PRIMARY_BUTTON_STYLE : GHOST_BUTTON_STYLE}
          onClick={onSelectRight}
        >
          B
        </button>
      </div>
    </li>
  );
}

interface BodyDiffViewProps {
  leftVersion: string;
  rightVersion: string;
  bodyCache: Record<string, string>;
  setBody: (version: string, body: string) => void;
}

function BodyDiffView({ leftVersion, rightVersion, bodyCache, setBody }: BodyDiffViewProps) {
  const leftBody = leftVersion.length > 0 ? bodyCache[leftVersion] : undefined;
  const rightBody = rightVersion.length > 0 ? bodyCache[rightVersion] : undefined;

  const diff = useMemo(() => {
    if (leftBody === undefined || rightBody === undefined) return null;
    return computeLineDiff(leftBody, rightBody);
  }, [leftBody, rightBody]);

  if (leftVersion.length === 0 || rightVersion.length === 0) {
    return (
      <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Pick versions A and B from the timeline to diff their bodies.
      </p>
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <BodyPaneEditor
          label={`A: ${leftVersion}`}
          body={leftBody}
          onChange={(v) => setBody(leftVersion, v)}
        />
        <BodyPaneEditor
          label={`B: ${rightVersion}`}
          body={rightBody}
          onChange={(v) => setBody(rightVersion, v)}
        />
      </div>
      {diff && (
        <div className="flex flex-col" style={{ gap: 4 }}>
          <span style={LABEL_STYLE}>UNIFIED DIFF</span>
          <pre
            style={{
              maxHeight: 380, overflow: "auto",
              padding: 10, fontSize: 10.5, fontFamily: "var(--font-mono)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-faint)", borderRadius: 3,
              whiteSpace: "pre-wrap", margin: 0,
            }}
          >
            {diff.map((line, idx) => {
              const color =
                line.kind === "add" ? toneColor("ok")
                : line.kind === "del" ? toneColor("critical")
                : "var(--text-muted)";
              const prefix = line.kind === "add" ? "+ " : line.kind === "del" ? "- " : "  ";
              return (
                <span key={idx} style={{ color }}>{`${prefix}${line.text}\n`}</span>
              );
            })}
          </pre>
        </div>
      )}
      {(leftBody === undefined || rightBody === undefined) && (
        <p className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)", lineHeight: 1.55 }}>
          The list endpoint returns metadata only. Paste the raw body into the pane above --
          or click New version and re-register it (content-hash-dedup safe) to hydrate.
        </p>
      )}
    </div>
  );
}

interface BodyPaneEditorProps {
  label: string;
  body: string | undefined;
  onChange: (next: string) => void;
}

function BodyPaneEditor({ label, body, onChange }: BodyPaneEditorProps) {
  return (
    <div className="flex flex-col" style={{ gap: 4 }}>
      <span style={LABEL_STYLE}>{label.toUpperCase()}</span>
      <textarea
        value={body ?? ""}
        onChange={(e) => onChange(e.target.value)}
        rows={12}
        placeholder="(body not cached in page; paste to diff)"
        spellCheck={false}
        style={TEXTAREA_STYLE}
      />
    </div>
  );
}

interface DiffLine { kind: "eq" | "add" | "del"; text: string }

/**
 * LCS-based line diff. n*m table, fine for the prompt body sizes this UI
 * carries (few KB, tens to hundreds of lines).
 */
function computeLineDiff(a: string, b: string): DiffLine[] {
  const A = a.split("\n");
  const B = b.split("\n");
  const n = A.length;
  const m = B.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lcs[i]![j] = A[i] === B[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) {
      out.push({ kind: "eq", text: A[i]! });
      i += 1;
      j += 1;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ kind: "del", text: A[i]! });
      i += 1;
    } else {
      out.push({ kind: "add", text: B[j]! });
      j += 1;
    }
  }
  while (i < n) { out.push({ kind: "del", text: A[i]! }); i += 1; }
  while (j < m) { out.push({ kind: "add", text: B[j]! }); j += 1; }
  return out;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type Concern = "lifecycle" | "evals" | "prompts";

export function MlOpsPage() {
  const [tab, setTab] = useState<Concern>("lifecycle");
  const [activeKey, setActiveKey] = useState("");

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25c6"}
        title="ml ops"
        actions={
          activeKey.length > 0 ? (
            <Segmented<Concern>
              options={[
                { value: "lifecycle", label: "LIFECYCLE" },
                { value: "evals", label: "EVALS" },
                { value: "prompts", label: "PROMPTS" },
              ]}
              value={tab}
              onChange={setTab}
            />
          ) : undefined
        }
      />

      <KeyPicker activeKey={activeKey} onCommit={setActiveKey} />

      {activeKey.length === 0 ? (
        <WindowPanel title="awaiting key" tone="muted">
          <div className="flex items-center" style={{ gap: 12, padding: 12 }}>
            <Brain size={32} aria-hidden style={{ color: "var(--text-faint)" }} />
            <div className="flex flex-col" style={{ gap: 4 }}>
              <span
                className="font-mono uppercase"
                style={{ fontSize: 11, letterSpacing: "0.1em", color: "var(--text-primary)" }}
              >
                type a registry key to begin
              </span>
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
                Every ML-Ops surface is scoped to a single model or prompt registry key.
              </span>
            </div>
          </div>
        </WindowPanel>
      ) : (
        <>
          {tab === "lifecycle" && (
            <FeatureBoundary label="Lifecycle" resetKeys={[activeKey, tab]}>
              <LifecycleTab activeKey={activeKey} />
            </FeatureBoundary>
          )}
          {tab === "evals" && (
            <FeatureBoundary label="Evals" resetKeys={[activeKey, tab]}>
              <EvalsTab activeKey={activeKey} />
            </FeatureBoundary>
          )}
          {tab === "prompts" && (
            <FeatureBoundary label="Prompts" resetKeys={[activeKey, tab]}>
              <PromptsTab activeKey={activeKey} />
            </FeatureBoundary>
          )}
        </>
      )}
    </div>
  );
}
