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
 * All endpoints take a ``key`` (a model / prompt registry key). There is
 * no list-keys endpoint by contract: the operator types the key and the
 * page keeps a rolling list of the ten most-recent keys in localStorage
 * for one-click recall.
 */
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Brain } from "@phosphor-icons/react/dist/csr/Brain";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { Play } from "@phosphor-icons/react/dist/csr/Play";
import { Eye } from "@phosphor-icons/react/dist/csr/Eye";
import { GitCommit } from "@phosphor-icons/react/dist/csr/GitCommit";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { Flask } from "@phosphor-icons/react/dist/csr/Flask";
import { Sparkle } from "@phosphor-icons/react/dist/csr/Sparkle";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { FeatureBoundary } from "@app/FeatureBoundary";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
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
// Recent-keys memory -- localStorage-backed rolling list of the last ten
// operator-entered keys. There is no list-keys endpoint by contract; this
// gives one-click recall without persisting server-side.
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

interface StageBadgeProps {
  stage: string | null;
}

function StageBadge({ stage }: StageBadgeProps) {
  if (!stage) return <span className="font-mono text-[11px] text-text-muted">--</span>;
  const s = stage.toLowerCase();
  let severity: "critical" | "high" | "medium" | "low" | "info" | "neutral" = "neutral";
  if (s === "production") severity = "info";
  else if (s === "rolled_back" || s === "failed") severity = "critical";
  else if (s === "canary") severity = "medium";
  else if (s === "shadow") severity = "low";
  else if (s === "evaluated" || s === "approved") severity = "info";
  return <AilaBadge severity={severity}>{stage}</AilaBadge>;
}

interface VerdictBadgeProps {
  verdict: string | null;
}

function VerdictBadge({ verdict }: VerdictBadgeProps) {
  if (!verdict) return <span className="font-mono text-[11px] text-text-muted">--</span>;
  const v = verdict.toLowerCase();
  let severity: "critical" | "high" | "medium" | "low" | "info" | "neutral" = "neutral";
  if (v === "pass" || v === "passed") severity = "info";
  else if (v === "fail" || v === "failed") severity = "critical";
  else if (v === "regression") severity = "high";
  return <AilaBadge severity={severity}>{verdict}</AilaBadge>;
}

// ---------------------------------------------------------------------------
// Key picker -- text input + recent-keys chip row. Bubbles the committed
// key up via onCommit; the tabs mount their queries against that key.
// ---------------------------------------------------------------------------

interface KeyPickerProps {
  activeKey: string;
  onCommit: (key: string) => void;
}

function KeyPicker({ activeKey, onCommit }: KeyPickerProps) {
  const [draft, setDraft] = useState(activeKey);
  const [recent, setRecent] = useState<string[]>(() => loadRecentKeys());

  useEffect(() => {
    setDraft(activeKey);
  }, [activeKey]);

  function commit(next: string) {
    const trimmed = next.trim();
    if (trimmed.length === 0) return;
    const nextRecent = [trimmed, ...recent.filter((k) => k !== trimmed)].slice(0, RECENT_KEYS_LIMIT);
    setRecent(nextRecent);
    saveRecentKeys(nextRecent);
    onCommit(trimmed);
  }

  return (
    <AilaCard variant="default" padding="md">
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="ml-ops-key" className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Model / prompt registry key
          </label>
          <div className="flex gap-2">
            <Input
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
              className="font-mono text-xs"
              spellCheck={false}
            />
            <Button
              type="button"
              onClick={() => commit(draft)}
              disabled={draft.trim().length === 0 || draft.trim() === activeKey}
              className="gap-1.5"
            >
              Load
            </Button>
          </div>
          <p className="font-mono text-[10px] text-text-muted">
            There is no list-keys endpoint; type the exact registry key or pick a recent one.
            The ten most-recent keys are remembered per-browser.
          </p>
        </div>
        {recent.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {recent.map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => {
                  setDraft(k);
                  commit(k);
                }}
                className={
                  "rounded-[2px] border px-2 py-1 font-mono text-[11px] transition-colors " +
                  (k === activeKey
                    ? "border-accent text-accent"
                    : "border-border text-text-muted hover:border-accent hover:text-text")
                }
              >
                {k}
              </button>
            ))}
          </div>
        )}
      </div>
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Confirm dialog -- single reusable modal for destructive actions.
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

function ConfirmDialog({
  open, title, description, confirmLabel, onConfirm, onCancel, pending,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) onCancel(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">{title}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="rounded-[4px] border border-warning/40 bg-warning/10 px-4 py-3 font-mono text-xs text-text">
            {description}
          </div>
          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="destructive"
              className="flex-1"
              onClick={onConfirm}
              disabled={pending}
            >
              {pending ? "Working…" : confirmLabel}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={onCancel} disabled={pending}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
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
  const [shadowOpen, setShadowOpen] = useState<{ row: VersionMetricsRow } | null>(null);
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
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,1fr)]">
      {/* Left column: metrics table + shadow panel */}
      <div className="flex flex-col gap-6">
        <AilaCard variant="default" padding="md">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Per-version metrics
            </h2>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setRouteOpen((v) => !v)}
              className="gap-1.5"
            >
              <Eye className="h-3.5 w-3.5" />
              Route preview
            </Button>
          </div>

          {routeOpen && (
            <div className="mb-4 rounded-[4px] border border-border bg-elevated px-3 py-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <Input
                  value={routeInvestigationId}
                  onChange={(e) => setRouteInvestigationId(e.target.value)}
                  placeholder="investigation_id"
                  className="font-mono text-xs"
                />
                <Button
                  type="button"
                  size="sm"
                  onClick={() => setRouteInvestigationCommitted(routeInvestigationId.trim())}
                  disabled={routeInvestigationId.trim().length === 0}
                >
                  Resolve
                </Button>
              </div>
              {routeQuery.isLoading && (
                <p className="mt-2 font-mono text-[11px] text-text-muted">Resolving…</p>
              )}
              {routeQuery.isError && (
                <p className="mt-2 font-mono text-[11px] text-critical">
                  {extractErrorMessage(routeQuery.error, "Route resolve failed.")}
                </p>
              )}
              {routeQuery.data && (
                <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 font-mono text-[11px]">
                  <dt className="text-text-muted">resolved version</dt>
                  <dd className="text-text">{routeQuery.data.version ?? "--"}</dd>
                  <dt className="text-text-muted">bucket</dt>
                  <dd className="text-text">{routeQuery.data.bucket}</dd>
                  <dt className="text-text-muted">on canary</dt>
                  <dd className="text-text">{routeQuery.data.on_canary ? "yes" : "no"}</dd>
                  <dt className="text-text-muted">canary_version</dt>
                  <dd className="text-text">{routeQuery.data.canary_version ?? "--"}</dd>
                  <dt className="text-text-muted">production_version</dt>
                  <dd className="text-text">{routeQuery.data.production_version ?? "--"}</dd>
                  <dt className="text-text-muted">cohort_percent</dt>
                  <dd className="text-text">{routeQuery.data.cohort_percent ?? "--"}</dd>
                </dl>
              )}
            </div>
          )}

          {metricsQuery.isLoading && <LoadingSkeletonGroup lines={5} />}
          {metricsQuery.isError && (
            <p className="font-mono text-xs text-critical">
              {extractErrorMessage(metricsQuery.error, "Failed to load metrics.")}
            </p>
          )}
          {metricsQuery.data && rows.length === 0 && (
            <EmptyState
              icon={<GitBranch className="h-10 w-10" />}
              title="No versions found"
              description="No lifecycle rows exist for this key yet."
            />
          )}

          {rows.length > 0 && (
            <div className="overflow-x-auto">
              <table aria-label="Prompt versions" className="w-full font-mono text-[11px] border-collapse [&_th]:border [&_th]:border-border [&_th]:uppercase [&_th]:tracking-wider [&_td]:border [&_td]:border-border">
                <thead>
                  <tr className="text-left text-text-muted">
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Version</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Stage</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Eval</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Approvers</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Quorum rate</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Cost</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Drift</th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px] text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.version} className="border-t border-border align-top">
                      <td className="py-2 text-text">{row.version}</td>
                      <td className="py-2"><StageBadge stage={row.latest_stage} /></td>
                      <td className="py-2"><VerdictBadge verdict={row.eval_verdict} /></td>
                      <td className="py-2 text-text">
                        {row.approver_count}
                        <span className="text-text-muted"> / {row.evaluated_count}</span>
                      </td>
                      <td className="py-2 text-text">{(row.quorum_accept_rate * 100).toFixed(0)}%</td>
                      <td className="py-2 text-text">
                        {`$${row.cost_usd_total.toFixed(4)}`}
                        <span className="text-text-muted"> ({row.cost_call_count})</span>
                      </td>
                      <td className="py-2">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-text">{row.drift_status ?? "--"}</span>
                          <span className="text-[10px] text-text-muted">
                            {formatTimestamp(row.drift_last_recorded)}
                          </span>
                        </div>
                      </td>
                      <td className="py-2">
                        <div className="flex flex-wrap justify-end gap-1">
                          <Button type="button" size="sm" variant="ghost"
                            onClick={() => setEvalOpen({ row })}
                          >evaluate</Button>
                          <Button type="button" size="sm" variant="ghost"
                            onClick={() => void handleApprove(row)}
                          >approve</Button>
                          <Button type="button" size="sm" variant="ghost"
                            onClick={() => setPending({ kind: "promote", row })}
                          >promote</Button>
                          <Button type="button" size="sm" variant="ghost"
                            onClick={() => setPending({ kind: "rollback", row, targetVersion: "" })}
                          >rollback</Button>
                          <Button type="button" size="sm" variant="ghost"
                            onClick={() => void handleShadow(row)}
                          >shadow</Button>
                          <Button type="button" size="sm" variant="ghost"
                            onClick={() => setCanaryOpen({ row })}
                          >canary</Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AilaCard>

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
      <AilaCard variant="default" padding="md">
        <h2 className="mb-4 font-mono text-xs uppercase tracking-wider text-text-muted">
          Transitions
        </h2>
        {transitionsQuery.isLoading && <LoadingSkeletonGroup lines={6} />}
        {transitionsQuery.isError && (
          <p className="font-mono text-xs text-critical">
            {extractErrorMessage(transitionsQuery.error, "Failed to load transitions.")}
          </p>
        )}
        {transitionsQuery.data && transitions.length === 0 && (
          <p className="font-mono text-xs text-text-muted">No transitions journaled for this key.</p>
        )}
        {transitions.length > 0 && (
          <ol className="flex flex-col gap-3">
            {transitions.map((t) => (
              <TransitionEntry key={t.id} transition={t} />
            ))}
          </ol>
        )}
      </AilaCard>

      {/* Evaluate modal */}
      <Dialog
        open={evalOpen !== null}
        onOpenChange={(next) => { if (!next) { setEvalOpen(null); setEvalBenchmarkId(""); } }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              Evaluate {evalOpen?.row.version}
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
              benchmark_id
            </label>
            <Input
              value={evalBenchmarkId}
              onChange={(e) => setEvalBenchmarkId(e.target.value)}
              placeholder="e.g. vuln-classify-2025q4"
              className="font-mono text-xs"
            />
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                className="flex-1"
                onClick={() => evalOpen && void handleEvaluate(evalOpen.row)}
                disabled={evaluateMutation.isPending}
              >
                {evaluateMutation.isPending ? "Running…" : "Evaluate"}
              </Button>
              <Button type="button" size="sm" variant="outline"
                onClick={() => { setEvalOpen(null); setEvalBenchmarkId(""); }}
              >Cancel</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Canary modal */}
      <Dialog
        open={canaryOpen !== null}
        onOpenChange={(next) => { if (!next) setCanaryOpen(null); }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              Canary {canaryOpen?.row.version}
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
              cohort_percent (1-100)
            </label>
            <Input
              type="number"
              min={1}
              max={100}
              value={canaryPercent}
              onChange={(e) => {
                const v = Number.parseInt(e.target.value, 10);
                if (Number.isFinite(v)) setCanaryPercent(Math.min(100, Math.max(1, v)));
              }}
              className="font-mono text-xs"
            />
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                className="flex-1"
                onClick={() => canaryOpen && void handleCanary(canaryOpen.row)}
                disabled={canaryMutation.isPending}
              >
                {canaryMutation.isPending ? "Assigning…" : "Assign canary"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setCanaryOpen(null)}>
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Rollback dialog (uses ConfirmDialog + inline target input) */}
      <Dialog
        open={pending?.kind === "rollback"}
        onOpenChange={(next) => { if (!next) setPending(null); }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              Rollback {pending?.kind === "rollback" ? pending.row.version : ""}
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="rounded-[4px] border border-warning/40 bg-warning/10 px-4 py-3 font-mono text-xs text-text">
              Flips the production alias for <code className="font-mono">{activeKey}</code> back to the target version.
              Every team's investigations resolve through this alias.
            </div>
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
              target_version (optional)
            </label>
            <Input
              value={pending?.kind === "rollback" ? pending.targetVersion : ""}
              onChange={(e) => setPending((prev) =>
                prev?.kind === "rollback" ? { ...prev, targetVersion: e.target.value } : prev,
              )}
              placeholder="leave empty for prior production"
              className="font-mono text-xs"
            />
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                variant="destructive"
                className="flex-1"
                onClick={() => void handleConfirmPending()}
                disabled={rollbackMutation.isPending}
              >
                {rollbackMutation.isPending ? "Rolling back…" : "Confirm rollback"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setPending(null)}>
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Promote confirm */}
      <ConfirmDialog
        open={pending?.kind === "promote"}
        title={`Promote ${pending?.kind === "promote" ? pending.row.version : ""} to production?`}
        description={(
          <>
            Flips the production alias for <code className="font-mono">{activeKey}</code>.
            Requires a passing eval and a distinct-approver quorum -- the controller will
            reject the transition if either gate is unmet.
          </>
        )}
        confirmLabel="Confirm promote"
        pending={promoteMutation.isPending}
        onConfirm={() => void handleConfirmPending()}
        onCancel={() => setPending(null)}
      />

      {/* Placeholder to consume unused local (silences noUnusedParameters if TS strict) */}
      {shadowOpen === null ? null : (
        <Dialog open onOpenChange={() => setShadowOpen(null)}><DialogContent /></Dialog>
      )}
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
    <AilaCard variant="default" padding="md">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted">Shadow run + report</h3>
        <Flask className="h-4 w-4 text-text-muted" />
      </div>
      {shadowRows.length === 0 ? (
        <p className="font-mono text-xs text-text-muted">
          No version currently sits in the shadow stage. Assign one from the row actions above.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1.5">
              <label className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
                shadow version
              </label>
              <select
                value={selectedVersion}
                onChange={(e) => setSelectedVersion(e.target.value)}
                className="rounded-[2px] border border-border bg-base px-2 py-1 font-mono text-xs text-text"
              >
                {shadowRows.map((r) => (
                  <option key={r.version} value={r.version}>{r.version}</option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
                sample_n
              </label>
              <Input
                type="number"
                min={1}
                max={100}
                value={sampleN}
                onChange={(e) => {
                  const v = Number.parseInt(e.target.value, 10);
                  if (Number.isFinite(v)) setSampleN(Math.min(100, Math.max(1, v)));
                }}
                style={{ width: 96 }}
                className="font-mono text-xs"
              />
            </div>
            <Button
              type="button"
              size="sm"
              onClick={() => selectedRow && void onRun(selectedRow)}
              disabled={runPending || !selectedRow}
              className="gap-1.5"
            >
              <Play className="h-3.5 w-3.5" />
              {runPending ? "Running…" : "Run shadow"}
            </Button>
          </div>

          {reportQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
          {reportQuery.isError && (
            <p className="font-mono text-xs text-critical">
              {extractErrorMessage(reportQuery.error, "Failed to load report.")}
            </p>
          )}
          {reportQuery.data === null && (
            <p className="font-mono text-xs text-text-muted">
              No report persisted yet -- click Run shadow.
            </p>
          )}
          {reportQuery.data && (
            <ShadowReportView report={reportQuery.data} />
          )}
        </div>
      )}
    </AilaCard>
  );
}

interface ShadowReportViewProps { report: ShadowReportInfo }

function ShadowReportView({ report }: ShadowReportViewProps) {
  return (
    <div className="flex flex-col gap-3 rounded-[4px] border border-border bg-elevated px-3 py-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <ReportMetric label="mean faithfulness" value={report.mean_faithfulness.toFixed(3)} />
        <ReportMetric label="mean determinism" value={report.mean_determinism.toFixed(3)} />
        <ReportMetric
          label="regressions"
          value={String(report.regressions)}
          tone={report.regressions > 0 ? "critical" : "info"}
        />
        <ReportMetric
          label="samples"
          value={`${report.sample_succeeded}/${report.sample_attempted}`}
        />
      </div>
      <div>
        <span className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-text-muted">
          diff_summary
        </span>
        <pre className="max-h-56 overflow-auto rounded-[4px] border border-border bg-base px-3 py-2 font-mono text-[11px] text-text whitespace-pre-wrap">
          {JSON.stringify(report.diff_summary, null, 2)}
        </pre>
      </div>
      <span className="font-mono text-[10px] text-text-muted">
        recorded {formatTimestamp(report.created_at)} by {report.actor}
      </span>
    </div>
  );
}

interface ReportMetricProps { label: string; value: string; tone?: "critical" | "info" | "neutral" }

function ReportMetric({ label, value, tone = "neutral" }: ReportMetricProps) {
  const color = tone === "critical" ? "text-critical" : tone === "info" ? "text-accent" : "text-text";
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">{label}</span>
      <span className={`font-mono text-sm ${color}`}>{value}</span>
    </div>
  );
}

interface TransitionEntryProps { transition: TransitionInfo }

function TransitionEntry({ transition }: TransitionEntryProps) {
  return (
    <li className="flex gap-2">
      <GitCommit className="mt-0.5 h-3.5 w-3.5 shrink-0 text-text-muted" />
      <div className="flex min-w-0 flex-col gap-0.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[11px] text-text">{transition.version}</span>
          <span className="font-mono text-[10px] text-text-muted">{transition.from_stage}</span>
          <CaretRight className="h-3 w-3 text-text-muted" />
          <StageBadge stage={transition.to_stage} />
        </div>
        {transition.reason && (
          <span className="font-mono text-[10px] text-text-muted break-words">{transition.reason}</span>
        )}
        <span className="font-mono text-[10px] text-text-muted">
          {formatTimestamp(transition.created_at)} {"\u00b7"} {transition.actor}
        </span>
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Tab 2 -- Evals
// ---------------------------------------------------------------------------

interface EvalsTabProps { activeKey: string }

function EvalsTab({ activeKey }: EvalsTabProps) {
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
    if (cases.length === 0) {
      toast.error("At least one case is required.");
      return;
    }
    if (benchName.trim().length === 0) {
      toast.error("name is required.");
      return;
    }
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
    const approver_ids = approversDraft
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
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
    <div className="flex flex-col gap-6">
      {/* Eval runs */}
      <AilaCard variant="default" padding="md">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">Eval runs</h2>
          <Button type="button" size="sm" onClick={() => setScoreOpen(true)} className="gap-1.5">
            <Sparkle className="h-3.5 w-3.5" />
            Score version
          </Button>
        </div>
        {runsQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
        {runsQuery.isError && (
          <p className="font-mono text-xs text-critical">
            {extractErrorMessage(runsQuery.error, "Failed to load eval runs.")}
          </p>
        )}
        {runsQuery.data && runs.length === 0 && (
          <EmptyState
            icon={<Flask className="h-10 w-10" />}
            title="No eval runs recorded"
            description="Click Score version to run a candidate against a registered benchmark."
          />
        )}
        {runs.length > 0 && (
          <div className="overflow-x-auto">
            <table aria-label="Traffic split" className="w-full font-mono text-[11px] border-collapse [&_th]:border [&_th]:border-border [&_th]:uppercase [&_th]:tracking-wider [&_td]:border [&_td]:border-border">
              <thead>
                <tr className="text-left text-text-muted">
                  <th className="pb-2 w-4"></th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">When</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Candidate</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Baseline</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Benchmark</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Verdict</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Actor</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <EvalRunRow
                    key={run.id}
                    run={run}
                    expanded={expandedRunId === run.id}
                    onToggle={() =>
                      setExpandedRunId((prev) => (prev === run.id ? null : run.id))
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </AilaCard>

      {/* Calibrators */}
      <AilaCard variant="default" padding="md">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">Calibrators</h2>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              placeholder="task_type filter (blank = all)"
              value={taskTypeDraft}
              onChange={(e) => setTaskTypeDraft(e.target.value)}
              className="font-mono text-xs"
              style={{ width: 220 }}
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setTaskType(taskTypeDraft.trim())}
            >
              Filter
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={() => void handleTrain()}
              disabled={trainMutation.isPending || taskTypeDraft.trim().length === 0}
              className="gap-1.5"
            >
              <Play className="h-3.5 w-3.5" />
              {trainMutation.isPending ? "Training…" : "Train"}
            </Button>
          </div>
        </div>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
            approver_ids (comma-separated)
          </label>
          <Input
            value={approversDraft}
            onChange={(e) => setApproversDraft(e.target.value)}
            placeholder="user-a, user-b"
            className="font-mono text-xs"
            style={{ width: 260 }}
          />
        </div>
        {calibratorsQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
        {calibratorsQuery.isError && (
          <p className="font-mono text-xs text-critical">
            {extractErrorMessage(calibratorsQuery.error, "Failed to load calibrators.")}
          </p>
        )}
        {calibratorsQuery.data && calibrators.length === 0 && (
          <p className="font-mono text-xs text-text-muted">
            No calibrator versions match {taskType.length > 0 ? `task_type=${taskType}` : "any filter"}.
          </p>
        )}
        {calibrators.length > 0 && (
          <div className="overflow-x-auto">
            <table aria-label="Version metrics" className="w-full font-mono text-[11px] border-collapse [&_th]:border [&_th]:border-border [&_th]:uppercase [&_th]:tracking-wider [&_td]:border [&_td]:border-border">
              <thead>
                <tr className="text-left text-text-muted">
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Task type</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Method</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">ECE before</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">ECE after</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Samples</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">Status</th>
                  <th className="pb-2 font-normal uppercase tracking-wider text-[10px] text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {calibrators.map((row) => (
                  <tr key={row.id} className="border-t border-border">
                    <td className="py-2 text-text">{row.task_type}</td>
                    <td className="py-2 text-text">{row.method}</td>
                    <td className="py-2 text-text">{row.ece_before.toFixed(3)}</td>
                    <td className="py-2 text-text">{row.ece_after.toFixed(3)}</td>
                    <td className="py-2 text-text">{row.sample_count}</td>
                    <td className="py-2">
                      <AilaBadge severity={row.status === "active" ? "info" : "neutral"}>
                        {row.status}
                      </AilaBadge>
                    </td>
                    <td className="py-2 text-right">
                      <Button type="button" size="sm" variant="ghost"
                        onClick={() => void handlePromoteCalibrator(row)}
                        disabled={promoteCalibratorMutation.isPending || row.status === "active"}
                      >
                        promote
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </AilaCard>

      {/* Bottom action row -- new benchmark */}
      <div className="flex justify-end">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => setBenchOpen(true)}
          className="gap-1.5"
        >
          <ArrowClockwise className="h-3.5 w-3.5" />
          New benchmark
        </Button>
      </div>

      {/* Score version modal */}
      <Dialog
        open={scoreOpen}
        onOpenChange={(next) => { if (!next) setScoreOpen(false); }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Score a candidate version</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
              candidate_version
            </label>
            <Input
              value={scoreCandidate}
              onChange={(e) => setScoreCandidate(e.target.value)}
              className="font-mono text-xs"
              placeholder="v42"
            />
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
              benchmark_id
            </label>
            <Input
              value={scoreBenchmark}
              onChange={(e) => setScoreBenchmark(e.target.value)}
              className="font-mono text-xs"
              placeholder="bench-uuid-or-slug"
            />
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                className="flex-1"
                onClick={() => void handleScore()}
                disabled={scoreMutation.isPending}
              >
                {scoreMutation.isPending ? "Scoring…" : "Score"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setScoreOpen(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* New benchmark modal */}
      <Dialog
        open={benchOpen}
        onOpenChange={(next) => { if (!next) setBenchOpen(false); }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Register new benchmark</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">name</label>
            <Input
              value={benchName}
              onChange={(e) => setBenchName(e.target.value)}
              className="font-mono text-xs"
              placeholder="human-readable name"
            />
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
              cases (JSON array of BenchmarkCaseSpec)
            </label>
            <Textarea
              value={benchCasesJson}
              onChange={(e) => setBenchCasesJson(e.target.value)}
              rows={10}
              className="font-mono text-[11px]"
              spellCheck={false}
              placeholder={'[\n  {\n    "outcome_kind": "vuln_classify",\n    "predicted_verdict": "true_positive",\n    "verified_verdict": "true_positive",\n    "confidence": 0.92,\n    "version": "v41"\n  }\n]'}
            />
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                className="flex-1"
                onClick={() => void handleRegisterBenchmark()}
                disabled={benchMutation.isPending}
              >
                {benchMutation.isPending ? "Registering…" : "Register"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setBenchOpen(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
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
      <tr className="border-t border-border">
        <td className="py-2">
          <button type="button" onClick={onToggle} className="text-text-muted hover:text-text">
            {expanded ? <CaretDown className="h-3.5 w-3.5" /> : <CaretRight className="h-3.5 w-3.5" />}
          </button>
        </td>
        <td className="py-2 text-text">{formatTimestamp(run.created_at)}</td>
        <td className="py-2 text-text">{run.candidate_version}</td>
        <td className="py-2 text-text-muted">{run.baseline_version ?? "--"}</td>
        <td className="py-2 text-text-muted break-all">{run.benchmark_id}</td>
        <td className="py-2"><VerdictBadge verdict={run.verdict} /></td>
        <td className="py-2 text-text-muted">{run.actor}</td>
      </tr>
      {expanded && (
        <tr className="border-t border-border/40 bg-elevated/40">
          <td colSpan={7} className="px-3 py-3">
            <pre className="max-h-96 overflow-auto rounded-[4px] border border-border bg-base px-3 py-2 font-mono text-[11px] text-text whitespace-pre-wrap">
              {JSON.stringify(run.report, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Tab 3 -- Prompts
// ---------------------------------------------------------------------------

interface PromptsTabProps { activeKey: string }

function PromptsTab({ activeKey }: PromptsTabProps) {
  const versionsQuery = usePromptVersions(activeKey);
  const aliasesQuery = usePromptAliases(activeKey);
  const registerMutation = useRegisterPromptVersion();
  const setAliasMutation = useSetPromptAlias();

  const [selectedLeft, setSelectedLeft] = useState<string>("");
  const [selectedRight, setSelectedRight] = useState<string>("");
  // The list_versions endpoint returns metadata only. To diff bodies the
  // operator registers a version (idempotent by content-hash) and we cache
  // the body locally, or they paste the body in.
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
    () => [...(versionsQuery.data ?? [])].sort(
      (a, b) => (a.created_at < b.created_at ? 1 : -1),
    ),
    [versionsQuery.data],
  );
  const aliases = aliasesQuery.data ?? [];

  const productionAlias = aliases.find((a) => a.alias === "production");
  const latestVersion = versions[0]?.version ?? null;
  const productionLagging =
    productionAlias !== undefined &&
    latestVersion !== null &&
    productionAlias.version !== latestVersion;

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
    if (newBody.length === 0) {
      toast.error("body is required.");
      return;
    }
    try {
      const env = await registerMutation.mutateAsync({
        key: activeKey,
        body: newBody,
        author: newAuthor.length > 0 ? newAuthor : undefined,
        notes: newNotes.length > 0 ? newNotes : undefined,
      });
      // Cache body against version so the diff view can render it without
      // a round-trip. Register is content-hash-dedup so this is safe on repeat.
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
    if (aliasVersion.trim().length === 0) {
      toast.error("version is required.");
      return;
    }
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
    <div className="flex flex-col gap-6">
      {/* Aliases bar */}
      <AilaCard variant="default" padding="md">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">Aliases</h2>
            {productionLagging && (
              <span
                title={`production is at ${productionAlias?.version} but the latest registered version is ${latestVersion}`}
              >
                <AilaBadge severity="medium">
                  <Warning className="mr-1 inline h-3 w-3" />
                  production lags latest
                </AilaBadge>
              </span>
            )}
          </div>
          <Button
            type="button"
            size="sm"
            onClick={() => setAliasOpen(true)}
            className="gap-1.5"
          >
            Deploy to alias
          </Button>
        </div>
        {aliasesQuery.isLoading && <LoadingSkeletonGroup lines={2} />}
        {aliasesQuery.isError && (
          <p className="font-mono text-xs text-critical">
            {extractErrorMessage(aliasesQuery.error, "Failed to load aliases.")}
          </p>
        )}
        {aliasesQuery.data && aliases.length === 0 && (
          <p className="font-mono text-xs text-text-muted">No alias pointers for this key.</p>
        )}
        {aliases.length > 0 && (
          <div className="flex flex-wrap gap-3">
            {aliases.map((a) => (
              <AliasChip key={a.alias} alias={a} lagging={a.alias === "production" && productionLagging} />
            ))}
          </div>
        )}
      </AilaCard>

      {/* Split pane: timeline + diff */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        {/* Versions timeline */}
        <AilaCard variant="default" padding="md">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">Versions</h2>
            <Button type="button" size="sm" onClick={() => setNewOpen(true)}>New version</Button>
          </div>
          {versionsQuery.isLoading && <LoadingSkeletonGroup lines={5} />}
          {versionsQuery.isError && (
            <p className="font-mono text-xs text-critical">
              {extractErrorMessage(versionsQuery.error, "Failed to load versions.")}
            </p>
          )}
          {versionsQuery.data && versions.length === 0 && (
            <p className="font-mono text-xs text-text-muted">
              No versions registered for this key. Click New version to write the first.
            </p>
          )}
          {versions.length > 0 && (
            <ol className="flex flex-col gap-2">
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
        </AilaCard>

        {/* Diff view */}
        <AilaCard variant="default" padding="md">
          <h2 className="mb-4 font-mono text-xs uppercase tracking-wider text-text-muted">
            Body diff
          </h2>
          <BodyDiffView
            leftVersion={selectedLeft}
            rightVersion={selectedRight}
            bodyCache={bodyCache}
            setBody={(v, b) => setBodyCache((prev) => ({ ...prev, [v]: b }))}
          />
        </AilaCard>
      </div>

      {/* New version modal */}
      <Dialog
        open={newOpen}
        onOpenChange={(next) => { if (!next) setNewOpen(false); }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Register new prompt version</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">body</label>
            <Textarea
              value={newBody}
              onChange={(e) => setNewBody(e.target.value)}
              rows={12}
              className="font-mono text-[11px]"
              spellCheck={false}
            />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
                  author (optional)
                </label>
                <Input
                  value={newAuthor}
                  onChange={(e) => setNewAuthor(e.target.value)}
                  className="font-mono text-xs"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="font-mono text-xs uppercase tracking-wider text-text-muted">
                  notes (optional)
                </label>
                <Input
                  value={newNotes}
                  onChange={(e) => setNewNotes(e.target.value)}
                  className="font-mono text-xs"
                />
              </div>
            </div>
            <p className="font-mono text-[10px] text-text-muted">
              Registration is content-hash-deduplicated: identical bodies return the existing version.
              The body is cached in-page against its assigned version so the diff view renders immediately.
            </p>
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                className="flex-1"
                onClick={() => void handleRegisterNew()}
                disabled={registerMutation.isPending}
              >
                {registerMutation.isPending ? "Registering…" : "Register"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setNewOpen(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Alias modal */}
      <Dialog
        open={aliasOpen}
        onOpenChange={(next) => { if (!next) setAliasOpen(false); }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Deploy version to alias</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="rounded-[4px] border border-warning/40 bg-warning/10 px-4 py-3 font-mono text-xs text-text">
              Pointing <code className="font-mono">production</code> flips the live prompt for every team
              resolving <code className="font-mono">{activeKey}</code>. Use <code className="font-mono">staging</code>
              or <code className="font-mono">candidate</code> for out-of-line rollouts.
            </div>
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">alias</label>
            <Input aria-label="Alias name" value={aliasName} onChange={(e) => setAliasName(e.target.value)} className="font-mono text-xs" />
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">version</label>
            <Input aria-label="Version identifier" value={aliasVersion} onChange={(e) => setAliasVersion(e.target.value)} className="font-mono text-xs" />
            <label className="font-mono text-xs uppercase tracking-wider text-text-muted">reason</label>
            <Textarea
              value={aliasReason}
              onChange={(e) => setAliasReason(e.target.value)}
              rows={3}
              className="font-mono text-xs"
              spellCheck={false}
            />
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                variant={aliasName.trim() === "production" ? "destructive" : "default"}
                className="flex-1"
                onClick={() => void handleSetAlias()}
                disabled={setAliasMutation.isPending}
              >
                {setAliasMutation.isPending ? "Deploying…" : "Deploy"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setAliasOpen(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface AliasChipProps { alias: PromptAliasInfo; lagging: boolean }

function AliasChip({ alias, lagging }: AliasChipProps) {
  const severity =
    alias.alias === "production" ? (lagging ? "medium" : "info")
    : alias.alias === "staging" ? "low"
    : "neutral";
  return (
    <div className="flex flex-col gap-1 rounded-[4px] border border-border bg-elevated px-3 py-2">
      <div className="flex items-center gap-2">
        <AilaBadge severity={severity}>{alias.alias}</AilaBadge>
        <span className="font-mono text-xs text-text">{alias.version}</span>
      </div>
      <span className="font-mono text-[10px] text-text-muted">
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
    <li className="flex flex-col gap-1 rounded-[2px] border border-border px-3 py-2">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-text">{version.version}</span>
        <div className="flex flex-wrap gap-1">
          {aliasBadges.map((a) => (
            <AilaBadge key={a} severity={a === "production" ? "info" : "neutral"}>{a}</AilaBadge>
          ))}
        </div>
      </div>
      <span className="font-mono text-[10px] text-text-muted break-all">
        {version.content_hash.slice(0, 16)}{"\u2026 \u00b7 "}{formatTimestamp(version.created_at)}
      </span>
      {version.author && (
        <span className="font-mono text-[10px] text-text-muted">by {version.author}</span>
      )}
      {version.notes && (
        <span className="font-mono text-[10px] text-text break-words">{version.notes}</span>
      )}
      <div className="mt-1 flex gap-1">
        <Button type="button" size="sm" variant={isLeft ? "default" : "ghost"} onClick={onSelectLeft}>
          A
        </Button>
        <Button type="button" size="sm" variant={isRight ? "default" : "ghost"} onClick={onSelectRight}>
          B
        </Button>
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
      <p className="font-mono text-xs text-text-muted">
        Pick versions A and B from the timeline to diff their bodies.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3">
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
        <div>
          <span className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-text-muted">
            unified diff
          </span>
          <pre className="max-h-96 overflow-auto rounded-[4px] border border-border bg-base px-3 py-2 font-mono text-[11px] whitespace-pre-wrap">
            {diff.map((line, idx) => {
              const color =
                line.kind === "add" ? "text-accent"
                : line.kind === "del" ? "text-critical"
                : "text-text-muted";
              const prefix = line.kind === "add" ? "+ " : line.kind === "del" ? "- " : "  ";
              return (
                <span key={idx} className={color}>{`${prefix}${line.text}\n`}</span>
              );
            })}
          </pre>
        </div>
      )}
      {(leftBody === undefined || rightBody === undefined) && (
        <p className="font-mono text-[11px] text-text-muted">
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
    <div className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">{label}</span>
      <Textarea
        value={body ?? ""}
        onChange={(e) => onChange(e.target.value)}
        rows={12}
        className="font-mono text-[11px]"
        placeholder="(body not cached in page; paste to diff)"
        spellCheck={false}
      />
    </div>
  );
}

interface DiffLine { kind: "eq" | "add" | "del"; text: string }

/**
 * Small LCS-based line diff. n*m table, fine for the prompt body sizes
 * this UI carries (few KB, tens to hundreds of lines).
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

export function MlOpsPage() {
  const [tab, setTab] = useState("lifecycle");
  const [activeKey, setActiveKey] = useState("");

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <KeyPicker activeKey={activeKey} onCommit={setActiveKey} />

      {activeKey.length === 0 ? (
        <EmptyState
          icon={<Brain className="h-10 w-10" />}
          title="Type a registry key to begin"
          description="Every ML-Ops surface is scoped to a single model or prompt registry key."
        />
      ) : (
        <Tabs value={tab} onValueChange={setTab}>
          <div className="overflow-x-auto">
            <TabsList variant="line" className="mb-4">
              <TabsTrigger value="lifecycle">Lifecycle</TabsTrigger>
              <TabsTrigger value="evals">Evals</TabsTrigger>
              <TabsTrigger value="prompts">Prompts</TabsTrigger>
            </TabsList>
          </div>
          {/* Per-tab FeatureBoundary: a single tab's queries can misbehave
              (recharts render fault, malformed transition payload, unknown
              alias schema) without blanking the whole ML-Ops surface. Tab
              switches remount via resetKeys so a repeat fault gets a fresh
              render pass. */}
          <TabsContent value="lifecycle">
            <FeatureBoundary label="Lifecycle" resetKeys={[activeKey, tab]}>
              <LifecycleTab activeKey={activeKey} />
            </FeatureBoundary>
          </TabsContent>
          <TabsContent value="evals">
            <FeatureBoundary label="Evals" resetKeys={[activeKey, tab]}>
              <EvalsTab activeKey={activeKey} />
            </FeatureBoundary>
          </TabsContent>
          <TabsContent value="prompts">
            <FeatureBoundary label="Prompts" resetKeys={[activeKey, tab]}>
              <PromptsTab activeKey={activeKey} />
            </FeatureBoundary>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
