/**
 * PlatformOpsPage -- god-tier admin console wiring the three platform
 * endpoints that had no UI: sandbox exec, corpus export/stats, and
 * journal deadletter replay.
 *
 * The page is bare content -- protectPage() in router.tsx already wraps
 * it in PageFrame (title bar + corner brackets). See CLAUDE.md #16.
 */
import { useMemo, useState } from "react";
import { Play } from "@phosphor-icons/react/dist/csr/Play";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { Database } from "@phosphor-icons/react/dist/csr/Database";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";
import { TrendUp } from "@phosphor-icons/react/dist/csr/TrendUp";
import { Files } from "@phosphor-icons/react/dist/csr/Files";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaTable } from "@/components/aila/AilaTable";
import { EmptyState } from "@/components/aila/EmptyState";
import { KpiTile } from "@/components/aila/KpiTile";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
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
  useCorpusExport,
  useCorpusStats,
  useJournalDeadletterReplay,
  useSandboxExec,
  type ReplayResponse,
  type ReplayResponseEntry,
  type SandboxResult,
} from "./platformOpsQueries";
import type { ColumnDef } from "@tanstack/react-table";

// ---------------------------------------------------------------------------
// argv parsing -- "one arg per line, or a single command line split on spaces"
// ---------------------------------------------------------------------------

function parseArgv(raw: string): string[] {
  const trimmed = raw.replace(/\r/g, "").trim();
  if (!trimmed) return [];
  const lines = trimmed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length > 1) return lines;
  // Single line -- split on runs of whitespace. No quote handling; power
  // users switch to the multi-line form for anything with embedded spaces.
  return lines[0].split(/\s+/g).filter((token) => token.length > 0);
}

// ---------------------------------------------------------------------------
// Tab 1 -- Sandbox
// ---------------------------------------------------------------------------

function SandboxTab() {
  const [argvRaw, setArgvRaw] = useState("");
  const [stdin, setStdin] = useState("");
  const [timeoutS, setTimeoutS] = useState<number>(30);
  const [network, setNetwork] = useState(false);
  const [result, setResult] = useState<SandboxResult | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  const execMutation = useSandboxExec();

  const argv = useMemo(() => parseArgv(argvRaw), [argvRaw]);
  const argvValid = argv.length > 0;

  async function handleSubmit() {
    if (!argvValid) {
      toast.error("argv is required (one arg per line).");
      return;
    }
    setResult(null);
    setUnavailable(false);
    try {
      const env = await execMutation.mutateAsync({
        argv,
        stdin: stdin.length > 0 ? stdin : null,
        timeout_s: timeoutS,
        network,
      });
      setResult(env.data);
      const label =
        env.data.exit_code === 0 ? "exited 0" : `exit_code=${env.data.exit_code ?? "?"}`;
      toast.success(`Sandbox ${label} in ${env.data.duration_s.toFixed(2)}s`);
    } catch (err) {
      if (err instanceof ApiHttpError && err.status === 503) {
        // Expected on deployments with no sandbox backend provisioned.
        setUnavailable(true);
        return;
      }
      if (err instanceof ApiHttpError && err.status === 502) {
        toast.error(`Sandbox execution error: ${err.detail}`);
        return;
      }
      const message =
        err instanceof ApiHttpError
          ? err.envelope?.message ?? err.detail
          : err instanceof Error
            ? err.message
            : "Sandbox request failed.";
      toast.error(message);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_1fr]">
      {/* Left: form */}
      <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
        <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-4">
          Execute command
        </h2>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="platform-ops-sandbox-argv"
              className="font-mono text-xs uppercase tracking-wider text-text-muted"
            >
              argv
            </label>
            <Textarea
              id="platform-ops-sandbox-argv"
              value={argvRaw}
              onChange={(e) => setArgvRaw(e.target.value)}
              rows={5}
              placeholder={"echo hello world\n\n-- or one arg per line --\n\necho\nhello\nworld"}
              className="font-mono text-xs"
              spellCheck={false}
            />
            <p className="font-mono text-[10px] text-text-muted">
              {argv.length === 0
                ? "One arg per line, or a single command line split on spaces."
                : `Parsed to ${argv.length} token${argv.length === 1 ? "" : "s"}: [${argv.map((a) => JSON.stringify(a)).join(", ")}]`}
            </p>
          </div>

          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="platform-ops-sandbox-stdin"
              className="font-mono text-xs uppercase tracking-wider text-text-muted"
            >
              stdin (optional)
            </label>
            <Textarea
              id="platform-ops-sandbox-stdin"
              value={stdin}
              onChange={(e) => setStdin(e.target.value)}
              rows={3}
              placeholder="Piped to the child's stdin. Empty means /dev/null."
              className="font-mono text-xs"
              spellCheck={false}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <label
                htmlFor="platform-ops-sandbox-timeout"
                className="font-mono text-xs uppercase tracking-wider text-text-muted"
              >
                timeout_s
              </label>
              <Input
                id="platform-ops-sandbox-timeout"
                type="number"
                min={1}
                step={1}
                value={timeoutS}
                onChange={(e) => {
                  const v = Number.parseFloat(e.target.value);
                  setTimeoutS(Number.isFinite(v) && v > 0 ? v : 30);
                }}
                className="font-mono text-xs"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
                network
              </span>
              {/* Single-toggle checkbox: WCAG 1.3.1 fieldset/legend applies to related-option groups, not to individual on/off toggles labelled via wrapping <label>. */}
              <label className="inline-flex h-8 items-center gap-2 font-mono text-xs text-text">
                <input
                  type="checkbox"
                  checked={network}
                  onChange={(e) => setNetwork(e.target.checked)}
                  className="h-3.5 w-3.5"
                />
                Allow outbound network
              </label>
            </div>
          </div>

          <div>
            <Button
              type="button"
              onClick={handleSubmit}
              disabled={!argvValid || execMutation.isPending}
              className="gap-1.5"
            >
              <Play className="h-3.5 w-3.5" />
              {execMutation.isPending ? "Running…" : "Execute in sandbox"}
            </Button>
          </div>
        </div>
      </AilaCard>

      {/* Right: result */}
      <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
        <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-4">
          Result
        </h2>

        {unavailable && (
          <div className="rounded-[4px] border border-border bg-elevated px-4 py-3">
            <div className="flex items-start gap-2">
              <Warning className="mt-0.5 h-4 w-4 shrink-0 text-text-muted" />
              <div className="flex flex-col gap-1">
                <p className="font-mono text-xs text-text">
                  No sandbox backend is configured.
                </p>
                <p className="font-mono text-[11px] text-text-muted">
                  The platform returned <span className="text-text">503 Service Unavailable</span>{" "}
                  -- this is the expected state on deployments that have not provisioned
                  a sandbox host. Ask the operator to point{" "}
                  <code className="font-mono">platform.sandbox_backend</code> at a live
                  backend, or invoke the module-scoped{" "}
                  <code className="font-mono">sandbox_exec</code> tool inside an
                  agent turn where the team's backend is bound automatically.
                </p>
              </div>
            </div>
          </div>
        )}

        {!unavailable && !result && !execMutation.isPending && (
          <p className="font-mono text-xs text-text-muted">
            Submit a command to see stdout, stderr, and status flags.
          </p>
        )}

        {execMutation.isPending && <LoadingSkeletonGroup lines={5} />}

        {result && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <AilaBadge
                severity={result.exit_code === 0 ? "info" : "critical"}
              >
                exit_code={result.exit_code ?? "?"}
              </AilaBadge>
              <AilaBadge severity="neutral">backend: {result.backend}</AilaBadge>
              <AilaBadge severity="neutral">
                {result.duration_s.toFixed(3)}s
              </AilaBadge>
              {result.timed_out && (
                <AilaBadge severity="medium">timed out</AilaBadge>
              )}
              {result.oom && <AilaBadge severity="critical">oom</AilaBadge>}
              {result.truncated && (
                <AilaBadge severity="medium">truncated</AilaBadge>
              )}
            </div>

            <div className="flex flex-col gap-1">
              <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
                stdout
              </span>
              <pre className="max-h-64 overflow-auto rounded-[4px] border border-border bg-base px-3 py-2 font-mono text-[11px] text-text whitespace-pre-wrap">
                {result.stdout || "(empty)"}
              </pre>
            </div>

            <div className="flex flex-col gap-1">
              <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
                stderr
              </span>
              <pre className="max-h-64 overflow-auto rounded-[4px] border border-border bg-base px-3 py-2 font-mono text-[11px] text-text whitespace-pre-wrap">
                {result.stderr || "(empty)"}
              </pre>
            </div>
          </div>
        )}
      </AilaCard>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab 2 -- Trajectory Corpus
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null): string {
  if (!value) return "--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function CorpusTab() {
  const statsQuery = useCorpusStats();
  const exportMutation = useCorpusExport();

  async function handleExport() {
    try {
      const env = await exportMutation.mutateAsync();
      toast.success(
        `Corpus export queued: task ${env.data.task_id.slice(0, 8)}…`,
      );
    } catch (err) {
      const message =
        err instanceof ApiHttpError
          ? err.envelope?.message ?? err.detail
          : err instanceof Error
            ? err.message
            : "Corpus export failed to enqueue.";
      toast.error(message);
    }
  }

  const stats = statsQuery.data;
  const breakdownEntries = useMemo(
    () =>
      stats
        ? Object.entries(stats.module_breakdown).sort(
            ([a], [b]) => a.localeCompare(b),
          )
        : [],
    [stats],
  );

  return (
    <div className="flex flex-col gap-6">
      {/* Action row */}
      <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-col gap-1">
            <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Trajectory corpus export
            </h2>
            <p className="font-mono text-[11px] text-text-muted">
              Walks every configured module's outcome table and writes
              SFT + DPO jsonl files. Runs as a background task on the{" "}
              <code className="font-mono">default</code> queue.
            </p>
          </div>
          <Button
            type="button"
            onClick={handleExport}
            disabled={exportMutation.isPending}
            className="gap-1.5"
          >
            <ArrowClockwise className="h-3.5 w-3.5" />
            {exportMutation.isPending ? "Queueing…" : "Run export"}
          </Button>
        </div>
      </AilaCard>

      {/* Stats */}
      {statsQuery.isLoading && (
        <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
          <LoadingSkeletonGroup lines={6} />
        </AilaCard>
      )}

      {statsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load corpus stats: {(statsQuery.error as Error).message}
        </div>
      )}

      {stats && !stats.has_corpus && (
        <EmptyState
          icon={<Database className="h-10 w-10" />}
          title="No corpus generated yet"
          description={
            stats.detail ??
            "Click Run export above to build the first SFT + DPO jsonl pair."
          }
        />
      )}

      {stats && stats.has_corpus && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <KpiTile
              label="SFT rows"
              value={stats.sft_count}
              icon={<Files className="h-4 w-4" />}
              tone="accent"
              hint={`min_turns=${stats.min_turns}`}
            />
            <KpiTile
              label="DPO pairs"
              value={stats.dpo_count}
              icon={<Files className="h-4 w-4" />}
              tone="ok"
            />
            <KpiTile
              label="Investigations"
              value={stats.investigations}
              icon={<TrendUp className="h-4 w-4" />}
              tone="neutral"
              hint={`skipped: ${stats.skipped_short_branches} short, ${stats.skipped_unparseable_decisions} unparseable`}
            />
            <KpiTile
              label="Generated"
              value={formatTimestamp(stats.generated_at)}
              icon={<ArrowClockwise className="h-4 w-4" />}
              tone="neutral"
            />
          </div>

          <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
            <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">
              Manifest
            </h3>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-[max-content_1fr]">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
                corpus_dir
              </dt>
              <dd className="font-mono text-xs text-text break-all">
                {stats.corpus_dir}
              </dd>
              <dt className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
                sft_path
              </dt>
              <dd className="font-mono text-xs text-text break-all">
                {stats.sft_path ?? "--"}
              </dd>
              <dt className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
                dpo_path
              </dt>
              <dd className="font-mono text-xs text-text break-all">
                {stats.dpo_path ?? "--"}
              </dd>
              <dt className="font-mono text-[11px] uppercase tracking-wider text-text-muted">
                modules
              </dt>
              <dd className="font-mono text-xs text-text">
                {stats.modules.length > 0 ? stats.modules.join(", ") : "--"}
              </dd>
            </dl>
          </AilaCard>

          <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
            <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">
              Module breakdown
            </h3>
            {breakdownEntries.length === 0 ? (
              <p className="font-mono text-xs text-text-muted">
                Manifest carried no per-module counts.
              </p>
            ) : (
              <table aria-label="Sandbox runs" className="w-full font-mono text-xs">
                <thead>
                  <tr className="text-left text-text-muted">
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px]">
                      Module
                    </th>
                    <th className="pb-2 font-normal uppercase tracking-wider text-[10px] text-right">
                      Rows
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {breakdownEntries.map(([mod, count]) => (
                    <tr key={mod} className="border-t border-border">
                      <td className="py-1.5 text-text">{mod}</td>
                      <td className="py-1.5 text-right text-text">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </AilaCard>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab 3 -- Journal deadletter replay
// ---------------------------------------------------------------------------

function buildReplayColumns(): ColumnDef<ReplayResponseEntry>[] {
  return [
    {
      accessorKey: "deadletter_id",
      header: "Deadletter ID",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-text break-all">
          {row.original.deadletter_id}
        </span>
      ),
    },
    {
      accessorKey: "chain_id",
      header: "Chain",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-text break-all">
          {row.original.chain_id}
        </span>
      ),
    },
    {
      accessorKey: "team_id",
      header: "Team",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-text-muted">
          {row.original.team_id ?? "--"}
        </span>
      ),
    },
    {
      accessorKey: "replayed",
      header: "Status",
      cell: ({ row }) => (
        <AilaBadge severity={row.original.replayed ? "info" : "critical"}>
          {row.original.replayed ? "replayed" : "failed"}
        </AilaBadge>
      ),
    },
    {
      accessorKey: "seq",
      header: "Seq",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-text">
          {row.original.seq ?? "--"}
        </span>
      ),
    },
    {
      accessorKey: "error",
      header: "Error",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-critical">
          {row.original.error ?? ""}
        </span>
      ),
    },
  ];
}

function JournalReplayTab() {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const replayMutation = useJournalDeadletterReplay();
  const [lastResult, setLastResult] = useState<ReplayResponse | null>(null);

  const columns = useMemo(() => buildReplayColumns(), []);

  async function handleConfirm() {
    setConfirmOpen(false);
    try {
      const env = await replayMutation.mutateAsync();
      setLastResult(env.data);
      toast.success(
        `Replay complete -- scanned ${env.data.scanned}, replayed ${env.data.replayed}, failed ${env.data.failed}.`,
      );
    } catch (err) {
      const message =
        err instanceof ApiHttpError
          ? err.envelope?.message ?? err.detail
          : err instanceof Error
            ? err.message
            : "Journal replay failed.";
      toast.error(message);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <AilaCard variant="default" padding="md" decorations={["tech-border"]}>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-col gap-1">
            <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Journal deadletter replay
            </h2>
            <p className="font-mono text-[11px] text-text-muted">
              Drains un-replayed rows from{" "}
              <code className="font-mono">journal_deadletter</code> back into
              their chains. Rows that still fail stay in the deadletter table
              with a fresh error.
            </p>
          </div>
          <Button
            type="button"
            variant="destructive"
            onClick={() => setConfirmOpen(true)}
            disabled={replayMutation.isPending}
            className="gap-1.5"
          >
            <Skull className="h-3.5 w-3.5" />
            {replayMutation.isPending
              ? "Replaying…"
              : "Replay dead-lettered entries"}
          </Button>
        </div>
      </AilaCard>

      {lastResult && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <KpiTile
              label="Scanned"
              value={lastResult.scanned}
              icon={<Database className="h-4 w-4" />}
              tone="neutral"
            />
            <KpiTile
              label="Replayed"
              value={lastResult.replayed}
              icon={<ArrowClockwise className="h-4 w-4" />}
              tone="ok"
            />
            <KpiTile
              label="Still failing"
              value={lastResult.failed}
              icon={<Warning className="h-4 w-4" />}
              tone={lastResult.failed > 0 ? "crit" : "neutral"}
            />
          </div>

          {lastResult.entries.length === 0 ? (
            <EmptyState
              icon={<Skull className="h-10 w-10" />}
              title="No deadletter entries returned"
              description="The scan found nothing to replay -- the deadletter table is either empty or every row was already marked replayed."
            />
          ) : (
            <AilaTable
              data={lastResult.entries}
              columns={columns}
              pageSize={25}
              enableSorting
              enableFiltering={false}
            >
              <AilaTable.Header />
              <AilaTable.Body emptyState="No deadletter entries." />
              <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
            </AilaTable>
          )}
        </>
      )}

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              Replay journal deadletters?
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-4">
            <div className="rounded-[4px] border border-warning/40 bg-warning/10 px-4 py-3">
              <p className="font-mono text-xs text-text mb-1">
                This writes rows into chains you may not own.
              </p>
              <p className="font-mono text-xs text-text-muted">
                Every un-replayed deadletter row is re-appended to its
                originating chain. Rows that still fail are left in place
                with the fresh error attached.
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                variant="destructive"
                className="flex-1"
                onClick={handleConfirm}
              >
                Confirm replay
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setConfirmOpen(false)}
              >
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function PlatformOpsPage() {
  const [tab, setTab] = useState("sandbox");

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <Tabs value={tab} onValueChange={setTab}>
        <div className="overflow-x-auto">
          <TabsList variant="line" className="mb-4">
            <TabsTrigger value="sandbox">Sandbox</TabsTrigger>
            <TabsTrigger value="corpus">Trajectory Corpus</TabsTrigger>
            <TabsTrigger value="journal">Journal Replay</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="sandbox">
          <SandboxTab />
        </TabsContent>

        <TabsContent value="corpus">
          <CorpusTab />
        </TabsContent>

        <TabsContent value="journal">
          <JournalReplayTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
