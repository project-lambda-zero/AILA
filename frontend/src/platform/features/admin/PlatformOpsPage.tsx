/**
 * PlatformOpsPage -- god-tier admin console wiring the three platform
 * endpoints that had no UI: sandbox exec, corpus export/stats, and
 * journal deadletter replay.
 *
 * Rebuilt to the AILA mock: SectionHeader top with a Segmented switcher for
 * the three concerns; each concern renders as WindowPanels with DataGrid /
 * MonoBadge / BigStat. Data hooks, mutations, and confirm flow preserved.
 *
 * The page is bare content -- protectPage() in router.tsx already wraps
 * it in PageFrame (title bar + corner brackets).
 */
import { useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { Play } from "@phosphor-icons/react/dist/csr/Play";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { X } from "@phosphor-icons/react/dist/csr/X";

import {
  SectionHeader,
  Segmented,
  MonoBadge,
  DataGrid,
  BigStat,
  StatBar,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
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

// ---------------------------------------------------------------------------
// Shared inline element styles (mock button + input + textarea).
// ---------------------------------------------------------------------------

const BUTTON_STYLE: CSSProperties = {
  height: 26, padding: "0 11px", fontSize: 9.5,
  fontFamily: "var(--font-mono)", letterSpacing: "0.08em", textTransform: "uppercase",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3, cursor: "pointer",
};

const PRIMARY_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  color: "var(--text-on-accent)",
};

const WARN_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "color-mix(in srgb, var(--status-warn) 14%, transparent)",
  border: "1px solid var(--status-warn)",
  color: "var(--status-warn)",
};

const INPUT_STYLE: CSSProperties = {
  height: 26, padding: "0 8px", fontSize: 11,
  fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const TEXTAREA_STYLE: CSSProperties = {
  padding: "6px 8px", fontSize: 11,
  fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3, resize: "vertical",
};

const LABEL_STYLE: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9, letterSpacing: "0.14em",
  color: "var(--text-faint)",
  textTransform: "uppercase",
};

// ---------------------------------------------------------------------------
// Modal shell -- centred WindowPanel over a scrim. Replaces shadcn Dialog.
// ---------------------------------------------------------------------------

interface ModalShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  tone?: "accent" | "warn" | "muted" | "ok" | "info";
  children: ReactNode;
  width?: number;
}

function ModalShell({ open, onClose, title, tone = "accent", children, width = 460 }: ModalShellProps) {
  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
        display: "flex", alignItems: "center", justifyContent: "center", padding: 16,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ width: "100%", maxWidth: width }}
      >
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
// argv parsing -- one arg per line, or a single command line split on spaces
// ---------------------------------------------------------------------------

function parseArgv(raw: string): string[] {
  const trimmed = raw.replace(/\r/g, "").trim();
  if (!trimmed) return [];
  const lines = trimmed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length > 1) return lines;
  return lines[0].split(/\s+/g).filter((token) => token.length > 0);
}

// ---------------------------------------------------------------------------
// Concern 1 -- Sandbox
// ---------------------------------------------------------------------------

function SandboxConcern() {
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
    <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      {/* Form */}
      <WindowPanel title="execute command">
        <div className="flex flex-col" style={{ gap: 12 }}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label htmlFor="platform-ops-sandbox-argv" style={LABEL_STYLE}>ARGV</label>
            <textarea
              id="platform-ops-sandbox-argv"
              value={argvRaw}
              onChange={(e) => setArgvRaw(e.target.value)}
              rows={5}
              placeholder={"echo hello world\n\n-- or one arg per line --\n\necho\nhello\nworld"}
              spellCheck={false}
              style={TEXTAREA_STYLE}
            />
            <p className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.5 }}>
              {argv.length === 0
                ? "One arg per line, or a single command line split on spaces."
                : `Parsed to ${argv.length} token${argv.length === 1 ? "" : "s"}: [${argv.map((a) => JSON.stringify(a)).join(", ")}]`}
            </p>
          </div>

          <div className="flex flex-col" style={{ gap: 4 }}>
            <label htmlFor="platform-ops-sandbox-stdin" style={LABEL_STYLE}>STDIN (OPTIONAL)</label>
            <textarea
              id="platform-ops-sandbox-stdin"
              value={stdin}
              onChange={(e) => setStdin(e.target.value)}
              rows={3}
              placeholder="Piped to the child's stdin. Empty means /dev/null."
              spellCheck={false}
              style={TEXTAREA_STYLE}
            />
          </div>

          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label htmlFor="platform-ops-sandbox-timeout" style={LABEL_STYLE}>TIMEOUT_S</label>
              <input
                id="platform-ops-sandbox-timeout"
                type="number"
                min={1}
                step={1}
                value={timeoutS}
                onChange={(e) => {
                  const v = Number.parseFloat(e.target.value);
                  setTimeoutS(Number.isFinite(v) && v > 0 ? v : 30);
                }}
                style={INPUT_STYLE}
              />
            </div>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <span style={LABEL_STYLE}>NETWORK</span>
              <label
                className="inline-flex items-center font-mono"
                style={{ gap: 8, height: 26, fontSize: 11, color: "var(--text-primary)" }}
              >
                <input
                  type="checkbox"
                  checked={network}
                  onChange={(e) => setNetwork(e.target.checked)}
                  style={{ width: 12, height: 12, accentColor: "var(--accent)" }}
                />
                Allow outbound network
              </label>
            </div>
          </div>

          <div>
            <button
              type="button"
              onClick={() => void handleSubmit()}
              disabled={!argvValid || execMutation.isPending}
              style={PRIMARY_BUTTON_STYLE}
            >
              <Play size={11} aria-hidden style={{ marginRight: 6, verticalAlign: "-1px" }} />
              {execMutation.isPending ? "RUNNING\u2026" : "EXECUTE IN SANDBOX"}
            </button>
          </div>
        </div>
      </WindowPanel>

      {/* Result */}
      <WindowPanel
        title="result"
        tone={result ? (result.exit_code === 0 ? "ok" : "warn") : "muted"}
        status={
          result
            ? `EXIT ${result.exit_code ?? "?"} \u00b7 ${result.duration_s.toFixed(3)}S`
            : execMutation.isPending
              ? "RUNNING"
              : unavailable
                ? "UNAVAILABLE"
                : "IDLE"
        }
      >
        {unavailable && (
          <div
            className="flex items-start"
            style={{
              gap: 10,
              padding: 10,
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              borderRadius: 3,
            }}
          >
            <Warning size={14} aria-hidden style={{ marginTop: 1, color: "var(--status-warn)" }} />
            <div className="flex flex-col font-mono" style={{ gap: 4, fontSize: 11, color: "var(--text-primary)" }}>
              <span>No sandbox backend is configured.</span>
              <span style={{ color: "var(--text-muted)", fontSize: 10.5, lineHeight: 1.6 }}>
                The platform returned <span style={{ color: "var(--text-primary)" }}>503 Service Unavailable</span>{" "}
                -- this is the expected state on deployments that have not provisioned a sandbox host.
                Point <span style={{ color: "var(--text-primary)" }}>platform.sandbox_backend</span> at a live
                backend or invoke the module-scoped <span style={{ color: "var(--text-primary)" }}>sandbox_exec</span> tool
                inside an agent turn where the team's backend is bound automatically.
              </span>
            </div>
          </div>
        )}

        {!unavailable && !result && !execMutation.isPending && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Submit a command to see stdout, stderr, and status flags.
          </p>
        )}

        {execMutation.isPending && <LoadingSkeletonGroup lines={5} />}

        {result && (
          <div className="flex flex-col" style={{ gap: 10 }}>
            <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
              <MonoBadge tone={result.exit_code === 0 ? "info" : "critical"}>
                exit_code={result.exit_code ?? "?"}
              </MonoBadge>
              <MonoBadge tone="muted">backend: {result.backend}</MonoBadge>
              <MonoBadge tone="muted">{result.duration_s.toFixed(3)}s</MonoBadge>
              {result.timed_out && <MonoBadge tone="medium">timed out</MonoBadge>}
              {result.oom && <MonoBadge tone="critical">oom</MonoBadge>}
              {result.truncated && <MonoBadge tone="medium">truncated</MonoBadge>}
            </div>

            <div className="flex flex-col" style={{ gap: 4 }}>
              <span style={LABEL_STYLE}>STDOUT</span>
              <pre
                style={{
                  maxHeight: 260, overflow: "auto",
                  padding: 8, fontSize: 10.5, fontFamily: "var(--font-mono)",
                  color: "var(--text-primary)",
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-faint)", borderRadius: 3,
                  whiteSpace: "pre-wrap", margin: 0,
                }}
              >
                {result.stdout || "(empty)"}
              </pre>
            </div>

            <div className="flex flex-col" style={{ gap: 4 }}>
              <span style={LABEL_STYLE}>STDERR</span>
              <pre
                style={{
                  maxHeight: 260, overflow: "auto",
                  padding: 8, fontSize: 10.5, fontFamily: "var(--font-mono)",
                  color: "var(--text-primary)",
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-faint)", borderRadius: 3,
                  whiteSpace: "pre-wrap", margin: 0,
                }}
              >
                {result.stderr || "(empty)"}
              </pre>
            </div>
          </div>
        )}
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Concern 2 -- Trajectory Corpus
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null): string {
  if (!value) return "--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function CorpusConcern() {
  const statsQuery = useCorpusStats();
  const exportMutation = useCorpusExport();

  async function handleExport() {
    try {
      const env = await exportMutation.mutateAsync();
      toast.success(`Corpus export queued: task ${env.data.task_id.slice(0, 8)}\u2026`);
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
        ? Object.entries(stats.module_breakdown).sort(([a], [b]) => a.localeCompare(b))
        : [],
    [stats],
  );
  const totalRows = useMemo(
    () => breakdownEntries.reduce((acc, [, count]) => acc + count, 0),
    [breakdownEntries],
  );

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      {/* Action row */}
      <WindowPanel
        title="trajectory corpus export"
        actions={
          <button
            type="button"
            onClick={() => void handleExport()}
            disabled={exportMutation.isPending}
            style={PRIMARY_BUTTON_STYLE}
          >
            <ArrowClockwise size={11} aria-hidden style={{ marginRight: 6, verticalAlign: "-1px" }} />
            {exportMutation.isPending ? "QUEUEING\u2026" : "RUN EXPORT"}
          </button>
        }
      >
        <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
          Walks every configured module's outcome table and writes SFT + DPO
          jsonl files. Runs as a background task on the <span style={{ color: "var(--text-primary)" }}>default</span> queue.
        </p>
      </WindowPanel>

      {statsQuery.isLoading && (
        <WindowPanel title="stats" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {statsQuery.isError && (
        <div
          className="font-mono"
          style={{
            border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "8px 12px", fontSize: 11, borderRadius: 3,
          }}
        >
          Failed to load corpus stats: {(statsQuery.error as Error).message}
        </div>
      )}

      {stats && !stats.has_corpus && (
        <WindowPanel title="stats" tone="muted" status="EMPTY">
          <div
            className="font-mono"
            style={{ padding: 24, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
          >
            No corpus generated yet.
            <br />
            {stats.detail ?? "Click Run export above to build the first SFT + DPO jsonl pair."}
          </div>
        </WindowPanel>
      )}

      {stats && stats.has_corpus && (
        <>
          <div
            className="grid"
            style={{ gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 12 }}
          >
            <WindowPanel title="sft rows">
              <BigStat value={stats.sft_count} sub={`min_turns = ${stats.min_turns}`} />
            </WindowPanel>
            <WindowPanel title="dpo pairs" tone="ok">
              <BigStat value={stats.dpo_count} sub="preference pairs" />
            </WindowPanel>
            <WindowPanel title="investigations" tone="muted">
              <BigStat
                value={stats.investigations}
                sub={`skipped: ${stats.skipped_short_branches} short, ${stats.skipped_unparseable_decisions} unparseable`}
              />
            </WindowPanel>
            <WindowPanel title="generated" tone="muted">
              <div
                className="font-mono"
                style={{ fontSize: 13, color: "var(--text-primary)", letterSpacing: "-0.01em" }}
              >
                {formatTimestamp(stats.generated_at)}
              </div>
              <div
                className="font-mono"
                style={{ marginTop: 4, fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.04em" }}
              >
                last manifest write
              </div>
            </WindowPanel>
          </div>

          <WindowPanel title="manifest">
            <div
              className="grid font-mono"
              style={{ gridTemplateColumns: "max-content 1fr", gap: "6px 20px", fontSize: 11 }}
            >
              <span style={LABEL_STYLE}>CORPUS_DIR</span>
              <span style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>{stats.corpus_dir}</span>
              <span style={LABEL_STYLE}>SFT_PATH</span>
              <span style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>{stats.sft_path ?? "--"}</span>
              <span style={LABEL_STYLE}>DPO_PATH</span>
              <span style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>{stats.dpo_path ?? "--"}</span>
              <span style={LABEL_STYLE}>MODULES</span>
              <span style={{ color: "var(--text-primary)" }}>
                {stats.modules.length > 0 ? stats.modules.join(", ") : "--"}
              </span>
            </div>
          </WindowPanel>

          <WindowPanel title="module breakdown" flush>
            {breakdownEntries.length === 0 ? (
              <div
                className="font-mono"
                style={{ padding: 24, textAlign: "center", fontSize: 11, color: "var(--text-muted)" }}
              >
                Manifest carried no per-module counts.
              </div>
            ) : (
              <DataGrid
                columns={[
                  { label: "MODULE", width: "1fr" },
                  { label: "ROWS", width: "80px", align: "right" },
                  { label: "SHARE", width: "260px" },
                ]}
                rows={breakdownEntries}
                getKey={([mod]) => mod}
                renderCells={([mod, count]) => [
                  <span className="font-mono" style={{ color: "var(--text-primary)", fontSize: 11 }}>{mod}</span>,
                  <span className="font-mono" style={{ color: "var(--text-primary)", fontSize: 11 }}>{count}</span>,
                  <StatBar
                    label=""
                    color="var(--accent)"
                    value={count}
                    max={Math.max(1, totalRows)}
                  />,
                ]}
              />
            )}
          </WindowPanel>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Concern 3 -- Journal deadletter replay
// ---------------------------------------------------------------------------

function JournalReplayConcern() {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const replayMutation = useJournalDeadletterReplay();
  const [lastResult, setLastResult] = useState<ReplayResponse | null>(null);

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
    <div className="flex flex-col" style={{ gap: 12 }}>
      <WindowPanel
        title="journal deadletter replay"
        tone="warn"
        actions={
          <button
            type="button"
            onClick={() => setConfirmOpen(true)}
            disabled={replayMutation.isPending}
            style={WARN_BUTTON_STYLE}
          >
            <Skull size={11} aria-hidden style={{ marginRight: 6, verticalAlign: "-1px" }} />
            {replayMutation.isPending ? "REPLAYING\u2026" : "REPLAY DEAD-LETTERED"}
          </button>
        }
      >
        <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
          Drains un-replayed rows from <span style={{ color: "var(--text-primary)" }}>journal_deadletter</span>{" "}
          back into their chains. Rows that still fail stay in the deadletter table with a fresh error attached.
        </p>
      </WindowPanel>

      {lastResult && (
        <>
          <div
            className="grid"
            style={{ gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12 }}
          >
            <WindowPanel title="scanned" tone="muted">
              <BigStat value={lastResult.scanned} sub="rows examined" />
            </WindowPanel>
            <WindowPanel title="replayed" tone="ok">
              <BigStat value={lastResult.replayed} sub="re-appended to chains" />
            </WindowPanel>
            <WindowPanel title="still failing" tone={lastResult.failed > 0 ? "warn" : "muted"}>
              <BigStat value={lastResult.failed} sub={lastResult.failed > 0 ? "left in deadletter" : "clean sweep"} />
            </WindowPanel>
          </div>

          {lastResult.entries.length === 0 ? (
            <WindowPanel title="entries" tone="muted" status="EMPTY">
              <div
                className="font-mono"
                style={{ padding: 24, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
              >
                No deadletter entries returned.
                <br />
                Either the table was empty or every row was already marked replayed.
              </div>
            </WindowPanel>
          ) : (
            <WindowPanel title="entries" flush>
              <DataGrid<ReplayResponseEntry>
                columns={[
                  { label: "DEADLETTER ID", width: "1fr" },
                  { label: "CHAIN", width: "1fr" },
                  { label: "TEAM", width: "140px" },
                  { label: "STATUS", width: "110px" },
                  { label: "SEQ", width: "60px", align: "right" },
                  { label: "ERROR", width: "1.4fr" },
                ]}
                rows={lastResult.entries}
                getKey={(row) => row.deadletter_id}
                renderCells={(row) => [
                  <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)", wordBreak: "break-all" }}>
                    {row.deadletter_id}
                  </span>,
                  <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)", wordBreak: "break-all" }}>
                    {row.chain_id}
                  </span>,
                  <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>{row.team_id ?? "--"}</span>,
                  <MonoBadge tone={row.replayed ? "info" : "critical"}>
                    {row.replayed ? "replayed" : "failed"}
                  </MonoBadge>,
                  <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)" }}>{row.seq ?? "--"}</span>,
                  <span className="font-mono" style={{ fontSize: 10.5, color: "var(--accent)" }}>{row.error ?? ""}</span>,
                ]}
              />
            </WindowPanel>
          )}
        </>
      )}

      <ModalShell
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="replay journal deadletters"
        tone="warn"
        width={420}
      >
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
            <div style={{ marginBottom: 4 }}>
              This writes rows into chains you may not own.
            </div>
            <div style={{ color: "var(--text-muted)", fontSize: 10.5 }}>
              Every un-replayed deadletter row is re-appended to its originating chain.
              Rows that still fail are left in place with the fresh error attached.
            </div>
          </div>
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{ ...WARN_BUTTON_STYLE, flex: 1 }}
              onClick={() => void handleConfirm()}
            >
              CONFIRM REPLAY
            </button>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => setConfirmOpen(false)}
            >
              CANCEL
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type Concern = "sandbox" | "corpus" | "journal";

export function PlatformOpsPage() {
  const [tab, setTab] = useState<Concern>("sandbox");

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25a0"}
        title="platform ops"
        actions={
          <Segmented<Concern>
            options={[
              { value: "sandbox", label: "SANDBOX" },
              { value: "corpus", label: "TRAJECTORY CORPUS" },
              { value: "journal", label: "JOURNAL REPLAY" },
            ]}
            value={tab}
            onChange={setTab}
          />
        }
      />

      {tab === "sandbox" && <SandboxConcern />}
      {tab === "corpus" && <CorpusConcern />}
      {tab === "journal" && <JournalReplayConcern />}
    </div>
  );
}
