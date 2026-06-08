import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { AnalystDirectivesPanel } from "../components/AnalystDirectivesPanel";
import { FetchRawFilePanel } from "../components/FetchRawFilePanel";
import { RetrieveFilePanel } from "../components/RetrieveFilePanel";
import { ArtifactExplorer } from "../components/ArtifactExplorer";
import { FindingsPanel } from "../components/FindingsPanel";
import { EvidenceTree } from "../components/EvidenceTree";
import { LeadScoreCard } from "../components/LeadScoreCard";
import { MachineReadinessCheck } from "../components/MachineReadinessCheck";
import { CarvedFilesPanel } from "../components/CarvedFilesPanel";
import { NetworkAnalysisPanel } from "../components/NetworkAnalysisPanel";
import { RegistryViewer } from "../components/RegistryViewer";
import { SolidEvidencePanel } from "../components/SolidEvidencePanel";
import { TimelineViewer } from "../components/TimelineViewer";
import { WriteUpViewer } from "../components/WriteUpViewer";
import { useRerunInvestigation, useStartInvestigation, useTriggerFullAnalysis } from "../mutations";
import {
  useForensicsProject,
  useInvestigationPolling,
  useProjectInvestigations,
} from "../queries";
import type { InvestigationSummary, MachineReadinessResult, ProjectKind } from "../types";
import { buildApiUrl } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

type TabId =
  | "investigations"
  | "solid_evidence"
  | "evidence"
  | "findings"
  | "timeline"
  | "network"
  | "registry"
  | "writeup"
  | "readiness";

const TABS: { id: TabId; label: string }[] = [
  { id: "investigations", label: "Investigations" },
  { id: "solid_evidence", label: "Solid Evidence" },
  { id: "findings", label: "Auto-findings" },
  { id: "evidence", label: "Evidence" },
  { id: "timeline", label: "Timeline" },
  { id: "network", label: "Network" },
  { id: "registry", label: "Registry" },
  { id: "writeup", label: "Writeup" },
  { id: "readiness", label: "Readiness" },
];

const STATUS_SEVERITY: Record<string, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  ready: "low",
  analyzing: "medium",
  queued: "info",
  running: "medium",
  completed: "low",
  failed: "critical",
};

// "pending" is the initial status of a freshly-submitted investigation — the
// earlier workflow states emit progress while status is still "pending", so
// the SSE subscriber must treat it as running or the live feed never opens.
const RUNNING_STATUSES = new Set(["pending", "queued", "running", "analyzing"]);

// ----- SSE readiness streaming -----

interface ReadinessEvent {
  stage: string;
  tool?: string;
  status?: string;
  version?: string;
  install_method?: string;
  required?: boolean;
  ready?: boolean;
  installed_count?: number;
  missing_count?: number;
  total?: number;
  message?: string;
  command?: string;
  error?: string;
  output_tail?: string;
  offline_type?: string;
  offline_bundle?: string;
}

function useReadinessStream(projectId: string) {
  const [events, setEvents] = useState<ReadinessEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<MachineReadinessResult | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const start = useCallback(async () => {
    if (running) return;
    abortRef.current?.abort();
    setEvents([]);
    setResult(null);
    setRunning(true);

    const ac = new AbortController();
    abortRef.current = ac;

    let token: string | null = null;
    try {
      token = await getAuthTokenStandalone();
    } catch {
      // unauthenticated — let the server reject
    }

    let response: Response;
    try {
      response = await fetch(
        buildApiUrl(`/forensics/projects/${encodeURIComponent(projectId)}/readiness-check/stream`),
        {
          headers: {
            Accept: "text/event-stream",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          signal: ac.signal,
        }
      );
    } catch (err) {
      if (!ac.signal.aborted) setRunning(false);
      return;
    }

    if (!response.ok || !response.body) {
      setRunning(false);
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    const push = (line: string) => {
      if (!line.startsWith("data:")) return;
      const raw = line.slice(5).trimStart();
      try {
        const event: ReadinessEvent = JSON.parse(raw);
        setEvents((prev) => [...prev, event]);
        if (event.stage === "done") {
          setResult({
            ready: event.ready ?? false,
            message: event.message ?? "",
            system_id: 0,
            system_name: "",
            analyzer_os: "",
            tools: [],
          } as unknown as MachineReadinessResult);
          setRunning(false);
          ac.abort();
        }
      } catch {
        // malformed — skip
      }
    };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split(/\r?\n/);
        buf = lines.pop() ?? "";
        for (const line of lines) push(line);
      }
    } catch {
      // aborted or network error
    } finally {
      setRunning(false);
    }
  }, [projectId, running]);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setEvents([]);
    setResult(null);
    setRunning(false);
  }, []);

  return { events, running, result, start, reset };
}

// ----- Investigation row with live polling when running -----
function InvestigationRow({
  investigation,
  projectId,
  onNavigate,
}: {
  investigation: InvestigationSummary;
  projectId: string;
  onNavigate: () => void;
}) {
  const isRunning = RUNNING_STATUSES.has(investigation.status);
  const { data: live } = useInvestigationPolling(
    isRunning ? projectId : "",
    isRunning ? investigation.id : ""
  );
  const display = live ?? investigation;
  const rerun = useRerunInvestigation(projectId);

  const handleRerun = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (isRunning || rerun.isPending) return;
    rerun.mutate({ investigationId: investigation.id });
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onNavigate}
      onKeyDown={(e) => e.key === "Enter" && onNavigate()}
      className="px-4 py-3 border border-border rounded-md bg-surface hover:bg-surface-secondary cursor-pointer transition-colors"
    >
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm text-foreground font-medium line-clamp-2 flex-1">
          {display.question}
        </p>
        <div className="flex items-center gap-2 shrink-0">
          {display.parent_investigation_id && (
            <AilaBadge severity="info" size="sm">enriched</AilaBadge>
          )}
          {isRunning && (
            <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
          )}
          <AilaBadge severity={STATUS_SEVERITY[display.status] ?? "info"} size="sm">
            {display.status}
          </AilaBadge>
          <button
            type="button"
            onClick={handleRerun}
            disabled={isRunning || rerun.isPending}
            title={
              isRunning
                ? "Wait for the current run to finish"
                : "Rerun this investigation, carrying findings forward"
            }
            className="text-xs px-2 py-0.5 rounded border border-border bg-surface hover:bg-blue-600 hover:text-white hover:border-blue-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {rerun.isPending ? "..." : "Rerun"}
          </button>
        </div>
      </div>
      <div className="flex gap-3 mt-1 text-xs text-text-muted">
        <span>
          {display.attempts_used}
          {display.max_attempts ? `/${display.max_attempts}` : ""} attempts
        </span>
        {display.final_answer && (
          <span className="truncate max-w-xs">{display.final_answer}</span>
        )}
      </div>
    </div>
  );
}

// ----- Start investigation form -----
function FullAnalysisButton({ projectId }: { projectId: string }) {
  const trigger = useTriggerFullAnalysis();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [events, setEvents] = useState<Array<{ stage?: string; message?: string; timestamp?: string }>>([]);
  const [status, setStatus] = useState<"idle" | "streaming" | "done" | "error">("idle");

  useEffect(() => {
    if (!taskId) return;
    const ac = new AbortController();
    setEvents([]);
    setStatus("streaming");
    (async () => {
      let token: string | null = null;
      try { token = await getAuthTokenStandalone(); } catch { /* noop */ }
      const resp = await fetch(buildApiUrl(`/tasks/${encodeURIComponent(taskId)}/events`), {
        headers: { Accept: "text/event-stream", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        signal: ac.signal,
      }).catch(() => null);
      if (!resp || !resp.ok || !resp.body) { setStatus("error"); return; }
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const lines = buf.split(/\r?\n/);
          buf = lines.pop() ?? "";
          for (const line of lines) {
            if (!line.startsWith("data:")) continue;
            try {
              const ev = JSON.parse(line.slice(5).trimStart());
              setEvents((prev) => [...prev, ev]);
              if (ev.stage === "__succeeded__" || ev.stage === "__crashed__") setStatus("done");
            } catch { /* skip */ }
          }
        }
      } finally {
        setStatus((s) => (s === "streaming" ? "done" : s));
      }
    })();
    return () => ac.abort();
  }, [taskId]);

  async function handleClick() {
    const res = await trigger.mutateAsync(projectId);
    setTaskId(res.data.task_id);
  }

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between">
      <div>
        <h3 className="text-sm font-semibold text-foreground">Pre-populate artifacts</h3>
        <p className="text-xs text-text-muted mt-0.5">
          Runs intake → collection → deep_analysis so the freeflow agent can answer questions
          instantly from cached evidence instead of re-scanning.
        </p>
      </div>
      <button
        type="button"
        onClick={handleClick}
        disabled={trigger.isPending || status === "streaming"}
        className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
      >
        {status === "streaming" ? "Running..." : trigger.isPending ? "Queueing..." : "Run Full Analysis"}
      </button>
    </div>
    {taskId && (
      <div className="mt-3 space-y-1">
        <div className="flex items-center gap-2 text-3xs text-text-muted font-mono">
          <span className={`inline-block w-1.5 h-1.5 rounded-full ${
            status === "streaming" ? "bg-amber-400 animate-pulse"
            : status === "done" ? "bg-green-400"
            : status === "error" ? "bg-red-400" : "bg-surface-secondary"
          }`} />
          <span>task:{taskId.slice(0, 8)} · {status} · {events.length} event(s)</span>
        </div>
        <div className="max-h-64 overflow-y-auto rounded border border-border bg-black/30 p-2 font-mono text-3xs space-y-0.5">
          {events.length === 0 && <p className="text-text-muted italic">Waiting for first event…</p>}
          {events.map((ev, i) => {
            const stage = ev.stage ?? "event";
            const color = stage.includes("failed") || stage.includes("crashed") ? "text-red-400"
              : stage.includes("done") || stage.includes("succeeded") ? "text-green-400"
              : stage.includes("start") || stage.includes("begin") ? "text-amber-400"
              : "text-accent";
            return (
              <div key={i}>
                <span className={color}>[{stage}]</span>
                <span className="text-text-muted ml-2">{ev.message ?? ""}</span>
              </div>
            );
          })}
        </div>
      </div>
    )}</AilaCard>
  );
}

function StartInvestigationForm({ projectId }: { projectId: string }) {
  const [question, setQuestion] = useState("");
  const [maxAttempts, setMaxAttempts] = useState(5);
  const [expanded, setExpanded] = useState(false);
  const startInvestigation = useStartInvestigation();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!question.trim()) return;
    await startInvestigation.mutateAsync({ projectId, question, maxAttempts });
    setQuestion("");
    setExpanded(false);
  }

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={() => setExpanded(true)}
        className="w-full px-4 py-3 text-sm font-medium rounded-md border-2 border-dashed border-border text-text-muted hover:border-accent hover:text-accent transition-colors"
      >
        + Start New Investigation
      </button>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3 p-4 border border-border rounded-md bg-surface">
      <label htmlFor="pd-question" className="block text-sm font-medium text-foreground">
        Investigation question
      </label>
      <textarea
        id="pd-question"
        value={question}
        onChange={(e) => setQuestion(e.target.value)}
        placeholder="Ask a question about the evidence"
        rows={3}
        className="w-full px-3 py-2 text-sm rounded-md border border-border bg-surface text-foreground resize-none"
        autoFocus
      />
      <div className="flex items-center gap-3">
        <label htmlFor="pd-max-attempts" className="text-xs text-text-muted whitespace-nowrap">Max attempts</label>
        <input
          id="pd-max-attempts"
          type="number"
          min={1}
          max={20}
          value={maxAttempts}
          onChange={(e) => setMaxAttempts(Number(e.target.value))}
          className="w-20 px-2 py-1 text-sm rounded-md border border-border bg-surface text-foreground"
        />
      </div>
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="px-3 py-1.5 text-sm rounded-md border border-border text-foreground hover:bg-surface-secondary"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={!question.trim() || startInvestigation.isPending}
          className="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {startInvestigation.isPending ? "Starting..." : "Start"}
        </button>
      </div>
      {startInvestigation.isError && (
        <p className="text-xs text-text-danger">Failed to start investigation.</p>
      )}
    </form>
  );
}

// ----- Investigations tab -----
function RawDirectoryNotice() {
  return (
    <AilaCard  techBorder glow><div className="flex items-start justify-between gap-3">
      <div>
        <h3 className="text-sm font-semibold text-foreground">Raw Directory — intake only</h3>
        <p className="text-xs text-text-muted mt-0.5">
          This project treats the evidence directory as a real filesystem on the analyzer.
          The pre/full-analysis pipeline (disk, memory, network, log lanes) is skipped —
          ask questions directly and the investigator will read files off the analyzer.
        </p>
      </div>
      <span className="shrink-0 px-2 py-0.5 text-2xs rounded border border-border text-text-muted">
        raw_directory
      </span>
    </div></AilaCard>
  );
}

function InvestigationsTab({
  projectId,
  projectKind,
}: {
  projectId: string;
  projectKind: ProjectKind;
}) {
  const navigate = useNavigate();
  const { data: investigations, isLoading, isError } = useProjectInvestigations(projectId);
  const isRaw = projectKind === "raw_directory";

  return (
    <div className="space-y-4 bg-surface text-foreground p-4 rounded-md border border-border">
      <AnalystDirectivesPanel projectId={projectId} compact />
      {isRaw ? (
        <FetchRawFilePanel projectId={projectId} compact />
      ) : (
        <RetrieveFilePanel projectId={projectId} compact />
      )}
      {isRaw ? <RawDirectoryNotice /> : <FullAnalysisButton projectId={projectId} />}
      <StartInvestigationForm projectId={projectId} />

      {isLoading && <LoadingSkeleton size="md" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load investigations.</p></AilaCard>
      )}

      {!isLoading && !isError && (investigations ?? []).length === 0 && (
        <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-6">
          No investigations yet. Start one above.
        </p></AilaCard>
      )}

      <div className="space-y-2">
        {(investigations ?? []).map((inv) => (
          <InvestigationRow
            key={inv.id}
            investigation={inv}
            projectId={projectId}
            onNavigate={() =>
              navigate(`/forensics/projects/${projectId}/investigations/${inv.id}`)
            }
          />
        ))}
      </div>
    </div>
  );
}

// ----- Readiness stream display -----
const TOOL_STATUS_COLOR: Record<string, string> = {
  installed: "text-green-400",
  missing: "text-red-400",
  skipped: "text-text-muted",
};

function ReadinessStreamPanel({ projectId }: { projectId: string }) {
  const { events, running, result, start, reset } = useReadinessStream(projectId);

  const toolEvents = events.filter((e) => e.stage === "tool_done");
  const currentAction = running
    ? [...events].reverse().find((e: ReadinessEvent) => e.stage === "checking" || e.stage === "installing") ?? null
    : null;
  const startEvent = events.find((e) => e.stage === "start");

  return (
    <div className="space-y-4">
      <AilaCard  techBorder glow><div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold font-mono text-foreground">Machine Readiness Check</h3>
          {startEvent && (
            <p className="text-xs text-text-muted mt-0.5">{startEvent.message}</p>
          )}
        </div>
        <div className="flex gap-2">
          {result && (
            <button
              type="button"
              onClick={reset}
              className="px-3 py-1.5 text-xs rounded-md border border-border text-text-muted hover:text-foreground"
            >
              Reset
            </button>
          )}
          <button
            type="button"
            onClick={start}
            disabled={running}
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {running && <span className="inline-block w-2 h-2 rounded-full bg-white/70 animate-pulse" />}
            {running ? "Running..." : result ? "Re-run Check" : "Run Check"}
          </button>
        </div>
      </div>
      
      {/* Current action */}
      {currentAction && (
        <div className="mb-3 px-3 py-2 rounded-md bg-surface-secondary border border-border text-xs text-text-muted font-mono flex items-center gap-2">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
          {currentAction.message}
        </div>
      )}
      
      {/* Tool results */}
      {toolEvents.length > 0 && (
        <div className="space-y-1 max-h-96 overflow-y-auto">
          {toolEvents.map((e, i) => (
            <div
              key={i}
              className="flex items-center justify-between px-3 py-1.5 rounded text-xs font-mono hover:bg-surface-secondary"
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className={TOOL_STATUS_COLOR[e.status ?? ""] ?? "text-text-muted"}>
                  {e.status === "installed" ? "✓" : e.status === "missing" ? "✗" : "—"}
                </span>
                <span className="text-foreground truncate">{e.tool}</span>
                {e.version && (
                  <span className="text-text-muted shrink-0">{e.version}</span>
                )}
                {e.install_method && e.install_method !== "pre_installed" && (
                  <span className="text-accent shrink-0 text-3xs">[{e.install_method}]</span>
                )}
              </div>
              {e.required && e.status === "missing" && (
                <span className="text-red-400 shrink-0 ml-2">REQUIRED</span>
              )}
            </div>
          ))}
        </div>
      )}
      
      {/* Full event log (xray) — shows every streamed event so debugging isn't a black box */}
      {events.length > 0 && (
        <details className="mt-4">
          <summary className="text-xs font-mono text-text-muted cursor-pointer select-none hover:text-foreground">
            xray log ({events.length} events) — expand for full stream
          </summary>
          <div className="mt-2 max-h-96 overflow-y-auto rounded border border-border bg-black/40">
            {events.map((e, i) => {
              const stage = e.stage ?? "event";
              const color =
                stage.includes("failed") ? "text-red-400" :
                stage === "tool_done" && e.status === "installed" ? "text-green-400" :
                stage === "install_verified" ? "text-green-400" :
                stage === "installing" || stage === "install_exec" ? "text-amber-400" :
                stage === "checking" ? "text-blue-400" :
                stage === "heartbeat" ? "text-text-muted/60" :
                "text-text-muted";
              return (
                <div key={i} className="px-2 py-1 text-3xs font-mono border-b border-border/40 last:border-b-0">
                  <span className={`${color} font-semibold`}>[{stage}]</span>
                  {e.tool && <span className="text-foreground ml-2">{e.tool}</span>}
                  {e.message && <span className="text-text-muted ml-2">— {e.message}</span>}
                  {e.command && (
                    <div className="text-text-muted/70 text-4xs ml-6 mt-0.5 break-all">$ {e.command}</div>
                  )}
                  {e.error && (
                    <div className="text-red-300/80 text-4xs ml-6 mt-0.5 break-all whitespace-pre-wrap">{e.error}</div>
                  )}
                  {e.output_tail && (
                    <div className="text-text-muted/70 text-4xs ml-6 mt-0.5 break-all whitespace-pre-wrap">{e.output_tail}</div>
                  )}
                </div>
              );
            })}
          </div>
        </details>
      )}
      
      {/* Summary */}
      {result && (
        <div className={`mt-4 px-4 py-3 rounded-md border text-sm font-medium ${
          result.ready
            ? "border-green-800 bg-green-950/30 text-green-400"
            : "border-red-800 bg-red-950/30 text-red-400"
        }`}>
          {result.ready ? "✓ Machine is ready" : "✗ Some required tools are missing"}
        </div>
      )}
      
      {!running && events.length === 0 && (
        <p className="text-sm text-text-muted text-center py-6">
          Run a readiness check to verify forensic tools on the analyzer machine.
        </p>
      )}</AilaCard>

      {/* Legacy result view if needed */}
      {result && (
        <MachineReadinessCheck
          readinessResult={result}
          isLoading={false}
          onRetry={start}
          onContinue={() => {}}
        />
      )}
    </div>
  );
}

// ----- Main dashboard -----
export function ProjectDashboardPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const { data: project, isLoading, isError } = useForensicsProject(projectId ?? "");

  useUpdatePageHeader({
    title: project?.name,
    subtitle: project?.status,
    status: project?.status === 'active' ? 'live' : project?.status === 'archived' ? 'paused' : null,
  });
  const [activeTab, setActiveTab] = useState<TabId>("investigations");

  if (!projectId) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Invalid project ID.</p></AilaCard>
    );
  }

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError || !project) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load project.</p></AilaCard>
    );
  }

  return (
    <div className="space-y-4 bg-surface text-foreground p-4 rounded-md border border-border">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-text-muted">
            <span>Machine: {project.system_name ?? "Unknown"}</span>
            <span className="font-mono">{project.evidence_directory}</span>
            {project.created_at && (
              <span>{new Date(project.created_at).toLocaleDateString()}</span>
            )}
          </div>
          <div className="flex gap-4 text-xs text-text-muted">
            <span>{project.artifact_count} artifacts</span>
            <span>{project.lead_count} leads</span>
            <span>{project.investigation_count} investigations</span>
          </div>
        </div>
        <button
          type="button"
          onClick={() => navigate(`/forensics/projects/${projectId}/details`)}
          className="shrink-0 px-3 py-1.5 text-xs rounded-md border border-border text-foreground hover:bg-surface-secondary"
        >
          Full Details
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
              activeTab === tab.id
                ? "bg-surface border border-b-0 border-border text-foreground"
                : "text-text-muted hover:text-foreground hover:bg-surface-secondary"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="pt-1">
        {activeTab === "investigations" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <InvestigationsTab projectId={projectId} projectKind={project.project_kind} />
            </div>
            <div>
              <LeadScoreCard projectId={projectId} />
            </div>
          </div>
        )}
        {activeTab === "solid_evidence" && <SolidEvidencePanel projectId={projectId} />}
        {activeTab === "findings" && <FindingsPanel projectId={projectId} />}
        {activeTab === "evidence" && (
          <div className="space-y-6">
            <EvidenceTree projectId={projectId} />
            <ArtifactExplorer projectId={projectId} />
          </div>
        )}
        {activeTab === "timeline" && <TimelineViewer projectId={projectId} />}
        {activeTab === "network" && (
          <div className="space-y-6">
            <NetworkAnalysisPanel projectId={projectId} />
            <CarvedFilesPanel projectId={projectId} />
          </div>
        )}
        {activeTab === "registry" && <RegistryViewer projectId={projectId} />}
        {activeTab === "writeup" && <WriteUpViewer projectId={projectId} />}
        {activeTab === "readiness" && <ReadinessStreamPanel projectId={projectId} />}
      </div>
    </div>
  );
}
