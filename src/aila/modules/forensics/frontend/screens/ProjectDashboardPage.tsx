import * as React from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { Detective } from "@phosphor-icons/react/dist/csr/Detective";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { EmptyState } from "@/components/aila/EmptyState";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { PixelIcon } from "@/components/aila/PixelIcon";
import {
  SectionHeader,
  MonoBadge,
  Segmented,
  StatBar,
  DataGrid,
  toneColor,
  type GridColumn,
} from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";
import { buildApiUrl } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";

import { InvestigationRowSkeletonList, InvestigationDetailSkeleton } from "../components/skeletons";
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
import { useDebouncedValue, useRowKeyboardNav, sortRows } from "../powerTable";
import { useForensicsListLive } from "../useLiveInvalidation";
import { SavedViews } from "../components/SavedViews";
import type { InvestigationSummary, MachineReadinessResult, ProjectKind } from "../types";

// ----- Constants and helpers -----

type TabId =
  | "investigations"
  | "solid_evidence"
  | "findings"
  | "evidence"
  | "timeline"
  | "network"
  | "registry"
  | "writeup"
  | "readiness";

const TABS: { value: TabId; label: string }[] = [
  { value: "investigations", label: "investigations" },
  { value: "solid_evidence", label: "solid evidence" },
  { value: "findings", label: "findings" },
  { value: "evidence", label: "evidence" },
  { value: "timeline", label: "timeline" },
  { value: "network", label: "network" },
  { value: "registry", label: "registry" },
  { value: "writeup", label: "writeup" },
  { value: "readiness", label: "readiness" },
];

const TAB_TITLES: Record<TabId, string> = {
  investigations: "investigations",
  solid_evidence: "solid evidence",
  findings: "auto-findings",
  evidence: "evidence",
  timeline: "timeline",
  network: "network",
  registry: "registry",
  writeup: "writeup",
  readiness: "readiness",
};

const STATUS_TONE: Record<string, string> = {
  created: "info",
  queued: "info",
  pending: "info",
  ready: "low",
  analyzing: "medium",
  running: "medium",
  completed: "low",
  failed: "critical",
  exhausted: "high",
  cancelled: "high",
  abandoned: "muted",
  stalled: "muted",
};

// "pending" is the initial status of a freshly-submitted investigation -- the
// earlier workflow states emit progress while status is still "pending", so
// the SSE subscriber must treat it as running or the live feed never opens.
const RUNNING_STATUSES = new Set(["pending", "queued", "running", "analyzing"]);

// Sort keys for the InvestigationsTab. The server only returns page + page_size
// so ordering and text search are applied client-side over the loaded page.
type InvestigationSortKey = "question" | "status" | "attempts_used";

// Serialized shape stored in SavedFilterRecord.filter_json for the
// investigations list. Kept intentionally narrow -- when new controls
// arrive, extend the type and default missing keys on apply so older
// saved views still round-trip cleanly.
interface InvestigationsViewState {
  search: string;
  sortKey: InvestigationSortKey;
  sortDir: "asc" | "desc";
}

const INVESTIGATION_SORT_KEYS: readonly InvestigationSortKey[] = [
  "question",
  "status",
  "attempts_used",
];

// Reusable inline styles keyed to the mock language.
const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  minWidth: 220,
  flex: 1,
};

const SELECT_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 10,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const DIR_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 10,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-muted)",
  borderRadius: 3,
  cursor: "pointer",
  letterSpacing: "0.08em",
};

const ACCENT_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  boxShadow: "var(--bevel-key)",
};

const MUTED_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const TEXTAREA_STYLE: React.CSSProperties = {
  width: "100%",
  padding: "8px 10px",
  fontSize: 12,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  resize: "none" as const,
  fontFamily: "var(--font-mono)",
};

const NUMBER_STYLE: React.CSSProperties = {
  width: 80,
  height: 26,
  padding: "0 8px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

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

// The readiness stream hook is preserved verbatim (behavior identical to
// prior implementation): it's the source of truth for this page's readiness
// tab, distinct from the shared ReadinessStreamPanel component.
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
      // unauthenticated -- let the server reject
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
    } catch {
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
        // malformed -- skip
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

// ----- Investigation grid (DataGrid-shaped, per-row polling) -----

const INVESTIGATION_COLUMNS: GridColumn[] = [
  { label: "#", width: "40px" },
  { label: "QUESTION", width: "1fr" },
  { label: "STATUS", width: "120px" },
  { label: "ATTEMPTS", width: "110px" },
  { label: "", width: "90px" },
];

// One investigation row -- owns the live-polling hook so a running row
// picks up server-side updates without the parent list rerendering the
// whole grid. Rendered as a bare grid child matching the DataGrid track
// template so the visual language stays consistent with the rest of the
// mock kit even though we can't use <DataGrid/> directly (it doesn't
// support per-row hooks).
function InvestigationLiveRow({
  investigation,
  index,
  projectId,
  onNavigate,
  template,
}: {
  investigation: InvestigationSummary;
  index: number;
  projectId: string;
  onNavigate: () => void;
  template: string;
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

  const statusTone = STATUS_TONE[display.status] ?? "info";

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onNavigate}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          onNavigate();
        }
      }}
      data-power-row="investigation"
      aria-label={`Open investigation: ${display.question}`}
      className="grid font-mono"
      style={{
        gridTemplateColumns: template,
        gap: 10,
        padding: "8px 12px",
        borderBottom: "1px solid var(--border-faint)",
        background: "var(--surface-card)",
        alignItems: "center",
        cursor: "pointer",
      }}
    >
      <span
        style={{
          fontSize: 10,
          color: "var(--text-faint)",
          letterSpacing: "0.06em",
        }}
      >
        {String(index + 1).padStart(2, "0")}
      </span>
      <span style={{ minWidth: 0 }}>
        <span
          className="truncate block"
          style={{ fontSize: 12, color: "var(--text-primary)" }}
          title={display.question}
        >
          {display.question}
        </span>
        {display.parent_investigation_id && (
          <span style={{ fontSize: 9, color: "var(--status-info)", letterSpacing: "0.06em" }}>
            enriched
          </span>
        )}
      </span>
      <span className="flex items-center gap-2" style={{ minWidth: 0 }}>
        <MonoBadge tone={statusTone}>{display.status}</MonoBadge>
        {isRunning && (
          <span
            className="motion-safe:animate-pulse"
            style={{
              display: "inline-block",
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: "var(--status-warn)",
            }}
          />
        )}
      </span>
      <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
        {display.attempts_used}
        {display.max_attempts ? `/${display.max_attempts}` : ""}
      </span>
      <span style={{ textAlign: "right" }}>
        <button
          type="button"
          onClick={handleRerun}
          disabled={isRunning || rerun.isPending}
          title={
            isRunning
              ? "Wait for the current run to finish"
              : "Rerun this investigation, carrying findings forward"
          }
          className="font-mono uppercase"
          style={{
            height: 22,
            padding: "0 8px",
            fontSize: 9,
            letterSpacing: "0.08em",
            color: isRunning || rerun.isPending ? "var(--text-faint)" : "var(--text-muted)",
            background: "transparent",
            border: "1px solid var(--border-soft)",
            borderRadius: 2,
            cursor: isRunning || rerun.isPending ? "not-allowed" : "pointer",
            opacity: isRunning || rerun.isPending ? 0.5 : 1,
          }}
        >
          {rerun.isPending ? "..." : "rerun"}
        </button>
      </span>
    </div>
  );
}

function InvestigationGrid({
  investigations,
  projectId,
  onNavigate,
  listRef,
}: {
  investigations: InvestigationSummary[];
  projectId: string;
  onNavigate: (inv: InvestigationSummary) => void;
  listRef: React.RefObject<HTMLDivElement | null>;
}) {
  const template = INVESTIGATION_COLUMNS.map((c) => c.width).join(" ");
  return (
    <div>
      <div
        className="grid font-mono uppercase"
        style={{
          gridTemplateColumns: template,
          gap: 10,
          padding: "8px 12px",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderBottom: 0,
          borderRadius: "4px 4px 0 0",
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {INVESTIGATION_COLUMNS.map((c, i) => (
          <span key={i} style={{ textAlign: c.align }}>
            {c.label}
          </span>
        ))}
      </div>
      <div
        ref={listRef}
        style={{
          border: "1px solid var(--border-soft)",
          borderRadius: "0 0 4px 4px",
          overflow: "hidden",
        }}
      >
        {investigations.map((inv, i) => (
          <InvestigationLiveRow
            key={inv.id}
            investigation={inv}
            index={i}
            projectId={projectId}
            onNavigate={() => onNavigate(inv)}
            template={template}
          />
        ))}
      </div>
    </div>
  );
}

// ----- Start-investigation forms -----

const FULL_ANALYSIS_COLUMNS: GridColumn[] = [
  { label: "STAGE", width: "120px" },
  { label: "MESSAGE", width: "1fr" },
];

// Preserved SSE-streaming implementation with a mock-language presentational
// shell. Fires the trigger-full-analysis mutation, subscribes to the resulting
// task's event stream, renders progress as a DataGrid of stage/message rows.
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

  const statusTone =
    status === "streaming" ? "warn"
    : status === "done" ? "ok"
    : status === "error" ? "critical"
    : "muted";

  return (
    <WindowPanel
      title="pre-populate artifacts"
      tone="info"
      status={
        taskId
          ? `task ; ${taskId.slice(0, 8)} ; ${status} ; ${events.length} event(s)`
          : "pipeline ; intake / collection / deep_analysis"
      }
    >
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3">
          <p
            className="font-mono min-w-0"
            style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
          >
            runs intake &rarr; collection &rarr; deep_analysis so the freeflow agent can answer
            questions instantly from cached evidence instead of re-scanning.
          </p>
          <button
            type="button"
            onClick={handleClick}
            disabled={trigger.isPending || status === "streaming"}
            className="font-mono uppercase shrink-0"
            style={{
              ...ACCENT_BUTTON_STYLE,
              opacity: trigger.isPending || status === "streaming" ? 0.5 : 1,
              cursor: trigger.isPending || status === "streaming" ? "not-allowed" : "pointer",
            }}
          >
            {status === "streaming" ? "running..." : trigger.isPending ? "queueing..." : "run full analysis"}
          </button>
        </div>
        {taskId && (
          <div className="space-y-2">
            <div
              className="flex items-center gap-2 font-mono"
              style={{ fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.06em" }}
            >
              <span
                className={status === "streaming" ? "motion-safe:animate-pulse" : undefined}
                style={{
                  display: "inline-block",
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: toneColor(statusTone),
                }}
              />
              <span>
                task {taskId.slice(0, 8)} &middot; {status} &middot; {events.length} event(s)
              </span>
            </div>
            <DataGrid
              columns={FULL_ANALYSIS_COLUMNS}
              rows={events}
              renderCells={(ev) => {
                const stage = ev.stage ?? "event";
                const tone =
                  stage.includes("failed") || stage.includes("crashed") ? "critical"
                  : stage.includes("done") || stage.includes("succeeded") ? "ok"
                  : stage.includes("start") || stage.includes("begin") ? "warn"
                  : "info";
                return [
                  <MonoBadge tone={tone}>{stage}</MonoBadge>,
                  <span
                    className="truncate block"
                    style={{ fontSize: 11, color: "var(--text-muted)" }}
                    title={ev.message ?? ""}
                  >
                    {ev.message ?? ""}
                  </span>,
                ];
              }}
              getKey={(_ev, i) => i}
              empty={
                <div
                  className="font-mono"
                  style={{ padding: 18, textAlign: "center", fontSize: 11, color: "var(--text-faint)" }}
                >
                  waiting for first event...
                </div>
              }
            />
          </div>
        )}
      </div>
    </WindowPanel>
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
        className="font-mono uppercase w-full"
        style={{
          height: 34,
          padding: "0 12px",
          fontSize: 10,
          letterSpacing: "0.1em",
          color: "var(--accent)",
          background: "color-mix(in srgb, var(--accent) 8%, transparent)",
          border: "1px dashed var(--accent)",
          borderRadius: 3,
          cursor: "pointer",
        }}
      >
        + new investigation
      </button>
    );
  }

  return (
    <WindowPanel title="new investigation" tone="accent">
      <form onSubmit={handleSubmit} className="space-y-3">
        <label
          htmlFor="pd-question"
          className="font-mono uppercase block"
          style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.1em" }}
        >
          question
        </label>
        <textarea
          id="pd-question"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="ask a question about the evidence"
          rows={3}
          style={TEXTAREA_STYLE}
          autoFocus
        />
        <div className="flex items-center gap-3">
          <label
            htmlFor="pd-max-attempts"
            className="font-mono uppercase"
            style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.1em" }}
          >
            max attempts
          </label>
          <input
            id="pd-max-attempts"
            type="number"
            min={1}
            max={20}
            value={maxAttempts}
            onChange={(e) => setMaxAttempts(Number(e.target.value))}
            className="font-mono"
            style={NUMBER_STYLE}
          />
        </div>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={() => setExpanded(false)}
            className="font-mono uppercase"
            style={MUTED_BUTTON_STYLE}
          >
            cancel
          </button>
          <button
            type="submit"
            disabled={!question.trim() || startInvestigation.isPending}
            className="font-mono uppercase"
            style={{
              ...ACCENT_BUTTON_STYLE,
              opacity: !question.trim() || startInvestigation.isPending ? 0.5 : 1,
              cursor: !question.trim() || startInvestigation.isPending ? "not-allowed" : "pointer",
            }}
          >
            {startInvestigation.isPending ? "starting..." : "start"}
          </button>
        </div>
        {startInvestigation.isError && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
            failed to start investigation.
          </p>
        )}
      </form>
    </WindowPanel>
  );
}

// ----- Raw directory notice -----

function RawDirectoryNotice() {
  return (
    <WindowPanel
      title="raw directory -- intake only"
      tone="muted"
      status="pipeline ; skipped ; direct fs access"
    >
      <div className="flex items-start justify-between gap-3">
        <p
          className="font-mono min-w-0"
          style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
        >
          this project treats the evidence directory as a real filesystem on the analyzer. the
          pre/full-analysis pipeline (disk, memory, network, log lanes) is skipped -- ask questions
          directly and the investigator will read files off the analyzer.
        </p>
        <MonoBadge tone="muted">raw_directory</MonoBadge>
      </div>
    </WindowPanel>
  );
}

// ----- Investigations tab -----

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
  // Additive live refetch: any forensics-scoped platform SSE event
  // invalidates the investigations cache for this project, so a new
  // investigation started by a teammate (or a state transition on an
  // existing one) surfaces without waiting on the polling cadence.
  const investigationsListKey = React.useMemo(
    () => ["forensics", "investigations", projectId] as const,
    [projectId],
  );
  useForensicsListLive(investigationsListKey);

  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search.trim().toLowerCase(), 300);
  const [sortKey, setSortKey] = useState<InvestigationSortKey>("status");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const listRef = useRef<HTMLDivElement | null>(null);
  useRowKeyboardNav({
    containerRef: listRef,
    rowSelector: '[data-power-row="investigation"]',
  });

  const savedViewState: InvestigationsViewState = { search, sortKey, sortDir };

  function applySavedView(state: InvestigationsViewState) {
    // filter_json is caller-controlled; guard each key so an older or
    // hand-edited payload can't wedge the tab into an unknown sort.
    if (typeof state.search === "string") setSearch(state.search);
    if (state.sortKey && INVESTIGATION_SORT_KEYS.includes(state.sortKey)) {
      setSortKey(state.sortKey);
    }
    if (state.sortDir === "asc" || state.sortDir === "desc") {
      setSortDir(state.sortDir);
    }
  }

  const visible = React.useMemo(() => {
    const rows = investigations ?? [];
    const q = debouncedSearch;
    const filtered = q
      ? rows.filter((inv) => {
          const question = inv.question?.toLowerCase() ?? "";
          const answer = inv.final_answer?.toLowerCase() ?? "";
          const status = inv.status?.toLowerCase() ?? "";
          return question.includes(q) || answer.includes(q) || status.includes(q);
        })
      : rows;
    return sortRows(
      filtered,
      (inv) => {
        switch (sortKey) {
          case "question":
            return inv.question ?? "";
          case "status":
            return inv.status ?? "";
          case "attempts_used":
            return inv.attempts_used;
        }
      },
      sortDir,
    );
  }, [investigations, debouncedSearch, sortKey, sortDir]);

  return (
    <div className="space-y-4">
      <AnalystDirectivesPanel projectId={projectId} compact />
      {isRaw ? (
        <FetchRawFilePanel projectId={projectId} compact />
      ) : (
        <RetrieveFilePanel projectId={projectId} compact />
      )}
      {isRaw ? <RawDirectoryNotice /> : <FullAnalysisButton projectId={projectId} />}
      <StartInvestigationForm projectId={projectId} />

      {isLoading && <InvestigationRowSkeletonList count={4} />}

      {isError && (
        <WindowPanel
          title="investigations"
          tone="warn"
          status="forensics ; investigations unavailable"
        >
          <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
            failed to load investigations.
          </p>
        </WindowPanel>
      )}

      {!isLoading && !isError && (investigations ?? []).length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="search question / answer / status..."
            aria-label="Search investigations"
            data-testid="forensics-investigations-search"
            className="font-mono"
            style={INPUT_STYLE}
          />
          <span
            className="font-mono uppercase"
            style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.1em" }}
          >
            sort
          </span>
          <select
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as InvestigationSortKey)}
            aria-label="Sort investigations by"
            data-testid="forensics-investigations-sort-key"
            className="font-mono uppercase"
            style={SELECT_STYLE}
          >
            <option value="status">Status</option>
            <option value="question">Question</option>
            <option value="attempts_used">Attempts</option>
          </select>
          <button
            type="button"
            onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
            aria-label={`Sort direction, currently ${sortDir === "asc" ? "ascending" : "descending"}`}
            data-testid="forensics-investigations-sort-dir"
            className="font-mono uppercase"
            style={DIR_BUTTON_STYLE}
          >
            {sortDir === "asc" ? "\u2191" : "\u2193"}
          </button>
          <SavedViews<InvestigationsViewState>
            entityType="forensics_investigation"
            currentState={savedViewState}
            onApply={applySavedView}
            testIdPrefix="forensics-investigations-views"
          />
        </div>
      )}

      {!isLoading && !isError && (investigations ?? []).length === 0 && (
        <EmptyState
          icon={<Detective className="h-10 w-10" />}
          title="No investigations yet."
          description="Ask a question in the box above to start the first investigation on this project."
        />
      )}

      {!isLoading && !isError && (investigations ?? []).length > 0 && visible.length === 0 && (
        <EmptyState
          icon={<MagnifyingGlass className="h-10 w-10" />}
          title={`No investigations match \u201c${search}\u201d.`}
          description="Clear the search to see every investigation for this project."
          action={{ label: "Clear search", onClick: () => setSearch("") }}
        />
      )}

      {!isLoading && !isError && visible.length > 0 && (
        <InvestigationGrid
          investigations={visible}
          projectId={projectId}
          listRef={listRef}
          onNavigate={(inv) =>
            navigate(`/forensics/projects/${projectId}/investigations/${inv.id}`)
          }
        />
      )}
    </div>
  );
}

// ----- Readiness stream display -----

function ReadinessStreamPanel({ projectId }: { projectId: string }) {
  const { events, running, result, start, reset } = useReadinessStream(projectId);

  const toolEvents = events.filter((e) => e.stage === "tool_done");
  const currentAction = running
    ? [...events].reverse().find((e: ReadinessEvent) => e.stage === "checking" || e.stage === "installing") ?? null
    : null;
  const startEvent = events.find((e) => e.stage === "start");

  return (
    <div className="space-y-4">
      <WindowPanel
        title="machine readiness"
        tone={result ? (result.ready ? "ok" : "warn") : "accent"}
        status={
          running
            ? "readiness ; checking tools"
            : result
              ? result.ready
                ? "readiness ; machine ready"
                : "readiness ; tools missing"
              : "readiness ; idle"
        }
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              {startEvent && (
                <p
                  className="font-mono truncate"
                  style={{ fontSize: 11, color: "var(--text-muted)" }}
                >
                  {startEvent.message}
                </p>
              )}
            </div>
            <div className="flex gap-2 shrink-0">
              {result && (
                <button
                  type="button"
                  onClick={reset}
                  className="font-mono uppercase"
                  style={MUTED_BUTTON_STYLE}
                >
                  reset
                </button>
              )}
              <button
                type="button"
                onClick={start}
                disabled={running}
                className="font-mono uppercase flex items-center gap-2"
                style={{
                  ...ACCENT_BUTTON_STYLE,
                  opacity: running ? 0.6 : 1,
                  cursor: running ? "not-allowed" : "pointer",
                }}
              >
                {running && (
                  <span
                    className="motion-safe:animate-pulse"
                    style={{
                      display: "inline-block",
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: "var(--text-on-accent)",
                    }}
                  />
                )}
                {running ? "running..." : result ? "re-run check" : "run check"}
              </button>
            </div>
          </div>

          {currentAction && (
            <div
              className="font-mono flex items-center gap-2"
              style={{
                padding: "8px 12px",
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                borderRadius: 3,
                fontSize: 11,
                color: "var(--text-muted)",
              }}
            >
              <span
                className="motion-safe:animate-pulse"
                style={{
                  display: "inline-block",
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--status-warn)",
                }}
              />
              {currentAction.message}
            </div>
          )}

          {toolEvents.length > 0 && (
            <div className="space-y-2" style={{ maxHeight: 384, overflowY: "auto" }}>
              {toolEvents.map((e, i) => {
                const tone =
                  e.status === "installed" ? "ok"
                  : e.status === "missing" ? "critical"
                  : "muted";
                return (
                  <div
                    key={i}
                    className="flex items-center gap-3"
                    style={{
                      padding: "6px 10px",
                      background: "var(--surface-card)",
                      border: "1px solid var(--border-faint)",
                      borderRadius: 3,
                    }}
                  >
                    <span style={{ color: toneColor(tone), flex: "0 0 auto" }}>
                      {e.status === "installed" ? (
                        <PixelIcon name="ok" size={12} />
                      ) : e.status === "missing" ? (
                        <PixelIcon name="close" size={12} />
                      ) : (
                        <PixelIcon name="divider" size={12} />
                      )}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <StatBar
                        label={e.tool ?? "\u2014"}
                        color={toneColor(tone)}
                        value={e.status === "installed" ? 1 : 0}
                        max={1}
                      />
                    </div>
                    {e.version && (
                      <span
                        className="font-mono shrink-0"
                        style={{ fontSize: 10, color: "var(--text-muted)" }}
                      >
                        {e.version}
                      </span>
                    )}
                    {e.install_method && e.install_method !== "pre_installed" && (
                      <span
                        className="font-mono shrink-0"
                        style={{ fontSize: 9, color: "var(--accent)", letterSpacing: "0.06em" }}
                      >
                        [{e.install_method}]
                      </span>
                    )}
                    {e.required && e.status === "missing" && (
                      <MonoBadge tone="critical">required</MonoBadge>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {events.length > 0 && (
            <details style={{ marginTop: 4 }}>
              <summary
                className="font-mono uppercase cursor-pointer select-none"
                style={{ fontSize: 10, color: "var(--text-faint)", letterSpacing: "0.1em" }}
              >
                xray log ({events.length} events) -- expand for full stream
              </summary>
              <div
                style={{
                  marginTop: 8,
                  maxHeight: 384,
                  overflowY: "auto",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  background: "var(--surface-sunk)",
                }}
              >
                {events.map((e, i) => {
                  const stage = e.stage ?? "event";
                  const color =
                    stage.includes("failed") ? "var(--accent)"
                    : stage === "tool_done" && e.status === "installed" ? "var(--status-ok)"
                    : stage === "install_verified" ? "var(--status-ok)"
                    : stage === "installing" || stage === "install_exec" ? "var(--status-warn)"
                    : stage === "checking" ? "var(--status-info)"
                    : stage === "heartbeat" ? "color-mix(in srgb, var(--text-muted) 60%, transparent)"
                    : "var(--text-muted)";
                  return (
                    <div
                      key={i}
                      className="font-mono"
                      style={{
                        padding: "4px 10px",
                        fontSize: 10,
                        borderBottom: "1px solid var(--border-faint)",
                      }}
                    >
                      <span style={{ color, fontWeight: 600 }}>[{stage}]</span>
                      {e.tool && (
                        <span style={{ color: "var(--text-primary)", marginLeft: 8 }}>{e.tool}</span>
                      )}
                      {e.message && (
                        <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>
                          -- {e.message}
                        </span>
                      )}
                      {e.command && (
                        <div
                          style={{
                            marginTop: 2,
                            marginLeft: 20,
                            fontSize: 9,
                            color: "var(--text-faint)",
                            wordBreak: "break-all",
                          }}
                        >
                          $ {e.command}
                        </div>
                      )}
                      {e.error && (
                        <div
                          style={{
                            marginTop: 2,
                            marginLeft: 20,
                            fontSize: 9,
                            color: "var(--accent)",
                            wordBreak: "break-all",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          {e.error}
                        </div>
                      )}
                      {e.output_tail && (
                        <div
                          style={{
                            marginTop: 2,
                            marginLeft: 20,
                            fontSize: 9,
                            color: "var(--text-faint)",
                            wordBreak: "break-all",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          {e.output_tail}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </details>
          )}

          {result && (
            <div
              className="font-mono flex items-center gap-2"
              style={{
                padding: "10px 12px",
                borderRadius: 3,
                fontSize: 12,
                color: result.ready ? "var(--status-ok)" : "var(--accent)",
                background: result.ready
                  ? "color-mix(in srgb, var(--status-ok) 10%, transparent)"
                  : "color-mix(in srgb, var(--accent) 10%, transparent)",
                border: `1px solid color-mix(in srgb, ${
                  result.ready ? "var(--status-ok)" : "var(--accent)"
                } 40%, transparent)`,
              }}
            >
              <PixelIcon name={result.ready ? "ok" : "close"} size={16} />
              {result.ready ? "machine is ready" : "some required tools are missing"}
            </div>
          )}

          {!running && events.length === 0 && (
            <p
              className="font-mono text-center"
              style={{ padding: "24px 0", fontSize: 12, color: "var(--text-muted)" }}
            >
              run a readiness check to verify forensic tools on the analyzer machine.
            </p>
          )}
        </div>
      </WindowPanel>

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
    status: project?.status === "active" ? "live" : project?.status === "archived" ? "paused" : null,
  });
  const [activeTab, setActiveTab] = useState<TabId>("investigations");

  if (!projectId) {
    return (
      <WindowPanel title="project" tone="warn" status="forensics ; invalid project id">
        <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
          invalid project id.
        </p>
      </WindowPanel>
    );
  }

  if (isLoading) return <InvestigationDetailSkeleton />;

  if (isError || !project) {
    return (
      <WindowPanel title="project" tone="warn" status="forensics ; project unavailable">
        <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
          failed to load project.
        </p>
      </WindowPanel>
    );
  }

  const tabTitle = TAB_TITLES[activeTab];

  return (
    <div className="space-y-4">
      {/* sr-only section heading bridges PageShell h1 -> panel titles for screen readers. */}
      <h2 className="sr-only">Project dashboard</h2>

      <SectionHeader
        icon={<PixelIcon name="folder" />}
        title={project.name.toLowerCase()}
        actions={
          <button
            type="button"
            onClick={() => navigate(`/forensics/projects/${projectId}/details`)}
            className="font-mono uppercase"
            style={MUTED_BUTTON_STYLE}
          >
            full details
          </button>
        }
      />

      <div
        className="flex items-center gap-3 flex-wrap"
        style={{
          padding: "8px 12px",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
        }}
      >
        <span
          style={{ fontSize: 10, color: "var(--text-muted)" }}
          className="font-mono uppercase"
        >
          machine ; {project.system_name ?? "unknown"}
        </span>
        <span
          style={{ fontSize: 10, color: "var(--text-faint)" }}
          className="font-mono uppercase truncate"
          title={project.evidence_directory}
        >
          {project.evidence_directory}
        </span>
        {project.created_at && (
          <span
            style={{ fontSize: 10, color: "var(--text-faint)" }}
            className="font-mono uppercase"
          >
            {new Date(project.created_at).toLocaleDateString()}
          </span>
        )}
        <span style={{ flex: 1 }} />
        <span
          style={{ fontSize: 10, color: "var(--text-muted)" }}
          className="font-mono uppercase"
        >
          <span style={{ color: "var(--text-primary)" }}>{project.artifact_count}</span> artifacts
        </span>
        <span
          style={{ fontSize: 10, color: "var(--text-muted)" }}
          className="font-mono uppercase"
        >
          <span style={{ color: "var(--text-primary)" }}>{project.lead_count}</span> leads
        </span>
        <span
          style={{ fontSize: 10, color: "var(--text-muted)" }}
          className="font-mono uppercase"
        >
          <span style={{ color: "var(--text-primary)" }}>{project.investigation_count}</span>{" "}
          investigations
        </span>
      </div>

      <Segmented<TabId> options={TABS} value={activeTab} onChange={setActiveTab} />

      <div>
        {activeTab === "investigations" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            <div className="lg:col-span-2">
              <WindowPanel title={tabTitle} tone="accent">
                <InvestigationsTab projectId={projectId} projectKind={project.project_kind} />
              </WindowPanel>
            </div>
            <div>
              <LeadScoreCard projectId={projectId} />
            </div>
          </div>
        )}
        {activeTab === "solid_evidence" && (
          <WindowPanel title={tabTitle} tone="accent">
            <SolidEvidencePanel projectId={projectId} />
          </WindowPanel>
        )}
        {activeTab === "findings" && (
          <WindowPanel title={tabTitle} tone="accent">
            <FindingsPanel projectId={projectId} />
          </WindowPanel>
        )}
        {activeTab === "evidence" && (
          <WindowPanel title={tabTitle} tone="accent">
            <div className="space-y-4">
              <EvidenceTree projectId={projectId} />
              <ArtifactExplorer projectId={projectId} />
            </div>
          </WindowPanel>
        )}
        {activeTab === "timeline" && (
          <WindowPanel title={tabTitle} tone="accent">
            <TimelineViewer projectId={projectId} />
          </WindowPanel>
        )}
        {activeTab === "network" && (
          <WindowPanel title={tabTitle} tone="accent">
            <div className="space-y-4">
              <NetworkAnalysisPanel projectId={projectId} />
              <CarvedFilesPanel projectId={projectId} />
            </div>
          </WindowPanel>
        )}
        {activeTab === "registry" && (
          <WindowPanel title={tabTitle} tone="accent">
            <RegistryViewer projectId={projectId} />
          </WindowPanel>
        )}
        {activeTab === "writeup" && (
          <WindowPanel title={tabTitle} tone="accent">
            <WriteUpViewer projectId={projectId} />
          </WindowPanel>
        )}
        {activeTab === "readiness" && <ReadinessStreamPanel projectId={projectId} />}
      </div>
    </div>
  );
}
