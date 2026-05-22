import { useCallback, useRef, useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { buildApiUrl } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";

import type { MachineReadinessResult } from "../types";

export interface ReadinessEvent {
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

const TOOL_STATUS_COLOR: Record<string, string> = {
  installed: "text-green-400",
  missing: "text-red-400",
  skipped: "text-text-muted",
};

/**
 * Streams `/forensics/projects/<id>/readiness-check/stream` via SSE and
 * exposes the event log, a synthesized MachineReadinessResult on completion,
 * plus start/reset controls. Shared between the project dashboard and the
 * new-project wizard so both get the same live progress view.
 */
export function useReadinessStream(projectId: string) {
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

export function ReadinessStreamPanel({
  projectId,
  autoStart = false,
}: {
  projectId: string;
  autoStart?: boolean;
}) {
  const { events, running, result, start, reset } = useReadinessStream(projectId);

  // Auto-start for flows like the wizard where the user already committed to running a check.
  const autoStartedRef = useRef(false);
  if (autoStart && !autoStartedRef.current && projectId) {
    autoStartedRef.current = true;
    void start();
  }

  const toolEvents = events.filter((e) => e.stage === "tool_done");
  const currentAction = running
    ? [...events].reverse().find((e) => e.stage === "checking" || e.stage === "installing" || e.stage === "install_exec") ?? null
    : null;
  const startEvent = events.find((e) => e.stage === "start");

  return (
    <AilaCard  techBorder glow><div className="flex items-center justify-between mb-4">
      <div>
        <h3 className="text-sm font-semibold font-mono text-foreground">Machine Readiness Check</h3>
        {startEvent?.message && (
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
    
    {currentAction && (
      <div className="mb-3 px-3 py-2 rounded-md bg-surface-secondary border border-border text-xs text-text-muted font-mono flex items-center gap-2">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
        {currentAction.message}
      </div>
    )}
    
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
              {e.version && <span className="text-text-muted shrink-0">{e.version}</span>}
              {e.install_method && e.install_method !== "pre_installed" && (
                <span className="text-accent shrink-0 text-[10px]">[{e.install_method}]</span>
              )}
            </div>
            {e.required && e.status === "missing" && (
              <span className="text-red-400 shrink-0 ml-2">REQUIRED</span>
            )}
          </div>
        ))}
      </div>
    )}
    
    {events.length > 0 && (
      <details className="mt-4">
        <summary className="text-xs font-mono text-text-muted cursor-pointer select-none hover:text-foreground">
          xray log ({events.length} events) — expand for full stream
        </summary>
        <div className="mt-2 max-h-96 overflow-y-auto rounded border border-border bg-black/40">
          {events.map((e, i) => {
            const stage = e.stage ?? "event";
            const color =
              stage.includes("failed")
                ? "text-red-400"
                : stage === "tool_done" && e.status === "installed"
                ? "text-green-400"
                : stage === "install_verified"
                ? "text-green-400"
                : stage === "installing" || stage === "install_exec"
                ? "text-amber-400"
                : stage === "checking"
                ? "text-blue-400"
                : stage === "heartbeat"
                ? "text-text-muted/60"
                : "text-text-muted";
            return (
              <div key={i} className="px-2 py-1 text-[10px] font-mono border-b border-border/40 last:border-b-0">
                <span className={`${color} font-semibold`}>[{stage}]</span>
                {e.tool && <span className="text-foreground ml-2">{e.tool}</span>}
                {e.message && <span className="text-text-muted ml-2">— {e.message}</span>}
                {e.command && (
                  <div className="text-text-muted/70 text-[9px] ml-6 mt-0.5 break-all">$ {e.command}</div>
                )}
                {e.error && (
                  <div className="text-red-300/80 text-[9px] ml-6 mt-0.5 break-all whitespace-pre-wrap">{e.error}</div>
                )}
                {e.output_tail && (
                  <div className="text-text-muted/70 text-[9px] ml-6 mt-0.5 break-all whitespace-pre-wrap">{e.output_tail}</div>
                )}
              </div>
            );
          })}
        </div>
      </details>
    )}
    
    {result && (
      <div
        className={`mt-4 px-4 py-3 rounded-md border text-sm font-medium ${
          result.ready
            ? "border-green-800 bg-green-950/30 text-green-400"
            : "border-red-800 bg-red-950/30 text-red-400"
        }`}
      >
        {result.ready ? "✓ Machine is ready" : "✗ Some required tools are missing"}
      </div>
    )}
    
    {!running && events.length === 0 && (
      <p className="text-sm text-text-muted text-center py-6">
        Run a readiness check to verify forensic tools on the analyzer machine.
      </p>
    )}</AilaCard>
  );
}
