import { useCallback, useRef, useState } from "react";

import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, MonoBadge } from "@/components/aila/mock";
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

// ---------------------------------------------------------------------------
// Presentation -- mock-kit rebuild. Composes WindowPanel + DataGrid +
// MonoBadge; no shadcn / AilaBadge / palette-class primitives. Every event
// stream and lifecycle branch of the previous panel is preserved verbatim,
// only the surface language shifts to the dense-mono mock grammar.
// ---------------------------------------------------------------------------

const XRAY_STAGE_COLOR: Record<string, string> = {
  install_verified: "var(--status-ok)",
  installing: "var(--status-warn)",
  install_exec: "var(--status-warn)",
  checking: "var(--status-info)",
};

function xrayColor(event: ReadinessEvent): string {
  const stage = event.stage ?? "event";
  if (stage.includes("failed")) return "var(--accent)";
  if (stage === "tool_done" && event.status === "installed") return "var(--status-ok)";
  if (stage === "heartbeat") return "color-mix(in srgb, var(--text-muted) 60%, transparent)";
  return XRAY_STAGE_COLOR[stage] ?? "var(--text-muted)";
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
    ? [...events]
        .reverse()
        .find(
          (e) =>
            e.stage === "checking" ||
            e.stage === "installing" ||
            e.stage === "install_exec",
        ) ?? null
    : null;
  const startEvent = events.find((e) => e.stage === "start");

  const panelTone: "ok" | "warn" | "accent" = result
    ? result.ready
      ? "ok"
      : "warn"
    : "accent";
  const panelStatus = running
    ? "readiness ; checking tools"
    : result
      ? result.ready
        ? "readiness ; machine ready"
        : "readiness ; tools missing"
      : "readiness ; idle";

  const runDisabled = running;

  return (
    <WindowPanel title="machine readiness" tone={panelTone} status={panelStatus}>
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            {startEvent?.message && (
              <p
                className="font-mono truncate"
                style={{ fontSize: 11, color: "var(--text-muted)" }}
              >
                {startEvent.message}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {result && (
              <button
                type="button"
                onClick={reset}
                className="font-mono uppercase"
                style={{
                  height: 28,
                  padding: "0 12px",
                  fontSize: 10,
                  letterSpacing: "0.08em",
                  color: "var(--text-muted)",
                  background: "transparent",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  cursor: "pointer",
                }}
              >
                RESET
              </button>
            )}
            <button
              type="button"
              onClick={start}
              disabled={runDisabled}
              className="font-mono uppercase inline-flex items-center gap-2"
              style={{
                height: 28,
                padding: "0 12px",
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-on-accent)",
                background: "var(--accent)",
                border: "1px solid var(--accent)",
                borderRadius: 3,
                cursor: runDisabled ? "not-allowed" : "pointer",
                opacity: runDisabled ? 0.6 : 1,
              }}
            >
              {running && (
                <span
                  aria-hidden
                  className="inline-block rounded-full motion-safe:animate-pulse"
                  style={{
                    width: 6,
                    height: 6,
                    backgroundColor: "var(--text-on-accent)",
                  }}
                />
              )}
              {running ? "RUNNING\u2026" : result ? "RE-RUN CHECK" : "RUN CHECK"}
            </button>
          </div>
        </div>

        {currentAction && (
          <WindowPanel flush tone="info">
            <div
              className="flex items-center gap-2 font-mono"
              style={{ padding: "8px 12px", fontSize: 11 }}
            >
              <span
                aria-hidden
                className="inline-block rounded-full motion-safe:animate-pulse shrink-0"
                style={{
                  width: 6,
                  height: 6,
                  backgroundColor: "var(--status-info)",
                }}
              />
              <span
                className="shrink-0"
                style={{ color: "var(--status-info)", fontWeight: 600 }}
              >
                [{currentAction.stage}]
              </span>
              <span
                className="break-all"
                style={{ color: "var(--text-primary)" }}
              >
                {currentAction.message ?? ""}
              </span>
            </div>
          </WindowPanel>
        )}

        {toolEvents.length > 0 && (
          <DataGrid<ReadinessEvent>
            columns={[
              { label: "TOOL", width: "2fr" },
              { label: "VERSION", width: "120px" },
              { label: "STATUS", width: "110px" },
              { label: "REQUIRED", width: "110px" },
              { label: "METHOD", width: "110px" },
            ]}
            rows={toolEvents}
            getKey={(_row, i) => i}
            renderCells={(e) => {
              const statusTone =
                e.status === "installed"
                  ? "ok"
                  : e.status === "missing"
                    ? "critical"
                    : "muted";
              return [
                <span
                  key="tool"
                  className="truncate"
                  style={{ color: "var(--text-primary)", fontSize: 11 }}
                >
                  {e.tool ?? ""}
                </span>,
                <span
                  key="ver"
                  className="truncate"
                  style={{ color: "var(--text-muted)", fontSize: 11 }}
                >
                  {e.version ?? ""}
                </span>,
                <MonoBadge key="status" tone={statusTone}>
                  {e.status ?? "--"}
                </MonoBadge>,
                e.required && e.status === "missing" ? (
                  <MonoBadge key="req" tone="warn">REQUIRED</MonoBadge>
                ) : null,
                e.install_method && e.install_method !== "pre_installed" ? (
                  <MonoBadge key="method" tone="info">{e.install_method}</MonoBadge>
                ) : null,
              ];
            }}
          />
        )}

        {events.length > 0 && (
          <details>
            <summary
              className="font-mono uppercase cursor-pointer"
              style={{
                fontSize: 10,
                color: "var(--text-muted)",
                letterSpacing: "0.08em",
                padding: "4px 0",
              }}
            >
              XRAY LOG ({events.length} EVENTS) -- EXPAND FOR FULL STREAM
            </summary>
            <div
              className="font-mono overflow-y-auto"
              style={{
                marginTop: 8,
                maxHeight: 384,
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                borderRadius: 3,
              }}
            >
              {events.map((e, i) => {
                const stage = e.stage ?? "event";
                const color = xrayColor(e);
                return (
                  <div
                    key={i}
                    style={{
                      padding: "4px 10px",
                      fontSize: 10,
                      borderBottom:
                        "1px solid color-mix(in srgb, var(--border-soft) 55%, transparent)",
                    }}
                  >
                    <span style={{ color, fontWeight: 600 }}>[{stage}]</span>
                    {e.tool && (
                      <span
                        style={{ color: "var(--text-primary)", marginLeft: 8 }}
                      >
                        {e.tool}
                      </span>
                    )}
                    {e.message && (
                      <span
                        style={{ color: "var(--text-muted)", marginLeft: 8 }}
                      >
                        -- {e.message}
                      </span>
                    )}
                    {e.command && (
                      <div
                        style={{
                          marginLeft: 24,
                          marginTop: 2,
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
                          marginLeft: 24,
                          marginTop: 2,
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
                          marginLeft: 24,
                          marginTop: 2,
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
          <WindowPanel flush tone={result.ready ? "ok" : "warn"}>
            <div
              className="flex items-center gap-2 font-mono uppercase"
              style={{
                padding: "10px 14px",
                fontSize: 11,
                letterSpacing: "0.08em",
                color: result.ready ? "var(--status-ok)" : "var(--accent)",
              }}
            >
              {result.ready ? (
                <PixelIcon name="ok" size={14} />
              ) : (
                <PixelIcon name="close" size={14} />
              )}
              <span>
                {result.ready
                  ? "MACHINE IS READY"
                  : "SOME REQUIRED TOOLS ARE MISSING"}
              </span>
            </div>
          </WindowPanel>
        )}

        {!running && events.length === 0 && (
          <WindowPanel flush tone="muted">
            <div
              className="font-mono uppercase"
              style={{
                padding: "18px 14px",
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
                textAlign: "center",
              }}
            >
              RUN A READINESS CHECK TO VERIFY FORENSIC TOOLS.
            </div>
          </WindowPanel>
        )}
      </div>
    </WindowPanel>
  );
}
