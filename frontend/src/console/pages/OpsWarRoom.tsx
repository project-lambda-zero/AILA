/**
 * Ops War Room (#212) -- one admin view of what the platform is doing now.
 *
 *   - vitals: task queue depth by status (GET /tasks/queue-depth), the
 *     dead-letter count (GET /admin/tasks/dead-letter), and the state of the
 *     shell's /events/stream connection;
 *   - active runs: running tasks (GET /tasks?status=running) and running VR /
 *     malware investigations (list endpoints filtered by status=running); a
 *     row opens the existing task queue or X-Ray window;
 *   - live feed: the LiveEventsProvider ring buffer with per-type filter chips.
 *
 * The feed reads the provider's single stream; this page never opens its own
 * /events/stream socket. The running-investigation queries live under the
 * ["vr" | "malware", "investigations", ...] prefixes, so a pushed
 * investigation.status_changed event refreshes them immediately.
 */

import { useQuery } from "@tanstack/react-query";
import type { CSSProperties, JSX } from "react";
import { useMemo, useState } from "react";

import { useAuth } from "../../api/auth";
import { apiFetch } from "../../api/client";
import { useLiveEvents, type LiveEvent } from "../../api/liveEvents";
import { asRecord, readNum, readRecordArray, readStr } from "../../api/parse";
import type { SseConnectionState } from "../../api/sse";
import type { PageOpenerProps, WindowChromeProps } from "../contract";
import { ConsoleWindow } from "../window";

/* ------------------------------- data ------------------------------------ */

const POLL_MS = 10_000;

interface RunningTask {
  taskId: string;
  track: string;
  fnPath: string;
  startedAt: string | null;
  heartbeatAt: string | null;
}

interface RunningInvestigation {
  module: "vr" | "malware";
  id: string;
  title: string;
  startedAt: string | null;
}

function parseRunningTasks(raw: unknown): RunningTask[] {
  const o = asRecord(raw);
  if (!o) throw new Error("Unexpected /tasks response shape");
  return readRecordArray(o, "tasks").flatMap((t) => {
    const taskId = readStr(t, "task_id");
    if (taskId === null) return [];
    return [{
      taskId,
      track: readStr(t, "track") ?? "",
      fnPath: readStr(t, "fn_path") ?? "",
      startedAt: readStr(t, "started_at"),
      heartbeatAt: readStr(t, "heartbeat_at"),
    }];
  });
}

function parseRunningInvestigations(module: "vr" | "malware", raw: unknown): RunningInvestigation[] {
  if (!Array.isArray(raw)) throw new Error(`Unexpected /${module}/investigations response shape`);
  return raw.flatMap((row) => {
    const r = asRecord(row);
    const id = r ? readStr(r, "id") : null;
    if (!r || id === null) return [];
    return [{ module, id, title: readStr(r, "title") ?? id, startedAt: readStr(r, "started_at") }];
  });
}

function parseQueueDepth(raw: unknown): [string, number][] {
  const o = asRecord(raw);
  if (!o) throw new Error("Unexpected /tasks/queue-depth response shape");
  return Object.keys(o).flatMap((k) => {
    const n = readNum(o, k);
    return n === null ? [] : [[k, n] as [string, number]];
  });
}

function useRunningInvestigations(module: "vr" | "malware") {
  return useQuery({
    queryKey: [module, "investigations", "ops-war-room-running"],
    queryFn: async () =>
      parseRunningInvestigations(module, await apiFetch<unknown>(`/${module}/investigations?status=running&limit=100`)),
    refetchInterval: POLL_MS,
  });
}

/* ------------------------------ styling ---------------------------------- */

const sectionCss: CSSProperties = {
  border: "1px solid var(--border-soft)",
  background: "var(--surface-chrome)",
  padding: 12,
  display: "flex",
  flexDirection: "column",
  gap: 8,
  minWidth: 0,
};

const headingCss: CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: 11,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-muted)",
  margin: 0,
};

const mutedCss: CSSProperties = { fontSize: 11, color: "var(--text-faint)" };

const rowButtonCss: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "70px 1fr auto",
  gap: 8,
  alignItems: "center",
  minHeight: 28,
  width: "100%",
  padding: "4px 8px",
  border: "1px solid var(--border-soft)",
  background: "transparent",
  color: "var(--text-primary)",
  fontSize: 12,
  textAlign: "left",
  cursor: "pointer",
};

const STATE_COLOR = {
  open: "var(--status-ok)",
  connecting: "var(--status-warn)",
  reconnecting: "var(--status-warn)",
  closed: "var(--status-signal)",
} satisfies Record<SseConnectionState, string>;

function chipCss(active: boolean): CSSProperties {
  return {
    minHeight: 28,
    padding: "4px 10px",
    fontSize: 11,
    border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
    background: active ? "var(--surface-hover)" : "transparent",
    color: active ? "var(--accent)" : "var(--text-muted)",
    cursor: "pointer",
  };
}

function since(iso: string | null): string {
  if (!iso) return "\u2014";
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "\u2014";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function errorLine(err: unknown): string {
  return err instanceof Error ? err.message : "request failed";
}

/* ------------------------------- page ------------------------------------ */

export default function OpsWarRoom(props: WindowChromeProps & PageOpenerProps): JSX.Element {
  const { windowId, title, isFullscreen, isFocused, onFocus, onBack, onMinimize, onToggleFullscreen } = props;
  const isAdmin = useAuth((s) => s.user?.role === "admin");
  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
    >
      {isAdmin ? (
        <WarRoomBody onOpenPage={props.onOpenPage} />
      ) : (
        <div style={{ ...mutedCss, padding: 16 }}>The ops war room is available to admins only.</div>
      )}
    </ConsoleWindow>
  );
}

function WarRoomBody({ onOpenPage }: { onOpenPage: PageOpenerProps["onOpenPage"] }): JSX.Element {
  const live = useLiveEvents();

  const queueDepth = useQuery({
    queryKey: ["ops-war-room", "queue-depth"],
    queryFn: async () => parseQueueDepth(await apiFetch<unknown>("/tasks/queue-depth")),
    refetchInterval: POLL_MS,
  });
  const deadLetter = useQuery({
    queryKey: ["ops-war-room", "dead-letter-count"],
    queryFn: async () => {
      const rows = await apiFetch<unknown>("/admin/tasks/dead-letter");
      if (!Array.isArray(rows)) throw new Error("Unexpected dead-letter response shape");
      return rows.length;
    },
    refetchInterval: POLL_MS,
  });
  const tasks = useQuery({
    queryKey: ["ops-war-room", "running-tasks"],
    queryFn: async () => parseRunningTasks(await apiFetch<unknown>("/tasks?status=running&limit=100")),
    refetchInterval: POLL_MS,
  });
  const vrRunning = useRunningInvestigations("vr");
  const malwareRunning = useRunningInvestigations("malware");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: 12, overflow: "auto", height: "100%" }}>
      <section style={sectionCss} aria-label="vitals">
        <h3 style={headingCss}>vitals</h3>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "baseline" }}>
          <Vital label="event stream">
            <span style={{ color: STATE_COLOR[live.state] }}>{live.state}</span>
            {live.reconnects > 0 ? <span style={mutedCss}>{` \u00b7 ${live.reconnects} reconnects`}</span> : null}
            {live.error ? <span style={{ ...mutedCss, color: "var(--status-signal)" }}>{` \u00b7 ${live.error}`}</span> : null}
          </Vital>
          <Vital label="dead letter">
            {deadLetter.isPending ? "\u2026" : deadLetter.isError ? <span style={{ color: "var(--status-signal)" }}>{errorLine(deadLetter.error)}</span> : (
              <button
                type="button"
                onClick={() => onOpenPage?.("admin", "dead-letter", "dead letter")}
                style={{ ...chipCss(deadLetter.data > 0), color: deadLetter.data > 0 ? "var(--status-signal)" : "var(--text-primary)" }}
              >
                {deadLetter.data}
              </button>
            )}
          </Vital>
          <Vital label="queue depth">
            {queueDepth.isPending ? "\u2026" : queueDepth.isError ? <span style={{ color: "var(--status-signal)" }}>{errorLine(queueDepth.error)}</span> : (
              <span style={{ display: "inline-flex", gap: 10, flexWrap: "wrap" }}>
                {queueDepth.data.map(([status, n]) => (
                  <span key={status}>
                    <span style={mutedCss}>{status}</span> {n}
                  </span>
                ))}
              </span>
            )}
          </Vital>
        </div>
      </section>

      <section style={sectionCss} aria-label="active runs">
        <h3 style={headingCss}>active runs</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
          <RunColumn
            label="tasks"
            pending={tasks.isPending}
            error={tasks.isError ? errorLine(tasks.error) : null}
            rows={(tasks.data ?? []).map((t) => ({
              key: t.taskId,
              tag: t.track,
              label: t.fnPath || t.taskId,
              meta: `${since(t.startedAt)} \u00b7 beat ${since(t.heartbeatAt)}`,
              onOpen: () => onOpenPage?.("admin", "task-queue", "task queue", t.taskId),
            }))}
          />
          <RunColumn
            label="investigations"
            pending={vrRunning.isPending || malwareRunning.isPending}
            error={[vrRunning, malwareRunning].flatMap((q) => (q.isError ? [errorLine(q.error)] : [])).join("; ") || null}
            rows={[...(vrRunning.data ?? []), ...(malwareRunning.data ?? [])].map((inv) => ({
              key: `${inv.module}:${inv.id}`,
              tag: inv.module,
              label: inv.title,
              meta: since(inv.startedAt),
              onOpen: () => onOpenPage?.(inv.module, "xray", "x-ray", inv.id),
            }))}
          />
        </div>
      </section>

      <LiveFeed events={live.events} />
    </div>
  );
}

function Vital({ label, children }: { label: string; children: JSX.Element | (JSX.Element | string | null)[] | string }): JSX.Element {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13 }}>
      <span style={mutedCss}>{label}</span>
      <span>{children}</span>
    </div>
  );
}

interface RunRow {
  key: string;
  tag: string;
  label: string;
  meta: string;
  onOpen: () => void;
}

function RunColumn({ label, pending, error, rows }: { label: string; pending: boolean; error: string | null; rows: RunRow[] }): JSX.Element {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
      <span style={mutedCss}>{`${label} (${rows.length})`}</span>
      {error ? <span style={{ fontSize: 11, color: "var(--status-signal)" }}>{error}</span> : null}
      {pending ? <span style={mutedCss}>loading&#8230;</span> : null}
      {!pending && !error && rows.length === 0 ? <span style={mutedCss}>{`no running ${label}.`}</span> : null}
      {rows.map((r) => (
        <button key={r.key} type="button" onClick={r.onOpen} style={rowButtonCss} title={r.label}>
          <span style={{ ...mutedCss, overflow: "hidden", textOverflow: "ellipsis" }}>{r.tag}</span>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.label}</span>
          <span style={mutedCss}>{r.meta}</span>
        </button>
      ))}
    </div>
  );
}

function LiveFeed({ events }: { events: LiveEvent[] }): JSX.Element {
  // null = every type shown; otherwise only the selected types.
  const [selected, setSelected] = useState<ReadonlySet<string> | null>(null);
  const types = useMemo(() => [...new Set(events.map((e) => e.type))].sort(), [events]);
  const shown = useMemo(
    () => [...events].reverse().filter((e) => selected === null || selected.has(e.type)),
    [events, selected],
  );

  const toggle = (type: string) => {
    setSelected((prev) => {
      const next = new Set(prev ?? []);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next.size === 0 ? null : next;
    });
  };

  return (
    <section style={{ ...sectionCss, flex: "1 1 auto", minHeight: 200 }} aria-label="live feed">
      <h3 style={headingCss}>{`live feed (${events.length})`}</h3>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        <button type="button" style={chipCss(selected === null)} onClick={() => setSelected(null)}>
          all
        </button>
        {types.map((t) => (
          <button key={t} type="button" style={chipCss(selected?.has(t) ?? false)} onClick={() => toggle(t)}>
            {t}
          </button>
        ))}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 2, overflow: "auto" }}>
        {shown.length === 0 ? (
          <span style={mutedCss}>no events received on this session yet.</span>
        ) : (
          shown.map((e) => (
            <div key={e.seq} style={{ display: "grid", gridTemplateColumns: "80px 220px 1fr", gap: 8, fontSize: 12, padding: "3px 0", borderBottom: "1px solid var(--border-soft)" }}>
              <span style={mutedCss}>{new Date(e.timestamp).toLocaleTimeString()}</span>
              <span style={{ color: "var(--accent)", overflow: "hidden", textOverflow: "ellipsis" }}>{e.type}</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.summary}>{e.summary}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
