/**
 * The shell's single subscription to GET /events/stream.
 *
 * Mounted once (App.tsx) for an authenticated session. Keeps a bounded ring
 * buffer of received platform events plus the connection state, exposed via
 * {@link useLiveEvents}; pages read it instead of opening a second socket
 * (the endpoint is rate limited to 10 connects per user per minute).
 *
 * `investigation.status_changed` events invalidate that module's investigation
 * list caches and the affected detail query. After a reconnect every
 * investigation cache is invalidated, because events emitted while the stream
 * was down are not replayed.
 *
 * Forensics keys carry the project id (`["forensics", projectId, ...]`) and the
 * investigation event does not, so forensics invalidation matches on key
 * shape instead of a fixed prefix. `project.status_changed` events refresh the
 * project detail and the rail list.
 */

import { createContext, useContext, useRef, useState, type JSX, type ReactNode } from "react";

import { useQueryClient, type QueryClient } from "@tanstack/react-query";

import { asRecord, readStr } from "./parse";
import { useSseStream, type SseConnectionState, type SseMessage } from "./sse";

export const INVESTIGATION_STATUS_CHANGED = "investigation.status_changed";

/** Ring buffer capacity for the live feed. */
const LIVE_EVENT_CAPACITY = 200;

/** Modules whose investigations use the `[module, "investigations"]` key layout. */
const GENERIC_INVESTIGATION_MODULES = ["vr", "malware"] as const;
type GenericInvestigationModule = (typeof GENERIC_INVESTIGATION_MODULES)[number];

/** Modules whose investigations push status changes over the stream. */
const LIVE_INVESTIGATION_MODULES = [...GENERIC_INVESTIGATION_MODULES, "forensics"] as const;
type LiveInvestigationModule = (typeof LIVE_INVESTIGATION_MODULES)[number];

export const PROJECT_STATUS_CHANGED = "project.status_changed";

export interface InvestigationStatusChange {
  module: LiveInvestigationModule;
  investigationId: string;
  status: string;
  previousStatus: string | null;
}

/** A forensics project status change (the only module that pushes them). */
export interface ProjectStatusChange {
  module: "forensics";
  projectId: string;
  status: string;
  previousStatus: string | null;
}

export interface LiveEvent {
  /** Monotonic per-session sequence, stable React key. */
  seq: number;
  /** SSE event type (e.g. "investigation.status_changed", "notification"). */
  type: string;
  /** Server timestamp when present, else the local receive time (ISO). */
  timestamp: string;
  /** Set for investigation.status_changed frames. */
  investigation: InvestigationStatusChange | null;
  /** Set for project.status_changed frames. */
  project: ProjectStatusChange | null;
  /** One-line rendering of the payload for the feed. */
  summary: string;
}

export interface LiveEventsValue {
  events: LiveEvent[];
  state: SseConnectionState;
  error: string | null;
  /** Number of successful re-opens after the first connection. */
  reconnects: number;
}

const LiveEventsContext = createContext<LiveEventsValue | null>(null);

function isLiveModule(v: string): v is LiveInvestigationModule {
  return (LIVE_INVESTIGATION_MODULES as readonly string[]).includes(v);
}

function parseLiveEvent(msg: SseMessage, seq: number): LiveEvent {
  let raw: unknown = null;
  try {
    raw = JSON.parse(msg.data);
  } catch {
    raw = null;
  }
  const envelope = asRecord(raw);
  const data = envelope ? asRecord(envelope.data) : null;
  const timestamp = (envelope && readStr(envelope, "timestamp")) ?? new Date().toISOString();

  let investigation: InvestigationStatusChange | null = null;
  if (msg.event === INVESTIGATION_STATUS_CHANGED && data) {
    const module = readStr(data, "module");
    const investigationId = readStr(data, "investigation_id");
    const status = readStr(data, "status");
    if (module !== null && isLiveModule(module) && investigationId !== null && status !== null) {
      investigation = { module, investigationId, status, previousStatus: readStr(data, "previous_status") };
    }
  }
  let project: ProjectStatusChange | null = null;
  if (msg.event === PROJECT_STATUS_CHANGED && data) {
    const module = readStr(data, "module");
    const projectId = readStr(data, "project_id");
    const status = readStr(data, "status");
    if (module === "forensics" && projectId !== null && status !== null) {
      project = { module, projectId, status, previousStatus: readStr(data, "previous_status") };
    }
  }
  const summary = investigation
    ? `${investigation.module} ${investigation.investigationId.slice(0, 8)}: ${investigation.previousStatus ?? "new"} \u2192 ${investigation.status}`
    : project
      ? `${project.module} ${project.projectId.slice(0, 8)}: ${project.previousStatus ?? "new"} \u2192 ${project.status}`
      : data
        ? JSON.stringify(data)
        : msg.data;
  return { seq, type: msg.event, timestamp, investigation, project, summary };
}

function invalidateInvestigationLists(qc: QueryClient, module: GenericInvestigationModule): void {
  const endpoint = `/${module}/investigations`;
  void qc.invalidateQueries({ queryKey: [module, "investigations"] });
  void qc.invalidateQueries({ queryKey: ["datapage", endpoint] });
  void qc.invalidateQueries({ queryKey: ["target-investigations", endpoint] });
}

/**
 * Forensics keys are `["forensics", projectId, ...]`. An investigation event
 * carries no project id, so it matches every project's investigation keys.
 */
function invalidateForensicsInvestigation(qc: QueryClient, investigationId: string): void {
  void qc.invalidateQueries({
    predicate: (q) =>
      q.queryKey[0] === "forensics" &&
      (q.queryKey[2] === "investigations" ||
        (q.queryKey[2] === "investigation" && q.queryKey[3] === investigationId)),
  });
}

/** Project keys for one project plus the project list and rail. */
function invalidateForensicsProject(qc: QueryClient, projectId: string): void {
  void qc.invalidateQueries({
    predicate: (q) =>
      q.queryKey[0] === "forensics" && (q.queryKey[1] === projectId || q.queryKey[1] === "projects"),
  });
}


export function LiveEventsProvider({ children }: { children: ReactNode }): JSX.Element {
  const qc = useQueryClient();
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [reconnects, setReconnects] = useState(0);
  const seq = useRef(0);

  const stream = useSseStream({
    path: "/events/stream",
    onOpen: ({ reconnected }) => {
      if (!reconnected) return;
      setReconnects((n) => n + 1);
      for (const module of GENERIC_INVESTIGATION_MODULES) {
        invalidateInvestigationLists(qc, module);
        void qc.invalidateQueries({ queryKey: [module, "investigation"] });
      }
      void qc.invalidateQueries({ predicate: (q) => q.queryKey[0] === "forensics" });
    },
    onMessage: (msg) => {
      seq.current += 1;
      const evt = parseLiveEvent(msg, seq.current);
      setEvents((prev) => {
        const next = prev.length >= LIVE_EVENT_CAPACITY ? prev.slice(prev.length - LIVE_EVENT_CAPACITY + 1) : prev.slice();
        next.push(evt);
        return next;
      });
      const change = evt.investigation;
      if (change) {
        if (change.module === "forensics") {
          invalidateForensicsInvestigation(qc, change.investigationId);
        } else {
          invalidateInvestigationLists(qc, change.module);
          void qc.invalidateQueries({ queryKey: [change.module, "investigation", change.investigationId] });
        }
      }
      if (evt.project) {
        invalidateForensicsProject(qc, evt.project.projectId);
      }
    },
  });

  const value: LiveEventsValue = { events, state: stream.state, error: stream.error, reconnects };
  return <LiveEventsContext.Provider value={value}>{children}</LiveEventsContext.Provider>;
}

export function useLiveEvents(): LiveEventsValue {
  const value = useContext(LiveEventsContext);
  if (!value) throw new Error("useLiveEvents must be used inside <LiveEventsProvider>");
  return value;
}
