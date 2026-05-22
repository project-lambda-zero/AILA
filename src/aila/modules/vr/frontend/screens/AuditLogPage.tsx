import { Link } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useInvestigations, useMcpCalls } from "../queries";

/** VR audit log surface (08_FRONTEND_UX.md §6.2).
 *
 *  Two streams are surfaced:
 *
 *  1. Delegated MCP calls — every forward() through audit-mcp /
 *     ida-headless bridges, with server / action / status / latency.
 *     Sourced from vr_mcp_call_log (real table).
 *
 *  2. Operator events — pause / resume / inject context / manual
 *     hypothesis confirm / etc. Spec wants these in a dedicated
 *     VRAuditEventRecord; v0.5 surfaces them from operator-sender
 *     messages on each investigation.
 *
 *  Per spec §6.2 — "Reading the timeline plus the audit log gives a
 *  complete picture of what happened on this engagement, by whom,
 *  when." */
export function AuditLogPage() {
  const { data: callsResult, isLoading: callsLoading } = useMcpCalls();
  const { data: invsResult, isLoading: invsLoading } = useInvestigations();

  const calls = callsResult?.data ?? [];
  const investigations = invsResult?.data ?? [];

  // Mutation events derived from the investigation list: each is the
  // signature point where the operator changed state ("paused N
  // investigations", "created M").
  const operatorEvents = investigations
    .filter((i) => i.status === "paused" || i.status === "abandoned" || i.status === "completed")
    .map((i) => ({
      id: `inv-${i.id}`,
      kind: "investigation_state" as const,
      label: `${i.title} → ${i.status}`,
      time: i.updated_at ?? i.stopped_at ?? i.created_at,
      link: `/vr/investigations/${i.id}`,
    }));

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          Audit log
        </h1>
        <p className="text-sm text-text-muted mt-1">
          Per §6.2: every state-changing action on a VR engagement —
          operator pauses / resumes / context injections + delegated MCP
          calls. Reading the per-investigation timeline plus this log
          gives a complete who-did-what-when picture.
        </p>
      </div>

      <AilaCard className="border-dashed" techBorder glow><AilaBadge severity="info" size="sm">
        backend pending
      </AilaBadge>
      <p className="text-[10px] text-text-muted mt-1">
        A dedicated VRAuditEventRecord table (operator action /
        actor_id / target / details / timestamp) isn't on the
        schema yet. v0.5 surfaces what's queryable today: operator-
        driven investigation state changes + the MCP call log.
      </p></AilaCard>

      {/* MCP calls — direct read from the log */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between gap-2 mb-2">
        <h2 className="text-sm font-semibold text-foreground">
          Delegated MCP calls
        </h2>
        <Link
          to="/vr/mcp/calls"
          className="text-xs text-accent hover:underline"
        >
          full log →
        </Link>
      </div>
      {callsLoading ? (
        <LoadingSkeleton size="md" width="full" />
      ) : calls.length === 0 ? (
        <EmptyState
          title="No MCP calls yet"
          description="Run an analyze, rank, or upload action to populate this list."
        />
      ) : (
        <ul className="text-xs font-mono space-y-1 max-h-96 overflow-y-auto">
          {calls.slice(0, 20).map((c) => (
            <li
              key={c.id}
              className="flex items-center gap-2 border border-border-default rounded px-2 py-1"
            >
              <span className="text-text-muted whitespace-nowrap">
                {new Date(c.called_at).toLocaleTimeString()}
              </span>
              <span className="text-foreground">{c.server_id}</span>
              <span className="text-foreground">{c.action}</span>
              <AilaBadge
                severity={
                  c.status === "ready"
                    ? "low"
                    : c.status === "error"
                      ? "critical"
                      : "medium"
                }
                size="sm"
              >
                {c.status}
              </AilaBadge>
              {c.latency_ms != null && (
                <span className="text-text-muted ml-auto">
                  {c.latency_ms}ms
                </span>
              )}
            </li>
          ))}
        </ul>
      )}</AilaCard>

      {/* Operator events — investigation state changes */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
        Operator events ({operatorEvents.length})
      </h2>
      {invsLoading ? (
        <LoadingSkeleton size="md" width="full" />
      ) : operatorEvents.length === 0 ? (
        <EmptyState
          title="No operator state changes recorded"
          description="Pause, complete, or abandon an investigation and it appears here. Per-message operator-intent events (steering / correction / dismissal) require a dedicated audit endpoint that's backend pending."
        />
      ) : (
        <ul className="text-xs space-y-1">
          {operatorEvents.map((e) => (
            <li
              key={e.id}
              className="flex items-start gap-2 border border-border-default rounded px-2 py-1.5"
            >
              <span className="w-2 h-2 rounded-full bg-accent mt-1.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <Link
                  to={e.link}
                  className="font-mono text-foreground hover:underline truncate"
                >
                  {e.label}
                </Link>
                <span className="text-text-muted text-[10px] ml-2">
                  {e.time
                    ? new Date(e.time).toLocaleString()
                    : "—"}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}</AilaCard>
    </div>
  );
}
