import { Link } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  MonoBadge,
  SectionHeader,
  type GridColumn,
} from "@/components/aila/mock";

import { useInvestigations, useMcpCalls } from "../queries";

/** VR audit log surface (08_FRONTEND_UX.md §6.2).
 *
 *  Two streams are surfaced:
 *
 *  1. Delegated MCP calls -- every forward() through audit-mcp /
 *     ida-headless bridges, with server / action / status / latency.
 *     Sourced from vr_mcp_call_log (real table).
 *
 *  2. Operator events -- pause / resume / inject context / manual
 *     hypothesis confirm / etc. Spec wants these in a dedicated
 *     VRAuditEventRecord; v0.5 surfaces them from operator-sender
 *     messages on each investigation.
 */
export function AuditLogPage() {
  const { data: callsResult, isLoading: callsLoading } = useMcpCalls();
  const { data: invsResult, isLoading: invsLoading } = useInvestigations();

  const calls = callsResult?.data ?? [];
  const investigations = invsResult?.data ?? [];

  const recentCalls = calls.slice(0, 20);

  // Mutation events derived from the investigation list: each is the
  // signature point where the operator changed state.
  const operatorEvents = investigations
    .filter(
      (i) =>
        i.status === "paused" ||
        i.status === "abandoned" ||
        i.status === "completed",
    )
    .map((i) => ({
      id: `inv-${i.id}`,
      kind: "investigation_state" as const,
      label: `${i.title} \u2192 ${i.status}`,
      time: i.updated_at ?? i.stopped_at ?? i.created_at,
      link: `/vr/investigations/${i.id}`,
    }));

  const callColumns: GridColumn[] = [
    { label: "time", width: "90px" },
    { label: "server", width: "130px" },
    { label: "action", width: "1fr" },
    { label: "status", width: "90px", align: "center" },
    { label: "latency", width: "80px", align: "right" },
  ];

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="\u25c8" title="audit log" />

      <WindowPanel title="scope" tone="muted">
        <div className="flex items-start" style={{ gap: 10 }}>
          <MonoBadge tone="info">backend pending</MonoBadge>
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              lineHeight: 1.5,
              color: "var(--text-muted)",
              letterSpacing: "0.02em",
            }}
          >
            a dedicated vr_audit_event_record table (operator action /
            actor_id / target / details / timestamp) is not on the schema
            yet. v0.5 surfaces what is queryable today: operator-driven
            investigation state changes plus the mcp call log.
          </p>
        </div>
      </WindowPanel>

      <WindowPanel
        title="delegated mcp calls"
        tone="info"
        flush
        actions={
          <Link
            to="/vr/mcp/calls"
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.12em",
              color: "var(--accent)",
              textDecoration: "none",
            }}
          >
            {"full log \u2192"}
          </Link>
        }
      >
        <h2 className="sr-only">Delegated MCP calls</h2>
        {callsLoading ? (
          <div style={{ padding: 12 }}>
            <LoadingSkeleton size="lg" width="full" />
          </div>
        ) : (
          <DataGrid
            columns={callColumns}
            rows={recentCalls}
            getKey={(c) => c.id}
            renderCells={(c) => [
              <span
                key="t"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {new Date(c.called_at).toLocaleTimeString()}
              </span>,
              <span
                key="s"
                style={{ fontSize: 10.5, color: "var(--text-primary)" }}
              >
                {c.server_id}
              </span>,
              <span
                key="a"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-primary)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {c.action}
              </span>,
              <MonoBadge
                key="st"
                tone={
                  c.status === "ready"
                    ? "ok"
                    : c.status === "error"
                      ? "critical"
                      : "warn"
                }
              >
                {c.status}
              </MonoBadge>,
              <span
                key="l"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {c.latency_ms != null ? `${c.latency_ms}ms` : "\u2014"}
              </span>,
            ]}
            empty={
              <div
                className="font-mono"
                style={{
                  padding: 34,
                  textAlign: "center",
                  fontSize: 11.5,
                  color: "var(--text-muted)",
                  letterSpacing: "0.04em",
                }}
              >
                no mcp calls yet. run an analyze, rank, or upload action to
                populate this list.
              </div>
            }
          />
        )}
      </WindowPanel>

      <WindowPanel
        title="operator events"
        tone="muted"
        actions={
          <span
            className="font-mono tabular-nums"
            style={{
              fontSize: 10,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
            }}
          >
            {operatorEvents.length}
          </span>
        }
      >
        <h2 className="sr-only">
          Operator events ({operatorEvents.length})
        </h2>
        {invsLoading ? (
          <LoadingSkeleton size="lg" width="full" />
        ) : operatorEvents.length === 0 ? (
          <div
            className="font-mono"
            style={{
              padding: 24,
              textAlign: "center",
              fontSize: 11,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no operator state changes recorded. pause, complete, or abandon
            an investigation and it appears here. per-message operator-intent
            events require a dedicated audit endpoint that is backend
            pending.
          </div>
        ) : (
          <ul
            className="flex flex-col"
            style={{ gap: 4, margin: 0, padding: 0, listStyle: "none" }}
          >
            {operatorEvents.map((e) => (
              <li
                key={e.id}
                className="flex items-center font-mono"
                style={{
                  gap: 10,
                  padding: "6px 10px",
                  border: "1px solid var(--border-faint)",
                  borderRadius: 3,
                  background: "var(--surface-sunk)",
                  fontSize: 11,
                }}
              >
                <span
                  aria-hidden="true"
                  style={{
                    width: 6,
                    height: 6,
                    background: "var(--accent)",
                    borderRadius: 1,
                    flex: "0 0 auto",
                  }}
                />
                <Link
                  to={e.link}
                  style={{
                    color: "var(--text-primary)",
                    textDecoration: "none",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                    minWidth: 0,
                  }}
                >
                  {e.label}
                </Link>
                <span
                  style={{
                    fontSize: 9.5,
                    color: "var(--text-faint)",
                    letterSpacing: "0.04em",
                    flex: "0 0 auto",
                  }}
                >
                  {e.time ? new Date(e.time).toLocaleString() : "\u2014"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </WindowPanel>
    </div>
  );
}
