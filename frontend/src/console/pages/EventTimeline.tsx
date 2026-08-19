import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { css } from "../css";
import { StatusBadge } from "./badges";

interface TimelineEvent {
  created_at?: string;
  stage?: string;
  action?: string;
  status?: string;
  target?: string;
  user_id?: string;
  run_id?: string;
  details?: Record<string, unknown> | null;
  [key: string]: unknown;
}

/**
 * EventTimeline -- newest-first activity history for one entity, rendered in
 * the DataPage detail panel when a config declares `detailEvents`. Feeds off
 * paginated audit-style envelopes ({items:[...], total}) such as
 * /audit/events?run_id=...; each row shows when/what/status/who.
 */
export function EventTimeline({
  endpoint,
  itemsKey = "items",
}: {
  endpoint: string;
  itemsKey?: string;
}): JSX.Element {
  const q = useQuery({
    queryKey: ["detail-events", endpoint],
    queryFn: async () => {
      const data = await apiFetch<Record<string, unknown>>(endpoint);
      const arr = Array.isArray(data)
        ? data
        : Array.isArray(data[itemsKey])
          ? (data[itemsKey] as unknown[])
          : [];
      return (arr as TimelineEvent[]).slice().sort((a, b) => {
        const ta = a.created_at ?? "";
        const tb = b.created_at ?? "";
        return ta < tb ? 1 : ta > tb ? -1 : 0;
      });
    },
    retry: false,
  });

  if (q.isLoading) return <div style={evNote}>loading events&#8230;</div>;
  if (q.isError) return <div style={evNote}>could not load events</div>;
  const events = q.data ?? [];
  if (events.length === 0) return <div style={evNote}>no events.</div>;

  return (
    <div style={css("display:flex;flex-direction:column;gap:5px;padding-top:8px;border-top:1px solid var(--border-faint);")}>
      <div style={css("font-size:8.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>activity</div>
      {events.map((ev, i) => (
        <div
          key={`${ev.created_at ?? ""}-${ev.stage ?? ""}-${i}`}
          style={css("display:flex;align-items:center;gap:8px;padding:4px 6px;border:1px solid var(--border-faint);border-radius:2px;background:var(--surface-sunk);font-size:9.5px;")}
        >
          <span style={css("color:var(--text-faint);white-space:nowrap;font-variant-numeric:tabular-nums;")}>
            {typeof ev.created_at === "string" ? ev.created_at.replace("T", " ").slice(0, 19) : ""}
          </span>
          <span style={css("color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;font-size:8.5px;")}>{ev.stage ?? ""}</span>
          <span style={css("color:var(--text-primary);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>
            {ev.action ?? ev.target ?? ""}
          </span>
          <StatusBadge value={ev.status} />
          {ev.user_id ? <span style={css("color:var(--text-faint);white-space:nowrap;")}>{ev.user_id.slice(0, 8)}</span> : null}
        </div>
      ))}
    </div>
  );
}

const evNote = css("padding:6px 4px;font-size:9.5px;color:var(--text-faint);");
