import { useQuery } from "@tanstack/react-query";
import type { JSX } from "react";

import { apiFetch } from "../../api/client";
import { css } from "../css";

interface TeamMember {
  id: string;
  user_id: string;
  username: string;
  email: string | null;
  role: string;
  created_at: string;
}

/** Shape of GET /admin/teams/{team_id} (apiFetch unwraps the DataEnvelope so
 * the returned body is the TeamDetailResponse itself). */
interface TeamDetailBody {
  team: {
    id: string;
    name: string;
    description: string;
    created_at: string;
    updated_at: string;
    member_count: number;
  };
  members: TeamMember[];
}

// The detail panel body is a `140px 1fr` CSS grid; a bespoke detail body must
// span both tracks or it collapses into the 140px label column. Mirrors the
// grid-column span WorkspaceTargets uses.
const SPAN = "grid-column:1/-1;";

/** Row-detail body for `admin:teams-cross-view`: drills a cross-view row into
 * that team's detail + member roster from GET /admin/teams/{team_id}. Mirrors
 * the bespoke-detail pattern used by admin:mcp-instances / vr:workspaces so a
 * god-tier operator moves from cross-tenant counts to one team's roster
 * without leaving the detail panel. */
export function TeamCrossDetail({ row }: { row: Record<string, unknown> }): JSX.Element {
  const teamId = String(row["team_id"] ?? "");
  const q = useQuery<TeamDetailBody>({
    queryKey: ["admin-team-detail", teamId],
    queryFn: () => apiFetch<TeamDetailBody>(`/admin/teams/${encodeURIComponent(teamId)}`),
    enabled: teamId !== "",
    retry: false,
    refetchOnWindowFocus: false,
  });

  if (q.isLoading) {
    return <div style={css(SPAN + "color:var(--text-faint);font-size:10px;font-family:var(--font-mono);")}>loading team detail{"\u2026"}</div>;
  }
  if (q.error) {
    return (
      <div style={css(SPAN + "color:var(--status-warn);font-size:10px;font-family:var(--font-mono);")}>
        could not load team {"\u2014"} {(q.error as Error).message}
      </div>
    );
  }
  const team = q.data?.team;
  const members = q.data?.members ?? [];
  if (!team) {
    return <div style={css(SPAN + "color:var(--text-faint);font-size:10px;font-family:var(--font-mono);")}>no detail for this team.</div>;
  }

  return (
    <div style={css(SPAN + "display:flex;flex-direction:column;gap:12px;min-width:0;")}>
      <div style={css("display:grid;grid-template-columns:110px 1fr;gap:5px 12px;font-size:11.5px;align-items:center;")}>
        <span style={css("color:var(--text-faint);")}>team</span>
        <span style={css("color:var(--text-primary);word-break:break-word;")}>{team.name}</span>
        <span style={css("color:var(--text-faint);")}>description</span>
        <span style={css("color:var(--text-primary);word-break:break-word;")}>{team.description || "\u2014"}</span>
        <span style={css("color:var(--text-faint);")}>id</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{team.id}</span>
        <span style={css("color:var(--text-faint);")}>members</span>
        <span style={css("color:var(--text-primary);")}>{team.member_count}</span>
        <span style={css("color:var(--text-faint);")}>created</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{team.created_at}</span>
        <span style={css("color:var(--text-faint);")}>updated</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);")}>{team.updated_at}</span>
      </div>
      <div style={css("display:flex;flex-direction:column;gap:6px;")}>
        <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>members ({members.length})</div>
        <div style={css("display:flex;flex-direction:column;gap:4px;")}>
          {members.length === 0 ? (
            <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>no members on this team</div>
          ) : (
            members.map((m) => (
              <div key={m.id} style={css("border:1px solid var(--border-soft);border-radius:2px;padding:6px 8px;display:flex;align-items:center;gap:8px;min-width:0;")}>
                <span style={css("flex:1;min-width:0;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{m.username}</span>
                {m.email ? (
                  <span style={css("flex:0 1 auto;min-width:0;font-size:10.5px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{m.email}</span>
                ) : null}
                <span style={css("flex:0 0 auto;font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);border:1px solid var(--border-soft);border-radius:2px;padding:1px 6px;")}>{m.role}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
