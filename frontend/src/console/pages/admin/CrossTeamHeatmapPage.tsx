/** Cross-team heatmap over GET /admin/teams/cross-view (god-tier admin only):
 * teams as rows, the three activity metrics (systems, runs, members) as
 * columns, cell intensity proportional to each metric's share of its column
 * maximum so a glance shows which team dominates which axis. */
import type { JSX } from "react";

import { useCrossTeamStats, useIsGodTierAdmin } from "../../../api/admin";
import type { CrossTeamStats } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { AdminWindow, FAINT, MONO, QueryState, Section } from "./kit";

const METRICS = [
  ["systems_count", "systems"],
  ["runs_count", "runs"],
  ["members_count", "members"],
] as const satisfies readonly (readonly [keyof CrossTeamStats, string])[];

const MAX_TEAM_WIDTH = 220;

export default function CrossTeamHeatmapPage(props: ModulePageProps): JSX.Element {
  const godTier = useIsGodTierAdmin();
  const statsQ = useCrossTeamStats(godTier);
  const rows = statsQ.data ?? [];

  if (!godTier) {
    return (
      <AdminWindow page={props}>
        <div style={css(FAINT + "font-size:11px;")}>Cross-team heatmap is restricted to god-tier admins (admin with no team).</div>
      </AdminWindow>
    );
  }

  const columnMax = METRICS.map(([field]) => Math.max(1, ...rows.map((r) => r[field])));

  return (
    <AdminWindow page={props}>
      <Section title="cross-team heatmap" aside={<span style={css(FAINT + "font-size:11px;")}>GET /admin/teams/cross-view</span>}>
        <QueryState loading={statsQ.isLoading} error={statsQ.error} empty={rows.length === 0} emptyText="no teams to compare" />
        {rows.length > 0 ? (
          <div style={css("display:grid;gap:2px;min-width:0;")}>
            <div
              style={css(
                `display:grid;grid-template-columns:${MAX_TEAM_WIDTH}px repeat(${METRICS.length},minmax(110px,1fr));gap:2px;align-items:stretch;`,
              )}
            >
              <span style={css(FAINT + MONO + "font-size:11px;letter-spacing:0.1em;text-transform:uppercase;padding:4px 6px;")}>team</span>
              {METRICS.map(([, label]) => (
                <span key={label} style={css(FAINT + MONO + "font-size:11px;letter-spacing:0.1em;text-transform:uppercase;padding:4px 6px;text-align:right;")}>
                  {label}
                </span>
              ))}
            </div>
            {rows.map((r) => (
              <div
                key={r.team_id}
                style={css(
                  `display:grid;grid-template-columns:${MAX_TEAM_WIDTH}px repeat(${METRICS.length},minmax(110px,1fr));gap:2px;align-items:stretch;`,
                )}
              >
                <span style={css(MONO + "font-size:11px;color:var(--text-primary);padding:5px 6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")} title={r.team_name}>
                  {r.team_name}
                </span>
                {METRICS.map(([field], i) => {
                  const share = r[field] / columnMax[i];
                  return (
                    <span
                      key={field}
                      title={`${r.team_name} · ${field}: ${r[field]}`}
                      style={css(
                        `font-family:var(--font-mono);font-size:11px;color:var(--text-primary);padding:5px 6px;text-align:right;background:color-mix(in srgb,var(--accent) ${(share * 85).toFixed(0)}%,transparent);border:1px solid var(--border-soft);`,
                      )}
                    >
                      {r[field]}
                    </span>
                  );
                })}
              </div>
            ))}
          </div>
        ) : null}
        <span style={css(FAINT + "font-size:11px;")}>Cell intensity is each team's share of the column maximum.</span>
      </Section>
    </AdminWindow>
  );
}
