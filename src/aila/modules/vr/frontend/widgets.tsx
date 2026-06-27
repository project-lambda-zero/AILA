import { Link } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { AilaChart } from "@/components/aila/AilaChart";
import type { WidgetContribution } from "@platform/extension-registry/types";

import { CVSSBadge } from "./components/CVSSBadge";
import {
  useFuzzCampaigns,
  useFuzzCrashes,
  useFuzzProposals,
  useInvestigations,
  useVRProjects,
} from "./queries";

/** Four dashboard widgets per 08_FRONTEND_UX.md §5.
 *
 *  5.1 Active research projects count
 *  5.2 Total crashes found (with 7-day trend sparkline)
 *  5.3 Exploitable findings count
 *  5.4 Fuzzing coverage aggregate (stacked bar)
 *
 *  Each widget is a `WidgetContribution` registered via spec.ts. They
 *  use only react-query hooks the module already exports so they're
 *  zero net network calls when the user is on a VR page. */

function ActiveProjectsWidget() {
  const { data, isLoading } = useVRProjects();
  const projects = data?.data ?? [];
  const active = projects.filter((p) => p.status === "analyzing");
  const failed = projects.filter((p) => p.status === "failed");

  return (
    <AilaCard className="h-full flex flex-col" techBorder glow><div className="flex items-center justify-between mb-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
        Active Research
      </h3>
      <Link
        to="/vr"
        className="text-3xs text-accent hover:underline"
      >
        open →
      </Link>
    </div>
    <p className="text-3xl font-bold font-mono text-foreground">
      {isLoading ? "--" : active.length}
    </p>
    <p className="text-xs text-text-muted mt-1">
      {projects.length} total · {failed.length} failed
    </p></AilaCard>
  );
}

function CrashesFoundWidget() {
  // Hit the platform-wide fuzz crashes endpoint (no filter)
  const { data, isLoading } = useFuzzCrashes();
  const crashes = data?.data ?? [];

  // 7-day sparkline: bucket by calendar day
  const trend = bucketByDay(crashes, 7);
  const total = crashes.length;
  const last24h = bucketByDay(crashes, 1)[0]?.count ?? 0;

  return (
    <AilaCard className="h-full flex flex-col" techBorder glow><div className="flex items-center justify-between mb-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
        Crashes Found
      </h3>
    </div>
    <p className="text-3xl font-bold font-mono text-foreground">
      {isLoading ? "--" : total.toLocaleString()}
    </p>
    <p className="text-xs text-text-muted mt-1">
      +{last24h} in the last 24h
    </p>
    <div className="mt-2 -mx-2 -mb-2 flex-1" style={{ minHeight: 40 }}>
      {trend.length > 0 && (
        <AilaChart
          type="bar"
          data={trend}
          dataKey="count"
          xKey="day"
          size="sm"
          ariaLabel="Crashes per day (last 7 days)"
        />
      )}
    </div>
    {trend.length > 0 && (
      <table className="sr-only">
        <caption>Crashes per day, last 7 days</caption>
        <thead>
          <tr>
            <th>Day</th>
            <th>Count</th>
          </tr>
        </thead>
        <tbody>
          {trend.map((row) => (
            <tr key={row.day}>
              <td>{row.day}</td>
              <td>{row.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    )}</AilaCard>
  );
}

function ExploitableWidget() {
  const { data, isLoading } = useFuzzCrashes({});
  const crashes = data?.data ?? [];
  const security = crashes.filter((c) => c.triage_verdict === "security_relevant");
  const critical = security.filter((c) => c.severity === "critical").length;
  const high = security.filter((c) => c.severity === "high").length;
  const medium = security.filter((c) => c.severity === "medium").length;

  return (
    <AilaCard className="h-full flex flex-col" techBorder glow><div className="flex items-center justify-between mb-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
        Exploitable
      </h3>
      <Link
        to="/vr/fuzz/campaigns"
        className="text-3xs text-accent hover:underline"
      >
        fuzz crashes →
      </Link>
    </div>
    <p className="text-3xl font-bold font-mono text-foreground">
      {isLoading ? "--" : security.length}
    </p>
    <div className="text-xs text-text-muted mt-1 flex flex-wrap gap-1">
      {critical > 0 && (
        <span className="text-red-500 font-semibold">
          {critical} critical
        </span>
      )}
      {high > 0 && <span>{high} high</span>}
      {medium > 0 && <span>{medium} medium</span>}
      {security.length === 0 && <span>no exploitable crashes</span>}
    </div>
    <div className="mt-2">
      <CVSSBadge score={critical > 0 ? 9.8 : high > 0 ? 7.5 : 0} />
    </div></AilaCard>
  );
}

function FuzzingCoverageWidget() {
  const { data, isLoading } = useFuzzCampaigns();
  const all = data?.data ?? [];
  const running = all.filter((c) => c.status === "running");
  const paused = all.filter((c) => c.status === "paused");
  const failed = all.filter((c) => c.status === "failed");

  // "Stuck" heuristic per spec: running but no recent progress.
  const cutoff = Date.now() - 4 * 3600_000;
  const stuck = running.filter((c) => {
    const ts = c.last_progress_at ?? c.started_at;
    return !ts || new Date(ts).getTime() < cutoff;
  });
  const stable = running.length - stuck.length;

  const avgCoverage =
    running.length > 0
      ? running
          .map((c) => c.coverage_pct ?? 0)
          .reduce((a, b) => a + b, 0) / running.length
      : 0;

  return (
    <AilaCard className="h-full" techBorder glow><div className="flex items-center justify-between mb-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
        Fuzzing Coverage
      </h3>
      <Link
        to="/vr/fuzz/campaigns"
        className="text-3xs text-accent hover:underline"
      >
        campaigns →
      </Link>
    </div>
    <p className="text-3xl font-bold font-mono text-foreground">
      {isLoading ? "--" : `${avgCoverage.toFixed(1)}%`}
    </p>
    <p className="text-xs text-text-muted mt-1">
      avg across {running.length} running
    </p>
    <div className="mt-2 flex items-center gap-1.5 flex-wrap text-3xs">
      {stable > 0 && (
        <AilaBadge severity="low" size="sm">
          {stable} stable
        </AilaBadge>
      )}
      {stuck.length > 0 && (
        <AilaBadge severity="high" size="sm">
          {stuck.length} stuck
        </AilaBadge>
      )}
      {paused.length > 0 && (
        <AilaBadge severity="info" size="sm">
          {paused.length} paused
        </AilaBadge>
      )}
      {failed.length > 0 && (
        <AilaBadge severity="critical" size="sm">
          {failed.length} failed
        </AilaBadge>
      )}
    </div>
    <p className="text-3xs text-text-muted mt-1">
      Stuck = no progress in 4h despite high exec/sec.
    </p></AilaCard>
  );
}

function bucketByDay<T extends { discovered_at?: string | null; created_at?: string | null }>(
  items: ReadonlyArray<T>,
  days: number,
): Array<{ day: string; count: number }> {
  const out = new Map<string, number>();
  const now = Date.now();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now - i * 86_400_000);
    out.set(`${d.getMonth() + 1}/${d.getDate()}`, 0);
  }
  for (const item of items) {
    const ts = item.discovered_at ?? item.created_at;
    if (!ts) continue;
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) continue;
    if (now - d.getTime() > days * 86_400_000) continue;
    const k = `${d.getMonth() + 1}/${d.getDate()}`;
    out.set(k, (out.get(k) ?? 0) + 1);
  }
  return Array.from(out.entries()).map(([day, count]) => ({ day, count }));
}

// Unused import suppression -- also lets useInvestigations stay imported
// in case widgets need it later.
const _unused = useInvestigations;
void _unused;

function PendingFuzzProposalsWidget() {
  const { data, isLoading } = useFuzzProposals({ status: "pending" });
  const proposals = data?.data ?? [];
  return (
    <AilaCard className="h-full flex flex-col" techBorder glow><div className="flex items-center justify-between mb-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
        Pending Fuzz Proposals
      </h3>
      <Link
        to="/vr/investigations"
        className="text-3xs text-accent hover:underline"
      >
        review →
      </Link>
    </div>
    <p className="text-3xl font-bold font-mono text-foreground">
      {isLoading ? "--" : proposals.length}
    </p>
    <p className="text-xs text-text-muted mt-1">
      agent-authored, awaiting operator decision
    </p>
    {proposals.length > 0 && (
      <ul className="mt-2 space-y-1 text-3xs font-mono max-h-32 overflow-y-auto">
        {proposals.slice(0, 5).map((p) => (
          <li
            key={p.id}
            className="border border-border-default rounded px-2 py-1 flex items-center justify-between gap-2"
          >
            <span className="text-foreground truncate">{p.profile}</span>
            <AilaBadge
              severity={
                p.confidence === "strong" || p.confidence === "exact"
                  ? "info" : "medium"
              }
              size="sm"
            >
              {p.confidence}
            </AilaBadge>
          </li>
        ))}
      </ul>
    )}</AilaCard>
  );
}


export const widgets: WidgetContribution[] = [
  {
    id: "vr.active-projects",
    slot: "dashboard.primary",
    order: 70,
    name: "Active Research",
    description:
      "Count of currently-analysing VR projects + total + failed.",
    category: "vr",
    render: ActiveProjectsWidget,
    defaultSize: { w: 1, h: 1 },
  },
  {
    id: "vr.crashes-found",
    slot: "dashboard.primary",
    order: 71,
    name: "Crashes Found",
    description:
      "Total fuzz crashes across all projects with a 7-day trend.",
    category: "vr",
    render: CrashesFoundWidget,
    defaultSize: { w: 1, h: 1 },
  },
  {
    id: "vr.exploitable",
    slot: "dashboard.primary",
    order: 72,
    name: "Exploitable Findings",
    description:
      "Count of crashes triaged as security-relevant, broken down by severity.",
    category: "vr",
    render: ExploitableWidget,
    defaultSize: { w: 1, h: 1 },
  },
  {
    id: "vr.fuzz-coverage",
    slot: "dashboard.primary",
    order: 73,
    name: "Fuzzing Coverage",
    description:
      "Aggregate coverage across running campaigns + stable / stuck / paused breakdown.",
    category: "vr",
    render: FuzzingCoverageWidget,
    defaultSize: { w: 2, h: 1 },
  },
  {
    id: "vr.pending-fuzz-proposals",
    slot: "dashboard.primary",
    order: 74,
    name: "Pending Fuzz Proposals",
    description:
      "Operator-decision queue of agent-authored fuzz campaign proposals -- full harness + seeds prepared.",
    category: "vr",
    render: PendingFuzzProposalsWidget,
    defaultSize: { w: 2, h: 1 },
  },
];
