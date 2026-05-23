import { useNavigate, useParams } from "react-router";
import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaChart } from "@/components/aila/AilaChart";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import {
  useDeleteFuzzCampaign,
  useLaunchFuzzCampaign,
  usePatchFuzzCampaign,
} from "../mutations";
import {
  useCampaignTelemetry,
  useFuzzCampaign,
  useFuzzCrashes,
  useSystemHeartbeat,
  useSystemMap,
} from "../queries";
import type { CampaignStatus, CrashTriageVerdict } from "../types";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

const STATUS_COLOR: Record<
  CampaignStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  created: "info",
  running: "medium",
  paused: "info",
  completed: "low",
  failed: "high",
  aborted: "high",
};

const VERDICT_COLOR: Record<
  CrashTriageVerdict,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  untriaged: "info",
  security_relevant: "critical",
  likely_harmless: "low",
  duplicate: "info",
  needs_manual_review: "medium",
};

const NEXT_STATES: Record<CampaignStatus, CampaignStatus[]> = {
  created: ["running", "aborted"],
  running: ["paused", "completed", "failed", "aborted"],
  paused: ["running", "aborted"],
  completed: [],
  failed: [],
  aborted: [],
};

/** Bucket crashes by hour-of-discovery for the crash-rate bar chart.
 *  Returns the last 12 buckets (rolling 12h window) so the chart fits. */
function bucketCrashesByHour(
  crashes: ReadonlyArray<{ discovered_at?: string | null; created_at?: string | null }>,
): Array<{ bucket: string; count: number }> {
  const counts = new Map<string, number>();
  const now = Date.now();
  // Init buckets for the last 12 hours so empty hours render as zero
  for (let i = 11; i >= 0; i--) {
    const t = new Date(now - i * 3600_000);
    const k = `${t.getHours().toString().padStart(2, "0")}h`;
    counts.set(k, 0);
  }
  for (const c of crashes) {
    const ts = c.discovered_at ?? c.created_at;
    if (!ts) continue;
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) continue;
    if (now - d.getTime() > 12 * 3600_000) continue;
    const k = `${d.getHours().toString().padStart(2, "0")}h`;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return Array.from(counts.entries()).map(([bucket, count]) => ({ bucket, count }));
}

export function FuzzCampaignDetailPage() {
  const { campaignId } = useParams<{ campaignId: string }>();
  const cid = campaignId ?? "";
  const navigate = useNavigate();

  const { data: campaign, isLoading } = useFuzzCampaign(cid);
  const { data: crashesData } = useFuzzCrashes({ campaignId: cid });

  useUpdatePageHeader({
    title: campaign?.name,
    subtitle: campaign ? `${campaign.engine_id} · ${campaign.strategy_id}` : undefined,
    status: campaign?.status === 'running' ? 'live' : campaign?.status === 'paused' ? 'paused' : campaign?.status === 'failed' ? 'error' : 'ready',
  });
  const crashes = crashesData?.data ?? [];
  const patchMut = usePatchFuzzCampaign(cid);
  const launchMut = useLaunchFuzzCampaign(cid);
  const deleteMut = useDeleteFuzzCampaign();
  const [crashFilter, setCrashFilter] = useState<
    "all" | "exploitable" | "unique-stack" | "untriaged"
  >("all");
  const filteredCrashes = (() => {
    if (crashFilter === "exploitable") {
      return crashes.filter((c) => c.triage_verdict === "security_relevant");
    }
    if (crashFilter === "untriaged") {
      return crashes.filter((c) => c.triage_verdict === "untriaged");
    }
    if (crashFilter === "unique-stack") {
      // dedup by stack_hash, keep earliest per group
      const seen = new Set<string>();
      const out: typeof crashes = [];
      for (const c of crashes) {
        if (!c.stack_hash || seen.has(c.stack_hash)) continue;
        seen.add(c.stack_hash);
        out.push(c);
      }
      return out;
    }
    return crashes;
  })();

  if (isLoading || !campaign) return <LoadingSkeleton size="lg" width="full" />;

  const transitions = NEXT_STATES[campaign.status] ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <DeleteButton
          id={cid}
          label={`fuzz campaign "${campaign.name}"`}
          mutation={deleteMut}
          onDeleted={() => navigate("/vr/fuzz/campaigns")}
        />
      </div>

      <div className="flex gap-2 flex-wrap items-center">
        <AilaBadge severity={STATUS_COLOR[campaign.status]} size="sm">
          {campaign.status}
        </AilaBadge>
        <WorkstationBadge systemId={campaign.analysis_system_id} />
        <StuckBadge lastProgressAt={campaign.last_progress_at} status={campaign.status} />
        {campaign.duration_hours && (
          <AilaBadge severity="info" size="sm">
            duration:{campaign.duration_hours}h
          </AilaBadge>
        )}
      </div>

      {/* State control + Launcher (§1.5). Launch button enqueues an
          ARQ task that SSHes to the campaign's analysis_system_id and
          starts the fuzzer per its engine_id. Idempotent — clicking
          while running returns the existing PID. */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
        <h2 className="text-sm font-semibold text-foreground">
          State control
        </h2>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => launchMut.mutate({})}
            disabled={
              launchMut.isPending || !campaign.analysis_system_id
            }
            title={
              campaign.analysis_system_id
                ? "Enqueue the launcher ARQ task — SSHes to the workstation and starts the fuzzer"
                : "Set analysis_system_id on the campaign before launching"
            }
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-green-600 text-white hover:bg-green-500 disabled:opacity-40"
          >
            {launchMut.isPending
              ? "Launching…"
              : campaign.remote_pid
                ? `Re-launch (current PID ${campaign.remote_pid})`
                : "Launch on workstation"}
          </button>
        </div>
      </div>
      {campaign.remote_pid && (
        <p className="text-[10px] text-text-muted font-mono mb-2">
          remote_pid={campaign.remote_pid}
          {campaign.remote_corpus_dir
            ? ` · corpus=${campaign.remote_corpus_dir}`
            : ""}
          {campaign.remote_crashes_dir
            ? ` · crashes=${campaign.remote_crashes_dir}`
            : ""}
        </p>
      )}
      {transitions.length === 0 ? (
        <p className="text-xs text-text-muted">Campaign is terminal.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {transitions.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => patchMut.mutate({ status: s })}
              disabled={patchMut.isPending}
              className="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
            >
              → {s}
            </button>
          ))}
        </div>
      )}</AilaCard>


      {/* Rebuild + Tune (§1.5) — campaign config knobs. Backend wiring
          pending: rebuild requires a /campaigns/:id/rebuild endpoint
          that re-runs harness generation; tune requires PATCH on
          engine_config + strategy_config (the schemas exist on the
          summary contract, the endpoint is partial). */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
        <h2 className="text-sm font-semibold text-foreground">
          Rebuild + tune
        </h2>
        <AilaBadge severity="info" size="sm">backend pending</AilaBadge>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="border border-dashed border-border-default rounded p-3 bg-surface/40">
          <h3 className="text-xs font-semibold text-foreground">Rebuild harness</h3>
          <p className="text-[10px] text-text-muted mt-1">
            Re-runs harness generation with the last spec. Spec §1.5
            calls for this to be invokable from this drawer without
            leaving the page. POST /vr/fuzz/campaigns/{cid}/rebuild
            is pending.
          </p>
          <button
            type="button"
            disabled
            className="mt-2 px-3 py-1 text-xs font-medium rounded bg-accent text-white opacity-50 cursor-not-allowed"
          >
            Rebuild harness
          </button>
        </div>
        <div className="border border-dashed border-border-default rounded p-3 bg-surface/40">
          <h3 className="text-xs font-semibold text-foreground">Tune</h3>
          <p className="text-[10px] text-text-muted mt-1">
            Adjust timeout / dictionary / mutation rate. Reads
            engine_config + strategy_config from the current campaign;
            PATCH endpoint pending.
          </p>
          <dl className="mt-2 text-[10px] font-mono grid grid-cols-2 gap-1 text-text-muted">
            <dt>engine_config</dt>
            <dd className="truncate">
              {Object.keys(campaign.engine_config).length} keys
            </dd>
            <dt>strategy_config</dt>
            <dd className="truncate">
              {Object.keys(campaign.strategy_config).length} keys
            </dd>
          </dl>
        </div>
      </div></AilaCard>
      {/* Metrics */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">Metrics</h2>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
        <div>
          <dt className="text-text-muted text-xs">Total execs</dt>
          <dd className="font-mono text-foreground">
            {campaign.total_execs.toLocaleString()}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Execs / sec</dt>
          <dd className="font-mono text-foreground">
            {campaign.execs_per_sec != null
              ? campaign.execs_per_sec.toLocaleString()
              : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Corpus size</dt>
          <dd className="font-mono text-foreground">
            {campaign.corpus_size.toLocaleString()}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Coverage</dt>
          <dd className="font-mono text-foreground">
            {campaign.coverage_pct != null
              ? `${campaign.coverage_pct.toFixed(2)}%`
              : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Crashes found</dt>
          <dd className="font-mono text-foreground">{campaign.crashes_found}</dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Started</dt>
          <dd className="font-mono text-xs text-text-muted">
            {campaign.started_at
              ? new Date(campaign.started_at).toLocaleString()
              : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Stopped</dt>
          <dd className="font-mono text-xs text-text-muted">
            {campaign.stopped_at
              ? new Date(campaign.stopped_at).toLocaleString()
              : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Last progress</dt>
          <dd className="font-mono text-xs text-text-muted">
            {campaign.last_progress_at
              ? new Date(campaign.last_progress_at).toLocaleString()
              : "—"}
          </dd>
        </div>
      </dl></AilaCard>

      {/* Live charts (§1.5 — coverage / crashes / corpus / stability).
          v0.5: derived from scalar metrics + crash discovery timestamps.
          Real time-series telemetry stream is backend pending. */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <AilaCard  techBorder glow><h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
          Crashes over time
        </h3>
        {crashes.length === 0 ? (
          <p className="text-xs text-text-muted">
            No crashes yet — chart populates once the engine finds one.
          </p>
        ) : (
          <AilaChart
            type="bar"
            data={bucketCrashesByHour(crashes)}
            dataKey="count"
            xKey="bucket"
            size="sm"
            ariaLabel="Crashes per hour bucket"
          />
        )}
        {/* Accessibility: sr-only table mirrors the chart so screen
            readers get the same data series. */}
        {crashes.length > 0 && (
          <table className="sr-only">
            <caption>Crashes per hour (last 12 hours)</caption>
            <thead>
              <tr>
                <th>Hour</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {bucketCrashesByHour(crashes).map((row) => (
                <tr key={row.bucket}>
                  <td>{row.bucket}</td>
                  <td>{row.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}</AilaCard>

        <AilaCard  techBorder glow><h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
          Coverage / corpus / stability
        </h3>
        <CoverageChart campaignId={cid} /></AilaCard>
      </div>

      {/* Resource band (§1.5 — per-instance CPU/mem/IO from workstation polls) */}
      <AilaCard  techBorder glow><h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
        Workstation resources
      </h3>
      <div className="border border-dashed border-border-default rounded p-3 bg-surface/40">
        <AilaBadge severity="info" size="sm">
          backend pending
        </AilaBadge>
        <p className="text-[10px] text-text-muted mt-2">
          Spec calls for per-instance CPU / memory / disk-write-rate polled
          from the workstation every 10 s.{" "}
          {campaign.analysis_system_id
            ? `Workstation: registered system #${campaign.analysis_system_id}.`
            : "No analysis_system_id set on this campaign."}
        </p>
      </div></AilaCard>

      {/* Crashes */}
      <AilaCard  techBorder glow><div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
        <h2 className="text-sm font-semibold text-foreground">
          Crashes ({filteredCrashes.length}
          {filteredCrashes.length !== crashes.length && ` of ${crashes.length}`})
        </h2>
        <div className="flex items-center gap-1 flex-wrap text-[10px]">
          <span className="text-text-muted">Show:</span>
          {(["all", "exploitable", "unique-stack", "untriaged"] as const).map((chip) => (
            <button
              key={chip}
              type="button"
              onClick={() => setCrashFilter(chip)}
              className={
                "px-2 py-0.5 rounded font-mono border " +
                (crashFilter === chip
                  ? "bg-accent text-white border-accent"
                  : "bg-surface border-border-default text-text-muted hover:text-foreground hover:bg-surface-hover")
              }
            >
              {chip}
            </button>
          ))}
        </div>
      </div>
      {crashes.length === 0 ? (
        <p className="text-xs text-text-muted">
          No crashes registered yet.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-default text-left text-text-muted">
                <th className="px-2 py-1 font-semibold">Stack hash</th>
                <th className="px-2 py-1 font-semibold">Type</th>
                <th className="px-2 py-1 font-semibold">Verdict</th>
                <th className="px-2 py-1 font-semibold">Severity</th>
                <th className="px-2 py-1 font-semibold">Signature</th>
                <th className="px-2 py-1 font-semibold">Discovered</th>
              </tr>
            </thead>
            <tbody>
              {filteredCrashes.map((c) => (
                <tr
                  key={c.id}
                  onClick={() => navigate(`/vr/fuzz/crashes/${c.id}`)}
                  className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
                >
                  <td className="px-2 py-1 font-mono">
                    {c.stack_hash.slice(0, 16)}…
                  </td>
                  <td className="px-2 py-1 font-mono">
                    {c.crash_type ?? "—"}
                  </td>
                  <td className="px-2 py-1">
                    <AilaBadge severity={VERDICT_COLOR[c.triage_verdict]} size="sm">
                      {c.triage_verdict}
                    </AilaBadge>
                  </td>
                  <td className="px-2 py-1 font-mono">{c.severity}</td>
                  <td className="px-2 py-1 max-w-xs truncate">
                    {c.crash_signature ?? "—"}
                  </td>
                  <td className="px-2 py-1 font-mono text-text-muted">
                    {c.discovered_at
                      ? new Date(c.discovered_at).toLocaleString()
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}</AilaCard>
    </div>
  );
}

/** Time-series coverage / exec rate / corpus size chart fed from
 *  /vr/fuzz/campaigns/:id/telemetry (08_FRONTEND_UX.md §1.5). Renders
 *  a small line chart per metric, plus a sr-only table mirror. */
function CoverageChart({ campaignId }: { campaignId: string }) {
  const { data } = useCampaignTelemetry(campaignId);
  const points = data?.data ?? [];
  if (points.length === 0) {
    return (
      <div className="border border-dashed border-border-default rounded p-3 bg-surface/40">
        <p className="text-xs text-text-muted">
          No telemetry samples recorded yet. Workers POST to{" "}
          <code className="font-mono">
            /vr/fuzz/campaigns/{campaignId}/telemetry
          </code>{" "}
          and this chart populates as samples land.
        </p>
      </div>
    );
  }
  // Project into a single chart bound by the cheapest dimension:
  // coverage_pct % over time.
  const series = points.map((p) => ({
    t: p.measured_at.slice(11, 16),
    coverage: p.coverage_pct ?? 0,
    corpus: p.corpus_size ?? 0,
    eps: p.execs_per_sec ?? 0,
  }));
  return (
    <div className="space-y-2">
      <AilaChart
        type="bar"
        data={series}
        dataKey="coverage"
        xKey="t"
        size="sm"
        ariaLabel="Coverage percent over time"
      />
      <p className="text-[10px] text-text-muted font-mono">
        {series.length} samples · latest: {points.at(-1)?.coverage_pct ?? 0}% cov
        · {points.at(-1)?.corpus_size ?? 0} corpus
        · {points.at(-1)?.execs_per_sec?.toFixed(0) ?? 0} exec/s
      </p>
      <table className="sr-only">
        <caption>Fuzz telemetry samples</caption>
        <thead>
          <tr>
            <th>Time</th>
            <th>Coverage %</th>
            <th>Corpus size</th>
            <th>Execs/sec</th>
          </tr>
        </thead>
        <tbody>
          {series.map((row) => (
            <tr key={row.t}>
              <td>{row.t}</td>
              <td>{row.coverage}</td>
              <td>{row.corpus}</td>
              <td>{row.eps}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** "Stuck" detection — render an amber badge when the campaign has been
 *  running but hasn't reported progress in > 4h (08_FRONTEND_UX.md §1.5). */
function StuckBadge({
  lastProgressAt,
  status,
}: {
  lastProgressAt?: string | null;
  status: CampaignStatus;
}) {
  if (status !== "running" || !lastProgressAt) return null;
  const ms = Date.now() - new Date(lastProgressAt).getTime();
  if (Number.isNaN(ms) || ms < 4 * 3600_000) return null;
  const hours = Math.floor(ms / 3600_000);
  return (
    <AilaBadge severity="medium" size="sm">
      stuck · no progress in {hours}h
    </AilaBadge>
  );
}

/** Workstation identity + live reachability for the campaign header.
 *  Combines the system map (id → name/host lookup) with the heartbeat
 *  poll (cached 30 s server-side). A green LiveDot + name when reachable,
 *  amber when unreachable, "no workstation" when no FK is set. */
function WorkstationBadge({ systemId }: { systemId: number | null | undefined }) {
  const systems = useSystemMap();
  const { data: heartbeat } = useSystemHeartbeat(systemId ?? null);
  if (!systemId) {
    return (
      <AilaBadge severity="info" size="sm">
        no workstation
      </AilaBadge>
    );
  }
  const sys = systems.get(systemId);
  const label = sys ? `${sys.name} (${sys.host})` : `system #${systemId}`;
  const live = heartbeat?.reachable === true;
  const sev = heartbeat
    ? heartbeat.reachable ? "low" : "high"
    : "info";
  const tooltip = heartbeat
    ? heartbeat.reachable
      ? `reachable · ${heartbeat.latency_ms ?? "?"} ms · checked ${new Date(heartbeat.checked_at).toLocaleTimeString()}`
      : `unreachable: ${heartbeat.error ?? "no response"}`
    : "probing…";
  return (
    <span className="inline-flex items-center gap-1" title={tooltip}>
      <span
        className={
          "inline-block w-1.5 h-1.5 rounded-full "
          + (live ? "bg-green-500" : "bg-amber-500")
        }
        aria-label={live ? "reachable" : "unreachable"}
      />
      <AilaBadge severity={sev} size="sm">
        {label}
      </AilaBadge>
    </span>
  );
}
