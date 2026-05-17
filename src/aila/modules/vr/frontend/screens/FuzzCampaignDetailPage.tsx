import { useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaChart } from "@/components/aila/AilaChart";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useDeleteFuzzCampaign, usePatchFuzzCampaign } from "../mutations";
import { useFuzzCampaign, useFuzzCrashes } from "../queries";
import type { CampaignStatus, CrashTriageVerdict } from "../types";

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
  const crashes = crashesData?.data ?? [];
  const patchMut = usePatchFuzzCampaign(cid);
  const deleteMut = useDeleteFuzzCampaign();

  if (isLoading || !campaign) return <LoadingSkeleton size="lg" width="full" />;

  const transitions = NEXT_STATES[campaign.status] ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            {campaign.name}
          </h1>
          <p className="text-sm text-text-muted mt-1 font-mono">
            {campaign.engine_id} · {campaign.strategy_id}
          </p>
        </div>
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
        {campaign.workstation_host && (
          <AilaBadge severity="info" size="sm">
            host:{campaign.workstation_host}
          </AilaBadge>
        )}
        {campaign.duration_hours && (
          <AilaBadge severity="info" size="sm">
            duration:{campaign.duration_hours}h
          </AilaBadge>
        )}
      </div>

      {/* State transitions */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          State control
        </h2>
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
        )}
      </AilaCard>

      {/* Metrics */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">Metrics</h2>
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
        </dl>
      </AilaCard>

      {/* Live charts (§1.5 — coverage / crashes / corpus / stability).
          v0.5: derived from scalar metrics + crash discovery timestamps.
          Real time-series telemetry stream is backend pending. */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <AilaCard>
          <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
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
        </AilaCard>

        <AilaCard>
          <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
            Coverage / corpus / stability
          </h3>
          <div className="border border-dashed border-border-default rounded p-3 bg-surface/40">
            <AilaBadge severity="info" size="sm">
              backend pending
            </AilaBadge>
            <p className="text-[10px] text-text-muted mt-2">
              Live edge-coverage + corpus-size + stability% time-series
              charts ship once the workstation telemetry stream lands.
              Scalars above show the latest snapshot.
            </p>
          </div>
        </AilaCard>
      </div>

      {/* Resource band (§1.5 — per-instance CPU/mem/IO from workstation polls) */}
      <AilaCard>
        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
          Workstation resources
        </h3>
        <div className="border border-dashed border-border-default rounded p-3 bg-surface/40">
          <AilaBadge severity="info" size="sm">
            backend pending
          </AilaBadge>
          <p className="text-[10px] text-text-muted mt-2">
            Spec calls for per-instance CPU / memory / disk-write-rate polled
            from the workstation every 10 s.{" "}
            {campaign.workstation_host
              ? `Host: ${campaign.workstation_host}.`
              : "No workstation host registered."}
          </p>
        </div>
      </AilaCard>

      {/* Crashes */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Crashes ({crashes.length})
        </h2>
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
                {crashes.map((c) => (
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
        )}
      </AilaCard>
    </div>
  );
}
