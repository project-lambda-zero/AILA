import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  FilterChip,
  MonoBadge,
  SectionHeader,
  StatBar,
  type GridColumn,
} from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

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
import type {
  CampaignStatus,
  CrashTriageVerdict,
  VRFuzzCrashSummary,
} from "../types";

// ─────────────────────────────────────────────────────────────────────
// Vocabulary maps -- mock tones only.
// ─────────────────────────────────────────────────────────────────────
const STATUS_TONE: Record<CampaignStatus, string> = {
  created: "muted",
  running: "ok",
  paused: "warn",
  completed: "info",
  failed: "critical",
  aborted: "critical",
};

const VERDICT_TONE: Record<CrashTriageVerdict, string> = {
  untriaged: "muted",
  security_relevant: "critical",
  likely_harmless: "ok",
  duplicate: "info",
  needs_manual_review: "warn",
};

const NEXT_STATES: Record<CampaignStatus, CampaignStatus[]> = {
  created: ["running", "aborted"],
  running: ["paused", "completed", "failed", "aborted"],
  paused: ["running", "aborted"],
  completed: [],
  failed: [],
  aborted: [],
};

type CrashFilter = "all" | "exploitable" | "unique-stack" | "untriaged";

const CRASH_FILTER_OPTIONS: readonly CrashFilter[] = [
  "all",
  "exploitable",
  "unique-stack",
  "untriaged",
];

// ─────────────────────────────────────────────────────────────────────
// Shared control styles (mirror ProjectDetailPage / InvestigationsListPage).
// ─────────────────────────────────────────────────────────────────────
const BTN_BASE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

function actionButton(
  label: string,
  onClick: (() => void) | undefined,
  {
    primary = false,
    disabled = false,
    title,
    key,
  }: { primary?: boolean; disabled?: boolean; title?: string; key?: string } = {},
) {
  return (
    <button
      key={key}
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="font-mono uppercase"
      style={{
        ...BTN_BASE,
        background: primary ? "var(--accent)" : BTN_BASE.background,
        borderColor: primary ? "var(--accent)" : BTN_BASE.border ? "var(--border-soft)" : undefined,
        color: primary ? "var(--text-on-accent)" : BTN_BASE.color,
        opacity: disabled ? 0.4 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
      }}
    >
      {label}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Brief row -- uppercase mono label above value, border-bottom rule.
// ─────────────────────────────────────────────────────────────────────
function BriefRow({
  label,
  children,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
    </div>
  );
}

function formatDateTime(value?: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

// ─────────────────────────────────────────────────────────────────────
// Backend-pending inline block (bordered muted box).
// ─────────────────────────────────────────────────────────────────────
function PendingBox({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        padding: 12,
        fontSize: 11,
        lineHeight: 1.55,
        color: "var(--text-muted)",
        background: "var(--surface-sunk)",
        border: "1px dashed var(--border-soft)",
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Bucket crashes by hour-of-discovery -- 12h rolling window.
// (Preserved from prior implementation.)
// ─────────────────────────────────────────────────────────────────────
function bucketCrashesByHour(
  crashes: ReadonlyArray<{
    discovered_at?: string | null;
    created_at?: string | null;
  }>,
): Array<{ bucket: string; count: number }> {
  const counts = new Map<string, number>();
  const now = Date.now();
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

// ─────────────────────────────────────────────────────────────────────
// Crashes DataGrid columns.
// ─────────────────────────────────────────────────────────────────────
const CRASH_COLUMNS: GridColumn[] = [
  { label: "id", width: "110px" },
  { label: "type", width: "160px" },
  { label: "signature", width: "minmax(0, 1.6fr)" },
  { label: "verdict", width: "170px" },
  { label: "severity", width: "110px" },
  { label: "first seen", width: "170px" },
];

// ─────────────────────────────────────────────────────────────────────
// FuzzCampaignDetailPage
// ─────────────────────────────────────────────────────────────────────
export function FuzzCampaignDetailPage() {
  const { campaignId } = useParams<{ campaignId: string }>();
  const cid = campaignId ?? "";
  const navigate = useNavigate();

  const { data: campaign, isLoading, isError } = useFuzzCampaign(cid);
  const { data: crashesData } = useFuzzCrashes({ campaignId: cid });

  useUpdatePageHeader({
    title: campaign?.name,
    subtitle: campaign
      ? `${campaign.engine_id} \u00b7 ${campaign.strategy_id}`
      : undefined,
    status:
      campaign?.status === "running"
        ? "live"
        : campaign?.status === "paused"
          ? "paused"
          : campaign?.status === "failed"
            ? "error"
            : "ready",
  });

  const crashes = crashesData?.data ?? [];
  const patchMut = usePatchFuzzCampaign(cid);
  const launchMut = useLaunchFuzzCampaign(cid);
  const deleteMut = useDeleteFuzzCampaign();
  const [crashFilter, setCrashFilter] = useState<CrashFilter>("all");

  const filteredCrashes = useMemo(() => {
    if (crashFilter === "exploitable") {
      return crashes.filter((c) => c.triage_verdict === "security_relevant");
    }
    if (crashFilter === "untriaged") {
      return crashes.filter((c) => c.triage_verdict === "untriaged");
    }
    if (crashFilter === "unique-stack") {
      const seen = new Set<string>();
      const out: VRFuzzCrashSummary[] = [];
      for (const c of crashes) {
        if (!c.stack_hash || seen.has(c.stack_hash)) continue;
        seen.add(c.stack_hash);
        out.push(c);
      }
      return out;
    }
    return crashes;
  }, [crashes, crashFilter]);

  if (isLoading) {
    return (
      <WindowPanel title="fuzz campaign" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }
  if (isError || !campaign) {
    return (
      <WindowPanel title="fuzz campaign" tone="accent">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          failed to load fuzz campaign.
        </p>
      </WindowPanel>
    );
  }

  const transitions = NEXT_STATES[campaign.status] ?? [];
  const buckets = bucketCrashesByHour(crashes);
  const bucketMax = buckets.reduce((m, b) => Math.max(m, b.count), 0);

  const headerActions = (
    <DeleteButton
      id={cid}
      label={`fuzz campaign "${campaign.name}"`}
      mutation={deleteMut}
      onDeleted={() => navigate("/vr/fuzz/campaigns")}
    />
  );

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="\u25c8"
        title={campaign.name}
        actions={headerActions}
      />

      {/* Status / workstation / stuck / duration chip row */}
      <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
        <MonoBadge tone={STATUS_TONE[campaign.status] ?? "muted"}>
          {campaign.status}
        </MonoBadge>
        <WorkstationBadge systemId={campaign.analysis_system_id} />
        <StuckBadge
          lastProgressAt={campaign.last_progress_at}
          status={campaign.status}
        />
        {campaign.duration_hours != null ? (
          <MonoBadge tone="info">
            duration \u00b7 {campaign.duration_hours}h
          </MonoBadge>
        ) : null}
      </div>

      {/* State control */}
      <WindowPanel
        title="state control"
        tone="accent"
        actions={
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-faint)",
            }}
          >
            {campaign.remote_pid ? `pid ${campaign.remote_pid}` : "no pid"}
          </span>
        }
      >
        <div className="flex" style={{ flexWrap: "wrap", gap: 8 }}>
          {actionButton(
            launchMut.isPending
              ? "launching\u2026"
              : campaign.remote_pid
                ? "re-launch"
                : "launch on workstation",
            () => launchMut.mutate({}),
            {
              primary: true,
              disabled:
                launchMut.isPending || !campaign.analysis_system_id,
              title: campaign.analysis_system_id
                ? "enqueue the launcher arq task -- sshes to the workstation and starts the fuzzer"
                : "set analysis_system_id on the campaign before launching",
              key: "launch",
            },
          )}
          {transitions.map((s) =>
            actionButton(
              `\u2192 ${s}`,
              () => patchMut.mutate({ status: s }),
              { disabled: patchMut.isPending, key: `t-${s}` },
            ),
          )}
          {transitions.length === 0 ? (
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.1em",
                color: "var(--text-faint)",
                alignSelf: "center",
              }}
            >
              campaign is terminal.
            </span>
          ) : null}
        </div>
        {campaign.remote_pid ? (
          <p
            className="font-mono"
            style={{
              marginTop: 10,
              fontSize: 10,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
              overflowWrap: "anywhere",
            }}
          >
            remote_pid={campaign.remote_pid}
            {campaign.remote_corpus_dir
              ? ` \u00b7 corpus=${campaign.remote_corpus_dir}`
              : ""}
            {campaign.remote_crashes_dir
              ? ` \u00b7 crashes=${campaign.remote_crashes_dir}`
              : ""}
          </p>
        ) : null}
      </WindowPanel>

      {/* Rebuild + tune -- backend pending */}
      <WindowPanel
        title="rebuild + tune"
        tone="warn"
        actions={<MonoBadge tone="warn">backend pending</MonoBadge>}
      >
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: 10,
          }}
        >
          <PendingBox>
            <div
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.12em",
                color: "var(--text-primary)",
                marginBottom: 6,
              }}
            >
              rebuild harness
            </div>
            <p style={{ margin: 0 }}>
              re-runs harness generation with the last spec. post{" "}
              /vr/fuzz/campaigns/{cid}/rebuild is pending.
            </p>
            <div style={{ marginTop: 8 }}>
              {actionButton("rebuild harness", undefined, {
                primary: true,
                disabled: true,
              })}
            </div>
          </PendingBox>
          <PendingBox>
            <div
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.12em",
                color: "var(--text-primary)",
                marginBottom: 6,
              }}
            >
              tune
            </div>
            <p style={{ margin: 0 }}>
              adjust timeout / dictionary / mutation rate. patch endpoint
              pending.
            </p>
            <dl
              className="font-mono"
              style={{
                marginTop: 8,
                display: "grid",
                gridTemplateColumns: "auto 1fr",
                columnGap: 10,
                rowGap: 3,
                fontSize: 10,
              }}
            >
              <dt style={{ color: "var(--text-faint)" }}>engine_config</dt>
              <dd style={{ margin: 0, color: "var(--text-primary)" }}>
                {Object.keys(campaign.engine_config).length} keys
              </dd>
              <dt style={{ color: "var(--text-faint)" }}>strategy_config</dt>
              <dd style={{ margin: 0, color: "var(--text-primary)" }}>
                {Object.keys(campaign.strategy_config).length} keys
              </dd>
            </dl>
          </PendingBox>
        </div>
      </WindowPanel>

      {/* Metrics */}
      <WindowPanel title="metrics" tone="info">
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            columnGap: 18,
            rowGap: 0,
          }}
        >
          <BriefRow label="total execs">
            {campaign.total_execs.toLocaleString()}
          </BriefRow>
          <BriefRow label="execs / sec">
            {campaign.execs_per_sec != null
              ? campaign.execs_per_sec.toLocaleString()
              : "--"}
          </BriefRow>
          <BriefRow label="corpus size">
            {campaign.corpus_size.toLocaleString()}
          </BriefRow>
          <BriefRow label="coverage">
            {campaign.coverage_pct != null
              ? `${campaign.coverage_pct.toFixed(2)}%`
              : "--"}
          </BriefRow>
          <BriefRow label="crashes found">
            {campaign.crashes_found}
          </BriefRow>
          <BriefRow label="started">
            {formatDateTime(campaign.started_at)}
          </BriefRow>
          <BriefRow label="stopped">
            {formatDateTime(campaign.stopped_at)}
          </BriefRow>
          <BriefRow label="last progress">
            {formatDateTime(campaign.last_progress_at)}
          </BriefRow>
        </div>
      </WindowPanel>

      {/* Live charts row */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 14,
        }}
      >
        <WindowPanel
          title="crashes over time"
          tone="accent"
          actions={
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.12em",
                color: "var(--text-faint)",
              }}
            >
              last 12h
            </span>
          }
        >
          {crashes.length === 0 ? (
            <p
              className="font-mono"
              style={{
                margin: 0,
                fontSize: 11,
                color: "var(--text-muted)",
              }}
            >
              no crashes yet -- populates once the engine finds one.
            </p>
          ) : (
            <>
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {buckets.map((b) => (
                  <StatBar
                    key={b.bucket}
                    label={b.bucket}
                    color="var(--accent)"
                    value={b.count}
                    max={Math.max(1, bucketMax)}
                  />
                ))}
              </div>
              <table className="sr-only">
                <caption>Crashes per hour (last 12 hours)</caption>
                <thead>
                  <tr>
                    <th>Hour</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {buckets.map((row) => (
                    <tr key={row.bucket}>
                      <td>{row.bucket}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </WindowPanel>

        <WindowPanel title="coverage / corpus / stability" tone="info">
          <CoverageChart campaignId={cid} />
        </WindowPanel>
      </div>

      {/* Workstation resources -- backend pending */}
      <WindowPanel
        title="workstation resources"
        tone="muted"
        actions={<MonoBadge tone="warn">backend pending</MonoBadge>}
      >
        <PendingBox>
          per-instance cpu / memory / disk-write-rate polled from the
          workstation every 10s.{" "}
          {campaign.analysis_system_id
            ? `workstation: registered system #${campaign.analysis_system_id}.`
            : "no analysis_system_id set on this campaign."}
        </PendingBox>
      </WindowPanel>

      {/* Crashes grid */}
      <WindowPanel
        title="crashes"
        tone="accent"
        actions={
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.12em",
              color: "var(--text-faint)",
            }}
          >
            {filteredCrashes.length}
            {filteredCrashes.length !== crashes.length
              ? ` / ${crashes.length}`
              : ""}
          </span>
        }
      >
        <div
          className="flex"
          style={{ gap: 6, flexWrap: "wrap", marginBottom: 10 }}
        >
          {CRASH_FILTER_OPTIONS.map((chip) => (
            <FilterChip
              key={chip}
              active={crashFilter === chip}
              onClick={() => setCrashFilter(chip)}
            >
              {chip}
            </FilterChip>
          ))}
        </div>
        <DataGrid<VRFuzzCrashSummary>
          columns={CRASH_COLUMNS}
          rows={filteredCrashes}
          getKey={(c) => c.id}
          onRowClick={(c) => navigate(`/vr/fuzz/crashes/${c.id}`)}
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
              no crashes registered yet.
            </div>
          }
          renderCells={(c) => [
            <span
              style={{
                fontSize: 10.5,
                color: "var(--text-muted)",
                letterSpacing: "0.06em",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                display: "block",
              }}
            >
              {c.stack_hash.slice(0, 12)}\u2026
            </span>,
            c.crash_type ? (
              <MonoBadge tone="warn">{c.crash_type}</MonoBadge>
            ) : (
              <span style={{ fontSize: 10, color: "var(--text-faint)" }}>--</span>
            ),
            <span
              style={{
                fontSize: 11,
                color: "var(--text-primary)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                display: "block",
              }}
            >
              {c.crash_signature ?? "--"}
            </span>,
            <MonoBadge tone={VERDICT_TONE[c.triage_verdict] ?? "muted"}>
              {c.triage_verdict}
            </MonoBadge>,
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
              }}
            >
              {c.severity}
            </span>,
            <span
              style={{ fontSize: 10.5, color: "var(--text-muted)" }}
            >
              {formatDateTime(c.discovered_at ?? c.created_at ?? null)}
            </span>,
          ]}
        />
      </WindowPanel>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// CoverageChart -- time-series telemetry rendered as mono StatBar rows
// per metric (coverage % / corpus / execs / new-crashes) with an
// sr-only mirror table for screen readers. Preserves the
// useCampaignTelemetry + useThemeChartColors data path.
// ─────────────────────────────────────────────────────────────────────
function CoverageChart({ campaignId }: { campaignId: string }) {
  const { data } = useCampaignTelemetry(campaignId);
  const colors = useThemeChartColors();
  const points = data?.data ?? [];

  if (points.length === 0) {
    return (
      <PendingBox>
        no telemetry samples recorded yet. workers post to{" "}
        <span
          className="font-mono"
          style={{ color: "var(--text-primary)" }}
        >
          /vr/fuzz/campaigns/{campaignId}/telemetry
        </span>{" "}
        and this panel populates as samples land.
      </PendingBox>
    );
  }

  const series = points.map((p, i, arr) => {
    const prevCrashes = i > 0 ? (arr[i - 1].crashes_found ?? 0) : 0;
    const currCrashes = p.crashes_found ?? 0;
    const delta = Math.max(0, currCrashes - prevCrashes);
    return {
      t: p.measured_at.slice(11, 16),
      coverage: p.coverage_pct ?? 0,
      corpus: p.corpus_size ?? 0,
      eps: p.execs_per_sec ?? 0,
      crashes: i === 0 ? currCrashes : delta,
    };
  });

  const latest = series[series.length - 1];
  const maxCov = Math.max(1, ...series.map((s) => s.coverage));
  const maxCorpus = Math.max(1, ...series.map((s) => s.corpus));
  const maxEps = Math.max(1, ...series.map((s) => s.eps));
  const maxCrashes = Math.max(1, ...series.map((s) => s.crashes));

  const metrics: Array<{
    label: string;
    color: string;
    values: number[];
    max: number;
  }> = [
    {
      label: "coverage %",
      color: colors.accent ?? "var(--accent)",
      values: series.map((s) => s.coverage),
      max: maxCov,
    },
    {
      label: "execs / sec",
      color: colors.high ?? "var(--status-warn)",
      values: series.map((s) => s.eps),
      max: maxEps,
    },
    {
      label: "corpus size",
      color: colors.medium ?? "var(--status-info)",
      values: series.map((s) => s.corpus),
      max: maxCorpus,
    },
    {
      label: "new crashes",
      color: colors.critical ?? "var(--accent)",
      values: series.map((s) => s.crashes),
      max: maxCrashes,
    },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {metrics.map((m) => (
        <div key={m.label}>
          <div
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-faint)",
              marginBottom: 4,
            }}
          >
            {m.label}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {series.map((s, i) => (
              <StatBar
                key={`${m.label}-${i}`}
                label={s.t}
                color={m.color}
                value={m.values[i]}
                max={m.max}
              />
            ))}
          </div>
        </div>
      ))}
      <p
        className="font-mono"
        style={{
          margin: 0,
          fontSize: 10,
          color: "var(--text-muted)",
          letterSpacing: "0.04em",
        }}
      >
        {series.length} samples \u00b7 latest: {latest?.coverage.toFixed(2)}% cov
        {" "}\u00b7 {latest?.corpus} corpus \u00b7 {latest?.eps.toFixed(0)}{" "}
        exec/s \u00b7 {latest?.crashes} new crashes
      </p>
      <table className="sr-only">
        <caption>Fuzz telemetry samples</caption>
        <thead>
          <tr>
            <th>Time</th>
            <th>Coverage %</th>
            <th>Corpus size</th>
            <th>Execs/sec</th>
            <th>New crashes</th>
          </tr>
        </thead>
        <tbody>
          {series.map((row) => (
            <tr key={row.t}>
              <td>{row.t}</td>
              <td>{row.coverage}</td>
              <td>{row.corpus}</td>
              <td>{row.eps}</td>
              <td>{row.crashes}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// StuckBadge -- amber warn chip when the campaign is `running` but has
// not reported progress in > 4h.
// ─────────────────────────────────────────────────────────────────────
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
    <MonoBadge tone="warn">stuck \u00b7 no progress in {hours}h</MonoBadge>
  );
}

// ─────────────────────────────────────────────────────────────────────
// WorkstationBadge -- workstation name + live-reachability dot.
// ─────────────────────────────────────────────────────────────────────
function WorkstationBadge({
  systemId,
}: {
  systemId: number | null | undefined;
}) {
  const systems = useSystemMap();
  const { data: heartbeat } = useSystemHeartbeat(systemId ?? null);

  if (!systemId) {
    return <MonoBadge tone="muted">no workstation</MonoBadge>;
  }
  const sys = systems.get(systemId);
  const label = sys ? `${sys.name} (${sys.host})` : `system #${systemId}`;
  const live = heartbeat?.reachable === true;
  const tone = heartbeat ? (heartbeat.reachable ? "ok" : "critical") : "muted";
  const tooltip = heartbeat
    ? heartbeat.reachable
      ? `reachable \u00b7 ${heartbeat.latency_ms ?? "?"} ms \u00b7 checked ${new Date(heartbeat.checked_at).toLocaleTimeString()}`
      : `unreachable: ${heartbeat.error ?? "no response"}`
    : "probing\u2026";
  return (
    <span
      className="inline-flex items-center"
      style={{ gap: 6 }}
      title={tooltip}
    >
      <span
        aria-label={live ? "reachable" : "unreachable"}
        style={{
          display: "inline-block",
          width: 7,
          height: 7,
          borderRadius: 2,
          background: live
            ? "var(--status-ok)"
            : heartbeat
              ? "var(--accent)"
              : "var(--text-faint)",
        }}
      />
      <MonoBadge tone={tone}>{label}</MonoBadge>
    </span>
  );
}
