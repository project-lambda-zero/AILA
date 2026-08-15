/**
 * ConsoleVitalsRail -- the console home's right rail.
 *
 * Mirrors the design-system console mockup (`AILA Console.dc.html`), whose
 * three-column console pairs the chat centre with a right `<aside>` of engine
 * vitals. On the platform console home there is no single active investigation,
 * so the rail reports live platform vitals instead: fleet risk + coverage, the
 * finding severity ledger, and per-service health. Every value is real data
 * from GET /dashboard and GET /health -- nothing is synthesised.
 *
 * Row shape matches the mockup: a fixed-width muted key + a tone-coloured
 * value, on a hairline rule, in mono 10px.
 */
import * as React from "react";

import { WindowPanel, type WindowPanelTone } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  useDashboardData,
  useHealthData,
} from "@platform/features/dashboard/hooks/useDashboardData";

type Tone = "ok" | "info" | "warn" | "crit" | "muted";

const TONE_COLOR: Record<Tone, string> = {
  ok: "var(--color-mint)",
  info: "var(--color-lavender)",
  warn: "var(--color-amber)",
  crit: "var(--color-accent)",
  muted: "var(--color-text-muted)",
};

const ROW_RULE = "1px solid color-mix(in srgb, var(--color-border) 55%, transparent)";

function VitalRow({
  label,
  value,
  tone = "info",
}: {
  label: string;
  value: React.ReactNode;
  tone?: Tone;
}) {
  return (
    <div
      className="flex items-center gap-2 py-1 font-mono text-[10px]"
      style={{ borderBottom: ROW_RULE }}
    >
      <span
        className="uppercase"
        style={{ flex: "0 0 84px", color: "var(--color-text-muted)", letterSpacing: "0.04em" }}
      >
        {label}
      </span>
      <span className="min-w-0 flex-1 truncate" style={{ color: TONE_COLOR[tone] }}>
        {value}
      </span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div
        className="pb-1 font-mono text-[9px] uppercase"
        style={{
          color: "var(--color-text-faint)",
          letterSpacing: "0.14em",
          borderBottom: "1px solid var(--color-border)",
        }}
      >
        {title}
      </div>
      <div className="pt-0.5">{children}</div>
    </div>
  );
}

function riskTone(score: number): Tone {
  if (score >= 70) return "crit";
  if (score >= 40) return "warn";
  return "ok";
}

function healthTone(status: string): { panel: WindowPanelTone; row: Tone } {
  const s = status.toLowerCase();
  if (s === "healthy") return { panel: "ok", row: "ok" };
  if (s === "degraded") return { panel: "warn", row: "warn" };
  if (!s) return { panel: "muted", row: "muted" };
  return { panel: "accent", row: "crit" };
}

function checkTone(status: string): Tone {
  const s = status.toLowerCase();
  if (s === "healthy" || s === "ok" || s === "up" || s === "pass") return "ok";
  if (s === "degraded" || s === "warn" || s === "slow") return "warn";
  return "crit";
}

export function ConsoleVitalsRail() {
  const dash = useDashboardData();
  const health = useHealthData();

  const stats = dash.data?.fleet_stats;
  const risk = dash.data?.risk_score;
  const healthStatus = health.data?.status ?? "";
  const { panel: panelTone, row: healthRow } = healthTone(healthStatus);
  const checks = Object.entries(health.data?.checks ?? {});

  const loading = dash.isLoading && !dash.data;
  const failed = dash.isError && !dash.data;

  const generatedAt = dash.data?.generated_at;
  const statusFooter = generatedAt
    ? `updated ${new Date(generatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : "syncing";

  return (
    <WindowPanel
      title="vitals"
      tone={panelTone}
      status={statusFooter}
      className="hidden xl:flex xl:flex-col xl:self-stretch"
      style={{ flex: "0 0 260px" }}
      data-testid="console-vitals"
    >
      {loading ? (
        <LoadingSkeletonGroup lines={6} />
      ) : failed ? (
        <p className="font-mono text-[10px]" style={{ color: "var(--color-text-muted)" }}>
          vitals unavailable
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <Section title="platform">
            {typeof risk === "number" && (
              <VitalRow label="risk" value={risk.toFixed(0)} tone={riskTone(risk)} />
            )}
            {stats && (
              <VitalRow
                label="systems"
                value={`${stats.online_systems} / ${stats.total_systems}`}
                tone={stats.online_systems < stats.total_systems ? "warn" : "ok"}
              />
            )}
            <VitalRow label="health" value={healthStatus || "unknown"} tone={healthRow} />
          </Section>

          {stats && (
            <Section title="findings">
              <VitalRow
                label="critical"
                value={stats.critical_findings}
                tone={stats.critical_findings > 0 ? "crit" : "muted"}
              />
              <VitalRow
                label="high"
                value={stats.high_findings}
                tone={stats.high_findings > 0 ? "warn" : "muted"}
              />
              <VitalRow
                label="medium"
                value={stats.medium_findings}
                tone={stats.medium_findings > 0 ? "info" : "muted"}
              />
              <VitalRow label="low" value={stats.low_findings} tone="muted" />
              <VitalRow label="total" value={stats.total_findings} tone="info" />
            </Section>
          )}

          {checks.length > 0 && (
            <Section title="services">
              {checks.slice(0, 6).map(([name, check]) => (
                <VitalRow
                  key={name}
                  label={name}
                  value={check.status}
                  tone={checkTone(String(check.status))}
                />
              ))}
            </Section>
          )}
        </div>
      )}
    </WindowPanel>
  );
}

export default ConsoleVitalsRail;
