/**
 * ExecutivePage -- fleet-wide risk posture summary and downloadable artifacts.
 */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { AilaChart } from "@/components/aila/AilaChart";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  BigStat,
  StatBar,
  MonoBadge,
  DataGrid,
} from "@/components/aila/mock";
import { FeatureBoundary } from "@app/FeatureBoundary";
import { requestBlob } from "@platform/api/http";
import { saveBlobResponse } from "@platform/api/download";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { authorizedRequestJson } from "@platform/api/http";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

// ---------------------------------------------------------------------------
// Types -- mirror src/aila/api/schemas/endpoints.py:ExecutiveHealthResponse
// ---------------------------------------------------------------------------

interface ExecutiveHealthResponse {
  total_findings: number;
  severity_breakdown: Record<string, number>;
  last_scanned_at: string | null;
  systems_with_findings: number;
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

interface SeverityRow {
  key: string;
  label: string;
  tone: "critical" | "high" | "medium" | "low";
  color: string;
  count: number;
}

const SEVERITY_META: {
  key: string;
  label: string;
  tone: "critical" | "high" | "medium" | "low";
  color: string;
}[] = [
  { key: "Immediate", label: "Immediate", tone: "critical", color: "var(--accent)" },
  { key: "High", label: "High", tone: "high", color: "var(--status-warn)" },
  { key: "Moderate", label: "Moderate", tone: "medium", color: "var(--status-info)" },
  { key: "Planned", label: "Planned", tone: "low", color: "var(--status-ok)" },
];

// ---------------------------------------------------------------------------
// Mock button style
// ---------------------------------------------------------------------------

const BTN_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  letterSpacing: "0.08em",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
};

const BTN_ACCENT_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 14%, transparent)",
  color: "var(--accent)",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  fontSize: 11,
  padding: "0 10px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  outline: "none",
  fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ExecutivePage() {
  const [systemId, setSystemId] = useState("");
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [zipBusy, setZipBusy] = useState(false);
  const [zipError, setZipError] = useState<string | null>(null);

  const healthQuery = useQuery({
    queryKey: ["platform", "executive-health"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ExecutiveHealthResponse>>(
        "/executive/health",
      ),
  });

  const health = healthQuery.data?.data;

  const breakdown: SeverityRow[] = useMemo(() => {
    if (!health) return [];
    return SEVERITY_META.map((s) => ({
      ...s,
      count: health.severity_breakdown[s.key] ?? 0,
    }));
  }, [health]);

  const themeColors = useThemeChartColors();

  const severityPieData = useMemo(() => {
    if (!health) return [];
    const colorByKey: Record<string, string> = {
      Immediate: themeColors.critical,
      High: themeColors.high,
      Moderate: themeColors.medium,
      Planned: themeColors.low,
    };
    return breakdown
      .filter((row) => row.count > 0)
      .map((row) => ({
        name: row.label,
        count: row.count,
        color: colorByKey[row.key] ?? themeColors.textMuted,
      }));
  }, [breakdown, health, themeColors]);
  const severityPieColors = useMemo(
    () => severityPieData.map((row) => row.color),
    [severityPieData],
  );

  async function handleDownloadPdf() {
    setPdfError(null);
    setPdfBusy(true);
    try {
      const token = await getAuthTokenStandalone();
      const payload = await requestBlob("/executive/risk-summary-pdf", { token });
      saveBlobResponse(payload, "aila-risk-summary.pdf");
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : "Failed to download PDF");
    } finally {
      setPdfBusy(false);
    }
  }

  async function handleDownloadEvidence(e: React.FormEvent) {
    e.preventDefault();
    setZipError(null);
    const trimmed = systemId.trim();
    if (!trimmed) {
      setZipError("Enter a system_id");
      return;
    }
    const numeric = Number(trimmed);
    if (!Number.isInteger(numeric) || numeric <= 0) {
      setZipError("system_id must be a positive integer");
      return;
    }
    setZipBusy(true);
    try {
      const token = await getAuthTokenStandalone();
      const payload = await requestBlob(
        `/executive/systems/${numeric}/evidence-package`,
        { token },
      );
      saveBlobResponse(payload, `evidence-system-${numeric}.zip`);
    } catch (err) {
      setZipError(err instanceof Error ? err.message : "Failed to download ZIP");
    } finally {
      setZipBusy(false);
    }
  }

  const immediateCount = health?.severity_breakdown.Immediate ?? 0;
  const totalFindings = health?.total_findings ?? 0;
  const systemsCount = health?.systems_with_findings ?? 0;
  const lastScannedRaw = health?.last_scanned_at ?? null;
  const lastScannedLabel = lastScannedRaw
    ? new Date(lastScannedRaw).toLocaleString()
    : "--";

  // MTTR + KEV are not carried in the current envelope. Surface as "--" so
  // the layout stays faithful without inventing metrics.
  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="Executive posture"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              style={BTN_STYLE}
              className="font-mono uppercase"
              onClick={() => void healthQuery.refetch()}
              disabled={healthQuery.isFetching}
            >
              {healthQuery.isFetching ? "REFRESHING\u2026" : "REFRESH"}
            </button>
            <button
              type="button"
              style={BTN_ACCENT_STYLE}
              className="font-mono uppercase"
              onClick={handleDownloadPdf}
              disabled={pdfBusy}
            >
              {pdfBusy ? "GENERATING\u2026" : "\u2193 PDF"}
            </button>
          </div>
        }
      />

      {healthQuery.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          Failed to load executive health:{" "}
          {(healthQuery.error as Error).message}
        </div>
      )}

      {/* BigStat KPI row: posture / findings / MTTR / KEV */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title="risk posture">
          <BigStat
            value={
              totalFindings === 0
                ? "OK"
                : immediateCount > 0
                  ? "AT RISK"
                  : "WATCH"
            }
            sub="fleet risk grade"
          />
        </WindowPanel>
        <WindowPanel title="findings open">
          <BigStat value={totalFindings} sub="across the fleet" />
        </WindowPanel>
        <WindowPanel title="mttr">
          <BigStat value={"\u2014"} sub="mean time to remediate" />
        </WindowPanel>
        <WindowPanel title="immediate risk">
          <BigStat
            value={immediateCount}
            sub={
              immediateCount === 0 ? "no critical findings" : "requires action"
            }
          />
        </WindowPanel>
      </div>

      {/* Distribution + chart row */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}
      >
        <WindowPanel title="severity distribution">
          {healthQuery.isLoading ? (
            <LoadingSkeletonGroup lines={4} />
          ) : totalFindings === 0 ? (
            <p
              className="font-mono"
              style={{
                padding: 24,
                textAlign: "center",
                fontSize: 12,
                color: "var(--text-muted)",
              }}
            >
              no active findings across the fleet.
            </p>
          ) : (
            <div className="flex flex-col" style={{ gap: 8 }}>
              {breakdown.map((row) => (
                <StatBar
                  key={row.key}
                  label={row.label.toUpperCase()}
                  color={row.color}
                  value={row.count}
                  max={totalFindings}
                />
              ))}
            </div>
          )}
        </WindowPanel>

        <FeatureBoundary
          label="Severity distribution chart"
          resetKeys={[severityPieData.length, totalFindings]}
          onReset={() => void healthQuery.refetch()}
        >
          <WindowPanel title="posture chart">
            {healthQuery.isLoading ? (
              <LoadingSkeletonGroup lines={4} />
            ) : severityPieData.length === 0 ? (
              <p
                className="font-mono"
                style={{
                  padding: 24,
                  textAlign: "center",
                  fontSize: 12,
                  color: "var(--text-muted)",
                }}
              >
                no findings to chart.
              </p>
            ) : (
              <AilaChart
                type="pie"
                data={severityPieData}
                dataKey="count"
                xKey="name"
                colors={severityPieColors}
                size="md"
                ariaLabel="Severity distribution pie chart"
              />
            )}
          </WindowPanel>
        </FeatureBoundary>
      </div>

      {/* Top risk grid + fleet vitals */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "2fr 1fr", gap: 12 }}
      >
        <WindowPanel title="top risks" flush>
          <DataGrid
            columns={[
              { label: "SEVERITY", width: "130px" },
              { label: "TIER", width: "1fr" },
              { label: "FINDINGS", width: "100px", align: "right" },
              { label: "SHARE", width: "80px", align: "right" },
            ]}
            rows={breakdown}
            getKey={(r) => r.key}
            empty={
              <div
                className="font-mono"
                style={{
                  padding: 34,
                  textAlign: "center",
                  fontSize: 12,
                  color: "var(--text-muted)",
                }}
              >
                {healthQuery.isLoading
                  ? "loading fleet posture\u2026"
                  : "no findings to rank."}
              </div>
            }
            renderCells={(r) => [
              <MonoBadge key="s" tone={r.tone}>
                {r.label}
              </MonoBadge>,
              <span
                key="t"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.label} risk tier
              </span>,
              <span
                key="c"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.count}
              </span>,
              <span
                key="p"
                style={{ color: "var(--text-faint)", fontSize: 10.5 }}
              >
                {totalFindings === 0
                  ? "\u2014"
                  : `${((r.count / totalFindings) * 100).toFixed(1)}%`}
              </span>,
            ]}
          />
        </WindowPanel>

        <WindowPanel title="fleet vitals">
          <div className="flex flex-col" style={{ gap: 8 }}>
            <div
              className="flex items-center justify-between font-mono"
              style={{
                padding: "6px 0",
                borderBottom: "1px solid var(--border-faint)",
                fontSize: 10.5,
              }}
            >
              <span
                className="uppercase"
                style={{
                  color: "var(--text-faint)",
                  fontSize: 9,
                  letterSpacing: "0.1em",
                }}
              >
                affected systems
              </span>
              <span style={{ color: "var(--text-primary)" }}>
                {systemsCount}
              </span>
            </div>
            <div
              className="flex items-center justify-between font-mono"
              style={{
                padding: "6px 0",
                borderBottom: "1px solid var(--border-faint)",
                fontSize: 10.5,
              }}
            >
              <span
                className="uppercase"
                style={{
                  color: "var(--text-faint)",
                  fontSize: 9,
                  letterSpacing: "0.1em",
                }}
              >
                total findings
              </span>
              <span style={{ color: "var(--text-primary)" }}>
                {totalFindings}
              </span>
            </div>
            <div
              className="flex items-center justify-between font-mono"
              style={{
                padding: "6px 0",
                borderBottom: "1px solid var(--border-faint)",
                fontSize: 10.5,
              }}
            >
              <span
                className="uppercase"
                style={{
                  color: "var(--text-faint)",
                  fontSize: 9,
                  letterSpacing: "0.1em",
                }}
              >
                last scan
              </span>
              <span style={{ color: "var(--text-primary)" }}>
                {lastScannedLabel}
              </span>
            </div>
            <div
              className="flex items-center justify-between font-mono"
              style={{
                padding: "6px 0",
                fontSize: 10.5,
              }}
            >
              <span
                className="uppercase"
                style={{
                  color: "var(--text-faint)",
                  fontSize: 9,
                  letterSpacing: "0.1em",
                }}
              >
                immediate
              </span>
              <MonoBadge tone={immediateCount > 0 ? "critical" : "ok"}>
                {immediateCount}
              </MonoBadge>
            </div>
          </div>
        </WindowPanel>
      </div>

      {/* Downloads */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}
      >
        <WindowPanel title="risk summary pdf">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 12 }}
          >
            Fleet-wide executive risk summary. Includes severity distribution,
            top-25 findings, and posture commentary.
          </p>
          <button
            type="button"
            className="font-mono uppercase"
            style={BTN_ACCENT_STYLE}
            onClick={handleDownloadPdf}
            disabled={pdfBusy}
          >
            {pdfBusy ? "GENERATING\u2026" : "\u2193 DOWNLOAD PDF"}
          </button>
          {pdfError && (
            <p
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--status-warn)", marginTop: 8 }}
            >
              {pdfError}
            </p>
          )}
        </WindowPanel>

        <WindowPanel title="system evidence package">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 12 }}
          >
            ZIP archive of findings, compliance tags, and scan metadata for a
            single system.
          </p>
          <form
            className="flex items-end"
            style={{ gap: 8 }}
            onSubmit={handleDownloadEvidence}
          >
            <div className="flex flex-col" style={{ gap: 4, flex: 1 }}>
              <label
                className="font-mono uppercase"
                htmlFor="ev-system-id"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                }}
              >
                system id
              </label>
              <input
                id="ev-system-id"
                value={systemId}
                onChange={(e) => setSystemId(e.target.value)}
                placeholder="42"
                inputMode="numeric"
                style={INPUT_STYLE}
              />
            </div>
            <button
              type="submit"
              className="font-mono uppercase"
              style={BTN_ACCENT_STYLE}
              disabled={zipBusy}
            >
              {zipBusy ? "BUILDING\u2026" : "\u2193 ZIP"}
            </button>
          </form>
          {zipError && (
            <p
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--status-warn)", marginTop: 8 }}
            >
              {zipError}
            </p>
          )}
        </WindowPanel>
      </div>
    </div>
  );
}
