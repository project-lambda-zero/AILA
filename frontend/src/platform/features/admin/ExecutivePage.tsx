/**
 * ExecutivePage — fleet-wide risk posture summary and downloadable artifacts.
 *
 * Phase 147: surfaces the same data that backs the executive PDF (severity
 * breakdown, total findings, last scan timestamp) and exposes the
 * downloadable PDF + per-system evidence ZIP.
 *
 * Endpoints:
 *   GET /executive/health               — JSON posture summary
 *   GET /executive/risk-summary-pdf     — fleet-wide PDF (binary)
 *   GET /executive/systems/{id}/evidence-package  — per-system ZIP (binary)
 */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Briefcase,
  FilePdf,
  FileArrowDown,
} from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { requestBlob } from "@platform/api/http";
import { saveBlobResponse } from "@platform/api/download";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types — mirror src/aila/api/schemas/endpoints.py:ExecutiveHealthResponse
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

// Expected severity order (matches PDF template)
const SEVERITY_ORDER: { key: string; label: string; color: string }[] = [
  { key: "Immediate", label: "Immediate", color: "text-critical" },
  { key: "High", label: "High", color: "text-high" },
  { key: "Moderate", label: "Moderate", color: "text-medium" },
  { key: "Planned", label: "Planned", color: "text-low" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

async function downloadAuthorizedBlob(path: string, fallbackFileName: string) {
  const token = await getAuthTokenStandalone();
  const payload = await requestBlob(path, { token });
  saveBlobResponse(payload, fallbackFileName);
}

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

  const breakdown = useMemo(() => {
    if (!health) return [];
    return SEVERITY_ORDER.map((s) => ({
      ...s,
      count: health.severity_breakdown[s.key] ?? 0,
    }));
  }, [health]);

  async function handleDownloadPdf() {
    setPdfError(null);
    setPdfBusy(true);
    try {
      await downloadAuthorizedBlob(
        "/executive/risk-summary-pdf",
        "aila-risk-summary.pdf",
      );
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
      await downloadAuthorizedBlob(
        `/executive/systems/${numeric}/evidence-package`,
        `evidence-system-${numeric}.zip`,
      );
    } catch (err) {
      setZipError(err instanceof Error ? err.message : "Failed to download ZIP");
    } finally {
      setZipBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div>
        <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
          <Briefcase className="h-5 w-5 text-accent" />
          Executive Dashboard
        </h1>
        <p className="font-mono text-sm text-text-muted mt-0.5">
          Fleet-wide risk posture and downloadable artifacts for stakeholders.
        </p>
      </div>

      {/* Top-level posture cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Findings
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {healthQuery.isLoading ? "—" : (health?.total_findings ?? 0)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Active across the fleet
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Affected Systems
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {healthQuery.isLoading ? "—" : (health?.systems_with_findings ?? 0)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          With at least one finding
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Immediate Risk
        </p>
        <p className="font-mono text-2xl font-semibold text-critical mt-1">
          {healthQuery.isLoading
            ? "—"
            : (health?.severity_breakdown.Immediate ?? 0)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Requires action now
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Last Scan
        </p>
        <p className="font-mono text-sm text-text mt-1">
          {healthQuery.isLoading
            ? "—"
            : formatTimestamp(health?.last_scanned_at)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Across all findings
        </p></AilaCard>
      </div>

      {/* Health error */}
      {healthQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load executive health: {(healthQuery.error as Error).message}
        </div>
      )}

      {/* Severity breakdown */}
      <AilaCard variant="default" padding="md" techBorder glow><h2 className="font-mono text-sm font-semibold text-text mb-3">
        Risk posture
      </h2>
      {healthQuery.isLoading && <LoadingSkeletonGroup lines={2} />}
      {!healthQuery.isLoading &&
        !healthQuery.isError &&
        health &&
        health.total_findings === 0 && (
          <EmptyState
            icon={<Briefcase className="h-10 w-10" />}
            title="No active findings"
            description="No findings to summarise. Run a scan against your fleet to populate the executive view."
          />
        )}
      {!healthQuery.isLoading && health && health.total_findings > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {breakdown.map((row) => (
            <div
              key={row.key}
              className="flex flex-col gap-1 rounded-[4px] border border-border bg-base px-4 py-3"
            >
              <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
                {row.label}
              </p>
              <p className={`font-mono text-3xl font-semibold ${row.color}`}>
                {row.count}
              </p>
              <AilaBadge severity="neutral" size="sm">
                {((row.count / health.total_findings) * 100).toFixed(1)}%
              </AilaBadge>
            </div>
          ))}
        </div>
      )}</AilaCard>

      {/* Downloads */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <AilaCard variant="default" padding="md" techBorder glow><div className="flex items-center gap-2 mb-3">
          <FilePdf className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            Risk summary PDF
          </h2>
        </div>
        <p className="font-mono text-xs text-text-muted mb-4">
          Stream a fleet-wide executive risk summary as PDF. Includes severity
          cards, top-25 findings, and posture commentary.
        </p>
        <Button
          type="button"
          size="sm"
          className="gap-1.5"
          disabled={pdfBusy}
          onClick={handleDownloadPdf}
        >
          <FileArrowDown className="h-4 w-4" />
          {pdfBusy ? "Generating…" : "Download PDF"}
        </Button>
        {pdfError && (
          <p className="font-mono text-xs text-destructive mt-2">{pdfError}</p>
        )}</AilaCard>

        <AilaCard variant="default" padding="md" techBorder glow><div className="flex items-center gap-2 mb-3">
          <FileArrowDown className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            System evidence package
          </h2>
        </div>
        <p className="font-mono text-xs text-text-muted mb-4">
          ZIP archive of findings, compliance tags, and scan metadata for a
          specific system. Useful for audit handoff.
        </p>
        <form
          className="flex flex-col gap-2 sm:flex-row sm:items-end"
          onSubmit={handleDownloadEvidence}
        >
          <div className="flex flex-col gap-1 flex-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="ev-system-id"
            >
              System ID
            </label>
            <Input
              id="ev-system-id"
              value={systemId}
              onChange={(e) => setSystemId(e.target.value)}
              placeholder="42"
              className="font-mono text-sm"
              inputMode="numeric"
            />
          </div>
          <Button
            type="submit"
            size="sm"
            className="gap-1.5"
            disabled={zipBusy}
          >
            <FileArrowDown className="h-4 w-4" />
            {zipBusy ? "Building…" : "Download ZIP"}
          </Button>
        </form>
        {zipError && (
          <p className="font-mono text-xs text-destructive mt-2">{zipError}</p>
        )}</AilaCard>
      </div>
    </div>
  );
}
