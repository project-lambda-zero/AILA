import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";
import { useState } from "react";

import { Link, useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

import { downloadArtifact, useSubmitForReview, useWizardResolution, useWizardSchema, useWizardSessionDetail } from "../queries";
import { canShowResults, firstWizardPath } from "../sessionFlow";
import type { ComponentClassificationResponse } from "../types";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

function formatDate(isoString: string | null): string {
  if (!isoString) return "—";
  try {
    return new Date(isoString).toLocaleDateString("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
    });
  } catch {
    return isoString;
  }
}

// Classification sort order: triggered → uncertain → not_triggered → rest
const CLASSIFICATION_ORDER: Record<string, number> = {
  triggered: 0,
  uncertain: 1,
  not_triggered: 2,
};

type BadgeSeverity = "high" | "medium" | "neutral";

function badgeSeverityFor(cls: string): BadgeSeverity {
  if (cls === "triggered") return "high";
  if (cls === "uncertain") return "medium";
  return "neutral";
}

function cardBorderFor(cls: string): string {
  if (cls === "triggered") return "border-accent/40";
  if (cls === "uncertain") return "border-medium/40";
  return "border-border";
}

// ──────────────────────────────────────────────────────────────────────────────
// Component card — cyberpunk styled with expandable reasoning
// ──────────────────────────────────────────────────────────────────────────────

interface ComponentCardProps {
  comp: ComponentClassificationResponse;
}

function ComponentCard({ comp }: ComponentCardProps) {
  const [expanded, setExpanded] = useState(false);
  const cls = comp.classification;

  return (
    <div
      className={cn(
        "rounded-[var(--radius-md)] border bg-surface p-4 flex flex-col gap-2",
        cardBorderFor(cls),
      )}
    >
      <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
        {comp.subtask_label}
      </span>
      <div>
        <AilaBadge severity={badgeSeverityFor(cls)} size="sm">
          {cls.replace(/_/g, " ")}
        </AilaBadge>
      </div>
      <span className="font-mono text-xs text-text-muted">
        {(comp.confidence * 100).toFixed(0)}% confidence · {comp.cited_question_ids.length} evidence
      </span>
      <button
        type="button"
        className="self-start text-xs text-accent hover:opacity-80"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
      >
        {expanded ? "Hide reasoning" : "Show reasoning"}
      </button>
      {expanded && (
        <p className="text-sm text-text">{comp.reasoning}</p>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Download button with per-artifact loading state (T-137-17: disabled during download)
// ──────────────────────────────────────────────────────────────────────────────

type ArtifactKind = "report/pdf" | "workbook" | "jira-draft";

interface DownloadButtonProps {
  label: string;
  artifact: ArtifactKind;
  sessionId: string;
}

function DownloadButton({ label, artifact, sessionId }: DownloadButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    if (loading) return;
    setLoading(true);
    setError(null);
    try {
      await downloadArtifact(sessionId, artifact);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Download failed.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-1">
      <Button
        type="button"
        variant="outline"
        onClick={() => void handleClick()}
        disabled={loading}
        aria-busy={loading}
      >
        {loading ? "Downloading..." : label}
      </Button>
      {error && <p className="text-sm text-critical">{error}</p>}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Skeleton
// ──────────────────────────────────────────────────────────────────────────────

function ResultsSkeleton() {
  return (
    <div className="min-h-screen bg-base p-8 font-sans">
      <div className="animate-pulse bg-surface rounded-[var(--radius-md)] h-7 w-2/5 mb-4" />
      <div className="animate-pulse bg-surface rounded-[var(--radius-md)] h-4 w-3/5 mb-8" />
      <div className="animate-pulse bg-surface rounded-[var(--radius-md)] h-20 mb-8" />
      <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="animate-pulse bg-surface rounded-[var(--radius-md)] h-24"
          />
        ))}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// WizardResultsPage — post-resolution results (WIZ-06)
// ──────────────────────────────────────────────────────────────────────────────

export function WizardResultsPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const sid = sessionId ?? "";
  const navigate = useNavigate();

  const sessionQuery = useWizardSessionDetail(sid);
  const resolutionQuery = useWizardResolution(sid);
  const schemaQuery = useWizardSchema();
  const submitForReview = useSubmitForReview();
  const [submitError, setSubmitError] = useState<string | null>(null);

  useUpdatePageHeader({
    title: sessionQuery.data?.session ? `${sessionQuery.data.session.project_name} — Results` : undefined,
    subtitle: resolutionQuery.data ? `Resolved ${formatDate(resolutionQuery.data.resolved_at)}` : undefined,
    status: null,
  });

  if (sessionQuery.isLoading || resolutionQuery.isLoading || schemaQuery.isLoading) {
    return <ResultsSkeleton />;
  }

  if (sessionQuery.isError || resolutionQuery.isError) {
    return (
      <div className="min-h-screen bg-base p-8">
        <EmptyState
          title="Failed to load results"
          description="The session may not be resolved yet."
          action={{ label: "Back to Assessments", href: "/assessments" }}
        />
      </div>
    );
  }

  const resolution = resolutionQuery.data;
  const session = sessionQuery.data?.session;

  if (!resolution || !session) {
    return (
      <div className="min-h-screen bg-base p-8">
        <EmptyState
          title="No resolution data available"
          action={{ label: "Back to Assessments", href: "/assessments" }}
        />
      </div>
    );
  }

  if (!canShowResults(session.status)) {
    const wizardPath = firstWizardPath(sid, schemaQuery.data?.sections[0]?.section_key);
    return (
      <div className="min-h-screen bg-base p-8">
        <EmptyState
          title="Results not ready"
          description={`This assessment has not produced results yet (status: ${session.status}).`}
          action={{ label: "Return to Wizard", href: wizardPath ?? "/assessments" }}
        />
      </div>
    );
  }

  // Sort: triggered → uncertain → not_triggered → rest (alphabetical within each group)
  const sortedComponents = [...resolution.components].sort((a, b) => {
    const aOrder = CLASSIFICATION_ORDER[a.classification] ?? 3;
    const bOrder = CLASSIFICATION_ORDER[b.classification] ?? 3;
    if (aOrder !== bOrder) return aOrder - bOrder;
    return a.subtask_key.localeCompare(b.subtask_key);
  });

  return (
    <div className="min-h-screen bg-base p-8 font-sans">
      {/* Back navigation */}
      <Link
        className="inline-flex items-center gap-1.5 text-accent text-sm mb-6 hover:opacity-80"
        to="/assessments"
      >
        ← Assessments
      </Link>

      {/* Header */}
      <header className="mb-8">
        {/* Title rendered by PageShell — kept this header wrapper for action-row layout below */}
        <div className="flex flex-wrap gap-2">
          {["approved", "report_generated"].includes(session.status) && (
            <Link
              className={cn(buttonVariants())}
              to={`/assessments/${sid}/report`}
            >
              View Full Report
            </Link>
          )}
          {session.status === "resolved" && (
            <Button
              type="button"
              disabled={submitForReview.isPending}
              onClick={() => {
                setSubmitError(null);
                submitForReview.mutate(
                  { sessionId: sid },
                  {
                    onSuccess: () => void navigate(`/assessments/${sid}/review`),
                    onError: (err) =>
                      setSubmitError(
                        err instanceof Error ? err.message : "Failed to submit for review",
                      ),
                  },
                );
              }}
            >
              {submitForReview.isPending ? "Submitting..." : "Submit for Review"}
            </Button>
          )}
        </div>
        {submitError && <p className="text-sm text-critical mt-2">{submitError}</p>}
      </header>

      {/* Executive summary */}
      {resolution.executive_summary && (
        <section
          className="rounded-[var(--radius-md)] border border-border bg-surface p-4 mb-8"
          aria-label="Executive summary"
        >
          <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-2">
            Executive Summary
          </h2>
          <p className="text-sm text-text">{resolution.executive_summary}</p>
        </section>
      )}

      {/* Component classification grid — sorted triggered-first */}
      <section className="mb-8" aria-label="Component classifications">
        <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-4">
          Component Classifications ({sortedComponents.length})
        </h2>
        <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-4">
          {sortedComponents.map((comp) => (
            <ComponentCard key={comp.subtask_key} comp={comp} />
          ))}
        </div>
      </section>

      {/* Download section */}
      <section aria-label="Download artifacts">
        <h2 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-4">
          Downloads
        </h2>
        <div className="flex flex-wrap gap-3">
          <DownloadButton label="Download Report (PDF)" artifact="report/pdf" sessionId={sid} />
          <DownloadButton label="Download Workbook (Excel)" artifact="workbook" sessionId={sid} />
          <DownloadButton label="Download Jira Draft (JSON)" artifact="jira-draft" sessionId={sid} />
        </div>
      </section>
    </div>
  );
}
