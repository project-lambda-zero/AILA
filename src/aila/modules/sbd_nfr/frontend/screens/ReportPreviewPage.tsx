import React from "react";
import { useParams } from "react-router";
import { Link } from "react-router";

import { AilaBadge } from "@/components/aila";
import { Button, buttonVariants } from "@/components/ui/button";
import { downloadArtifact, useReportHash, useSessionActivity, useWizardResolution, useWizardSessionDetail } from "../queries";
import type { ActivityResponse } from "../types";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

// ──────────────────────────────────────────────────────────────────────────────
// Confidence tier helpers
// ──────────────────────────────────────────────────────────────────────────────

function confidenceTier(confidence: number): { label: string; severity: "info" | "high" | "critical" } {
  if (confidence >= 0.85) return { label: "Certain", severity: "info" };
  if (confidence >= 0.5) return { label: "Uncertain", severity: "high" };
  return { label: "Gray Area", severity: "critical" };
}

function classificationLabel(classification: string): string {
  if (classification === "triggered") return "Triggered";
  if (classification === "uncertain") return "Uncertain";
  if (classification === "not_triggered") return "Not Applicable";
  return classification;
}

function classificationColor(classification: string): string {
  if (classification === "triggered") return "#97dbbe";
  if (classification === "uncertain") return "#fbbf24";
  return "#5e6e80";
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Activity timeline
// ──────────────────────────────────────────────────────────────────────────────

const EVENT_LABELS: Record<string, string> = {
  session_created: "Session created",
  session_completed: "Assessment completed",
  session_submitted_for_review: "Submitted for architect review",
  session_approved: "Approved by architect",
  architect_notes_saved: "Architect notes updated",
  status_changed: "Status changed",
};

function ActivityTimeline({ events }: { events: ActivityResponse[] }) {
  const filtered = events.filter((e) =>
    ["session_created", "session_completed", "session_submitted_for_review", "session_approved"].includes(e.event_type),
  );

  if (filtered.length === 0) return null;

  return (
    <div className="report-preview__timeline">
      <h3 className="report-preview__section-title">Version History</h3>
      <ul className="report-timeline">
        {filtered.map((event) => (
          <li key={`${event.id}-${event.created_at}`} className="report-timeline__item">
            <span className="report-timeline__dot" aria-hidden />
            <div className="report-timeline__content">
              <span className="report-timeline__label">
                {EVENT_LABELS[event.event_type] ?? event.event_type}
              </span>
              {event.actor_name && (
                <span className="report-timeline__actor"> by {event.actor_name}</span>
              )}
              <span className="report-timeline__time">{formatDate(event.created_at)}</span>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Component card with confidence indicator
// ──────────────────────────────────────────────────────────────────────────────

interface ComponentCardProps {
  subtaskLabel: string;
  classification: string;
  confidence: number;
  reasoning: string;
}

function ComponentCard({ subtaskLabel, classification, confidence, reasoning }: ComponentCardProps) {
  const tier = confidenceTier(confidence);
  const pct = Math.round(confidence * 100);
  const [expanded, setExpanded] = React.useState(false);

  return (
    <div className="report-component-card">
      <div className="report-component-card__header">
        <button
          type="button"
          className="report-component-card__label-btn"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
        >
          <span className="report-component-card__label">{subtaskLabel}</span>
        </button>
        <div className="report-component-card__badges">
          <AilaBadge severity={tier.severity} size="sm">{tier.label}</AilaBadge>
          <span
            className="report-component-card__classification"
            style={{ color: classificationColor(classification) }}
          >
            {classificationLabel(classification)}
          </span>
        </div>
      </div>

      {/* Confidence bar */}
      <div className="report-confidence-bar" aria-label={`Confidence: ${pct}%`}>
        <div
          className="report-confidence-bar__fill"
          style={{ width: `${pct}%` }}
        />
        <span className="report-confidence-bar__pct">{pct}%</span>
      </div>

      {expanded && (
        <p className="report-component-card__reasoning">{reasoning}</p>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// ReportPreviewPage
// ──────────────────────────────────────────────────────────────────────────────

export function ReportPreviewPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const sessionQuery = useWizardSessionDetail(sessionId ?? "");
  const resolutionQuery = useWizardResolution(sessionId ?? "");
  const activityQuery = useSessionActivity(sessionId ?? "");

  const hashQuery = useReportHash(sessionId ?? "");
  const [downloading, setDownloading] = React.useState(false);

  useUpdatePageHeader({
    title: sessionQuery.data?.session?.project_name,
    subtitle: sessionQuery.data?.session
      ? `${sessionQuery.data.session.requestor_name}${sessionQuery.data.session.business_unit ? ` · ${sessionQuery.data.session.business_unit}` : ''}`
      : undefined,
    status: null,
  });

  if (sessionQuery.isLoading || resolutionQuery.isLoading) {
    return (
      <div className="report-preview">
        <div className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 32, width: "40%", marginBottom: 16 }} />
        <div className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 16, width: "25%", marginBottom: 32 }} />
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 72, marginBottom: 8, borderRadius: 4 }} />
        ))}
      </div>
    );
  }

  if (sessionQuery.isError || !sessionQuery.data) {
    return (
      <div className="report-preview report-preview--error">
        <p className="text-sm text-critical">Failed to load report. The session may not exist.</p>
        <Link className={buttonVariants({ variant: "outline", size: "sm" })} to="/assessments">
          Back to Assessments
        </Link>
      </div>
    );
  }

  const { session } = sessionQuery.data;
  const resolution = resolutionQuery.data;
  const activities = activityQuery.data ?? [];

  if (!resolution || resolution.status !== "resolved") {
    return (
      <div className="report-preview report-preview--error">
        <p className="text-sm text-critical">
          This report is not available until the assessment has been resolved.
        </p>
        <Link className={buttonVariants({ variant: "outline", size: "sm" })} to="/assessments">
          Back to Assessments
        </Link>
      </div>
    );
  }

  async function handleDownload() {
    setDownloading(true);
    try {
      await downloadArtifact(session.id, "report/pdf");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="report-preview">
      {/* Header */}
      <div className="report-preview__header">
        <div className="report-preview__header-actions">
          <Link className={buttonVariants({ variant: "outline", size: "sm" })} to={`/assessments/${session.id}/review`}>
            Architect Review
          </Link>
          <Button
            type="button"
            disabled={downloading}
            onClick={() => void handleDownload()}
          >
            {downloading ? "Downloading..." : "Download PDF"}
          </Button>
        </div>
      </div>

      {/* Executive summary */}
      {resolution?.executive_summary && (
        <div className="report-preview__summary">
          <h2 className="report-preview__section-title">Executive Summary</h2>
          <p className="report-preview__summary-text">{resolution.executive_summary}</p>
        </div>
      )}

      {/* Component confidence grid */}
      <div className="report-preview__components">
        <h2 className="report-preview__section-title">
          Component Analysis ({resolution?.components.length ?? 0})
        </h2>
        {!resolution || resolution.components.length === 0 ? (
          <p className="report-preview__empty">
            Resolution data is not yet available. Run resolution first.
          </p>
        ) : (
          <div className="report-component-grid">
            {resolution.components.map((comp) => (
              <ComponentCard
                key={comp.subtask_key}
                subtaskLabel={comp.subtask_label}
                classification={comp.classification}
                confidence={comp.confidence}
                reasoning={comp.reasoning}
              />
            ))}
          </div>
        )}
      </div>

      {/* Report Integrity Hash (EXEC-04) */}
      <div className="report-preview__integrity">
        <h2 className="report-preview__section-title">Report Integrity</h2>
        {hashQuery.isLoading ? (
          <div className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 40, width: "80%" }} />
        ) : hashQuery.data?.status === "available" ? (
          <div className="report-hash-block">
            <p className="report-hash-block__label">SHA-256 Digest</p>
            <code className="report-hash-block__value">{hashQuery.data.sha256}</code>
            <p className="report-hash-block__note">
              Hash computed at {formatDate(hashQuery.data.computed_at)}.
              Re-downloading the PDF will not change this hash — it certifies the first generated artifact.
            </p>
          </div>
        ) : hashQuery.data?.status === "not_generated" ? (
          <p className="report-preview__empty">
            No hash available. Download the PDF report once to generate an integrity hash.
          </p>
        ) : null}
      </div>

      {/* Version history */}
      <ActivityTimeline events={activities} />
    </div>
  );
}
