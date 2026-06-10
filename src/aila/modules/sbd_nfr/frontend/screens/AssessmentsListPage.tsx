import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge, AilaCard, EmptyState } from "@/components/aila";
import type { AilaBadgeVariants } from "@/components/aila/AilaBadge";
import { Button } from "@/components/ui/button";
import type { SessionCreateRequest, SessionSummaryResponse } from "../types";
import {
  useCreateSession,
  useSubmitForReview,
  useWizardSchema,
  useWizardSessionList,
} from "../queries";
import { assessmentStatusDestination, canShowResults, firstWizardPath } from "../sessionFlow";

// ──────────────────────────────────────────────────────────────────────────────
// Status → AilaBadge severity mapping
// ──────────────────────────────────────────────────────────────────────────────

const STATUS_LABELS: Record<string, string> = {
  draft: "Draft",
  in_progress: "In Progress",
  completed: "Completed",
  resolving: "Resolving",
  resolved: "Resolved",
  in_review: "In Review",
  approved: "Approved",
  report_generated: "Report Ready",
  resolution_failed: "Failed",
  expired: "Expired",
};

type BadgeSeverity = AilaBadgeVariants["severity"];

function statusToSeverity(status: string): { severity: BadgeSeverity; pulse?: boolean } {
  switch (status) {
    case "draft":
    case "expired":
    case "report_generated":
      return { severity: "neutral" };
    case "in_progress":
    case "completed":
    case "resolved":
      return { severity: "info" };
    case "resolving":
      return { severity: "info", pulse: true };
    case "in_review":
      return { severity: "high" };
    case "approved":
      return { severity: "info" };
    case "resolution_failed":
      return { severity: "critical" };
    default:
      return { severity: "neutral" };
  }
}

function StatusBadge({ status }: { status: string }) {
  const label = STATUS_LABELS[status] ?? status;
  const { severity, pulse } = statusToSeverity(status);
  return (
    <AilaBadge severity={severity} size="sm" pulse={pulse}>
      {label}
    </AilaBadge>
  );
}


// ──────────────────────────────────────────────────────────────────────────────
// Relative time helper
// ──────────────────────────────────────────────────────────────────────────────

function relativeTime(isoDate: string): string {
  const diffMs = Date.now() - new Date(isoDate).getTime();
  const diffMin = Math.floor(diffMs / 60_000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;
  return new Date(isoDate).toLocaleDateString();
}

// ──────────────────────────────────────────────────────────────────────────────
// Session card skeleton
// ──────────────────────────────────────────────────────────────────────────────

function SessionCardSkeleton() {
  return (
    <AilaCard variant="default" padding="md" techBorder glow><div
      className="animate-pulse bg-surface rounded-md"
      style={{ height: 18, width: "60%", marginBottom: 10 }}
    />
    <div
      className="animate-pulse bg-surface rounded-md"
      style={{ height: 14, width: "30%", marginBottom: 14 }}
    />
    <div
      className="animate-pulse bg-surface rounded-md"
      style={{ height: 6, width: "100%", borderRadius: 3, marginBottom: 10 }}
    />
    <div
      className="animate-pulse bg-surface rounded-md"
      style={{ height: 12, width: "45%" }}
    /></AilaCard>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Session card
// ──────────────────────────────────────────────────────────────────────────────

interface SessionCardProps {
  session: SessionSummaryResponse;
  firstSectionKey: string | undefined;
  onSubmitForReview: (sessionId: string) => void;
  isSubmitting: boolean;
}

function SessionCard({
  session,
  firstSectionKey,
  onSubmitForReview,
  isSubmitting,
}: SessionCardProps) {
  const navigate = useNavigate();

  function handleCardClick() {
    const destination = assessmentStatusDestination(session.id, session.status, firstSectionKey);
    if (!destination) return;
    void navigate(destination);
  }

  const canSubmitForReview = session.status === "resolved";
  const canReview = session.status === "in_review";
  const hasResults = canShowResults(session.status);
  const hasReport = session.status === "report_generated" || session.status === "approved";
  const destinationLabel =
    session.status === "in_review"
      ? "Review ready"
      : session.status === "approved" || session.status === "report_generated"
        ? "Report ready"
        : session.status === "resolved"
          ? "Results ready"
          : "Continue wizard";

  return (
    <AilaCard variant="interactive" padding="none" techBorder glow><button
      className="block w-full text-left"
      onClick={handleCardClick}
      disabled={!firstWizardPath(session.id, firstSectionKey) && !hasResults}
      type="button"
      aria-label={`Open ${session.project_name}`}
    >
      <div className="flex items-start justify-between gap-3 p-4">
        <div className="flex flex-col gap-1">
          <span className="font-sans text-sm font-semibold text-text">{session.project_name}</span>
          {session.description ? (
            <p className="text-xs text-text-muted">{session.description}</p>
          ) : null}
        </div>
        <StatusBadge status={session.status} />
      </div>
      <div className="flex flex-wrap items-center gap-2 px-4 pb-2 text-xs text-text-muted">
        <span>{session.requestor_name}</span>
        {session.business_unit ? (
          <>
            <span aria-hidden>·</span>
            <span>{session.business_unit}</span>
          </>
        ) : null}
        {session.assigned_architect_id && (
          <>
            <span aria-hidden>·</span>
            <span>Architect: {session.assigned_architect_id}</span>
          </>
        )}
        <span aria-hidden>·</span>
        <span>{relativeTime(session.updated_at)}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
        <AilaBadge severity={hasReport ? "info" : hasResults ? "medium" : "neutral"} size="sm">
          {destinationLabel}
        </AilaBadge>
        {session.tags.length > 0 ? (
          <div className="flex gap-1">
            {session.tags.slice(0, 4).map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center px-2 py-0.5 rounded-sm bg-elevated text-text-muted text-xs"
              >
                {tag}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </button>
    
    {/* Quick action buttons */}
    <div className="flex flex-wrap gap-2 px-4 pb-3 border-t border-border pt-3">
      {hasResults && (
        <Button
          variant="outline"
          size="xs"
          type="button"
          onClick={() => {
            const destination = assessmentStatusDestination(session.id, session.status, firstSectionKey);
            if (destination) {
              void navigate(destination);
            }
          }}
        >
          View Results
        </Button>
      )}
      {canReview && (
        <Button
          size="xs"
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            void navigate(`/assessments/${encodeURIComponent(session.id)}/review`);
          }}
        >
          Architect Review
        </Button>
      )}
      {hasReport && (
        <Button
          variant="outline"
          size="xs"
          type="button"
          onClick={() => void navigate(`/assessments/${encodeURIComponent(session.id)}/report`)}
        >
          Report
        </Button>
      )}
      {canSubmitForReview && (
        <Button
          size="xs"
          type="button"
          disabled={isSubmitting}
          onClick={(e) => {
            e.stopPropagation();
            onSubmitForReview(session.id);
          }}
        >
          Submit for Review
        </Button>
      )}
      <Button
        variant="outline"
        size="xs"
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          void navigate(`/assessments/compare?a=${encodeURIComponent(session.id)}`);
        }}
      >
        Compare
      </Button>
    </div></AilaCard>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Create session modal
// ──────────────────────────────────────────────────────────────────────────────

interface CreateModalProps {
  onClose: () => void;
  firstSectionKey: string | undefined;
}

function CreateSessionModal({ onClose, firstSectionKey }: CreateModalProps) {
  const navigate = useNavigate();
  const createMutation = useCreateSession();

  const [form, setForm] = useState<SessionCreateRequest>({
    project_name: "",
    description: null,
    business_unit: null,
    requestor_name: "",
    requestor_email: "",
    target_date: null,
    tags: [],
  });
  const [error, setError] = useState<string | null>(null);

  function set(field: keyof SessionCreateRequest, value: string | null) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!form.project_name.trim()) {
      setError("Project name is required.");
      return;
    }
    if (!form.requestor_name.trim()) {
      setError("Requestor name is required.");
      return;
    }
    if (!form.requestor_email.trim()) {
      setError("Requestor email is required.");
      return;
    }

    try {
      const created = await createMutation.mutateAsync(form);
      onClose();
      if (firstSectionKey) {
        void navigate(
          `/assessments/${encodeURIComponent(created.id)}/wizard/${encodeURIComponent(firstSectionKey)}`,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create assessment.");
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal
      aria-label="New Assessment"
    >
      <div className="w-full max-w-md overflow-y-auto rounded-lg border border-border bg-surface" style={{ maxHeight: "90vh" }}>
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="font-display text-lg text-text">New Assessment</h2>
          <button
            className="text-text-muted hover:text-text text-xl leading-none"
            onClick={onClose}
            type="button"
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <form
          className="flex flex-col gap-3 p-5"
          onSubmit={(e) => {
            void handleSubmit(e);
          }}
        >
          <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
            Project name <span className="text-critical">*</span>
            <input
              className="w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
              type="text"
              value={form.project_name}
              onChange={(e) => set("project_name", e.target.value)}
              maxLength={200}
              required
            />
          </label>
          <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
            Description
            <textarea
              className="w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
              value={form.description ?? ""}
              onChange={(e) => set("description", e.target.value || null)}
              maxLength={1000}
              rows={2}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
            Requestor name <span className="text-critical">*</span>
            <input
              className="w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
              type="text"
              value={form.requestor_name}
              onChange={(e) => set("requestor_name", e.target.value)}
              maxLength={200}
              required
            />
          </label>
          <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
            Requestor email <span className="text-critical">*</span>
            <input
              className="w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
              type="email"
              value={form.requestor_email}
              onChange={(e) => set("requestor_email", e.target.value)}
              maxLength={200}
              required
            />
          </label>
          <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
            Business unit
            <input
              className="w-full p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
              type="text"
              value={form.business_unit ?? ""}
              onChange={(e) => set("business_unit", e.target.value || null)}
              maxLength={200}
            />
          </label>
          {error && <p className="text-sm text-critical">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create Assessment"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Status options for filter dropdown
// ──────────────────────────────────────────────────────────────────────────────

const ALL_STATUSES = [
  "draft",
  "in_progress",
  "completed",
  "resolving",
  "resolved",
  "in_review",
  "approved",
  "report_generated",
  "resolution_failed",
  "expired",
];

// ──────────────────────────────────────────────────────────────────────────────
// Main page
// ──────────────────────────────────────────────────────────────────────────────

export function AssessmentsListPage() {
  const sessionListQuery = useWizardSessionList();
  const schemaQuery = useWizardSchema();
  const submitForReview = useSubmitForReview();

  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [showCreateModal, setShowCreateModal] = useState(false);

  const firstSectionKey = useMemo(() => {
    const sections = schemaQuery.data?.sections;
    if (!sections || sections.length === 0) return undefined;
    return [...sections].sort((a, b) => a.display_order - b.display_order)[0].section_key;
  }, [schemaQuery.data]);

  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, []);

  const sessions = useMemo(() => {
    let all = sessionListQuery.data ?? [];
    if (statusFilter !== "all") {
      all = all.filter((s) => s.status === statusFilter);
    }
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      all = all.filter((s) => s.project_name.toLowerCase().includes(q));
    }
    return all;
  }, [sessionListQuery.data, statusFilter, searchQuery]);

  const totalSessions = sessionListQuery.data?.length ?? 0;
  const activeCount = (sessionListQuery.data ?? []).filter((session) => ["draft", "in_progress", "completed", "resolving"].includes(session.status)).length;
  const reviewCount = (sessionListQuery.data ?? []).filter((session) => ["resolved", "in_review", "approved"].includes(session.status)).length;
  const schemaVersion = schemaQuery.data?.schema_version;

  function handleSubmitForReview(sessionId: string) {
    submitForReview.mutate({ sessionId });
  }

  return (
    <div className="flex flex-col gap-4 p-4">
      <AilaCard variant="elevated"
      padding="lg"
      className="flex flex-col md:flex-row md:items-center md:justify-between gap-4" techBorder glow><div className="flex flex-col gap-2 flex-1">
        <p className="font-mono text-xs uppercase tracking-wider text-text-muted">Secure by Design</p>
        <p className="text-sm text-text-muted">
          Run NFR assessments, review classification outcomes, and move sessions toward architect approval without losing the thread of recent work.
        </p>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          type="button"
          onClick={() => void window.location.assign("/assessments/templates")}
        >
          Templates
        </Button>
        <Button type="button" onClick={() => setShowCreateModal(true)}>
          New Assessment
        </Button>
      </div></AilaCard>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs text-text-muted uppercase tracking-wider">Schema</p>
        <strong className="font-mono text-xl font-bold text-text">v{schemaVersion ?? "—"}</strong></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs text-text-muted uppercase tracking-wider">Sessions</p>
        <strong className="font-mono text-xl font-bold text-text">{totalSessions}</strong></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs text-text-muted uppercase tracking-wider">Active Work</p>
        <strong className="font-mono text-xl font-bold text-text">{activeCount}</strong></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs text-text-muted uppercase tracking-wider">Review Queue</p>
        <strong className="font-mono text-xl font-bold text-text">{reviewCount}</strong></AilaCard>
      </div>

      <AilaCard variant="default" padding="md" techBorder glow><div className="flex flex-wrap items-end gap-3">
        <input
          className="touch-target flex-1 p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
          style={{ minWidth: "12rem" }}
          type="search"
          placeholder="Search assessments..."
          aria-label="Search assessments"
          value={searchQuery}
          onChange={handleSearchChange}
        />
        <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
          Status
          <select
            className="touch-target p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All statuses</option>
            {ALL_STATUSES.map((s) => (
              <option key={s} value={s}>{STATUS_LABELS[s] ?? s}</option>
            ))}
          </select>
        </label>
      </div></AilaCard>

      <div className="flex flex-wrap items-end gap-3">
        <input
          className="touch-target flex-1 p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
          style={{ minWidth: "12rem" }}
          type="search"
          placeholder="Search assessments..."
          aria-label="Search assessments"
          value={searchQuery}
          onChange={handleSearchChange}
        />
        <label className="flex flex-col gap-1 text-xs font-medium text-text-muted">
          Status
          <select
            className="touch-target p-2.5 rounded-md border border-border bg-surface text-text font-sans text-sm"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All statuses</option>
            {ALL_STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABELS[s] ?? s}
              </option>
            ))}
          </select>
        </label>
      </div>

      {sessionListQuery.isLoading && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <SessionCardSkeleton />
          <SessionCardSkeleton />
          <SessionCardSkeleton />
        </div>
      )}

      {sessionListQuery.isError && (
        <AilaCard variant="default" padding="md" techBorder glow><p className="text-sm text-critical">Failed to load assessments. Please try again.</p></AilaCard>
      )}

      {!sessionListQuery.isLoading && !sessionListQuery.isError && sessions.length === 0 && (
        <EmptyState
          title={statusFilter !== "all" || searchQuery ? "No assessments match this filter" : "No assessments yet"}
          description={statusFilter !== "all" || searchQuery ? "Try a different filter or search term." : "Create your first assessment to start the workflow."}
          action={statusFilter === "all" && !searchQuery ? { label: "New Assessment", onClick: () => setShowCreateModal(true) } : undefined}
        />
      )}

      {!sessionListQuery.isLoading && sessions.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {sessions.map((session) => (
            <SessionCard
              key={session.id}
              session={session}
              firstSectionKey={firstSectionKey}
              onSubmitForReview={handleSubmitForReview}
              isSubmitting={submitForReview.isPending}
            />
          ))}
        </div>
      )}

      {showCreateModal && (
        <CreateSessionModal
          onClose={() => setShowCreateModal(false)}
          firstSectionKey={firstSectionKey}
        />
      )}
    </div>
  );
}
