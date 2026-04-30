import { useCallback, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  useApproveSession,
  useSaveArchitectNotes,
  useSubmitForReview,
  useWizardResolution,
  useWizardSessionDetail,
} from "../queries";
import { WizardSubtaskPanel } from "../wizard/WizardSubtaskPanel";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

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
// Status badge helper
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
};

function statusSeverity(
  status: string,
): "neutral" | "info" | "high" | "critical" {
  if (status === "in_review") return "high";
  if (status === "approved" || status === "report_generated") return "info";
  if (status === "resolution_failed") return "critical";
  if (["in_progress", "resolved", "completed"].includes(status)) return "info";
  return "neutral";
}

// ──────────────────────────────────────────────────────────────────────────────
// Loading skeleton
// ──────────────────────────────────────────────────────────────────────────────

function ReviewSkeleton() {
  return (
    <div className="architect-review">
      <div className="architect-review__header">
        <div className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 28, width: "40%", marginBottom: 10 }} />
        <div className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 16, width: "25%" }} />
      </div>
      <div className="architect-review__body">
        <div className="architect-review__answers">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 48, marginBottom: 8, borderRadius: 4 }} />
          ))}
        </div>
        <div className="architect-review__panel">
          <div className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 200, borderRadius: 4 }} />
        </div>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Answer row
// ──────────────────────────────────────────────────────────────────────────────

interface AnswerRowProps {
  questionId: string;
  answerValue: string;
  noteText: string | null;
  answeredByName: string;
}

function AnswerRow({ questionId, answerValue, noteText, answeredByName }: AnswerRowProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="architect-answer-row">
      <div className="architect-answer-row__main">
        <span className="architect-answer-row__id">{questionId}</span>
        <span className="architect-answer-row__value">{answerValue}</span>
        <span className="architect-answer-row__by">{answeredByName}</span>
        {noteText && (
          <button
            type="button"
            className="architect-answer-row__note-toggle"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
          >
            {expanded ? "Hide note" : "Note"}
          </button>
        )}
      </div>
      {expanded && noteText && (
        <div className="architect-answer-row__note">{noteText}</div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Architect notes textarea (auto-save on blur)
// ──────────────────────────────────────────────────────────────────────────────

interface ArchitectNotesProps {
  sessionId: string;
  initialNotes: string | null;
}

function ArchitectNotesField({ sessionId, initialNotes }: ArchitectNotesProps) {
  const [notes, setNotes] = useState(initialNotes ?? "");
  const [saved, setSaved] = useState(false);
  const saveNotes = useSaveArchitectNotes();

  const handleBlur = useCallback(() => {
    if (notes === (initialNotes ?? "")) return;
    saveNotes.mutate(
      { sessionId, notes },
      {
        onSuccess: () => {
          setSaved(true);
          setTimeout(() => setSaved(false), 2000);
        },
      },
    );
  }, [notes, initialNotes, sessionId, saveNotes]);

  return (
    <div className="architect-notes">
      <label className="architect-notes__label" htmlFor="architect-notes-input">
        Architect Notes
        {saved && <span className="architect-notes__saved">Saved</span>}
        {saveNotes.isPending && <span className="architect-notes__saving">Saving...</span>}
      </label>
      <textarea
        id="architect-notes-input"
        className="w-full p-2.5 rounded-[var(--radius-md)] border border-border bg-surface text-text text-sm resize-y"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        onBlur={handleBlur}
        rows={5}
        placeholder="Add review notes, observations, or approval rationale..."
      />
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// ArchitectReviewPage
// ──────────────────────────────────────────────────────────────────────────────

export function ArchitectReviewPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();

  const sessionQuery = useWizardSessionDetail(sessionId ?? "");
  const resolutionQuery = useWizardResolution(sessionId ?? "");

  const submitForReview = useSubmitForReview();
  const approveSession = useApproveSession();

  const [actionError, setActionError] = useState<string | null>(null);

  if (sessionQuery.isLoading) return <ReviewSkeleton />;

  if (sessionQuery.isError || !sessionQuery.data) {
    return (
      <div className="architect-review architect-review--error">
        <p className="text-sm text-critical">Failed to load session. It may not exist.</p>
        <Link className={buttonVariants({ variant: "outline", size: "sm" })} to="/assessments">
          Back to Assessments
        </Link>
      </div>
    );
  }

  const { session, answers } = sessionQuery.data;
  const status = session.status;

  function handleSubmitForReview() {
    setActionError(null);
    submitForReview.mutate(
      { sessionId: session.id },
      {
        onSuccess: () => void navigate(`/assessments/${session.id}/review`),
        onError: (err) =>
          setActionError(err instanceof Error ? err.message : "Failed to submit for review"),
      },
    );
  }

  function handleApprove() {
    setActionError(null);
    approveSession.mutate(
      { sessionId: session.id },
      {
        onSuccess: () => void navigate(`/assessments/${session.id}/report`),
        onError: (err) =>
          setActionError(err instanceof Error ? err.message : "Failed to approve session"),
      },
    );
  }

  const canSubmit = status === "resolved";
  const canApprove = status === "in_review";
  const isResolved = ["resolved", "in_review", "approved", "report_generated"].includes(status);

  return (
    <div className="architect-review">
      {/* Header */}
      <div className="architect-review__header">
        <div className="architect-review__title-row">
          <div>
            <h1 className="architect-review__title">{session.project_name}</h1>
            <p className="architect-review__meta">
              {session.requestor_name}
              {session.business_unit ? ` · ${session.business_unit}` : ""}
              {" · "}
              {formatDate(session.updated_at)}
            </p>
          </div>
          <div className="architect-review__header-badges">
            <AilaBadge severity={statusSeverity(status)}>
              {STATUS_LABELS[status] ?? status}
            </AilaBadge>
          </div>
        </div>

        <div className="architect-review__actions">
          <Link className={buttonVariants({ variant: "outline", size: "sm" })} to="/assessments">
            All Assessments
          </Link>
          {isResolved && (
            <Link
              className={buttonVariants({ variant: "outline", size: "sm" })}
              to={`/assessments/${session.id}/results`}
            >
              View Results
            </Link>
          )}
          {canSubmit && (
            <Button
              type="button"
              disabled={submitForReview.isPending}
              onClick={handleSubmitForReview}
            >
              {submitForReview.isPending ? "Submitting..." : "Submit for Review"}
            </Button>
          )}
          {canApprove && (
            <Button
              type="button"
              disabled={approveSession.isPending}
              onClick={handleApprove}
            >
              {approveSession.isPending ? "Approving..." : "Approve Assessment"}
            </Button>
          )}
        </div>

        {actionError && <p className="text-sm text-critical">{actionError}</p>}
      </div>

      {/* Two-panel body */}
      <div className="architect-review__body">
        {/* Left: answers + notes */}
        <div className="architect-review__answers">
          <h2 className="architect-review__section-title">Answers ({answers.length})</h2>

          {answers.length === 0 && (
            <p className="architect-review__empty">No answers recorded for this session.</p>
          )}

          <div className="architect-answer-list">
            {answers.map((a) => (
              <AnswerRow
                key={a.question_id}
                questionId={a.question_id}
                answerValue={a.answer_value}
                noteText={a.note_text}
                answeredByName={a.answered_by_name}
              />
            ))}
          </div>

          <div className="architect-review__notes-section">
            <ArchitectNotesField
              sessionId={session.id}
              initialNotes={session.architect_notes ?? null}
            />
          </div>
        </div>

        {/* Right: sub-task panel */}
        <div className="architect-review__panel">
          <h2 className="architect-review__section-title">Sub-task Components</h2>
          {resolutionQuery.isLoading && (
            <p className="architect-review__loading">Loading resolution data...</p>
          )}
          {isResolved && (
            <WizardSubtaskPanel sessionId={session.id} sessionStatus={status} />
          )}
          {!isResolved && (
            <p className="architect-review__empty">
              Resolution data is not yet available for this session.
            </p>
          )}
          {canApprove && (
            <div className="architect-review__approve-block">
              <Button
                className="w-full"
                type="button"
                disabled={approveSession.isPending}
                onClick={handleApprove}
              >
                {approveSession.isPending ? "Approving..." : "Approve Assessment"}
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
