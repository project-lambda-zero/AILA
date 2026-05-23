import React from "react";
import { Link, useNavigate } from "react-router";

import { Button, buttonVariants } from "@/components/ui/button";
import { useCloneSession, useSaveAsTemplate, useTemplateList } from "../queries";
import type { SessionSummaryResponse } from "../types";

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
// Save-as-template dialog
// ──────────────────────────────────────────────────────────────────────────────

interface SaveAsTemplateDialogProps {
  sessionId: string;
  onClose: () => void;
}

function SaveAsTemplateDialog({ sessionId, onClose }: SaveAsTemplateDialogProps) {
  const [name, setName] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const saveAsTemplate = useSaveAsTemplate();

  function handleSave() {
    if (!name.trim()) {
      setError("Template name is required.");
      return;
    }
    setError(null);
    saveAsTemplate.mutate(
      { sessionId, templateName: name.trim() },
      {
        onSuccess: onClose,
        onError: (err) =>
          setError(err instanceof Error ? err.message : "Failed to save template."),
      },
    );
  }

  return (
    <div className="template-dialog-backdrop" role="dialog" aria-modal aria-label="Save as Template">
      <div className="template-dialog">
        <h2 className="template-dialog__title">Save as Template</h2>
        <label className="template-dialog__label" htmlFor="template-name-input">
          Template name
        </label>
        <input
          id="template-name-input"
          type="text"
          className="w-full p-2.5 rounded-[var(--radius-md)] border border-border bg-surface text-text font-sans text-sm template-dialog__input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Standard Security Assessment"
          autoFocus
        />
        {error && <p className="text-sm text-critical">{error}</p>}
        <div className="template-dialog__actions">
          <Button
            type="button"
            variant="outline"
            onClick={onClose}
            disabled={saveAsTemplate.isPending}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={handleSave}
            disabled={saveAsTemplate.isPending}
          >
            {saveAsTemplate.isPending ? "Saving..." : "Save Template"}
          </Button>
        </div>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Template card
// ──────────────────────────────────────────────────────────────────────────────

interface TemplateCardProps {
  template: SessionSummaryResponse;
}

function TemplateCard({ template }: TemplateCardProps) {
  const navigate = useNavigate();
  const cloneSession = useCloneSession();
  const [cloneError, setCloneError] = React.useState<string | null>(null);

  function handleUse() {
    setCloneError(null);
    cloneSession.mutate(template.id, {
      onSuccess: (session) => void navigate(`/assessments/${session.id}/wizard/scope`),
      onError: (err) =>
        setCloneError(err instanceof Error ? err.message : "Failed to clone template."),
    });
  }

  return (
    <div className="template-card">
      <div className="template-card__header">
        <h2 className="template-card__name">{template.template_name ?? template.project_name}</h2>
        <span className="template-card__project">{template.project_name}</span>
      </div>

      <div className="template-card__meta">
        <span className="template-card__meta-item">{template.requestor_name}</span>
        {template.business_unit && (
          <span className="template-card__meta-item">{template.business_unit}</span>
        )}
        <span className="template-card__meta-item">Created {formatDate(template.created_at)}</span>
      </div>

      {template.tags.length > 0 && (
        <div className="template-card__tags">
          {template.tags.map((tag) => (
            <span key={tag} className="template-card__tag">{tag}</span>
          ))}
        </div>
      )}

      {cloneError && <p className="text-sm text-critical">{cloneError}</p>}

      <div className="template-card__actions">
        <Button
          type="button"
          size="sm"
          disabled={cloneSession.isPending}
          onClick={handleUse}
        >
          {cloneSession.isPending ? "Loading..." : "Use Template"}
        </Button>
        <Link
          className={buttonVariants({ variant: "outline", size: "sm" })}
          to={`/assessments/${template.id}/results`}
        >
          View Source
        </Link>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// TemplateManagementPage
// ──────────────────────────────────────────────────────────────────────────────

export function TemplateManagementPage() {
  const templateQuery = useTemplateList();
  const [showDialog, setShowDialog] = React.useState(false);
  // For demo: dialog needs a sessionId — in practice opened from a specific session.
  // Here we show the dialog only from AssessmentsListPage; this page just manages existing templates.

  const templates = templateQuery.data ?? [];

  return (
    <div className="template-page">
      {/* Header */}
      <div className="template-page__header">
        <div className="template-page__header-actions">
          <Link className={buttonVariants({ variant: "outline" })} to="/assessments">
            All Assessments
          </Link>
        </div>
      </div>

      {/* Loading */}
      {templateQuery.isLoading && (
        <div className="template-page__loading">
          {[1, 2, 3].map((i) => (
            <div key={i} className="animate-pulse bg-surface rounded-[var(--radius-md)]" style={{ height: 120, marginBottom: 12, borderRadius: 4 }} />
          ))}
        </div>
      )}

      {/* Error */}
      {templateQuery.isError && (
        <p className="text-sm text-critical">Failed to load templates.</p>
      )}

      {/* Empty state */}
      {!templateQuery.isLoading && templates.length === 0 && (
        <div className="template-page__empty">
          <p className="template-page__empty-text">No templates yet.</p>
          <p className="template-page__empty-hint">
            Save a resolved assessment as a template from the{" "}
            <Link to="/assessments" className="template-page__link">
              Assessments list
            </Link>
            .
          </p>
        </div>
      )}

      {/* Template grid */}
      {templates.length > 0 && (
        <div className="template-grid">
          {templates.map((t) => (
            <TemplateCard key={t.id} template={t} />
          ))}
        </div>
      )}

      {/* Save-as-template dialog (triggered externally via state) */}
      {showDialog && (
        <SaveAsTemplateDialog
          sessionId=""
          onClose={() => setShowDialog(false)}
        />
      )}
    </div>
  );
}
