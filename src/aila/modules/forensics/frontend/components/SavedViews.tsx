/**
 * SavedViews -- compact saved-view control used by forensics list surfaces.
 *
 * Renders as a single toolbar strip:
 *   [pinned view chips ...]  [Views ▾]  [Save…]
 *
 * The chips row surfaces every pinned view (owner or team-shared) for
 * one-click apply; the "Views" popover exposes the full library with
 * pin/share/delete controls (owner-only for share/delete) and a
 * "Save current…" inline form. Palette and chrome mirror the rest of
 * the forensics surfaces (bg-surface / border-border / text-foreground)
 * so the strip drops in beside existing search/sort inputs without a
 * visual seam. prefers-reduced-motion is honored via the `motion-safe:`
 * transition prefix.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { BookmarkSimple } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { PushPin } from "@phosphor-icons/react/dist/csr/PushPin";
import { Share } from "@phosphor-icons/react/dist/csr/Share";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { X } from "@phosphor-icons/react/dist/csr/X";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { UsersThree } from "@phosphor-icons/react/dist/csr/UsersThree";

import { useSavedViews, type SavedView } from "../useSavedViews";

interface SavedViewsProps<TState> {
  /** Backend entity_type discriminator (e.g. "forensics_project"). */
  entityType: string;
  /** Current surface filter/search/sort state -- serialized on save. */
  currentState: TState;
  /** Applied when the operator picks a view (parsed filter_json). */
  onApply: (state: TState) => void;
  /**
   * Optional test-id prefix -- lets each surface distinguish its
   * strip (e.g. "forensics-projects-views" vs. "forensics-inv-views")
   * in Playwright without a wrapping data-testid attribute.
   */
  testIdPrefix: string;
}

export function SavedViews<TState>({
  entityType,
  currentState,
  onApply,
  testIdPrefix,
}: SavedViewsProps<TState>) {
  const {
    views,
    isLoading,
    saveCurrent,
    pin,
    share,
    remove,
    isOwner,
    parseState,
  } = useSavedViews<TState>(entityType);

  const [popoverOpen, setPopoverOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);

  const pinned = useMemo(() => views.filter((v) => v.is_pinned), [views]);

  function handleApply(view: SavedView) {
    const parsed = parseState(view);
    if (parsed === null) return;
    onApply(parsed);
    setPopoverOpen(false);
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {pinned.map((view) => (
        <PinnedChip
          key={view.id}
          view={view}
          canUnpin={isOwner(view)}
          onApply={() => handleApply(view)}
          onUnpin={() => { void pin(view.id, false); }}
          testId={`${testIdPrefix}-chip-${view.id}`}
        />
      ))}

      <button
        type="button"
        onClick={() => setPopoverOpen(true)}
        aria-haspopup="dialog"
        aria-expanded={popoverOpen}
        aria-label="Open saved views"
        data-testid={`${testIdPrefix}-open`}
        className="flex items-center gap-1 px-2 py-1 text-xs rounded-md border border-border bg-surface text-text-muted hover:text-foreground hover:border-accent focus:outline-none focus:border-accent motion-safe:transition-colors"
      >
        <BookmarkSimple size={13} />
        Views
        {views.length > 0 && (
          <span className="text-[10px] tabular-nums text-text-muted">({views.length})</span>
        )}
        <CaretDown size={11} />
      </button>

      <button
        type="button"
        onClick={() => setSaveOpen(true)}
        aria-label="Save current view"
        data-testid={`${testIdPrefix}-save`}
        className="flex items-center gap-1 px-2 py-1 text-xs rounded-md border border-border bg-surface text-text-muted hover:text-foreground hover:border-accent focus:outline-none focus:border-accent motion-safe:transition-colors"
      >
        <BookmarkSimple size={13} />
        Save…
      </button>

      {popoverOpen && (
        <SavedViewsDialog
          views={views}
          isLoading={isLoading}
          isOwner={isOwner}
          onClose={() => setPopoverOpen(false)}
          onApply={handleApply}
          onPin={(id, next) => { void pin(id, next); }}
          onShare={(id, next) => { void share(id, next); }}
          onRemove={(id) => { void remove(id); }}
          testIdPrefix={testIdPrefix}
        />
      )}

      {saveOpen && (
        <SaveViewDialog
          onClose={() => setSaveOpen(false)}
          onSubmit={async (name, opts) => {
            await saveCurrent(name, currentState, opts);
            setSaveOpen(false);
          }}
          testIdPrefix={testIdPrefix}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pinned chip
// ---------------------------------------------------------------------------

interface PinnedChipProps {
  view: SavedView;
  canUnpin: boolean;
  onApply: () => void;
  onUnpin: () => void;
  testId: string;
}

function PinnedChip({ view, canUnpin, onApply, onUnpin, testId }: PinnedChipProps) {
  const sharedLabel = view.shared_with_team ? " (team)" : "";
  return (
    <span
      className="group flex items-center gap-1 pl-2 pr-1 py-0.5 text-xs rounded-md border border-border bg-elevated hover:border-accent motion-safe:transition-colors"
      data-testid={testId}
    >
      <button
        type="button"
        onClick={onApply}
        className="text-foreground hover:text-accent focus:outline-none focus-visible:text-accent"
        title={`Apply saved view "${view.name}"${sharedLabel}`}
      >
        {view.shared_with_team && (
          <UsersThree size={11} className="inline mr-1 text-text-muted" aria-hidden />
        )}
        {view.name}
      </button>
      {canUnpin && (
        <button
          type="button"
          onClick={onUnpin}
          className="ml-0.5 p-0.5 text-text-muted hover:text-foreground opacity-0 group-hover:opacity-100 focus:opacity-100 focus:outline-none motion-safe:transition-opacity"
          aria-label={`Unpin saved view ${view.name}`}
        >
          <X size={10} />
        </button>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Save dialog
// ---------------------------------------------------------------------------

interface SaveViewDialogProps {
  onClose: () => void;
  onSubmit: (name: string, opts: { shared: boolean; pinned: boolean }) => Promise<void>;
  testIdPrefix: string;
}

function SaveViewDialog({ onClose, onSubmit, testIdPrefix }: SaveViewDialogProps) {
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const [pinned, setPinned] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = name.trim();
    if (!trimmed || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit(trimmed, { shared, pinned });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save view.");
      setSubmitting(false);
    }
  }

  return (
    <ModalShell onClose={onClose} labelledBy={`${testIdPrefix}-save-title`}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex items-center justify-between">
          <h3
            id={`${testIdPrefix}-save-title`}
            className="text-sm font-semibold font-mono text-foreground"
          >
            Save current view
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close save-view dialog"
            className="text-text-muted hover:text-foreground focus:outline-none"
          >
            <X size={14} />
          </button>
        </div>

        <div>
          <label
            htmlFor={`${testIdPrefix}-save-name`}
            className="block text-xs text-text-muted mb-1.5"
          >
            View name
          </label>
          <input
            ref={inputRef}
            id={`${testIdPrefix}-save-name`}
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Ready projects, sorted newest"
            maxLength={128}
            data-testid={`${testIdPrefix}-save-name`}
            className="w-full px-2.5 py-1.5 text-xs rounded-md border border-border bg-surface text-foreground placeholder:text-text-muted focus:outline-none focus:border-accent"
          />
        </div>

        <div className="space-y-2 text-xs text-foreground">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={pinned}
              onChange={(e) => setPinned(e.target.checked)}
              className="accent-accent"
              data-testid={`${testIdPrefix}-save-pinned`}
            />
            <PushPin size={12} className="text-text-muted" aria-hidden />
            <span>Pin to toolbar</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={shared}
              onChange={(e) => setShared(e.target.checked)}
              className="accent-accent"
              data-testid={`${testIdPrefix}-save-shared`}
            />
            <UsersThree size={12} className="text-text-muted" aria-hidden />
            <span>Share with team</span>
          </label>
        </div>

        {error && <p className="text-xs text-critical" role="alert">{error}</p>}

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs rounded-md border border-border text-text-muted hover:text-foreground focus:outline-none focus:border-accent motion-safe:transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!name.trim() || submitting}
            data-testid={`${testIdPrefix}-save-submit`}
            className="px-3 py-1.5 text-xs rounded-md bg-accent text-badge-text hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none motion-safe:transition-colors"
          >
            {submitting ? "Saving…" : "Save view"}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Full-library dialog
// ---------------------------------------------------------------------------

interface SavedViewsDialogProps {
  views: SavedView[];
  isLoading: boolean;
  isOwner: (view: SavedView) => boolean;
  onClose: () => void;
  onApply: (view: SavedView) => void;
  onPin: (id: string, next: boolean) => void;
  onShare: (id: string, next: boolean) => void;
  onRemove: (id: string) => void;
  testIdPrefix: string;
}

function SavedViewsDialog({
  views,
  isLoading,
  isOwner,
  onClose,
  onApply,
  onPin,
  onShare,
  onRemove,
  testIdPrefix,
}: SavedViewsDialogProps) {
  return (
    <ModalShell onClose={onClose} labelledBy={`${testIdPrefix}-list-title`} width={420}>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3
            id={`${testIdPrefix}-list-title`}
            className="text-sm font-semibold font-mono text-foreground"
          >
            Saved views
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close saved views"
            className="text-text-muted hover:text-foreground focus:outline-none"
          >
            <X size={14} />
          </button>
        </div>

        {isLoading && (
          <p className="text-xs text-text-muted px-1 py-2">Loading saved views…</p>
        )}

        {!isLoading && views.length === 0 && (
          <p className="text-xs text-text-muted px-1 py-2">
            No saved views yet. Use "Save…" on the toolbar to persist the current
            search, sort, and filter state.
          </p>
        )}

        {!isLoading && views.length > 0 && (
          <ul className="flex flex-col gap-1 max-h-80 overflow-y-auto" data-testid={`${testIdPrefix}-list`}>
            {views.map((view) => {
              const owned = isOwner(view);
              return (
                <li
                  key={view.id}
                  className="group flex items-center justify-between gap-2 px-2 py-1.5 rounded-md hover:bg-elevated focus-within:bg-elevated motion-safe:transition-colors"
                  data-testid={`${testIdPrefix}-row-${view.id}`}
                >
                  <button
                    type="button"
                    onClick={() => onApply(view)}
                    className="flex-1 min-w-0 text-left flex items-center gap-1.5 text-xs text-foreground hover:text-accent focus:outline-none focus-visible:text-accent"
                  >
                    <span className="truncate">{view.name}</span>
                    {view.shared_with_team && !owned && (
                      <UsersThree
                        size={11}
                        className="shrink-0 text-text-muted"
                        aria-label="Shared by teammate"
                      />
                    )}
                  </button>
                  <div className="flex items-center gap-1 opacity-70 group-hover:opacity-100 motion-safe:transition-opacity">
                    <button
                      type="button"
                      onClick={() => onPin(view.id, !view.is_pinned)}
                      disabled={!owned}
                      aria-label={view.is_pinned ? `Unpin ${view.name}` : `Pin ${view.name}`}
                      title={owned ? (view.is_pinned ? "Unpin" : "Pin to toolbar") : "Only the owner can pin"}
                      className={`p-1 rounded focus:outline-none focus-visible:text-accent disabled:opacity-30 disabled:cursor-not-allowed ${
                        view.is_pinned ? "text-accent" : "text-text-muted hover:text-foreground"
                      }`}
                    >
                      <PushPin size={12} weight={view.is_pinned ? "fill" : "regular"} />
                    </button>
                    <button
                      type="button"
                      onClick={() => onShare(view.id, !view.shared_with_team)}
                      disabled={!owned}
                      aria-label={view.shared_with_team ? `Unshare ${view.name}` : `Share ${view.name} with team`}
                      title={owned ? (view.shared_with_team ? "Unshare" : "Share with team") : "Only the owner can share"}
                      className={`p-1 rounded focus:outline-none focus-visible:text-accent disabled:opacity-30 disabled:cursor-not-allowed ${
                        view.shared_with_team ? "text-accent" : "text-text-muted hover:text-foreground"
                      }`}
                    >
                      <Share size={12} weight={view.shared_with_team ? "fill" : "regular"} />
                    </button>
                    <button
                      type="button"
                      onClick={() => onRemove(view.id)}
                      disabled={!owned}
                      aria-label={`Delete ${view.name}`}
                      title={owned ? "Delete" : "Only the owner can delete"}
                      className="p-1 rounded text-text-muted hover:text-critical focus:outline-none focus-visible:text-critical disabled:opacity-30 disabled:cursor-not-allowed"
                    >
                      <Trash size={12} />
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Modal shell (no external Dialog primitive -- mirrors ConfirmDeleteDialog)
// ---------------------------------------------------------------------------

interface ModalShellProps {
  onClose: () => void;
  labelledBy: string;
  width?: number;
  children: React.ReactNode;
}

function ModalShell({ onClose, labelledBy, width = 360, children }: ModalShellProps) {
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: "color-mix(in srgb, var(--surface-sunk) 60%, transparent)" }}
      role="button"
      tabIndex={0}
      aria-label="Close dialog"
      onClick={onClose}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " " || e.key === "Escape") {
          if (e.key === " ") e.preventDefault();
          onClose();
        }
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.stopPropagation()}
        className="bg-elevated border border-border rounded-lg p-5 mx-4"
        style={{ width, maxWidth: "calc(100vw - 2rem)" }}
      >
        {children}
      </div>
    </div>
  );
}
