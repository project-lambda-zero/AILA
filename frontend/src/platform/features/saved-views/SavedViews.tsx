/**
 * SavedViews -- compact toolbar control for named filter presets.
 *
 * Pinned views render inline as one-click chips. A "Views" dropdown lists
 * every visible view (own + team-shared) with pin / share / delete controls
 * scoped to the owner. "Save as…" opens a small inline modal that captures
 * the current filter state under a user-chosen name.
 *
 * Presentation reuses the shell's existing token palette (elevated / border
 * / accent, `rounded-sharp-md`, `font-mono`) so the control blends into
 * every page toolbar it is dropped into. No new dependencies; motion
 * respects prefers-reduced-motion via the shared `transition-colors` token.
 */
import { useEffect, useRef, useState } from "react";
import { BookmarkSimple } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { PushPin } from "@phosphor-icons/react/dist/csr/PushPin";
import { UsersThree } from "@phosphor-icons/react/dist/csr/UsersThree";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { X } from "@phosphor-icons/react/dist/csr/X";

import { useAuthStore } from "@platform/auth/useAuthStore";

import { useSavedViews, type SavedView } from "./useSavedViews";

// ---------------------------------------------------------------------------
// Save dialog
// ---------------------------------------------------------------------------

interface SaveViewDialogProps {
  entityLabel: string;
  onSubmit: (payload: {
    name: string;
    isPinned: boolean;
    sharedWithTeam: boolean;
  }) => Promise<void> | void;
  onClose: () => void;
  isPending: boolean;
}

function SaveViewDialog({
  entityLabel,
  onSubmit,
  onClose,
  isPending,
}: SaveViewDialogProps) {
  const [name, setName] = useState("");
  const [isPinned, setIsPinned] = useState(true);
  const [sharedWithTeam, setSharedWithTeam] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSave() {
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Name is required.");
      return;
    }
    if (trimmed.length > 128) {
      setError("Name must be 128 characters or fewer.");
      return;
    }
    setError(null);
    try {
      await onSubmit({ name: trimmed, isPinned, sharedWithTeam });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save view");
    }
  }

  return (
    <div
      className="fixed inset-0 flex items-center justify-center"
      style={{ zIndex: 60 }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="saved-views-save-title"
    >
      <div
        className="absolute inset-0 bg-black/30"
        role="button"
        tabIndex={-1}
        aria-label="Close save view dialog"
        onClick={onClose}
        onKeyDown={(e) => {
          if (e.key === "Escape") onClose();
        }}
      />
      <div
        className="relative z-10 bg-elevated rounded-sharp-md p-5"
        style={{ width: 380, border: "1px solid var(--color-border-bright)" }}
      >
        <div className="flex items-center justify-between mb-4">
          <h3
            id="saved-views-save-title"
            className="font-mono text-sm font-semibold text-text"
          >
            Save current view
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="text-text-muted hover:text-text transition-colors"
            aria-label="Close"
          >
            <X size={15} />
          </button>
        </div>
        <p className="font-mono text-[10px] text-text-muted uppercase tracking-wider mb-3">
          {entityLabel}
        </p>
        <label
          htmlFor="saved-view-name"
          className="block font-mono text-xs text-text-muted mb-1.5"
        >
          View name
        </label>
        <input
          id="saved-view-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              void handleSave();
            }
            if (e.key === "Escape") onClose();
          }}
          placeholder="e.g. Failed scans this week"
          maxLength={128}
          className="w-full font-mono text-xs bg-surface border border-border rounded-sharp px-2.5 py-1.5 text-text placeholder:text-text-muted focus:outline-none focus:border-accent mb-3"
          autoFocus
        />
        <div className="flex flex-col gap-2 mb-4">
          <label className="flex items-center gap-2 font-mono text-xs text-text-muted cursor-pointer">
            <input
              type="checkbox"
              checked={isPinned}
              onChange={(e) => setIsPinned(e.target.checked)}
              className="h-3.5 w-3.5 accent-accent"
            />
            Pin to toolbar
          </label>
          <label className="flex items-center gap-2 font-mono text-xs text-text-muted cursor-pointer">
            <input
              type="checkbox"
              checked={sharedWithTeam}
              onChange={(e) => setSharedWithTeam(e.target.checked)}
              className="h-3.5 w-3.5 accent-accent"
            />
            Share with team
          </label>
        </div>
        {error && (
          <p
            className="font-mono text-xs text-critical mb-3"
            role="alert"
          >
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 font-mono text-xs text-text-muted border border-border rounded-sharp-md hover:text-text transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void handleSave()}
            disabled={isPending || name.trim().length === 0}
            className="px-3 py-1.5 font-mono text-xs bg-accent/10 text-accent border border-accent/30 rounded-sharp-md hover:bg-accent/20 disabled:opacity-50 transition-colors"
          >
            {isPending ? "Saving…" : "Save view"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pinned chip
// ---------------------------------------------------------------------------

interface SavedViewChipProps<TState> {
  view: SavedView<TState>;
  onApply: () => void;
  onUnpin?: () => void;
}

function SavedViewChip<TState>({
  view,
  onApply,
  onUnpin,
}: SavedViewChipProps<TState>) {
  return (
    <div
      className="group flex items-center gap-1 px-2 py-1 bg-elevated border border-border rounded-sharp-md hover:border-accent/50 transition-colors"
      data-testid="saved-view-chip"
    >
      <button
        type="button"
        onClick={onApply}
        className="font-mono text-xs text-text hover:text-accent transition-colors"
        aria-label={`Apply saved view ${view.name}`}
      >
        {view.name}
      </button>
      {view.sharedWithTeam && (
        <UsersThree
          size={11}
          className="text-text-muted"
          aria-label="Shared with team"
        />
      )}
      {onUnpin && (
        <button
          type="button"
          onClick={onUnpin}
          className="text-text-muted hover:text-text ml-0.5 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity"
          aria-label={`Unpin ${view.name}`}
        >
          <X size={11} />
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dropdown menu
// ---------------------------------------------------------------------------

interface SavedViewsMenuProps<TState> {
  views: SavedView<TState>[];
  isLoading: boolean;
  onApply: (view: SavedView<TState>) => void;
  onPin: (id: string, next: boolean) => void;
  onShare: (id: string, next: boolean) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}

function SavedViewsMenu<TState>({
  views,
  isLoading,
  onApply,
  onPin,
  onShare,
  onDelete,
  onClose,
}: SavedViewsMenuProps<TState>) {
  const panelRef = useRef<HTMLDivElement | null>(null);

  // Click-outside + Escape close. Attaches once per open cycle; the ref
  // isolates the panel so its own buttons don't self-close.
  useEffect(() => {
    function handlePointer(event: MouseEvent) {
      const panel = panelRef.current;
      if (panel && event.target instanceof Node && !panel.contains(event.target)) {
        onClose();
      }
    }
    function handleKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", handlePointer);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handlePointer);
      document.removeEventListener("keydown", handleKey);
    };
  }, [onClose]);

  return (
    <div
      ref={panelRef}
      className="absolute right-0 mt-1 z-50 bg-elevated rounded-sharp-md"
      style={{ minWidth: 280, maxWidth: 360, border: "1px solid var(--color-border-bright)" }}
      role="menu"
    >
      <div className="max-h-72 overflow-y-auto py-1">
        {isLoading && (
          <p className="font-mono text-xs text-text-muted px-3 py-2">
            Loading views…
          </p>
        )}
        {!isLoading && views.length === 0 && (
          <p className="font-mono text-xs text-text-muted px-3 py-2">
            No saved views yet. Use "Save as…" to create one.
          </p>
        )}
        {views.map((view) => (
          <div
            key={view.id}
            className="group flex items-center justify-between gap-2 px-2 py-1.5 hover:bg-surface transition-colors"
          >
            <button
              type="button"
              onClick={() => onApply(view)}
              className="flex-1 min-w-0 text-left font-mono text-xs text-text hover:text-accent transition-colors truncate"
              role="menuitem"
              aria-label={`Apply saved view ${view.name}`}
              title={view.name}
            >
              {view.name}
              {!view.ownedByMe && (
                <span className="text-text-muted"> · shared</span>
              )}
            </button>
            <div className="flex items-center gap-1 shrink-0">
              {view.sharedWithTeam && !view.ownedByMe && (
                <UsersThree
                  size={12}
                  className="text-text-muted"
                  aria-label="Shared with team"
                />
              )}
              {view.ownedByMe && (
                <>
                  <button
                    type="button"
                    onClick={() => onPin(view.id, !view.isPinned)}
                    className={`transition-colors ${view.isPinned ? "text-accent" : "text-text-muted hover:text-text"}`}
                    aria-label={view.isPinned ? `Unpin ${view.name}` : `Pin ${view.name}`}
                    aria-pressed={view.isPinned}
                    title={view.isPinned ? "Unpin from toolbar" : "Pin to toolbar"}
                  >
                    <PushPin size={13} weight={view.isPinned ? "fill" : "regular"} />
                  </button>
                  <button
                    type="button"
                    onClick={() => onShare(view.id, !view.sharedWithTeam)}
                    className={`transition-colors ${view.sharedWithTeam ? "text-accent" : "text-text-muted hover:text-text"}`}
                    aria-label={
                      view.sharedWithTeam
                        ? `Unshare ${view.name} from team`
                        : `Share ${view.name} with team`
                    }
                    aria-pressed={view.sharedWithTeam}
                    title={
                      view.sharedWithTeam ? "Unshare from team" : "Share with team"
                    }
                  >
                    <UsersThree size={13} weight={view.sharedWithTeam ? "fill" : "regular"} />
                  </button>
                  <button
                    type="button"
                    onClick={() => onDelete(view.id)}
                    className="text-text-muted hover:text-critical transition-colors"
                    aria-label={`Delete ${view.name}`}
                    title="Delete view"
                  >
                    <Trash size={13} />
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root component
// ---------------------------------------------------------------------------

export interface SavedViewsProps<TState> {
  /** Discriminator persisted as `entity_type` on each SavedFilterRecord. */
  entityType: string;
  /** Snapshot of the surface's current filter state; serialized on save. */
  currentState: TState;
  /**
   * Applied when the operator clicks a chip / menu item. Parsed JSON is
   * passed through verbatim -- the caller decides how to reconcile it with
   * URL params, local state, preferences, etc.
   */
  onApply: (state: TState) => void;
  /** Toolbar label; defaults to "Views". */
  label?: string;
  /** Human-readable entity name used in the save dialog subtitle. */
  entityLabel?: string;
  className?: string;
}

export function SavedViews<TState>({
  entityType,
  currentState,
  onApply,
  label,
  entityLabel,
  className,
}: SavedViewsProps<TState>) {
  const userId = useAuthStore((state) => state.userId);
  const {
    views,
    pinned,
    isLoading,
    isError,
    error,
    isMutating,
    createView,
    patchView,
    removeView,
  } = useSavedViews<TState>(entityType, userId);
  const [menuOpen, setMenuOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);

  const toolbarLabel = label ?? "Views";
  const subtitle = entityLabel ?? `entity_type: ${entityType}`;

  return (
    <div
      className={`flex flex-wrap items-center gap-1.5 ${className ?? ""}`}
      data-testid="saved-views-control"
      data-entity-type={entityType}
    >
      {pinned.length > 0 && (
        <span className="font-mono text-[10px] text-text-muted uppercase tracking-wider">
          Pinned:
        </span>
      )}
      {pinned.map((view) => (
        <SavedViewChip
          key={view.id}
          view={view}
          onApply={() => onApply(view.state)}
          onUnpin={
            view.ownedByMe
              ? () => {
                  void patchView({ id: view.id, isPinned: false });
                }
              : undefined
          }
        />
      ))}
      <div className="relative">
        <button
          type="button"
          onClick={() => setMenuOpen((open) => !open)}
          className="flex items-center gap-1.5 px-2 py-1 font-mono text-xs border border-border rounded-sharp-md text-text-muted hover:border-accent/50 hover:text-text transition-colors disabled:opacity-50"
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          aria-label={`Show saved ${toolbarLabel.toLowerCase()}`}
          disabled={isLoading && views.length === 0}
        >
          <BookmarkSimple size={13} />
          {toolbarLabel}
          {views.length > 0 && (
            <span className="opacity-60">({views.length})</span>
          )}
          <CaretDown size={10} />
        </button>
        {menuOpen && (
          <SavedViewsMenu
            views={views}
            isLoading={isLoading}
            onApply={(view) => {
              onApply(view.state);
              setMenuOpen(false);
            }}
            onPin={(id, next) => {
              void patchView({ id, isPinned: next });
            }}
            onShare={(id, next) => {
              void patchView({ id, sharedWithTeam: next });
            }}
            onDelete={(id) => {
              void removeView(id);
            }}
            onClose={() => setMenuOpen(false)}
          />
        )}
      </div>
      <button
        type="button"
        onClick={() => setSaveOpen(true)}
        className="flex items-center gap-1.5 px-2 py-1 font-mono text-xs border border-border rounded-sharp-md text-text-muted hover:border-accent/50 hover:text-text transition-colors"
        aria-label={`Save current ${toolbarLabel.toLowerCase().replace(/s$/, "")} as`}
      >
        <BookmarkSimple size={13} />
        Save as…
      </button>
      {isError && (
        <span
          className="font-mono text-[10px] text-critical"
          role="alert"
        >
          {error?.message ?? "Failed to load saved views"}
        </span>
      )}
      {saveOpen && (
        <SaveViewDialog
          entityLabel={subtitle}
          isPending={isMutating}
          onSubmit={async ({ name, isPinned, sharedWithTeam }) => {
            await createView({
              name,
              state: currentState,
              isPinned,
              sharedWithTeam,
            });
          }}
          onClose={() => setSaveOpen(false)}
        />
      )}
    </div>
  );
}
