/**
 * VR SavedViews control.
 *
 * Compact chip row that lists saved views for one entity type
 * (`vr_investigation`, `vr_finding`, `vr_target`), lets the operator
 * apply / pin / share / delete each, and exposes a "Save current"
 * button that captures the caller-supplied `currentFilterJson` under
 * a name.
 *
 * The control is a pure presentation layer over `useSavedViews`;
 * every VR list surface serializes its own filter/search/sort state
 * to a JSON string, hands that string in, and receives it back
 * through `onApply` when a chip is clicked. The control makes no
 * assumptions about the shape.
 *
 * a11y: each chip is a real `<button>` with `aria-pressed` set when
 * its `filter_json` matches the caller's current serialization.
 * Every action inside the kebab menu has an `aria-label`.
 *
 * Motion: chip hover/press uses instant CSS transitions gated on
 * `prefers-reduced-motion` via `useReducedMotion` (D-21).
 */
import { useEffect, useMemo, useRef, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { useReducedMotion } from "@/hooks/useReducedMotion";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { BookmarkSimple } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { DotsThreeVertical } from "@phosphor-icons/react/dist/csr/DotsThreeVertical";
import { FloppyDisk } from "@phosphor-icons/react/dist/csr/FloppyDisk";
import { PushPin } from "@phosphor-icons/react/dist/csr/PushPin";
import { PushPinSlash } from "@phosphor-icons/react/dist/csr/PushPinSlash";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { UsersThree } from "@phosphor-icons/react/dist/csr/UsersThree";
import { X } from "@phosphor-icons/react/dist/csr/X";

import { useSavedViews, type SavedView } from "../useSavedViews";

export interface SavedViewsProps {
  /** Entity string persisted to `SavedFilterRecord.entity_type`. */
  entityType: string;
  /**
   * Serialized state to persist when the operator hits "Save current".
   * The caller owns the shape; the control never inspects it.
   */
  currentFilterJson: string;
  /**
   * Serialized state to match against each view's `filter_json` for
   * `aria-pressed`. Usually identical to `currentFilterJson` but
   * broken out so a page may normalize (e.g. sort keys) once and
   * pass the normalized form here while keeping the raw form as the
   * save payload.
   */
  activeFilterJson?: string;
  /** Applied when the operator clicks a chip. */
  onApply: (filterJson: string) => void;
  /** Optional short suffix (e.g. "investigations") for empty copy. */
  entityLabel?: string;
  /** Hide the whole row -- callers use during boot to avoid flicker. */
  hidden?: boolean;
}

export function SavedViews({
  entityType,
  currentFilterJson,
  activeFilterJson,
  onApply,
  entityLabel,
  hidden,
}: SavedViewsProps) {
  const reducedMotion = useReducedMotion();
  const currentUserId = useAuthStore((s) => s.userId);
  const {
    views,
    isLoading,
    isError,
    createView,
    updateView,
    deleteView,
    isMutating,
  } = useSavedViews(entityType);

  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [savePinned, setSavePinned] = useState(false);
  const [saveShared, setSaveShared] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [menuOpenFor, setMenuOpenFor] = useState<string | null>(null);
  const rootRef = useRef<HTMLDivElement | null>(null);

  // Close the kebab menu on outside click or Escape so a stale menu
  // does not linger over the table after the operator has moved on.
  useEffect(() => {
    if (menuOpenFor === null && !saveOpen) return;
    function onDocClick(e: MouseEvent) {
      if (!rootRef.current) return;
      if (rootRef.current.contains(e.target as Node)) return;
      setMenuOpenFor(null);
      setSaveOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setMenuOpenFor(null);
        setSaveOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpenFor, saveOpen]);

  // Sort: pinned first (stable within each half), then most-recently
  // updated. Matches operator expectation that a fresh save lands
  // near the top of the row.
  const sortedViews = useMemo(() => {
    return [...views].sort((a, b) => {
      if (a.is_pinned !== b.is_pinned) return a.is_pinned ? -1 : 1;
      return (b.updated_at ?? "").localeCompare(a.updated_at ?? "");
    });
  }, [views]);

  const activeJson = activeFilterJson ?? currentFilterJson;

  if (hidden) return null;

  // Loading / error surfaces: keep small so the chip row never
  // dominates the page during boot.
  if (isLoading) {
    return (
      <div
        ref={rootRef}
        className="flex items-center gap-2 text-xs text-text-muted"
        aria-busy="true"
      >
        <BookmarkSimple className="h-3.5 w-3.5" weight="regular" aria-hidden />
        <span>Loading saved views…</span>
      </div>
    );
  }
  if (isError) {
    return (
      <div
        ref={rootRef}
        className="flex items-center gap-2 text-xs text-critical"
        role="alert"
      >
        <BookmarkSimple className="h-3.5 w-3.5" weight="regular" aria-hidden />
        <span>Failed to load saved views.</span>
      </div>
    );
  }

  const transition = reducedMotion ? "none" : "border-color 120ms, background-color 120ms";

  return (
    <div
      ref={rootRef}
      className="flex flex-wrap items-center gap-2"
      aria-label={`Saved views for ${entityLabel ?? entityType}`}
      role="toolbar"
    >
      <span className="inline-flex items-center gap-1.5 text-xs uppercase tracking-wider text-text-muted font-mono">
        <BookmarkSimple className="h-3.5 w-3.5" weight="duotone" aria-hidden />
        Views
      </span>

      {sortedViews.length === 0 && (
        <span className="text-xs text-text-muted italic">
          No saved views yet.
        </span>
      )}

      {sortedViews.map((view) => {
        const active = view.filter_json === activeJson;
        const owned = view.user_id === currentUserId;
        const menuOpen = menuOpenFor === view.id;
        return (
          <div key={view.id} className="relative inline-flex items-stretch">
            <button
              type="button"
              onClick={() => onApply(view.filter_json)}
              aria-pressed={active}
              aria-label={`Apply saved view '${view.name}'${view.is_pinned ? " (pinned)" : ""}${view.shared_with_team ? " (shared with team)" : ""}`}
              title={view.name}
              className={
                "touch-target inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono rounded-l-md border uppercase tracking-wider focus:outline-none focus-visible:ring-2 focus-visible:ring-accent " +
                (active
                  ? "border-accent bg-elevated text-foreground"
                  : "border-border bg-surface text-text-muted hover:text-foreground")
              }
              style={{ transition }}
            >
              {view.is_pinned && (
                <PushPin
                  className="h-3 w-3 shrink-0 text-accent"
                  weight="fill"
                  aria-hidden
                />
              )}
              <span className="max-w-[16rem] truncate">{view.name}</span>
              {view.shared_with_team && (
                <AilaBadge severity="info" size="sm" className="ml-1">
                  team
                </AilaBadge>
              )}
            </button>
            <button
              type="button"
              onClick={() => setMenuOpenFor(menuOpen ? null : view.id)}
              aria-label={`Options for saved view '${view.name}'`}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              disabled={!owned}
              title={owned ? "View options" : "Read-only (shared by another user)"}
              className={
                "inline-flex items-center px-1.5 py-1.5 text-xs rounded-r-md border border-l-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent " +
                (active
                  ? "border-accent bg-elevated text-foreground"
                  : "border-border bg-surface text-text-muted hover:text-foreground") +
                (owned ? "" : " opacity-50 cursor-not-allowed")
              }
              style={{ transition }}
            >
              <DotsThreeVertical className="h-3.5 w-3.5" aria-hidden />
            </button>
            {menuOpen && owned && (
              <ViewMenu
                view={view}
                busy={isMutating}
                onClose={() => setMenuOpenFor(null)}
                onTogglePin={() =>
                  void updateView(view.id, { is_pinned: !view.is_pinned }).then(
                    () => setMenuOpenFor(null),
                  )
                }
                onToggleShare={() =>
                  void updateView(view.id, {
                    shared_with_team: !view.shared_with_team,
                  }).then(() => setMenuOpenFor(null))
                }
                onOverwrite={() =>
                  void updateView(view.id, {
                    filter_json: currentFilterJson,
                  }).then(() => setMenuOpenFor(null))
                }
                onDelete={() =>
                  void deleteView(view.id).then(() => setMenuOpenFor(null))
                }
              />
            )}
          </div>
        );
      })}

      <button
        type="button"
        onClick={() => {
          setSaveOpen((v) => !v);
          setSaveError(null);
        }}
        aria-label="Save current filters as a new view"
        aria-expanded={saveOpen}
        aria-haspopup="dialog"
        className="touch-target inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono uppercase tracking-wider rounded-md border border-dashed border-border bg-transparent text-text-muted hover:text-foreground hover:border-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        style={{ transition }}
      >
        <FloppyDisk className="h-3.5 w-3.5" weight="regular" aria-hidden />
        Save current
      </button>

      {saveOpen && (
        <SaveDialog
          busy={isMutating}
          name={saveName}
          pinned={savePinned}
          shared={saveShared}
          error={saveError}
          onNameChange={setSaveName}
          onPinnedChange={setSavePinned}
          onSharedChange={setSaveShared}
          onCancel={() => {
            setSaveOpen(false);
            setSaveError(null);
          }}
          onSubmit={async () => {
            const trimmed = saveName.trim();
            if (trimmed.length === 0) {
              setSaveError("Name is required.");
              return;
            }
            try {
              await createView({
                name: trimmed,
                filter_json: currentFilterJson,
                is_pinned: savePinned,
                shared_with_team: saveShared,
              });
              setSaveOpen(false);
              setSaveName("");
              setSavePinned(false);
              setSaveShared(false);
              setSaveError(null);
            } catch (e) {
              setSaveError(
                e instanceof Error ? e.message : "Could not save view.",
              );
            }
          }}
        />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Kebab menu -- absolutely positioned dropdown from each chip.
// Owner-only: caller has already gated visibility on `owned`.
// ─────────────────────────────────────────────────────────────────────

function ViewMenu({
  view,
  busy,
  onClose,
  onTogglePin,
  onToggleShare,
  onOverwrite,
  onDelete,
}: {
  view: SavedView;
  busy: boolean;
  onClose: () => void;
  onTogglePin: () => void;
  onToggleShare: () => void;
  onOverwrite: () => void;
  onDelete: () => void;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  return (
    <div
      role="menu"
      aria-label={`Options for '${view.name}'`}
      className="absolute z-20 top-full left-0 mt-1 min-w-[15rem] rounded-md border border-border bg-elevated shadow-lg p-1"
    >
      <button
        type="button"
        role="menuitem"
        onClick={onTogglePin}
        disabled={busy}
        className="flex w-full items-center gap-2 px-3 py-1.5 text-xs rounded hover:bg-surface focus:outline-none focus-visible:bg-surface disabled:opacity-50"
      >
        {view.is_pinned ? (
          <PushPinSlash className="h-3.5 w-3.5" weight="regular" aria-hidden />
        ) : (
          <PushPin className="h-3.5 w-3.5" weight="regular" aria-hidden />
        )}
        {view.is_pinned ? "Unpin" : "Pin"}
      </button>
      <button
        type="button"
        role="menuitem"
        onClick={onToggleShare}
        disabled={busy}
        className="flex w-full items-center gap-2 px-3 py-1.5 text-xs rounded hover:bg-surface focus:outline-none focus-visible:bg-surface disabled:opacity-50"
      >
        <UsersThree className="h-3.5 w-3.5" weight="regular" aria-hidden />
        {view.shared_with_team ? "Unshare with team" : "Share with team"}
      </button>
      <button
        type="button"
        role="menuitem"
        onClick={onOverwrite}
        disabled={busy}
        title="Replace this view's stored filters with the current selection"
        className="flex w-full items-center gap-2 px-3 py-1.5 text-xs rounded hover:bg-surface focus:outline-none focus-visible:bg-surface disabled:opacity-50"
      >
        <FloppyDisk className="h-3.5 w-3.5" weight="regular" aria-hidden />
        Overwrite with current
      </button>
      <div className="h-px bg-border my-1" role="separator" />
      {!confirmDelete ? (
        <button
          type="button"
          role="menuitem"
          onClick={() => setConfirmDelete(true)}
          disabled={busy}
          className="flex w-full items-center gap-2 px-3 py-1.5 text-xs rounded hover:bg-surface text-critical focus:outline-none focus-visible:bg-surface disabled:opacity-50"
        >
          <Trash className="h-3.5 w-3.5" weight="regular" aria-hidden />
          Delete
        </button>
      ) : (
        <div className="flex flex-col gap-1 px-3 py-2">
          <span className="text-xs text-critical">
            Delete '{view.name}'?
          </span>
          <div className="flex gap-1">
            <button
              type="button"
              role="menuitem"
              onClick={onDelete}
              disabled={busy}
              className="flex-1 px-2 py-1 text-xs rounded bg-critical/20 text-critical border border-critical/40 hover:bg-critical/30 focus:outline-none focus-visible:ring-2 focus-visible:ring-critical disabled:opacity-50"
            >
              Delete
            </button>
            <button
              type="button"
              onClick={() => setConfirmDelete(false)}
              disabled={busy}
              className="flex-1 px-2 py-1 text-xs rounded border border-border text-text-muted hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      <div className="h-px bg-border my-1" role="separator" />
      <button
        type="button"
        role="menuitem"
        onClick={onClose}
        className="flex w-full items-center gap-2 px-3 py-1.5 text-xs rounded hover:bg-surface text-text-muted focus:outline-none focus-visible:bg-surface"
      >
        <X className="h-3.5 w-3.5" weight="regular" aria-hidden />
        Close
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Save dialog -- inline popover under the "Save current" chip.
// Uses AilaCard so it inherits the same techBorder chrome as the
// surrounding filter card without pulling in a modal primitive.
// ─────────────────────────────────────────────────────────────────────

function SaveDialog({
  busy,
  name,
  pinned,
  shared,
  error,
  onNameChange,
  onPinnedChange,
  onSharedChange,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  name: string;
  pinned: boolean;
  shared: boolean;
  error: string | null;
  onNameChange: (v: string) => void;
  onPinnedChange: (v: boolean) => void;
  onSharedChange: (v: boolean) => void;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    inputRef.current?.focus();
  }, []);
  return (
    <div
      role="dialog"
      aria-label="Save current filters as a view"
      className="absolute z-20"
      style={{ top: "100%", right: 0, marginTop: 6 }}
    >
      <AilaCard techBorder padding="sm" className="min-w-[20rem]">
        <div className="space-y-2">
          <label className="block text-xs text-text-muted">
            View name
            <input
              ref={inputRef}
              type="text"
              value={name}
              onChange={(e) => onNameChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  onSubmit();
                }
              }}
              placeholder="e.g. Running variant hunts"
              aria-label="View name"
              maxLength={128}
              className="mt-1 w-full px-3 py-1.5 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
            />
          </label>
          <label className="flex items-center gap-2 text-xs text-text-muted cursor-pointer">
            <input
              type="checkbox"
              className="accent-accent"
              checked={pinned}
              onChange={(e) => onPinnedChange(e.target.checked)}
            />
            Pin to front of the chip row
          </label>
          <label className="flex items-center gap-2 text-xs text-text-muted cursor-pointer">
            <input
              type="checkbox"
              className="accent-accent"
              checked={shared}
              onChange={(e) => onSharedChange(e.target.checked)}
            />
            Share with my team
          </label>
          {error && (
            <p className="text-xs text-critical" role="alert">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onCancel}
              disabled={busy}
              className="px-3 py-1 text-xs rounded border border-border text-text-muted hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onSubmit}
              disabled={busy || name.trim().length === 0}
              className="px-3 py-1 text-xs rounded bg-accent text-background hover:bg-accent/90 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
            >
              {busy ? "Saving…" : "Save view"}
            </button>
          </div>
        </div>
      </AilaCard>
    </div>
  );
}
