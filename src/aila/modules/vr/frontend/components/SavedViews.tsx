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

import { MonoBadge } from "@/components/aila/mock";
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

// ─── Mock chip style tokens ────────────────────────────────────────────
const CHIP_H = 26;
const CHIP_FS = 9.5;
const CHIP_LS = "0.08em";

function chipBaseStyle(active: boolean, transition: string): React.CSSProperties {
  return {
    height: CHIP_H,
    padding: "0 10px",
    fontSize: CHIP_FS,
    letterSpacing: CHIP_LS,
    border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
    background: active
      ? "color-mix(in srgb, var(--accent) 12%, transparent)"
      : "var(--surface-sunk)",
    color: active ? "var(--accent)" : "var(--text-muted)",
    borderRadius: 2,
    cursor: "pointer",
    transition,
  };
}

function kebabStyle(active: boolean, owned: boolean, transition: string): React.CSSProperties {
  return {
    height: CHIP_H,
    width: 22,
    fontSize: CHIP_FS,
    border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
    borderLeft: 0,
    background: active
      ? "color-mix(in srgb, var(--accent) 12%, transparent)"
      : "var(--surface-sunk)",
    color: active ? "var(--accent)" : "var(--text-muted)",
    borderRadius: 2,
    cursor: owned ? "pointer" : "not-allowed",
    opacity: owned ? 1 : 0.5,
    transition,
  };
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

  const sortedViews = useMemo(() => {
    return [...views].sort((a, b) => {
      if (a.is_pinned !== b.is_pinned) return a.is_pinned ? -1 : 1;
      return (b.updated_at ?? "").localeCompare(a.updated_at ?? "");
    });
  }, [views]);

  const activeJson = activeFilterJson ?? currentFilterJson;

  if (hidden) return null;

  if (isLoading) {
    return (
      <div
        ref={rootRef}
        className="flex items-center font-mono"
        style={{
          gap: 6,
          fontSize: 10,
          color: "var(--text-faint)",
          letterSpacing: "0.06em",
        }}
        aria-busy="true"
      >
        <BookmarkSimple className="h-3 w-3" weight="regular" aria-hidden />
        <span>loading saved views…</span>
      </div>
    );
  }
  if (isError) {
    return (
      <div
        ref={rootRef}
        className="flex items-center font-mono"
        style={{
          gap: 6,
          fontSize: 10,
          color: "var(--accent)",
          letterSpacing: "0.06em",
        }}
        role="alert"
      >
        <BookmarkSimple className="h-3 w-3" weight="regular" aria-hidden />
        <span>failed to load saved views</span>
      </div>
    );
  }

  const transition = reducedMotion
    ? "none"
    : "border-color 120ms, background-color 120ms, color 120ms";

  return (
    <div
      ref={rootRef}
      className="flex flex-wrap items-center"
      style={{ gap: 6 }}
      aria-label={`Saved views for ${entityLabel ?? entityType}`}
      role="toolbar"
    >
      <span
        className="inline-flex items-center font-mono uppercase"
        style={{
          gap: 5,
          fontSize: 9,
          letterSpacing: "0.12em",
          color: "var(--text-faint)",
        }}
      >
        <BookmarkSimple className="h-3 w-3" weight="duotone" aria-hidden />
        views
      </span>

      {sortedViews.length === 0 && (
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-faint)",
            fontStyle: "italic",
            letterSpacing: "0.05em",
          }}
        >
          no saved views yet
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
              className="font-mono uppercase inline-flex items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              style={{
                ...chipBaseStyle(active, transition),
                gap: 5,
                borderTopRightRadius: 0,
                borderBottomRightRadius: 0,
              }}
            >
              {view.is_pinned && (
                <PushPin
                  className="h-3 w-3 shrink-0"
                  weight="fill"
                  aria-hidden
                  style={{ color: "var(--accent)" }}
                />
              )}
              <span
                style={{
                  maxWidth: "16rem",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {view.name}
              </span>
              {view.shared_with_team && <MonoBadge tone="info">team</MonoBadge>}
            </button>
            <button
              type="button"
              onClick={() => setMenuOpenFor(menuOpen ? null : view.id)}
              aria-label={`Options for saved view '${view.name}'`}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              disabled={!owned}
              title={owned ? "View options" : "Read-only (shared by another user)"}
              className="inline-flex items-center justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              style={{
                ...kebabStyle(active, owned, transition),
                borderTopLeftRadius: 0,
                borderBottomLeftRadius: 0,
              }}
            >
              <DotsThreeVertical className="h-3 w-3" aria-hidden />
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
        className="font-mono uppercase inline-flex items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        style={{
          ...chipBaseStyle(saveOpen, transition),
          gap: 5,
          color: saveOpen ? "var(--accent)" : "var(--accent)",
          borderColor: "var(--accent)",
          background: saveOpen
            ? "color-mix(in srgb, var(--accent) 18%, transparent)"
            : "color-mix(in srgb, var(--accent) 8%, transparent)",
        }}
      >
        <FloppyDisk className="h-3 w-3" weight="regular" aria-hidden />
        save current
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
// Kebab menu -- absolutely positioned mock overlay dropdown.
// Owner-only: caller has already gated visibility on `owned`.
// ─────────────────────────────────────────────────────────────────────

function menuItemStyle(danger?: boolean): React.CSSProperties {
  return {
    display: "flex",
    width: "100%",
    alignItems: "center",
    gap: 8,
    padding: "6px 10px",
    fontSize: 10,
    letterSpacing: "0.08em",
    color: danger ? "var(--accent)" : "var(--text-muted)",
    background: "transparent",
    border: 0,
    cursor: "pointer",
  };
}

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
      className="absolute z-20 font-mono uppercase"
      style={{
        top: "100%",
        left: 0,
        marginTop: 4,
        minWidth: 220,
        background: "var(--surface-card)",
        border: "1px solid var(--border-soft)",
        borderRadius: 3,
        boxShadow: "var(--bevel-raised)",
        padding: 3,
      }}
    >
      <button
        type="button"
        role="menuitem"
        onClick={onTogglePin}
        disabled={busy}
        style={{ ...menuItemStyle(), opacity: busy ? 0.5 : 1 }}
        onMouseOver={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
      >
        {view.is_pinned ? (
          <PushPinSlash className="h-3 w-3" weight="regular" aria-hidden />
        ) : (
          <PushPin className="h-3 w-3" weight="regular" aria-hidden />
        )}
        {view.is_pinned ? "unpin" : "pin"}
      </button>
      <button
        type="button"
        role="menuitem"
        onClick={onToggleShare}
        disabled={busy}
        style={{ ...menuItemStyle(), opacity: busy ? 0.5 : 1 }}
        onMouseOver={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <UsersThree className="h-3 w-3" weight="regular" aria-hidden />
        {view.shared_with_team ? "unshare with team" : "share with team"}
      </button>
      <button
        type="button"
        role="menuitem"
        onClick={onOverwrite}
        disabled={busy}
        title="Replace this view's stored filters with the current selection"
        style={{ ...menuItemStyle(), opacity: busy ? 0.5 : 1 }}
        onMouseOver={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <FloppyDisk className="h-3 w-3" weight="regular" aria-hidden />
        overwrite with current
      </button>
      <div
        role="separator"
        style={{ height: 1, background: "var(--border-faint)", margin: "3px 0" }}
      />
      {!confirmDelete ? (
        <button
          type="button"
          role="menuitem"
          onClick={() => setConfirmDelete(true)}
          disabled={busy}
          style={{ ...menuItemStyle(true), opacity: busy ? 0.5 : 1 }}
          onMouseOver={(e) =>
            (e.currentTarget.style.background =
              "color-mix(in srgb, var(--accent) 10%, transparent)")
          }
          onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
        >
          <Trash className="h-3 w-3" weight="regular" aria-hidden />
          delete
        </button>
      ) : (
        <div style={{ padding: "6px 10px", display: "flex", flexDirection: "column", gap: 6 }}>
          <span
            className="font-mono uppercase"
            style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.08em" }}
          >
            delete '{view.name}'?
          </span>
          <div className="flex" style={{ gap: 4 }}>
            <button
              type="button"
              role="menuitem"
              onClick={onDelete}
              disabled={busy}
              className="font-mono uppercase focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              style={{
                flex: 1,
                height: 24,
                fontSize: 9.5,
                letterSpacing: "0.08em",
                color: "var(--accent)",
                background: "color-mix(in srgb, var(--accent) 18%, transparent)",
                border: "1px solid var(--accent)",
                borderRadius: 2,
                cursor: "pointer",
                opacity: busy ? 0.5 : 1,
              }}
            >
              delete
            </button>
            <button
              type="button"
              onClick={() => setConfirmDelete(false)}
              disabled={busy}
              className="font-mono uppercase focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              style={{
                flex: 1,
                height: 24,
                fontSize: 9.5,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
                background: "transparent",
                border: "1px solid var(--border-soft)",
                borderRadius: 2,
                cursor: "pointer",
                opacity: busy ? 0.5 : 1,
              }}
            >
              cancel
            </button>
          </div>
        </div>
      )}
      <div
        role="separator"
        style={{ height: 1, background: "var(--border-faint)", margin: "3px 0" }}
      />
      <button
        type="button"
        role="menuitem"
        onClick={onClose}
        style={menuItemStyle()}
        onMouseOver={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <X className="h-3 w-3" weight="regular" aria-hidden />
        close
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Save dialog -- inline mock overlay popover under the "Save current" chip.
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
      style={{
        top: "100%",
        right: 0,
        marginTop: 6,
        minWidth: 320,
        padding: 12,
        background: "var(--surface-card)",
        border: "1px solid var(--border-soft)",
        borderRadius: 3,
        boxShadow: "var(--bevel-raised)",
      }}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <label
          className="font-mono uppercase"
          style={{
            display: "block",
            fontSize: 9,
            letterSpacing: "0.1em",
            color: "var(--text-faint)",
          }}
        >
          view name
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
            className="font-mono"
            style={{
              display: "block",
              marginTop: 5,
              width: "100%",
              height: 28,
              padding: "0 8px",
              fontSize: 11,
              letterSpacing: 0,
              textTransform: "none",
              color: "var(--text-primary)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              outline: "none",
            }}
          />
        </label>
        <label
          className="flex items-center font-mono"
          style={{
            gap: 6,
            fontSize: 10,
            color: "var(--text-muted)",
            letterSpacing: "0.05em",
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={pinned}
            onChange={(e) => onPinnedChange(e.target.checked)}
            style={{ accentColor: "var(--accent)" }}
          />
          pin to front of the chip row
        </label>
        <label
          className="flex items-center font-mono"
          style={{
            gap: 6,
            fontSize: 10,
            color: "var(--text-muted)",
            letterSpacing: "0.05em",
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={shared}
            onChange={(e) => onSharedChange(e.target.checked)}
            style={{ accentColor: "var(--accent)" }}
          />
          share with my team
        </label>
        {error && (
          <p
            className="font-mono"
            role="alert"
            style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.05em" }}
          >
            {error}
          </p>
        )}
        <div className="flex items-center justify-end" style={{ gap: 6, paddingTop: 2 }}>
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="font-mono uppercase focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            style={{
              height: 26,
              padding: "0 12px",
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
              background: "transparent",
              border: "1px solid var(--border-soft)",
              borderRadius: 2,
              cursor: "pointer",
              opacity: busy ? 0.5 : 1,
            }}
          >
            cancel
          </button>
          <button
            type="button"
            onClick={onSubmit}
            disabled={busy || name.trim().length === 0}
            className="font-mono uppercase focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            style={{
              height: 26,
              padding: "0 12px",
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-on-accent)",
              background: "var(--accent)",
              border: "1px solid var(--accent)",
              borderRadius: 2,
              cursor: "pointer",
              opacity: busy || name.trim().length === 0 ? 0.5 : 1,
            }}
          >
            {busy ? "saving…" : "save view"}
          </button>
        </div>
      </div>
    </div>
  );
}
