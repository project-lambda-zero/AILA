/**
 * SavedViews -- compact toolbar control for named filter presets.
 *
 * Pinned views render inline as one-click mono chips. A "VIEWS" dropdown
 * lists every visible view (own + team-shared) with pin / share / delete
 * controls scoped to the owner. "SAVE FILTER" opens a small backdrop +
 * WindowPanel modal that captures the current filter state under a
 * user-chosen name.
 */
import { useEffect, useRef, useState } from "react";
import { BookmarkSimple } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { PushPin } from "@phosphor-icons/react/dist/csr/PushPin";
import { UsersThree } from "@phosphor-icons/react/dist/csr/UsersThree";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { X } from "@phosphor-icons/react/dist/csr/X";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { useAuthStore } from "@platform/auth/useAuthStore";

import { useSavedViews, type SavedView } from "./useSavedViews";

// ---------------------------------------------------------------------------
// Shared inline styles -- mono toolbar controls
// ---------------------------------------------------------------------------

const MONO_BTN: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
  whiteSpace: "nowrap",
};

const MONO_INPUT: React.CSSProperties = {
  width: "100%",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  padding: "8px 10px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  color: "var(--text-primary)",
  outline: "none",
};

const CHIP_STYLE: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
  padding: "3px 8px",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  color: "var(--text-primary)",
};

const LABEL_STYLE: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-muted)",
};

// ---------------------------------------------------------------------------
// Save dialog -- backdrop + WindowPanel(title="save filter")
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
      style={{
        zIndex: 60,
        background: "color-mix(in srgb, black 55%, transparent)",
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="saved-views-save-title"
    >
      <div
        role="button"
        tabIndex={-1}
        aria-label="Close save view dialog"
        onClick={onClose}
        onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}
        style={{ position: "absolute", inset: 0 }}
      />
      <div style={{ position: "relative", width: 400, maxWidth: "94vw", zIndex: 1 }}>
        <WindowPanel
          title="save filter"
          tone="accent"
          actions={
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              style={{ ...MONO_BTN, height: 20, fontSize: 9, padding: "0 8px" }}
            >
              <X size={10} /> CLOSE
            </button>
          }
        >
          <div className="flex flex-col" style={{ gap: 12 }}>
            <p
              className="font-mono"
              style={{
                fontSize: 9,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                color: "var(--text-muted)",
              }}
              id="saved-views-save-title"
            >
              {entityLabel}
            </p>

            <div className="flex flex-col" style={{ gap: 4 }}>
              <label htmlFor="saved-view-name" style={LABEL_STYLE}>
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
                style={MONO_INPUT}
                autoFocus
              />
            </div>

            <div className="flex flex-col" style={{ gap: 6 }}>
              <label
                className="flex items-center"
                style={{
                  gap: 8,
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                  color: "var(--text-primary)",
                  cursor: "pointer",
                }}
              >
                <input
                  type="checkbox"
                  checked={isPinned}
                  onChange={(e) => setIsPinned(e.target.checked)}
                  style={{ accentColor: "var(--accent)" }}
                />
                Pin to toolbar
              </label>
              <label
                className="flex items-center"
                style={{
                  gap: 8,
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                  color: "var(--text-primary)",
                  cursor: "pointer",
                }}
              >
                <input
                  type="checkbox"
                  checked={sharedWithTeam}
                  onChange={(e) => setSharedWithTeam(e.target.checked)}
                  style={{ accentColor: "var(--accent)" }}
                />
                Share with team
              </label>
            </div>

            {error && (
              <div
                role="alert"
                className="font-mono"
                style={{
                  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                  color: "var(--status-warn)",
                  padding: "6px 10px",
                  fontSize: 11,
                  borderRadius: 3,
                }}
              >
                {error}
              </div>
            )}

            <div className="flex justify-end" style={{ gap: 8 }}>
              <button type="button" onClick={onClose} style={MONO_BTN}>
                CANCEL
              </button>
              <button
                type="button"
                onClick={() => void handleSave()}
                disabled={isPending || name.trim().length === 0}
                style={{
                  ...MONO_BTN,
                  background: "color-mix(in srgb, var(--accent) 20%, transparent)",
                  borderColor: "color-mix(in srgb, var(--accent) 45%, transparent)",
                  color: "var(--accent)",
                  opacity: isPending || name.trim().length === 0 ? 0.5 : 1,
                }}
              >
                {isPending ? "SAVING\u2026" : "SAVE VIEW"}
              </button>
            </div>
          </div>
        </WindowPanel>
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
    <div style={CHIP_STYLE} data-testid="saved-view-chip">
      <button
        type="button"
        onClick={onApply}
        aria-label={`Apply saved view ${view.name}`}
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: 10,
          color: "var(--text-primary)",
          background: "transparent",
          border: "none",
          padding: 0,
          cursor: "pointer",
        }}
      >
        {view.name}
      </button>
      {view.sharedWithTeam && (
        <UsersThree
          size={11}
          style={{ color: "var(--text-muted)" }}
          aria-label="Shared with team"
        />
      )}
      {onUnpin && (
        <button
          type="button"
          onClick={onUnpin}
          aria-label={`Unpin ${view.name}`}
          style={{
            background: "transparent",
            border: "none",
            padding: 0,
            color: "var(--text-muted)",
            cursor: "pointer",
            display: "inline-flex",
          }}
        >
          <X size={11} />
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dropdown menu -- mono popover anchored to the trigger button
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
      role="menu"
      style={{
        position: "absolute",
        right: 0,
        top: "calc(100% + 4px)",
        zIndex: 50,
        minWidth: 280,
        maxWidth: 360,
        background: "var(--surface-card)",
        border: "1px solid var(--border-soft)",
        borderRadius: 3,
        boxShadow: "0 8px 20px color-mix(in srgb, black 45%, transparent)",
      }}
    >
      <div style={{ maxHeight: 288, overflowY: "auto", padding: "4px 0" }}>
        {isLoading && (
          <p
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)", padding: "6px 12px" }}
          >
            Loading views{"\u2026"}
          </p>
        )}
        {!isLoading && views.length === 0 && (
          <p
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)", padding: "6px 12px" }}
          >
            No saved views yet. Use "SAVE FILTER" to create one.
          </p>
        )}
        {views.map((view) => (
          <div
            key={view.id}
            className="flex items-center justify-between"
            style={{
              gap: 8,
              padding: "5px 10px",
              borderBottom: "1px solid var(--border-faint)",
            }}
          >
            <button
              type="button"
              onClick={() => onApply(view)}
              role="menuitem"
              aria-label={`Apply saved view ${view.name}`}
              title={view.name}
              style={{
                flex: 1,
                minWidth: 0,
                textAlign: "left",
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                color: "var(--text-primary)",
                background: "transparent",
                border: "none",
                padding: 0,
                cursor: "pointer",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {view.name}
              {!view.ownedByMe && (
                <span style={{ color: "var(--text-faint)" }}>{" \u00b7 shared"}</span>
              )}
            </button>
            <div
              className="flex items-center"
              style={{ gap: 6, flexShrink: 0 }}
            >
              {view.sharedWithTeam && !view.ownedByMe && (
                <UsersThree
                  size={12}
                  style={{ color: "var(--text-muted)" }}
                  aria-label="Shared with team"
                />
              )}
              {view.ownedByMe && (
                <>
                  <button
                    type="button"
                    onClick={() => onPin(view.id, !view.isPinned)}
                    aria-label={view.isPinned ? `Unpin ${view.name}` : `Pin ${view.name}`}
                    aria-pressed={view.isPinned}
                    title={view.isPinned ? "Unpin from toolbar" : "Pin to toolbar"}
                    style={{
                      background: "transparent",
                      border: "none",
                      padding: 0,
                      color: view.isPinned ? "var(--accent)" : "var(--text-muted)",
                      cursor: "pointer",
                      display: "inline-flex",
                    }}
                  >
                    <PushPin size={13} weight={view.isPinned ? "fill" : "regular"} />
                  </button>
                  <button
                    type="button"
                    onClick={() => onShare(view.id, !view.sharedWithTeam)}
                    aria-label={
                      view.sharedWithTeam
                        ? `Unshare ${view.name} from team`
                        : `Share ${view.name} with team`
                    }
                    aria-pressed={view.sharedWithTeam}
                    title={
                      view.sharedWithTeam ? "Unshare from team" : "Share with team"
                    }
                    style={{
                      background: "transparent",
                      border: "none",
                      padding: 0,
                      color: view.sharedWithTeam ? "var(--accent)" : "var(--text-muted)",
                      cursor: "pointer",
                      display: "inline-flex",
                    }}
                  >
                    <UsersThree size={13} weight={view.sharedWithTeam ? "fill" : "regular"} />
                  </button>
                  <button
                    type="button"
                    onClick={() => onDelete(view.id)}
                    aria-label={`Delete ${view.name}`}
                    title="Delete view"
                    style={{
                      background: "transparent",
                      border: "none",
                      padding: 0,
                      color: "var(--text-muted)",
                      cursor: "pointer",
                      display: "inline-flex",
                    }}
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
      className={`flex flex-wrap items-center ${className ?? ""}`}
      style={{ gap: 6 }}
      data-testid="saved-views-control"
      data-entity-type={entityType}
    >
      {pinned.length > 0 && (
        <span style={LABEL_STYLE}>Pinned:</span>
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
      <div style={{ position: "relative" }}>
        <button
          type="button"
          onClick={() => setMenuOpen((open) => !open)}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          aria-label={`Show saved ${toolbarLabel.toLowerCase()}`}
          disabled={isLoading && views.length === 0}
          style={{
            ...MONO_BTN,
            opacity: isLoading && views.length === 0 ? 0.5 : 1,
          }}
        >
          <BookmarkSimple size={12} />
          {toolbarLabel.toUpperCase()}
          {views.length > 0 && (
            <span style={{ color: "var(--text-muted)" }}>({views.length})</span>
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
        aria-label={`Save current ${toolbarLabel.toLowerCase().replace(/s$/, "")} as`}
        style={MONO_BTN}
      >
        <BookmarkSimple size={12} />
        SAVE FILTER
      </button>
      {isError && (
        <span
          role="alert"
          className="font-mono"
          style={{ fontSize: 9, color: "var(--status-warn)" }}
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
