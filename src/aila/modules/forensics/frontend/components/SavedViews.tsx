/**
 * SavedViews -- forensics list-surface control rebuilt on the mock kit.
 *
 * Layout:
 *   [ pinned view chips ... ]  [ VIEWS \u25be ]
 *                                    |
 *                                    +-- popover WindowPanel:
 *                                          [ input | SAVE ]
 *                                          [ view row ... ]
 *
 * Pinned views apply on chip click; owner-only chips carry a close
 * pixel-icon that unpins. The trailing "VIEWS" button toggles a
 * positioned WindowPanel below itself with the full library and an
 * inline save-current form. Every data hook, mutation, and testid /
 * aria-label from the previous shadcn presentation is preserved --
 * only the visual grammar shifts.
 */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

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
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  const pinned = useMemo(() => views.filter((v) => v.is_pinned), [views]);

  const handleApply = useCallback(
    (view: SavedView) => {
      const parsed = parseState(view);
      if (parsed === null) return;
      onApply(parsed);
      setPopoverOpen(false);
    },
    [onApply, parseState],
  );

  // Popover lifecycle -- outside pointerdown + Escape close, matching the
  // ergonomics of the previous ModalShell for keyboard operators.
  useEffect(() => {
    if (!popoverOpen) return;
    function handlePointer(e: MouseEvent) {
      const wrapper = wrapperRef.current;
      if (!wrapper) return;
      if (!wrapper.contains(e.target as Node)) setPopoverOpen(false);
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setPopoverOpen(false);
    }
    window.addEventListener("mousedown", handlePointer);
    window.addEventListener("keydown", handleKey);
    return () => {
      window.removeEventListener("mousedown", handlePointer);
      window.removeEventListener("keydown", handleKey);
    };
  }, [popoverOpen]);

  return (
    <div
      ref={wrapperRef}
      className="relative flex flex-wrap items-center gap-2"
    >
      {pinned.map((view) => (
        <PinnedChip
          key={view.id}
          view={view}
          canUnpin={isOwner(view)}
          onApply={() => handleApply(view)}
          onUnpin={() => {
            void pin(view.id, false);
          }}
          testId={`${testIdPrefix}-chip-${view.id}`}
        />
      ))}

      <button
        type="button"
        onClick={() => setPopoverOpen((v) => !v)}
        aria-haspopup="dialog"
        aria-expanded={popoverOpen}
        aria-label="Open saved views"
        data-testid={`${testIdPrefix}-open`}
        className="font-mono uppercase inline-flex items-center gap-2"
        style={{
          height: 26,
          padding: "0 10px",
          fontSize: 10,
          letterSpacing: "0.08em",
          color: popoverOpen ? "var(--accent)" : "var(--text-muted)",
          background: "transparent",
          border: `1px solid ${popoverOpen ? "var(--accent)" : "var(--border-soft)"}`,
          borderRadius: 3,
          cursor: "pointer",
        }}
      >
        <span>VIEWS</span>
        {views.length > 0 && (
          <span
            className="tabular-nums"
            style={{ color: "var(--text-faint)" }}
          >
            ({views.length})
          </span>
        )}
        <span aria-hidden>{"\u25be"}</span>
      </button>

      {popoverOpen && (
        <SavedViewsPopover
          views={views}
          isLoading={isLoading}
          isOwner={isOwner}
          onApply={handleApply}
          onPin={(id, next) => {
            void pin(id, next);
          }}
          onShare={(id, next) => {
            void share(id, next);
          }}
          onRemove={(id) => {
            void remove(id);
          }}
          onSave={async (name) => {
            await saveCurrent(name, currentState, { pinned: true, shared: false });
          }}
          testIdPrefix={testIdPrefix}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pinned chip -- an active FilterChip-shape carrying a tiny close-pixel
// unpin control for owners. Rendered as a span so it can nest the two
// interactive buttons without a nested-button DOM warning.
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
      className="inline-flex items-center font-mono uppercase"
      style={{
        height: 26,
        padding: `0 ${canUnpin ? 4 : 10}px 0 10px`,
        gap: 6,
        fontSize: 9.5,
        letterSpacing: "0.08em",
        color: "var(--accent)",
        background: "color-mix(in srgb, var(--accent) 11%, transparent)",
        border: "1px solid var(--accent)",
        borderRadius: 3,
      }}
      data-testid={testId}
    >
      <button
        type="button"
        onClick={onApply}
        title={`Apply saved view "${view.name}"${sharedLabel}`}
        className="font-mono uppercase truncate"
        style={{
          background: "transparent",
          border: 0,
          color: "var(--accent)",
          fontSize: 9.5,
          letterSpacing: "0.08em",
          padding: 0,
          cursor: "pointer",
          maxWidth: 180,
        }}
      >
        {view.name}
      </button>
      {canUnpin && (
        <button
          type="button"
          onClick={onUnpin}
          aria-label={`Unpin saved view ${view.name}`}
          className="inline-flex items-center justify-center"
          style={{
            width: 16,
            height: 16,
            padding: 0,
            background: "transparent",
            border: 0,
            color: "var(--text-muted)",
            cursor: "pointer",
          }}
        >
          <PixelIcon name="close" size={10} />
        </button>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Popover -- WindowPanel absolutely positioned below the "VIEWS" trigger,
// carrying the inline save-current form and the scrollable view library.
// ---------------------------------------------------------------------------

interface SavedViewsPopoverProps {
  views: SavedView[];
  isLoading: boolean;
  isOwner: (view: SavedView) => boolean;
  onApply: (view: SavedView) => void;
  onPin: (id: string, next: boolean) => void;
  onShare: (id: string, next: boolean) => void;
  onRemove: (id: string) => void;
  onSave: (name: string) => Promise<void>;
  testIdPrefix: string;
}

function SavedViewsPopover({
  views,
  isLoading,
  isOwner,
  onApply,
  onPin,
  onShare,
  onRemove,
  onSave,
  testIdPrefix,
}: SavedViewsPopoverProps) {
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function handleSave(event: FormEvent) {
    event.preventDefault();
    const trimmed = name.trim();
    if (!trimmed || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onSave(trimmed);
      setName("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save view.");
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit = name.trim().length > 0 && !submitting;

  return (
    <div
      className="absolute z-50"
      style={{ top: "calc(100% + 6px)", right: 0, width: 400 }}
      role="dialog"
      aria-labelledby={`${testIdPrefix}-title`}
    >
      <WindowPanel
        title="saved views"
        tone="accent"
        status={
          isLoading
            ? "views ; loading"
            : views.length === 0
              ? "views ; empty"
              : `views ; ${views.length}`
        }
      >
        <div className="space-y-3">
          <h3
            id={`${testIdPrefix}-title`}
            className="sr-only"
          >
            Saved views
          </h3>

          <form onSubmit={handleSave} className="flex items-center gap-2">
            <input
              ref={inputRef}
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="save current as\u2026"
              maxLength={128}
              aria-label="Save current view"
              data-testid={`${testIdPrefix}-save-name`}
              className="flex-1 font-mono"
              style={{
                height: 28,
                padding: "0 10px",
                fontSize: 11,
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                color: "var(--text-primary)",
                borderRadius: 3,
              }}
            />
            <button
              type="submit"
              disabled={!canSubmit}
              data-testid={`${testIdPrefix}-save-submit`}
              className="font-mono uppercase"
              style={{
                height: 28,
                padding: "0 12px",
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-on-accent)",
                background: "var(--accent)",
                border: "1px solid var(--accent)",
                borderRadius: 3,
                cursor: canSubmit ? "pointer" : "not-allowed",
                opacity: canSubmit ? 1 : 0.6,
              }}
            >
              {submitting ? "SAVING\u2026" : "SAVE"}
            </button>
          </form>
          {error && (
            <p
              role="alert"
              className="font-mono"
              style={{ fontSize: 10, color: "var(--accent)" }}
            >
              {error}
            </p>
          )}

          {isLoading && (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              Loading saved views{"\u2026"}
            </p>
          )}

          {!isLoading && views.length === 0 && (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              No saved views yet. Use the input above to persist the current
              search, sort, and filter state.
            </p>
          )}

          {!isLoading && views.length > 0 && (
            <ul
              className="overflow-y-auto"
              style={{
                maxHeight: 300,
                margin: 0,
                padding: 0,
                listStyle: "none",
              }}
              data-testid={`${testIdPrefix}-list`}
            >
              {views.map((view) => (
                <SavedViewRow
                  key={view.id}
                  view={view}
                  owned={isOwner(view)}
                  onApply={() => onApply(view)}
                  onPin={() => onPin(view.id, !view.is_pinned)}
                  onShare={() => onShare(view.id, !view.shared_with_team)}
                  onRemove={() => onRemove(view.id)}
                  testId={`${testIdPrefix}-item-${view.id}`}
                />
              ))}
            </ul>
          )}
        </div>
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single library row: name + team/owner badge + pin/share/delete toggles.
// Extracted so the button styling table doesn't triplicate inside the
// popover map; used 1x today, kept as a component because the props form
// the row's stable contract (owned + view + three callbacks).
// ---------------------------------------------------------------------------

interface SavedViewRowProps {
  view: SavedView;
  owned: boolean;
  onApply: () => void;
  onPin: () => void;
  onShare: () => void;
  onRemove: () => void;
  testId: string;
}

function SavedViewRow({
  view,
  owned,
  onApply,
  onPin,
  onShare,
  onRemove,
  testId,
}: SavedViewRowProps) {
  return (
    <li
      className="flex items-center gap-2"
      style={{
        padding: "6px 4px",
        borderBottom:
          "1px solid color-mix(in srgb, var(--border-soft) 55%, transparent)",
      }}
      data-testid={testId}
    >
      <button
        type="button"
        onClick={onApply}
        className="flex-1 min-w-0 text-left font-mono truncate"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          background: "transparent",
          border: 0,
          cursor: "pointer",
          padding: "0 4px",
        }}
      >
        {view.name}
      </button>
      {!owned && <MonoBadge tone="muted">SHARED</MonoBadge>}
      {view.shared_with_team && owned && (
        <MonoBadge tone="info">TEAM</MonoBadge>
      )}

      <button
        type="button"
        onClick={onPin}
        disabled={!owned}
        aria-label={view.is_pinned ? `Unpin ${view.name}` : `Pin ${view.name}`}
        title={
          owned
            ? view.is_pinned
              ? "Unpin"
              : "Pin to toolbar"
            : "Only the owner can pin"
        }
        className="font-mono uppercase"
        style={{
          height: 22,
          padding: "0 6px",
          fontSize: 9,
          letterSpacing: "0.08em",
          color: view.is_pinned ? "var(--accent)" : "var(--text-muted)",
          background: "transparent",
          border: `1px solid ${view.is_pinned ? "var(--accent)" : "var(--border-soft)"}`,
          borderRadius: 3,
          cursor: owned ? "pointer" : "not-allowed",
          opacity: owned ? 1 : 0.4,
        }}
      >
        {view.is_pinned ? "PINNED" : "PIN"}
      </button>
      <button
        type="button"
        onClick={onShare}
        disabled={!owned}
        aria-label={
          view.shared_with_team
            ? `Unshare ${view.name}`
            : `Share ${view.name} with team`
        }
        title={
          owned
            ? view.shared_with_team
              ? "Unshare"
              : "Share with team"
            : "Only the owner can share"
        }
        className="font-mono uppercase"
        style={{
          height: 22,
          padding: "0 6px",
          fontSize: 9,
          letterSpacing: "0.08em",
          color: view.shared_with_team
            ? "var(--status-info)"
            : "var(--text-muted)",
          background: "transparent",
          border: `1px solid ${view.shared_with_team ? "var(--status-info)" : "var(--border-soft)"}`,
          borderRadius: 3,
          cursor: owned ? "pointer" : "not-allowed",
          opacity: owned ? 1 : 0.4,
        }}
      >
        {view.shared_with_team ? "SHARED" : "SHARE"}
      </button>
      {owned && (
        <button
          type="button"
          onClick={onRemove}
          aria-label={`Delete ${view.name}`}
          title="Delete"
          className="inline-flex items-center justify-center"
          style={{
            width: 22,
            height: 22,
            padding: 0,
            color: "var(--text-muted)",
            background: "transparent",
            border: "1px solid var(--border-soft)",
            borderRadius: 3,
            cursor: "pointer",
          }}
        >
          <PixelIcon name="close" size={10} />
        </button>
      )}
    </li>
  );
}
