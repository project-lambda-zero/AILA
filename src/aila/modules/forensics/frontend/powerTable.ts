// Local power-table primitives for @aila/forensics-frontend.
//
// Kept in-module (not shared with @aila/vulnerability-frontend) because
// modules MUST NOT depend on each other. If the vulnerability module also
// needs these, a byte-identical copy lives in its own frontend package.
//
// What this file provides:
//
//   * ``useSortState`` -- controlled tri-state (asc/desc/none) sort with
//     ``getHeaderProps`` that hands back ``onClick`` + ``aria-sort`` so the
//     resulting <th> passes WCAG 1.3.1 / 4.1.2 without the caller having to
//     remember to attach both.
//   * ``sortRows`` -- pure helper that applies the sort state to a row list
//     with a caller-supplied accessor. Uses ``Intl.Collator`` for stable,
//     locale-aware string ordering with a numeric-key tie-breaker.
//   * ``useDebouncedValue`` -- copy of the pattern already used by
//     ``CommandPalette.tsx`` (frontend/src/components/shell/CommandPalette.tsx).
//     Kept local because that hook is private to the shell.
//   * ``useRowKeyboardNav`` -- j / k / Enter / Home / End keyboard navigation
//     scoped to a container ref. Cooperates with the global cheatsheet /
//     go-chord layer (KeyboardShortcutsProvider) by:
//       - Ignoring keydowns fired while a text input / textarea / contenteditable
//         is focused (so typing "j" in a search box does not steal focus).
//       - Ignoring keydowns with any modifier (Cmd/Ctrl/Alt/Meta) -- those
//         belong to the palette + go-chord layer, never to the local table.
//       - Only handling the key when focus is already inside the container
//         (or has never been set within the table). This makes the shortcut
//         inert on any page that does not currently own the tabbed focus.

import * as React from "react";

// ---------------------------------------------------------------------------
// Sort state
// ---------------------------------------------------------------------------

export type SortDirection = "asc" | "desc" | null;

export interface SortState<K extends string = string> {
  key: K | null;
  direction: SortDirection;
}

export interface SortHeaderProps {
  onClick: () => void;
  onKeyDown: (event: React.KeyboardEvent<HTMLElement>) => void;
  "aria-sort": "ascending" | "descending" | "none";
  role: "button";
  tabIndex: 0;
  "data-power-sort": "asc" | "desc" | "none";
}

/**
 * Tri-state sort store. ``getHeaderProps(key)`` returns everything a
 * sortable <th> needs -- click + Enter/Space handlers, `aria-sort`,
 * `role="button"`, `tabIndex={0}` -- so the caller does not have to
 * re-derive them per column. Click / Enter cycles asc -> desc -> none.
 */
export function useSortState<K extends string>(
  initial: SortState<K> = { key: null, direction: null },
): {
  sort: SortState<K>;
  setSort: (next: SortState<K>) => void;
  toggle: (key: K) => void;
  getHeaderProps: (key: K) => SortHeaderProps;
} {
  const [sort, setSort] = React.useState<SortState<K>>(initial);

  const toggle = React.useCallback((key: K) => {
    setSort((prev) => {
      if (prev.key !== key) return { key, direction: "asc" };
      if (prev.direction === "asc") return { key, direction: "desc" };
      if (prev.direction === "desc") return { key: null, direction: null };
      return { key, direction: "asc" };
    });
  }, []);

  const getHeaderProps = React.useCallback(
    (key: K): SortHeaderProps => {
      const active = sort.key === key ? sort.direction : null;
      const ariaSort =
        active === "asc" ? "ascending" : active === "desc" ? "descending" : "none";
      return {
        onClick: () => toggle(key),
        onKeyDown: (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            toggle(key);
          }
        },
        "aria-sort": ariaSort,
        role: "button",
        tabIndex: 0,
        "data-power-sort": active === "asc" ? "asc" : active === "desc" ? "desc" : "none",
      };
    },
    [sort, toggle],
  );

  return { sort, setSort, toggle, getHeaderProps };
}

const collator =
  typeof Intl !== "undefined" && typeof Intl.Collator === "function"
    ? new Intl.Collator(undefined, { numeric: true, sensitivity: "base" })
    : null;

function compareValues(a: unknown, b: unknown): number {
  // Nulls sort last regardless of direction (so operators do not have to
  // scroll past a wall of blanks to find real rows). Callers that want
  // nulls-first should flip the direction.
  const aNull = a === null || a === undefined || a === "";
  const bNull = b === null || b === undefined || b === "";
  if (aNull && bNull) return 0;
  if (aNull) return 1;
  if (bNull) return -1;
  if (typeof a === "number" && typeof b === "number") {
    return a === b ? 0 : a < b ? -1 : 1;
  }
  if (typeof a === "boolean" && typeof b === "boolean") {
    return a === b ? 0 : a ? -1 : 1;
  }
  const sa = String(a);
  const sb = String(b);
  if (collator) return collator.compare(sa, sb);
  return sa === sb ? 0 : sa < sb ? -1 : 1;
}

/**
 * Pure sort helper. Returns a new array; the input is not mutated. When
 * ``direction`` is null the input order is preserved (returned as a shallow
 * copy so downstream code can safely mutate it).
 */
export function sortRows<T>(
  rows: readonly T[],
  accessor: (row: T) => unknown,
  direction: SortDirection,
): T[] {
  const copy = rows.slice();
  if (direction === null) return copy;
  const factor = direction === "asc" ? 1 : -1;
  copy.sort((a, b) => compareValues(accessor(a), accessor(b)) * factor);
  return copy;
}

// ---------------------------------------------------------------------------
// Debounced value -- copy of the CommandPalette pattern so we do not have to
// reach into a shell-private hook. Same behavior: schedules a timeout on
// every value change and cancels the previous one.
// ---------------------------------------------------------------------------

export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const handle = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(handle);
  }, [value, delayMs]);
  return debounced;
}

// ---------------------------------------------------------------------------
// Row keyboard nav
// ---------------------------------------------------------------------------

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (target.isContentEditable) return true;
  return false;
}

export interface RowKeyboardNavOptions {
  /** The container that owns the navigable rows. */
  containerRef: React.RefObject<HTMLElement | null>;
  /** Selector that resolves the ordered list of navigable rows. */
  rowSelector: string;
  /** Fired when Enter (or Space) activates the focused row. Defaults to click(). */
  onActivate?: (element: HTMLElement, index: number) => void;
  /** Disable the listener without unmounting the caller. */
  enabled?: boolean;
}

/**
 * Wire j / k / Enter / Home / End on a container ref. The listener is
 * mounted at ``document`` so it fires no matter which descendant currently
 * owns focus -- but it self-scopes to the container: unless focus is
 * inside the container (or the container is the sole navigable table on
 * screen), the keydown is ignored.
 *
 * Cooperation with the global chord / cheatsheet layer:
 *   - Any modifier (Cmd/Ctrl/Alt/Meta) short-circuits so palette and
 *     go-chord shortcuts keep their bindings.
 *   - Any keydown originating from an editable target (input / textarea /
 *     contenteditable) short-circuits so typing "j" in a search box never
 *     jumps rows.
 *   - "?" is left alone (the cheatsheet owns it).
 */
export function useRowKeyboardNav(opts: RowKeyboardNavOptions): void {
  const { containerRef, rowSelector, onActivate, enabled = true } = opts;

  React.useEffect(() => {
    if (!enabled) return undefined;
    const handler = (event: KeyboardEvent) => {
      if (event.defaultPrevented) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (isTypingTarget(event.target)) return;
      const container = containerRef.current;
      if (!container) return;
      const active = document.activeElement as HTMLElement | null;
      // Only claim the keydown when focus is already inside the container.
      // This lets multiple tables coexist without stealing each other's
      // keys, and keeps the shortcut inert on unrelated pages.
      if (active && !container.contains(active)) return;

      const key = event.key;
      if (key !== "j" && key !== "k" && key !== "Enter" && key !== "Home" && key !== "End") {
        return;
      }

      const rows = Array.from(
        container.querySelectorAll<HTMLElement>(rowSelector),
      ).filter((el) => !el.hasAttribute("disabled") && el.offsetParent !== null);
      if (rows.length === 0) return;

      const currentIndex = active ? rows.indexOf(active) : -1;

      if (key === "Enter") {
        if (currentIndex < 0) return;
        event.preventDefault();
        const row = rows[currentIndex];
        if (onActivate) onActivate(row, currentIndex);
        else row.click();
        return;
      }

      let nextIndex = currentIndex;
      if (key === "j") nextIndex = currentIndex < 0 ? 0 : Math.min(rows.length - 1, currentIndex + 1);
      else if (key === "k") nextIndex = currentIndex < 0 ? 0 : Math.max(0, currentIndex - 1);
      else if (key === "Home") nextIndex = 0;
      else if (key === "End") nextIndex = rows.length - 1;

      if (nextIndex === currentIndex) {
        // Still preventDefault so the browser doesn't scroll from Home/End.
        if (key === "Home" || key === "End") event.preventDefault();
        return;
      }
      event.preventDefault();
      rows[nextIndex].focus();
    };

    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [containerRef, rowSelector, onActivate, enabled]);
}
