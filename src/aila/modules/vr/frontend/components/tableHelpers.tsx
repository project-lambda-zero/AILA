import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from "react";

import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { CaretUp } from "@phosphor-icons/react/dist/csr/CaretUp";
import { CaretUpDown } from "@phosphor-icons/react/dist/csr/CaretUpDown";

/**
 * VR list-screen power-table helpers.
 *
 *  * useDebouncedValue -- generic debounce, matches the CommandPalette
 *    helper so callers get consistent behavior for typing into a
 *    search box that drives a TanStack Query key.
 *  * useSortableRows / SortHeader -- client-side sort cycle
 *    (asc → desc → none) with a stable tiebreaker on the original
 *    row order. Nulls sink regardless of direction.
 *  * useTableRowNav -- roving-tabindex j/k/Enter row navigation for
 *    a `<tbody>` (or any container element). Cooperates with the
 *    global KeyboardShortcutsController by short-circuiting on any
 *    Cmd/Ctrl/Alt modifier and on any editable descendant.
 */

// ── useDebouncedValue ──────────────────────────────────────────────────

export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const handle = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(handle);
  }, [value, delayMs]);
  return debounced;
}

// ── Sortable rows ─────────────────────────────────────────────────────

export type SortDir = "asc" | "desc" | null;

export type SortValue = string | number | Date | boolean | null | undefined;

/**
 * Client-side sort helper.
 *
 * Cycles asc → desc → none per column, keeps the original row order as
 * a stable tiebreaker, and pushes null/empty values to the tail
 * regardless of direction so an empty column doesn't win the top slot
 * on descending sort.
 *
 * `accessors` is captured via ref so callers may inline the object
 * literal without triggering a resort on every parent render.
 */
export function useSortableRows<T>(
  rows: readonly T[],
  accessors: Record<string, (row: T) => SortValue>,
): {
  sortedRows: readonly T[];
  sortKey: string;
  sortDir: SortDir;
  cycleSort: (columnKey: string) => void;
} {
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>({
    key: "",
    dir: null,
  });

  const accessorsRef = useRef(accessors);
  accessorsRef.current = accessors;

  const cycleSort = useCallback((next: string) => {
    setSort((prev) => {
      if (prev.key !== next) return { key: next, dir: "asc" };
      if (prev.dir === "asc") return { key: next, dir: "desc" };
      if (prev.dir === "desc") return { key: "", dir: null };
      return { key: next, dir: "asc" };
    });
  }, []);

  const sortedRows = useMemo(() => {
    const { key, dir } = sort;
    if (!key || !dir) return rows.slice();
    const acc = accessorsRef.current[key];
    if (!acc) return rows.slice();
    const sign = dir === "asc" ? 1 : -1;
    const indexed = rows.map(
      (row, i) => [row, i, acc(row)] as readonly [T, number, SortValue],
    );
    indexed.sort((a, b) => {
      const av = a[2];
      const bv = b[2];
      const aNull = av === null || av === undefined || av === "";
      const bNull = bv === null || bv === undefined || bv === "";
      if (aNull && bNull) return a[1] - b[1];
      if (aNull) return 1;
      if (bNull) return -1;
      let cmp = 0;
      if (typeof av === "number" && typeof bv === "number") {
        cmp = av - bv;
      } else if (av instanceof Date && bv instanceof Date) {
        cmp = av.getTime() - bv.getTime();
      } else if (typeof av === "boolean" && typeof bv === "boolean") {
        cmp = Number(av) - Number(bv);
      } else {
        cmp = String(av).localeCompare(String(bv), undefined, {
          numeric: true,
          sensitivity: "base",
        });
      }
      if (cmp === 0) return a[1] - b[1];
      return cmp * sign;
    });
    return indexed.map(([r]) => r);
  }, [rows, sort]);

  return {
    sortedRows,
    sortKey: sort.dir ? sort.key : "",
    sortDir: sort.dir,
    cycleSort,
  };
}

// ── SortHeader cell ────────────────────────────────────────────────────

interface SortHeaderProps {
  columnKey: string;
  currentKey: string;
  currentDir: SortDir;
  onSort: (columnKey: string) => void;
  children: ReactNode;
  align?: "left" | "right";
  /** Extra classes appended to the `<th>` (never to the inner button). */
  className?: string;
}

/**
 * A `<th>` whose entire label is a real button so keyboard operators
 * can Tab to it and press Enter/Space to cycle the sort. `aria-sort`
 * reflects the current column state per WAI-ARIA 1.2.
 */
export function SortHeader({
  columnKey,
  currentKey,
  currentDir,
  onSort,
  children,
  align = "left",
  className = "",
}: SortHeaderProps) {
  const active = currentKey === columnKey && currentDir !== null;
  const ariaSort: "ascending" | "descending" | "none" = active
    ? currentDir === "asc"
      ? "ascending"
      : "descending"
    : "none";
  const Arrow = active
    ? currentDir === "asc"
      ? CaretUp
      : CaretDown
    : CaretUpDown;
  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={`px-4 py-2 font-semibold ${align === "right" ? "text-right" : "text-left"} ${className}`}
    >
      <button
        type="button"
        onClick={() => onSort(columnKey)}
        className={
          "inline-flex items-center gap-1 uppercase tracking-wide font-semibold text-inherit rounded-sm " +
          "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent hover:text-foreground transition-colors " +
          (active ? "text-foreground" : "")
        }
      >
        <span>{children}</span>
        <Arrow
          className="h-3 w-3 shrink-0"
          weight={active ? "bold" : "regular"}
          aria-hidden
        />
      </button>
    </th>
  );
}

// ── useTableRowNav ─────────────────────────────────────────────────────

export interface TableRowNavRowProps {
  tabIndex: number;
  "aria-selected": boolean;
  "data-row-index": number;
  "data-row-active"?: "true";
  onFocus: () => void;
}

/**
 * Roving-tabindex keyboard navigation for a table body (or any list
 * container). Bind `tbodyProps.onKeyDown` to a wrapping element that
 * OWNS focus for the list -- j/k or Down/Up move the highlight, Enter
 * calls `onOpen` on the active row. Keys with meta/ctrl/alt or those
 * dispatched from an editable descendant are ignored so the global
 * chord layer and any inline text inputs keep their bindings; Enter
 * dispatched on a nested `<button>`/`<a>` also passes through so
 * per-row actions (delete, favorite) fire correctly.
 *
 * `containerRef` scopes the row lookup so multiple lists on one page
 * don't interfere; each list gets its own hook + ref.
 */
export function useTableRowNav<T>(
  rows: readonly T[],
  onOpen: (row: T) => void,
  containerRef: RefObject<HTMLElement | null>,
): {
  activeIdx: number;
  tbodyProps: { onKeyDown: (event: ReactKeyboardEvent<HTMLElement>) => void };
  getRowProps: (idx: number) => TableRowNavRowProps;
} {
  const [activeIdx, setActiveIdx] = useState<number>(-1);

  useEffect(() => {
    // Clamp when the list shrinks or empties.
    if (rows.length === 0) {
      if (activeIdx !== -1) setActiveIdx(-1);
    } else if (activeIdx >= rows.length) {
      setActiveIdx(rows.length - 1);
    }
  }, [rows.length, activeIdx]);

  const focusRowByIndex = useCallback(
    (idx: number) => {
      const root = containerRef.current;
      if (!root) return;
      const el = root.querySelector<HTMLElement>(
        `[data-row-index="${idx}"]`,
      );
      if (el && document.activeElement !== el) {
        el.focus({ preventScroll: false });
      }
    },
    [containerRef],
  );

  const onKeyDown = useCallback(
    (e: ReactKeyboardEvent<HTMLElement>) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      if (target) {
        const tag = target.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT")
          return;
        if (target.isContentEditable) return;
        const role = target.getAttribute("role");
        if (role === "textbox" || role === "combobox" || role === "searchbox")
          return;
      }
      if (rows.length === 0) return;

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        const next =
          activeIdx < 0 ? 0 : Math.min(rows.length - 1, activeIdx + 1);
        setActiveIdx(next);
        window.requestAnimationFrame(() => focusRowByIndex(next));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        const next = activeIdx < 0 ? 0 : Math.max(0, activeIdx - 1);
        setActiveIdx(next);
        window.requestAnimationFrame(() => focusRowByIndex(next));
      } else if (e.key === "Enter") {
        // Only intercept Enter on the row itself; nested buttons/links
        // handle their own activation.
        const tag = target?.tagName;
        if (tag === "BUTTON" || tag === "A") return;
        if (activeIdx >= 0 && activeIdx < rows.length) {
          e.preventDefault();
          onOpen(rows[activeIdx]);
        }
      }
    },
    [rows, activeIdx, onOpen, focusRowByIndex],
  );

  const getRowProps = useCallback(
    (idx: number): TableRowNavRowProps => {
      // Roving tabindex: exactly one row participates in tab order.
      // Before the user interacts, row 0 is the tab entry point.
      const isEntry = activeIdx < 0 ? idx === 0 : idx === activeIdx;
      return {
        tabIndex: isEntry ? 0 : -1,
        "aria-selected": activeIdx === idx,
        "data-row-index": idx,
        ...(activeIdx === idx ? { "data-row-active": "true" as const } : {}),
        onFocus: () => {
          if (activeIdx !== idx) setActiveIdx(idx);
        },
      };
    },
    [activeIdx],
  );

  return {
    activeIdx,
    tbodyProps: { onKeyDown },
    getRowProps,
  };
}
