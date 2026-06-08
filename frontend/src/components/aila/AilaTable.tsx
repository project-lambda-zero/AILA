import * as React from "react"
import {
  type ColumnDef,
  type SortingState,
  type ColumnFiltersState,
  type PaginationState,
  type Row,
  type RowData,
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
} from "@tanstack/react-table"

import { cn } from "@/lib/utils"

/**
 * Selectors that mark a descendant as "handle its own interaction —
 * do NOT trigger row click" (D-32). The `.no-row-click` class is the
 * documented escape hatch callers can apply to any wrapper.
 */
const INLINE_INTERACTIVE_SELECTOR =
  'button, a, input, select, textarea, [role="button"], .no-row-click, [data-no-row-click]'

function isInlineInteractive(target: EventTarget | null, container: HTMLElement): boolean {
  if (!(target instanceof HTMLElement)) return false
  const hit = target.closest(INLINE_INTERACTIVE_SELECTOR)
  if (!hit) return false
  // The hit must be a descendant of the row we're on, not something farther up.
  return container.contains(hit) && hit !== container
}

// ─────────────────────────────────────────────────────────
// Context — shared table instance between compound components
// ─────────────────────────────────────────────────────────

interface AilaTableContextValue<TData extends RowData> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  table: ReturnType<typeof useReactTable<any>>
  enableFiltering: boolean
  filterValue: string
  setFilterValue: (value: string) => void
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onRowClick?: (row: Row<any>) => void
}

// Using any here because React context generics are not inferrable at runtime
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const AilaTableContext = React.createContext<AilaTableContextValue<any> | null>(null)

function useAilaTable() {
  const ctx = React.useContext(AilaTableContext)
  if (!ctx) {
    throw new Error("AilaTable sub-components must be used inside <AilaTable>")
  }
  return ctx
}

// ─────────────────────────────────────────────────────────
// AilaTable Root
// ─────────────────────────────────────────────────────────

export interface AilaTableProps<TData extends RowData> {
  /**
   * Row data array. Typed via the TData generic parameter.
   */
  data: TData[]
  /**
   * TanStack Table column definitions. Use ColumnDef<TData> for type safety.
   */
  columns: ColumnDef<TData>[]
  /**
   * Initial page size. Defaults to 10. Pagination is always enabled (T-139-06: DoS mitigation).
   */
  pageSize?: number
  /**
   * Enable column header click-to-sort. Defaults to true.
   */
  enableSorting?: boolean
  /**
   * Enable global text filter input above the table. Defaults to false.
   */
  enableFiltering?: boolean
  /**
   * Additional class name for the outer container div.
   */
  className?: string
  /**
   * Children — typically AilaTable.Header, AilaTable.Body, AilaTable.Pagination.
   * If omitted, all three sub-components are rendered in default order.
   */
  children?: React.ReactNode
  /**
   * Optional row click handler (D-04). When set, each body row gains
   * `role="button"`, `tabIndex={0}`, click + keyboard (Enter/Space) navigation.
   * Inline interactive elements (button, a, input, etc.) and descendants of a
   * `.no-row-click` / `[data-no-row-click]` wrapper suppress the row click
   * via stopPropagation-equivalent target audit (D-32).
   */
  onRowClick?: (row: Row<TData>) => void
}

/**
 * AilaTable — headless TanStack Table with cyberpunk styling.
 *
 * Implements compound component pattern (D-20). Uses useReactTable with:
 * - getCoreRowModel() — basic row rendering
 * - getSortedRowModel() — click column header to sort
 * - getFilteredRowModel() — global search filter
 * - getPaginationRowModel() — pagination (always on, T-139-06: prevents unbounded render)
 *
 * Data shape is enforced at compile time via TypeScript generics.
 * Runtime: empty arrays render empty state (T-139-05).
 *
 * @example
 * ```tsx
 * <AilaTable data={vulnerabilities} columns={columns} enableFiltering pageSize={5}>
 *   <AilaTable.Header />
 *   <AilaTable.Body />
 *   <AilaTable.Pagination />
 * </AilaTable>
 * ```
 */
function AilaTable<TData extends RowData>({
  data,
  columns,
  pageSize = 10,
  enableSorting = true,
  enableFiltering = false,
  className,
  children,
  onRowClick,
}: AilaTableProps<TData>) {
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [pagination, setPagination] = React.useState<PaginationState>({
    pageIndex: 0,
    pageSize,
  })
  const [filterValue, setFilterValue] = React.useState("")

  const table = useReactTable({
    data,
    columns,
    state: {
      sorting,
      columnFilters,
      pagination,
      globalFilter: filterValue,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onPaginationChange: setPagination,
    onGlobalFilterChange: setFilterValue,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    enableSorting,
  })

  return (
    <AilaTableContext.Provider value={{ table, enableFiltering, filterValue, setFilterValue, onRowClick }}>
      <div className={cn("bg-surface border border-border rounded-[4px] overflow-hidden", className)}>
        {children ?? (
          <>
            <AilaTableHeader />
            <AilaTableBody />
            <AilaTablePagination />
          </>
        )}
      </div>
    </AilaTableContext.Provider>
  )
}

// ─────────────────────────────────────────────────────────
// AilaTable.Header
// ─────────────────────────────────────────────────────────

export interface AilaTableHeaderProps {
  /** Additional class name for the header section wrapper. */
  className?: string
}

/**
 * AilaTable.Header — renders column headers with optional sort indicators.
 *
 * Click a sortable column header to cycle: ascending → descending → unsorted.
 * Active sorted column shows amber accent indicator.
 * When `enableFiltering` is true on the parent, renders a global search input above headers.
 */
function AilaTableHeader({ className }: AilaTableHeaderProps) {
  const { table, enableFiltering, filterValue, setFilterValue } = useAilaTable()

  return (
    <div className={cn("", className)}>
      {enableFiltering && (
        <div className="px-4 py-2 border-b border-border">
          <input
            aria-label="Filter table rows"
            value={filterValue}
            onChange={(e) => setFilterValue(e.target.value)}
            placeholder="Filter..."
            className={cn(
              "w-full rounded-[2px] border border-border bg-base px-2.5 py-1",
              "font-mono text-text text-sm placeholder:text-text-muted",
              "outline-none focus:border-border-hover",
              "transition-colors duration-100"
            )}
          />
        </div>
      )}
      <table className="w-full border-collapse">
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id} className="bg-elevated border-b border-border">
              {headerGroup.headers.map((header) => {
                const isSorted = header.column.getIsSorted()
                const canSort = header.column.getCanSort()
                return (
                  <th
                    key={header.id}
                    className={cn(
                      "px-4 py-2 text-left font-mono text-xs uppercase tracking-wider text-text-muted",
                      canSort && "cursor-pointer select-none hover:text-text transition-colors duration-100",
                      isSorted && "text-accent"
                    )}
                    onClick={canSort ? header.column.getToggleSortingHandler() : undefined}
                  >
                    <span className="flex items-center gap-1">
                      {header.isPlaceholder
                        ? null
                        : flexRender(header.column.columnDef.header, header.getContext())}
                      {canSort && (
                        <span className="font-mono text-xs">
                          {isSorted === "asc" ? "↑" : isSorted === "desc" ? "↓" : ""}
                        </span>
                      )}
                    </span>
                  </th>
                )
              })}
            </tr>
          ))}
        </thead>
      </table>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// AilaTable.Body
// ─────────────────────────────────────────────────────────

export interface AilaTableBodyProps {
  /** Additional class name for the table body wrapper. */
  className?: string
  /** Content to render when there are no rows. Defaults to a centered empty state message. */
  emptyState?: React.ReactNode
}

/**
 * AilaTable.Body — renders data rows with cyberpunk row styling.
 *
 * Rows: dark surface bg, amber bottom border, hover to elevated/50 bg.
 * Renders empty state when no data or no rows match active filter (T-139-05).
 */
function AilaTableBody({ className, emptyState }: AilaTableBodyProps) {
  const { table, onRowClick } = useAilaTable()
  const rows = table.getRowModel().rows

  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full border-collapse">
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={table.getAllColumns().length}
                className="px-4 py-8 text-center font-mono text-sm text-text-muted"
              >
                {emptyState ?? "No data"}
              </td>
            </tr>
          ) : (
            rows.map((row) => {
              const interactive = Boolean(onRowClick)
              const handleActivate = (event: React.SyntheticEvent) => {
                const currentRow = event.currentTarget as HTMLElement
                if (isInlineInteractive(event.target, currentRow)) return
                onRowClick?.(row)
              }
              return (
                <tr
                  key={row.id}
                  role={interactive ? "button" : undefined}
                  tabIndex={interactive ? 0 : undefined}
                  data-testid="aila-table-row"
                  className={cn(
                    "border-b border-border hover:bg-elevated/50 transition-colors duration-100 last:border-0",
                    interactive && "cursor-pointer focus:outline focus:outline-2 focus:outline-accent",
                  )}
                  onClick={interactive ? handleActivate : undefined}
                  onKeyDown={
                    interactive
                      ? (event: React.KeyboardEvent<HTMLTableRowElement>) => {
                          if (event.key === "Enter" || event.key === " ") {
                            if (event.key === " ") event.preventDefault()
                            handleActivate(event)
                          }
                        }
                      : undefined
                  }
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="px-4 py-2.5 font-mono text-sm text-text"
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// AilaTable.Pagination
// ─────────────────────────────────────────────────────────

export interface AilaTablePaginationProps {
  /** Additional class name for the pagination bar. */
  className?: string
  /** Available page size options. Defaults to [10, 25, 50]. */
  pageSizeOptions?: number[]
}

/**
 * AilaTable.Pagination — pagination bar with page info, size selector, and nav buttons.
 *
 * Styled with amber accent for active controls (D-02).
 * Page size selector limits rendered rows (T-139-06: unbounded data DoS mitigation).
 */
function AilaTablePagination({ className, pageSizeOptions = [10, 25, 50] }: AilaTablePaginationProps) {
  const { table } = useAilaTable()
  const { pageIndex, pageSize } = table.getState().pagination
  const pageCount = table.getPageCount()
  const totalRows = table.getFilteredRowModel().rows.length

  const start = pageIndex * pageSize + 1
  const end = Math.min((pageIndex + 1) * pageSize, totalRows)

  return (
    <div
      className={cn(
        "flex items-center justify-between gap-4 px-4 py-2 border-t border-border bg-elevated",
        className
      )}
    >
      {/* Row info */}
      <span className="font-mono text-xs text-text-muted">
        {totalRows === 0 ? "0 rows" : `${start}–${end} of ${totalRows}`}
      </span>

      {/* Page size selector */}
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs text-text-muted">Rows</span>
        <select
          aria-label="Rows per page"
          value={pageSize}
          onChange={(e) => table.setPageSize(Number(e.target.value))}
          className={cn(
            "rounded-[2px] border border-border bg-base font-mono text-xs text-text",
            "px-1.5 py-0.5 outline-none cursor-pointer",
            "hover:border-border-hover transition-colors duration-100"
          )}
        >
          {pageSizeOptions.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </div>

      {/* Navigation */}
      <div className="flex items-center gap-1">
        <button
          onClick={() => table.setPageIndex(0)}
          disabled={!table.getCanPreviousPage()}
          className={cn(
            "rounded-[2px] border border-border px-2 py-0.5 font-mono text-xs",
            "transition-colors duration-100",
            table.getCanPreviousPage()
              ? "text-text hover:border-border-hover hover:text-accent"
              : "text-text-muted opacity-40 cursor-not-allowed"
          )}
          aria-label="First page"
        >
          {"<<"}
        </button>
        <button
          onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
          className={cn(
            "rounded-[2px] border border-border px-2 py-0.5 font-mono text-xs",
            "transition-colors duration-100",
            table.getCanPreviousPage()
              ? "text-text hover:border-border-hover hover:text-accent"
              : "text-text-muted opacity-40 cursor-not-allowed"
          )}
          aria-label="Previous page"
        >
          {"<"}
        </button>
        <span className="font-mono text-xs text-text-muted px-2">
          {pageIndex + 1} / {Math.max(1, pageCount)}
        </span>
        <button
          onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
          className={cn(
            "rounded-[2px] border border-border px-2 py-0.5 font-mono text-xs",
            "transition-colors duration-100",
            table.getCanNextPage()
              ? "text-text hover:border-border-hover hover:text-accent"
              : "text-text-muted opacity-40 cursor-not-allowed"
          )}
          aria-label="Next page"
        >
          {">"}
        </button>
        <button
          onClick={() => table.setPageIndex(pageCount - 1)}
          disabled={!table.getCanNextPage()}
          className={cn(
            "rounded-[2px] border border-border px-2 py-0.5 font-mono text-xs",
            "transition-colors duration-100",
            table.getCanNextPage()
              ? "text-text hover:border-border-hover hover:text-accent"
              : "text-text-muted opacity-40 cursor-not-allowed"
          )}
          aria-label="Last page"
        >
          {">>"}
        </button>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Compound component attachment
// ─────────────────────────────────────────────────────────

AilaTable.Header = AilaTableHeader
AilaTable.Body = AilaTableBody
AilaTable.Pagination = AilaTablePagination

export { AilaTable }
