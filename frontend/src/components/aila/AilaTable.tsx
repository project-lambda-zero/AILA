import * as React from "react"
import {
  type ColumnDef,
  type SortingState,
  type ColumnFiltersState,
  type PaginationState,
  type Row,
  type RowData,
  type Table,
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
} from "@tanstack/react-table"
import { Download, Eye } from "lucide-react"

import { cn } from "@/lib/utils"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  exportRowsAsCsv,
  exportRowsAsJson,
  type TableExportColumn,
} from "@/lib/tableExport"

/** Injected column id for the row peek affordance. Kept out of export. */
const PEEK_COLUMN_ID = "__aila_peek__"

/**
 * Selectors that mark a descendant as "handle its own interaction --
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
// Context -- shared table instance between compound components
// ─────────────────────────────────────────────────────────

/**
 * Shared context payload for the compound components. All row-typed slots
 * bottom out at `unknown` because the context is a single React runtime
 * instance shared across every AilaTable mount; callers who need their
 * `TData` narrowing use the strongly-typed props on the root, not the
 * context.
 */
export interface AilaTableContextValue {
  table: Table<RowData>
  enableFiltering: boolean
  filterValue: string
  setFilterValue: (value: string) => void
  onRowClick?: (row: Row<RowData>) => void
  enableExport: boolean
  exportFilename: string
  exportColumns?: readonly TableExportColumn<RowData>[]
  hasPeek: boolean
  onOpenPeek?: (row: RowData) => void
  peekLabel?: (row: RowData) => string
}

const AilaTableContext = React.createContext<AilaTableContextValue | null>(null)

function useAilaTable(): AilaTableContextValue {
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
   * Children -- typically AilaTable.Header, AilaTable.Body, AilaTable.Pagination.
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
  /**
   * Render the current view as CSV or JSON from a small toolbar control.
   * Defaults to `true`. Set `false` to hide the Export button entirely.
   * The exported row set is the current filter/sort output (all filtered
   * rows across pages, not just the visible page); the exported columns
   * default to every column with an accessor and can be overridden via
   * `exportColumns`.
   */
  enableExport?: boolean
  /**
   * Base filename (no extension) for CSV / JSON downloads. Non-word chars
   * are collapsed to `-`. Defaults to `"table-export"`.
   */
  exportFilename?: string
  /**
   * Optional explicit export column spec. When omitted, AilaTable derives
   * one column per accessor column (accessorKey OR accessorFn), using the
   * column's string header as the label. Provide this to flatten nested
   * fields, join arrays, or expose values that are computed in the cell
   * render but absent from the underlying row shape.
   */
  exportColumns?: readonly TableExportColumn<TData>[]
  /**
   * Opt-in row quick-peek. When set, each row grows a keyboard-accessible
   * peek button in a trailing actions column; clicking it opens a Sheet
   * (right-side slide-over) that renders the caller's peek content for
   * that row. When absent, no column is injected and the rendered table
   * markup is byte-identical to today.
   */
  renderRowPeek?: (row: TData) => React.ReactNode
  /**
   * aria-label producer for the peek button. Defaults to `"Show details"`.
   * Supply a per-row label (e.g. `` (row) => `Details for ${row.name}` ``)
   * so assistive tech can distinguish rows.
   */
  peekLabel?: (row: TData) => string
  /**
   * Sheet title. Defaults to `"Details"`. Rendered inside the standard
   * SheetHeader (visible + programmatically accessible).
   */
  peekTitle?: (row: TData) => React.ReactNode
  /**
   * Optional Sheet description, rendered under the title.
   */
  peekDescription?: (row: TData) => React.ReactNode
}

/**
 * AilaTable -- headless TanStack Table with cyberpunk styling.
 *
 * Implements compound component pattern (D-20). Uses useReactTable with:
 * - getCoreRowModel() -- basic row rendering
 * - getSortedRowModel() -- click column header to sort
 * - getFilteredRowModel() -- global search filter
 * - getPaginationRowModel() -- pagination (always on, T-139-06: prevents unbounded render)
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
  enableExport = true,
  exportFilename = "table-export",
  exportColumns,
  renderRowPeek,
  peekLabel,
  peekTitle,
  peekDescription,
}: AilaTableProps<TData>) {
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [pagination, setPagination] = React.useState<PaginationState>({
    pageIndex: 0,
    pageSize,
  })
  const [filterValue, setFilterValue] = React.useState("")
  const [peekRow, setPeekRow] = React.useState<TData | null>(null)

  // Inject a trailing peek column only when `renderRowPeek` is set. When the
  // caller does not provide one we return the caller's array by-reference so
  // TanStack's column identity stays stable and the rendered markup is
  // byte-identical to a plain AilaTable.
  const effectiveColumns = React.useMemo<ColumnDef<TData>[]>(() => {
    if (!renderRowPeek) return columns
    const peekColumn: ColumnDef<TData> = {
      id: PEEK_COLUMN_ID,
      enableSorting: false,
      enableGlobalFilter: false,
      header: () => <span className="sr-only">Row details</span>,
      cell: ({ row }) => (
        <button
          type="button"
          data-no-row-click=""
          onClick={(event) => {
            event.stopPropagation()
            setPeekRow(row.original)
          }}
          aria-label={peekLabel?.(row.original) ?? "Show details"}
          className={cn(
            "inline-flex items-center justify-center h-6 w-6 rounded-[2px]",
            "border border-border bg-base text-text-muted",
            "hover:text-accent hover:border-border-hover transition-colors duration-100",
            "focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-2",
          )}
        >
          <Eye className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      ),
    }
    return [...columns, peekColumn]
  }, [columns, renderRowPeek, peekLabel])

  const table = useReactTable({
    data,
    columns: effectiveColumns,
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

  // The context loses TData narrowing (see AilaTableContextValue). Widen at
  // this one boundary; the sub-components only reach into the row via
  // `flexRender`, which typechecks on the ColumnDef, not the context.
  const contextValue = React.useMemo<AilaTableContextValue>(
    () => ({
      table: table as unknown as Table<RowData>,
      enableFiltering,
      filterValue,
      setFilterValue,
      onRowClick: onRowClick as ((row: Row<RowData>) => void) | undefined,
      enableExport,
      exportFilename,
      exportColumns: exportColumns as readonly TableExportColumn<RowData>[] | undefined,
      hasPeek: Boolean(renderRowPeek),
      onOpenPeek: renderRowPeek
        ? ((row: RowData) => setPeekRow(row as TData))
        : undefined,
      peekLabel: peekLabel as ((row: RowData) => string) | undefined,
    }),
    [
      table,
      enableFiltering,
      filterValue,
      onRowClick,
      enableExport,
      exportFilename,
      exportColumns,
      renderRowPeek,
      peekLabel,
    ],
  )

  return (
    <AilaTableContext.Provider value={contextValue}>
      <div className={cn("bg-surface border border-border rounded-[4px] overflow-hidden", className)}>
        {children ?? (
          <>
            <AilaTableHeader />
            <AilaTableBody />
            <AilaTablePagination />
          </>
        )}
      </div>
      {renderRowPeek && (
        <Sheet
          open={peekRow !== null}
          onOpenChange={(open) => {
            if (!open) setPeekRow(null)
          }}
        >
          <SheetContent side="right" className="w-full max-w-md sm:max-w-md">
            <SheetHeader>
              <SheetTitle className="font-mono text-text">
                {peekRow !== null && peekTitle
                  ? peekTitle(peekRow)
                  : "Details"}
              </SheetTitle>
              {peekRow !== null && peekDescription && (
                <SheetDescription className="font-mono text-xs text-text-muted">
                  {peekDescription(peekRow)}
                </SheetDescription>
              )}
            </SheetHeader>
            <div className="flex-1 overflow-y-auto px-4 pb-4">
              {peekRow !== null && renderRowPeek(peekRow)}
            </div>
          </SheetContent>
        </Sheet>
      )}
    </AilaTableContext.Provider>
  )
}

// ─────────────────────────────────────────────────────────
// Toolbar -- Export control
// ─────────────────────────────────────────────────────────

/**
 * Derive an export column list from the table's visible columns whenever the
 * caller has not supplied `exportColumns`. Skip:
 *  - the injected peek column (no data)
 *  - any column without an accessor (selection checkbox, actions column)
 * Use the column's string header as the CSV / JSON key; fall back to the
 * column id when the header is a render function.
 */
function deriveExportColumnsFromTable(
  table: Table<RowData>,
): TableExportColumn<RowData>[] {
  const spec: TableExportColumn<RowData>[] = []
  for (const col of table.getVisibleFlatColumns()) {
    if (col.id === PEEK_COLUMN_ID) continue
    const def = col.columnDef
    const hasAccessorKey = "accessorKey" in def && def.accessorKey !== undefined
    const hasAccessorFn = "accessorFn" in def && typeof def.accessorFn === "function"
    if (!hasAccessorKey && !hasAccessorFn) continue
    const header =
      typeof def.header === "string" && def.header.length > 0 ? def.header : col.id
    spec.push({
      id: col.id,
      header,
      // `Column.accessorFn` is stored on the internal column instance and
      // reads the resolved value for a row -- this is the identical path
      // TanStack uses to render `getValue()`.
      accessor: (row) => {
        const fn = col.accessorFn
        if (typeof fn === "function") return fn(row, 0)
        return undefined
      },
    })
  }
  return spec
}

interface AilaTableExportControlProps {
  table: Table<RowData>
  filename: string
  exportColumns?: readonly TableExportColumn<RowData>[]
}

function AilaTableExportControl({
  table,
  filename,
  exportColumns,
}: AilaTableExportControlProps) {
  const runExport = (format: "csv" | "json") => {
    // Post-filter, post-sort, pre-pagination -- the full row set the operator
    // is currently viewing across pages.
    const rows = table.getSortedRowModel().rows.map((r) => r.original)
    const cols = exportColumns ?? deriveExportColumnsFromTable(table)
    if (format === "csv") {
      exportRowsAsCsv(rows, cols, filename)
    } else {
      exportRowsAsJson(rows, cols, filename)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label="Export current table view"
        className={cn(
          "inline-flex items-center gap-1 rounded-[2px] border border-border bg-base",
          "px-2 py-1 font-mono text-xs text-text",
          "hover:border-border-hover hover:text-accent transition-colors duration-100",
          "focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-2",
        )}
      >
        <Download className="h-3.5 w-3.5" aria-hidden="true" />
        <span>Export</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-[8rem]">
        <DropdownMenuItem
          onClick={() => runExport("csv")}
          aria-label="Export current view as CSV"
        >
          CSV
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => runExport("json")}
          aria-label="Export current view as JSON"
        >
          JSON
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
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
 * AilaTable.Header -- renders column headers with optional sort indicators.
 *
 * Click a sortable column header to cycle: ascending → descending → unsorted.
 * Active sorted column shows amber accent indicator.
 * When `enableFiltering` is true on the parent, renders a global search input above headers.
 */
function AilaTableHeader({ className }: AilaTableHeaderProps) {
  const {
    table,
    enableFiltering,
    filterValue,
    setFilterValue,
    enableExport,
    exportFilename,
    exportColumns,
  } = useAilaTable()

  const showToolbar = enableFiltering || enableExport

  return (
    <div className={cn("", className)}>
      {showToolbar && (
        <div className="flex items-center gap-2 px-4 py-2 border-b border-border">
          {enableFiltering ? (
            <input
              aria-label="Filter table rows"
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
              placeholder="Filter..."
              className={cn(
                "flex-1 min-w-0 rounded-[2px] border border-border bg-base px-2.5 py-1",
                "font-mono text-text text-sm placeholder:text-text-muted",
                "focus:border-border-hover",
                "transition-colors duration-100"
              )}
            />
          ) : (
            <span className="flex-1" aria-hidden="true" />
          )}
          {enableExport && (
            <AilaTableExportControl
              table={table}
              filename={exportFilename}
              exportColumns={exportColumns}
            />
          )}
        </div>
      )}
      <table aria-label="Data table columns" className="w-full border-collapse">
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
 * AilaTable.Body -- renders data rows with cyberpunk row styling.
 *
 * Rows: dark surface bg, amber bottom border, hover to elevated/50 bg.
 * Renders empty state when no data or no rows match active filter (T-139-05).
 */
function AilaTableBody({ className, emptyState }: AilaTableBodyProps) {
  const { table, onRowClick } = useAilaTable()
  const rows = table.getRowModel().rows

  return (
    <div className={cn("overflow-x-auto", className)}>
      <table aria-label="Data table rows" className="w-full border-collapse">
        {/*
          The visible header lives in the sibling <AilaTableHeader> so
          the header row can stay pinned while the body scrolls. For
          assistive tech, we mirror the column headers into a
          visually-hidden <thead> here so this body table also carries
          the <th scope="col"> cells the WCAG 1.3.1 table-headers
          check requires.
        */}
        <thead className="sr-only">
          <tr>
            {table.getAllColumns().map((col) => (
              <th key={col.id} scope="col">
                {typeof col.columnDef.header === "string" ? col.columnDef.header : col.id}
              </th>
            ))}
          </tr>
        </thead>
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
                    interactive &&
                      "cursor-pointer focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent focus-visible:-outline-offset-2",
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
 * AilaTable.Pagination -- pagination bar with page info, size selector, and nav buttons.
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
            "px-1.5 py-0.5 cursor-pointer",
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
