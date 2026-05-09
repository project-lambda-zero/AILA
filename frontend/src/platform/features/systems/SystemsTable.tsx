import { useMemo } from "react";
import { Link } from "react-router";
import { Plus } from "lucide-react";
import type { ColumnDef } from "@tanstack/react-table";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { HelpTip } from "@/components/aila/HelpTip";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ConnectivityBadge } from "./ConnectivityBadge";
import { formatRelativeTime, type SystemSummaryEnriched, type SeverityLevel } from "./api";

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function severityToVariant(severity: SeverityLevel | null): "critical" | "high" | "medium" | "low" | "neutral" {
  if (!severity) return "neutral";
  return severity;
}

/**
 * Column visibility preset for responsive hiding (D-17).
 * SSH status and Tags columns hidden on mobile (< 768px).
 */
export const SystemsTableColumnVisibility = {
  connectivity_status: true,
  tags: true,
};

export const SystemsTableColumnVisibilityMobile = {
  connectivity_status: false,
  tags: false,
};

/**
 * useSystemColumns — stable TanStack ColumnDef array for SystemSummaryEnriched (D-01).
 *
 * Columns:
 * - Checkbox (row selection stub for D-19)
 * - Name (sortable, links to detail)
 * - Host:Port (monospace, not sortable)
 * - Distro (sortable)
 * - SSH Status (ConnectivityBadge, hidden on mobile)
 * - Tags (up to 3 badges + overflow + optional quick-add button, hidden on mobile)
 * - Last Scan (relative time with tooltip)
 * - Severity (top severity badge)
 *
 * @param onManageTags Optional callback. When provided, the Tags cell renders a
 * "+" button that triggers the parent to open a tag-management drawer for the
 * row's system. Pass `undefined` to suppress the inline button (e.g. for
 * read-only viewers).
 */
export function useSystemColumns(
  onManageTags?: (systemId: number) => void,
): ColumnDef<SystemSummaryEnriched>[] {
  return useMemo(
    () => [
      {
        id: "select",
        header: ({ table }) => (
          <input
            type="checkbox"
            checked={table.getIsAllPageRowsSelected()}
            onChange={table.getToggleAllPageRowsSelectedHandler()}
            className="cursor-pointer accent-accent"
            aria-label="Select all rows"
          />
        ),
        cell: ({ row }) => (
          <input
            type="checkbox"
            checked={row.getIsSelected()}
            onChange={row.getToggleSelectedHandler()}
            className="cursor-pointer accent-accent"
            aria-label={`Select ${row.original.name}`}
          />
        ),
        enableSorting: false,
        enableGlobalFilter: false,
        size: 40,
      },
      {
        accessorKey: "name",
        header: "Name",
        enableSorting: true,
        cell: ({ row }) => (
          <Link
            to={`/systems/${row.original.id}`}
            className="font-semibold text-accent hover:text-accent/80 transition-colors duration-100"
          >
            {row.original.name}
          </Link>
        ),
      },
      {
        id: "host_port",
        header: "Host:Port",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-sm text-text-muted">
            {row.original.host}:{row.original.port}
          </span>
        ),
      },
      {
        accessorKey: "distro",
        header: "Distro",
        enableSorting: true,
        cell: ({ row }) => <span>{row.original.distro}</span>,
      },
      {
        id: "connectivity_status",
        header: () => (
          <span className="inline-flex items-center gap-1">
            SSH Status
            <HelpTip
              title="SSH Connectivity"
              description="Checks if the system is reachable over SSH. ONLINE means the last probe succeeded. OFFLINE means connection was refused or timed out."
              side="top"
            />
          </span>
        ),
        enableSorting: false,
        cell: ({ row }) => (
          <ConnectivityBadge status={row.original.connectivity_status} />
        ),
      },
      {
        id: "tags",
        header: "Tags",
        enableSorting: false,
        cell: ({ row }) => {
          const tags = row.original.tags ?? [];
          const visible = tags.slice(0, 3);
          const overflow = tags.slice(3);
          return (
            <div className="flex flex-wrap items-center gap-1">
              {tags.length === 0 && (
                <span className="text-text-muted text-xs font-mono">—</span>
              )}
              {visible.map((tag) => (
                <AilaBadge key={`${tag.tag_key}:${tag.tag_value}`} severity="info" size="sm">
                  {tag.tag_key}:{tag.tag_value}
                </AilaBadge>
              ))}
              {overflow.length > 0 && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger>
                      <AilaBadge severity="neutral" size="sm">+{overflow.length} more</AilaBadge>
                    </TooltipTrigger>
                    <TooltipContent>
                      <div className="flex flex-col gap-0.5">
                        {overflow.map((tag) => (
                          <span key={`${tag.tag_key}:${tag.tag_value}`} className="font-mono text-xs">
                            {tag.tag_key}:{tag.tag_value}
                          </span>
                        ))}
                      </div>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
              {onManageTags && (
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  className="h-5 w-5 text-text-muted hover:text-accent"
                  onClick={(e) => {
                    e.stopPropagation();
                    onManageTags(row.original.id);
                  }}
                  aria-label={`Manage tags for ${row.original.name}`}
                >
                  <Plus className="h-3.5 w-3.5" />
                </Button>
              )}
            </div>
          );
        },
      },
      {
        id: "last_scan_at",
        header: "Last Scan",
        enableSorting: false,
        cell: ({ row }) => {
          const ts = row.original.last_scan_at;
          return (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger>
                  <span className="font-mono text-xs text-text-muted cursor-default">
                    {formatRelativeTime(ts)}
                  </span>
                </TooltipTrigger>
                {ts ? (
                  <TooltipContent>
                    <span className="font-mono text-xs">{new Date(ts).toISOString()}</span>
                  </TooltipContent>
                ) : null}
              </Tooltip>
            </TooltipProvider>
          );
        },
      },
      {
        id: "top_severity",
        header: "Severity",
        enableSorting: true,
        sortingFn: (rowA, rowB) => {
          const a = SEVERITY_ORDER[rowA.original.top_severity as SeverityLevel] ?? 0;
          const b = SEVERITY_ORDER[rowB.original.top_severity as SeverityLevel] ?? 0;
          return a - b;
        },
        cell: ({ row }) => {
          const sev = row.original.top_severity;
          return (
            <AilaBadge severity={severityToVariant(sev)} size="sm">
              {sev ? sev.toUpperCase() : "N/A"}
            </AilaBadge>
          );
        },
      },
    ],
    [onManageTags],
  );
}
