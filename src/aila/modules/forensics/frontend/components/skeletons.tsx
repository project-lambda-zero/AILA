import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

/**
 * Content-shaped skeletons for the forensics module.
 *
 * These match the exact layout of the components they replace so the
 * transition from skeleton → loaded content produces no cumulative
 * layout shift. `LoadingSkeleton` respects `prefers-reduced-motion`
 * via the shared `.skeleton-aila` CSS in globals.css, so the amber
 * scan-line animation is gated for reduced-motion visitors.
 */

// ---------------------------------------------------------------------------
// ProjectCardSkeleton -- mirrors ProjectCard on ProjectsPage.
// ---------------------------------------------------------------------------

export function ProjectCardSkeleton() {
  return (
    <AilaCard aria-hidden="true" techBorder glow>
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <LoadingSkeleton size="md" width="half" />
          <LoadingSkeleton size="sm" width="quarter" />
        </div>
        <LoadingSkeleton size="sm" width="full" />
        <div className="flex gap-3">
          <LoadingSkeleton size="sm" width="quarter" />
          <LoadingSkeleton size="sm" width="quarter" />
          <LoadingSkeleton size="sm" width="quarter" />
        </div>
        <LoadingSkeleton size="sm" width="third" />
      </div>
    </AilaCard>
  );
}

export function ProjectCardSkeletonGrid({ count = 6 }: { count?: number }) {
  return (
    <div
      aria-hidden="true"
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
    >
      {Array.from({ length: count }, (_, i) => (
        // eslint-disable-next-line react/no-array-index-key
        <ProjectCardSkeleton key={i} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// InvestigationRowSkeleton -- flat row in the investigations list on
// ProjectDashboardPage.
// ---------------------------------------------------------------------------

export function InvestigationRowSkeleton() {
  return (
    <AilaCard aria-hidden="true" techBorder glow>
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <LoadingSkeleton size="md" width="full" />
          <LoadingSkeleton size="sm" width="quarter" />
        </div>
        <LoadingSkeleton size="sm" width="third" />
      </div>
    </AilaCard>
  );
}

export function InvestigationRowSkeletonList({ count = 4 }: { count?: number }) {
  return (
    <div aria-hidden="true" className="space-y-2">
      {Array.from({ length: count }, (_, i) => (
        // eslint-disable-next-line react/no-array-index-key
        <InvestigationRowSkeleton key={i} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// FindingRowSkeleton -- one row inside <FindingsPanel/> mirroring the
// collapsible li shape.
// ---------------------------------------------------------------------------

export function FindingRowSkeleton() {
  return (
    <li
      aria-hidden="true"
      className="rounded-md border border-red-900/40 bg-red-950/20 p-3 space-y-2"
    >
      <div className="flex items-center justify-between gap-3">
        <LoadingSkeleton size="md" width="half" />
        <LoadingSkeleton size="sm" width="quarter" />
      </div>
      <LoadingSkeleton size="sm" width="full" />
    </li>
  );
}

export function FindingRowSkeletonList({ count = 5 }: { count?: number }) {
  return (
    <ol aria-hidden="true" className="space-y-1.5">
      {Array.from({ length: count }, (_, i) => (
        // eslint-disable-next-line react/no-array-index-key
        <FindingRowSkeleton key={i} />
      ))}
    </ol>
  );
}

// ---------------------------------------------------------------------------
// SnapshotRowSkeleton -- one row in the reasoning-replay snapshot list.
// ---------------------------------------------------------------------------

export function SnapshotRowSkeleton() {
  return (
    <div
      aria-hidden="true"
      className="w-full px-2 py-1 rounded-md border border-border bg-surface"
    >
      <LoadingSkeleton size="sm" width="full" />
    </div>
  );
}

export function SnapshotListSkeleton({ count = 6 }: { count?: number }) {
  return (
    <AilaCard aria-hidden="true" className="border-border" techBorder glow>
      <div className="space-y-2">
        <LoadingSkeleton size="sm" width="third" />
        <div className="space-y-1">
          {Array.from({ length: count }, (_, i) => (
            // eslint-disable-next-line react/no-array-index-key
            <SnapshotRowSkeleton key={i} />
          ))}
        </div>
      </div>
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// InvestigationDetailSkeleton -- header + tab-strip + first tab content.
// ---------------------------------------------------------------------------

export function InvestigationDetailSkeleton() {
  return (
    <div aria-hidden="true" className="space-y-4">
      <LoadingSkeleton size="sm" width="quarter" />
      <div className="space-y-2">
        <LoadingSkeleton size="md" width="full" />
        <LoadingSkeleton size="sm" width="half" />
      </div>
      <div className="flex gap-2">
        <LoadingSkeleton size="md" width="quarter" />
        <LoadingSkeleton size="md" width="quarter" />
        <LoadingSkeleton size="md" width="quarter" />
      </div>
      <InvestigationRowSkeletonList count={3} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// TableRowSkeleton -- generic 5-cell row skeleton used by artifact / carved /
// evidence / questions / registry tables.
// ---------------------------------------------------------------------------

export function TableRowSkeleton({ cells = 5 }: { cells?: number }) {
  return (
    <div
      aria-hidden="true"
      className="flex items-center gap-3 px-3 py-2 border-b border-border"
    >
      {Array.from({ length: cells }, (_, i) => (
        <div key={i} className="flex-1">
          <LoadingSkeleton size="sm" width="full" />
        </div>
      ))}
    </div>
  );
}

export function TableSkeleton({
  rows = 5,
  cells = 5,
}: {
  rows?: number;
  cells?: number;
}) {
  return (
    <AilaCard aria-hidden="true" techBorder glow>
      <div className="space-y-0">
        {Array.from({ length: rows }, (_, i) => (
          // eslint-disable-next-line react/no-array-index-key
          <TableRowSkeleton key={i} cells={cells} />
        ))}
      </div>
    </AilaCard>
  );
}
