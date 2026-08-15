import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

/**
 * Content-shaped skeletons for the forensics module.
 *
 * These match the exact layout of the components they replace so the
 * transition from skeleton -> loaded content produces no cumulative
 * layout shift. `LoadingSkeleton` respects `prefers-reduced-motion`
 * via the shared `.skeleton-aila` CSS in globals.css.
 */

// Reused mock-surface wrapper (no WindowPanel chrome -- skeletons stay
// visually quieter than the loaded content). Keeps the bordered mono
// language while avoiding a shadcn card.
const SKELETON_SURFACE: React.CSSProperties = {
  border: "1px solid var(--border-soft)",
  background: "var(--surface-card)",
  borderRadius: 3,
  padding: 12,
};

// ---------------------------------------------------------------------------
// ProjectCardSkeleton -- mirrors ProjectCard on ProjectsPage.
// ---------------------------------------------------------------------------

export function ProjectCardSkeleton() {
  return (
    <div aria-hidden="true" style={SKELETON_SURFACE}>
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
    </div>
  );
}

export function ProjectCardSkeletonGrid({ count = 6 }: { count?: number }) {
  return (
    <div
      aria-hidden="true"
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3"
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
    <div aria-hidden="true" style={SKELETON_SURFACE}>
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <LoadingSkeleton size="md" width="full" />
          <LoadingSkeleton size="sm" width="quarter" />
        </div>
        <LoadingSkeleton size="sm" width="third" />
      </div>
    </div>
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
      className="space-y-2"
      style={{
        border: "1px solid color-mix(in srgb, var(--accent) 35%, transparent)",
        background: "color-mix(in srgb, var(--accent) 8%, transparent)",
        borderRadius: 3,
        padding: 12,
      }}
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
      className="w-full"
      style={{
        padding: "6px 10px",
        border: "1px solid var(--border-soft)",
        background: "var(--surface-card)",
        borderRadius: 3,
      }}
    >
      <LoadingSkeleton size="sm" width="full" />
    </div>
  );
}

export function SnapshotListSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div aria-hidden="true" style={SKELETON_SURFACE}>
      <div className="space-y-2">
        <LoadingSkeleton size="sm" width="third" />
        <div className="space-y-1">
          {Array.from({ length: count }, (_, i) => (
            // eslint-disable-next-line react/no-array-index-key
            <SnapshotRowSkeleton key={i} />
          ))}
        </div>
      </div>
    </div>
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
      className="flex items-center gap-3"
      style={{
        padding: "8px 12px",
        borderBottom: "1px solid var(--border-faint)",
      }}
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
    <div
      aria-hidden="true"
      style={{
        border: "1px solid var(--border-soft)",
        background: "var(--surface-card)",
        borderRadius: 3,
        overflow: "hidden",
      }}
    >
      {Array.from({ length: rows }, (_, i) => (
        // eslint-disable-next-line react/no-array-index-key
        <TableRowSkeleton key={i} cells={cells} />
      ))}
    </div>
  );
}
