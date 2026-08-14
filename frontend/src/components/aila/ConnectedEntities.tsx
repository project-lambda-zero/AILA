/**
 * ConnectedEntities -- compact list of related entities linked from the
 * current surface. Each item renders a type badge, a title, and a
 * navigation target (in-app <Link> for internal routes, plain <a> for
 * external URLs). Intended for cross-entity navigation panels on shell
 * surfaces (e.g. a scan -> its vulnerability report).
 *
 * A11y: the region carries an aria-label; each entity is a labelled link
 * so screen readers announce both the type ("Report") and the title.
 * When the list is empty the component renders nothing so callers can
 * mount it unconditionally and let the operator see it only once
 * relationships exist.
 */
import type { ReactNode } from "react";
import { Link } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ConnectedEntitySeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "neutral";

export interface ConnectedEntity {
  /** Stable key when the same type appears more than once. */
  id: string;
  /** Short type label rendered as a badge, e.g. "Report", "Task", "Run". */
  type: string;
  /** Human-readable title, e.g. "Vulnerability Report" or a truncated id. */
  title: string;
  /**
   * Where the entity lives. Internal (starts with "/") routes go through
   * react-router; anything else opens in a new tab.
   */
  href: string;
  /** Optional badge severity -- defaults to `info`. */
  severity?: ConnectedEntitySeverity;
  /** Optional trailing meta line (e.g. "12 findings"). */
  meta?: ReactNode;
}

export interface ConnectedEntitiesProps {
  entities: ConnectedEntity[];
  /** Optional heading, defaults to "Connected". */
  heading?: string;
  className?: string;
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

function ConnectedEntityLink({ entity }: { entity: ConnectedEntity }) {
  const isInternal = entity.href.startsWith("/");
  const ariaLabel = `Open ${entity.type}: ${entity.title}`;
  const inner = (
    <>
      <AilaBadge severity={entity.severity ?? "info"} size="sm">
        {entity.type}
      </AilaBadge>
      <span className="flex-1 truncate font-mono text-xs font-medium text-text group-hover:text-accent">
        {entity.title}
      </span>
      {entity.meta ? (
        <span className="font-mono text-[10px] text-text-muted opacity-70">
          {entity.meta}
        </span>
      ) : null}
      <span aria-hidden="true" className="font-mono text-xs text-text-muted">
        →
      </span>
    </>
  );
  const className =
    "group flex items-center gap-2 rounded-[2px] border border-border bg-surface px-2.5 py-1.5 " +
    "transition-colors hover:border-border-hover hover:bg-elevated " +
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent";

  return isInternal ? (
    <Link to={entity.href} aria-label={ariaLabel} className={className}>
      {inner}
    </Link>
  ) : (
    <a
      href={entity.href}
      target="_blank"
      rel="noreferrer noopener"
      aria-label={ariaLabel}
      className={className}
    >
      {inner}
    </a>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ConnectedEntities({
  entities,
  heading = "Connected",
  className,
}: ConnectedEntitiesProps) {
  if (entities.length === 0) return null;
  return (
    <section
      aria-label={heading}
      className={`flex flex-col gap-2 ${className ?? ""}`}
    >
      <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted">
        {heading}
      </h3>
      <ul role="list" className="flex flex-col gap-1.5">
        {entities.map((entity) => (
          <li key={`${entity.type}:${entity.id}`}>
            <ConnectedEntityLink entity={entity} />
          </li>
        ))}
      </ul>
    </section>
  );
}
