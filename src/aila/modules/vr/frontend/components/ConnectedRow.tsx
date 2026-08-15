/**
 * ConnectedRow -- one entry in a "connected entities" list rendered
 * inside a WindowPanel. Mirrors the mock's dense mono row: a MonoBadge
 * carrying the entity type, the title, an optional meta line, and a
 * trailing arrow. Internal hrefs (starting with "/") route through
 * react-router; anything else opens in a new tab.
 */
import type { ReactNode } from "react";
import { Link } from "react-router";

import { MonoBadge } from "@/components/aila/mock";

export type ConnectedRowTone =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "neutral";

export interface ConnectedRowData {
  /** Stable key when the same type appears more than once. */
  id: string;
  /** Short type label rendered as a badge, e.g. "Target", "Finding". */
  type: string;
  /** Human-readable title. */
  title: string;
  /** Internal (starts with "/") routes go through react-router; anything else opens externally. */
  href: string;
  /** Optional tone -- defaults to `info`. */
  severity?: ConnectedRowTone;
  /** Optional trailing meta line (e.g. "12 findings"). */
  meta?: ReactNode;
}

const ROW_STYLE: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  padding: "6px 10px",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  borderRadius: 2,
  textDecoration: "none",
  color: "var(--text-primary)",
};

function toneKey(severity: ConnectedRowTone | undefined): string {
  if (!severity) return "info";
  return severity === "neutral" ? "muted" : severity;
}

export function ConnectedRow({ entity }: { entity: ConnectedRowData }) {
  const isInternal = entity.href.startsWith("/");
  const ariaLabel = `Open ${entity.type}: ${entity.title}`;
  const tone = toneKey(entity.severity);
  const inner = (
    <>
      <MonoBadge tone={tone}>{entity.type}</MonoBadge>
      <span
        className="font-mono truncate"
        style={{ flex: 1, fontSize: 11, color: "var(--text-primary)" }}
      >
        {entity.title}
      </span>
      {entity.meta ? (
        <span
          className="font-mono"
          style={{ fontSize: 9.5, color: "var(--text-faint)" }}
        >
          {entity.meta}
        </span>
      ) : null}
      <span
        aria-hidden="true"
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-faint)" }}
      >
        {"\u2192"}
      </span>
    </>
  );

  return isInternal ? (
    <Link to={entity.href} aria-label={ariaLabel} style={ROW_STYLE}>
      {inner}
    </Link>
  ) : (
    <a
      href={entity.href}
      target="_blank"
      rel="noreferrer noopener"
      aria-label={ariaLabel}
      style={ROW_STYLE}
    >
      {inner}
    </a>
  );
}

export function ConnectedList({ entities }: { entities: ConnectedRowData[] }) {
  return (
    <ul
      role="list"
      className="flex flex-col"
      style={{ gap: 6, margin: 0, padding: 0, listStyle: "none" }}
    >
      {entities.map((entity) => (
        <li key={`${entity.type}:${entity.id}`}>
          <ConnectedRow entity={entity} />
        </li>
      ))}
    </ul>
  );
}
