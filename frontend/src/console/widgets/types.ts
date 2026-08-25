/** Widget subsystem contract (req 32).
 *
 * A widget is a small, read-only surface that renders live platform state and
 * docks around the chat panel as a `<ConsoleWindow kind="floater">`. The host
 * (`WidgetHost`) owns the floater chrome, docking geometry, and per-session
 * open/close/minimize; each widget component renders BODY content only and
 * reads its own live data source. The persisted layout (`WidgetLayout`) is a
 * client-owned array stored verbatim through `PUT /widgets/layout`. */

import type { JSX } from "react";

import type { WindowRect } from "../window";

export type WidgetKind =
  | "bound-case"
  | "queue-depth"
  | "budget"
  | "recent-findings"
  | "mcp-health"
  | "dante-actions"
  | "clock";

export type WidgetSide = "left" | "right" | "top" | "bottom";

/** One entry in the persisted layout. `id` is stable and unique; the default
 * layout uses one instance per kind, so `id === kind`. `rect` is optional and
 * is NOT persisted by the live host (drag is ephemeral); it is tolerated on
 * read so a hand-edited layout with explicit geometry still loads. */
export interface WidgetLayoutEntry {
  id: string;
  kind: WidgetKind;
  side: WidgetSide;
  order: number;
  rect?: WindowRect;
  minimized?: boolean;
  hidden?: boolean;
}

export interface WidgetLayout {
  version: 1;
  widgets: WidgetLayoutEntry[];
}

/** Props every widget body receives from the host. Widgets read their own live
 * data; the host only threads the current module context + a page opener so a
 * widget can deep-link into a module surface (e.g. recent-findings row -> the
 * owning module's findings page). */
export interface WidgetProps {
  moduleId: string;
  boundId: string | null;
  onOpenPage: (module: string, section: string, label: string, investigationId?: string | null) => void;
}

/** Catalog metadata + renderer for one widget kind. `canFullscreen` is false
 * for the compact fixed-size widgets (clock, budget, bound-case) per spec. */
export interface WidgetCatalogEntry {
  kind: WidgetKind;
  title: string;
  canFullscreen: boolean;
  defaultSize: { w: number; h: number };
  render: (props: WidgetProps) => JSX.Element;
}

/** Canonical kind order for the admin editor + missing-kind backfill. */
export const WIDGET_KINDS: readonly WidgetKind[] = [
  "bound-case",
  "queue-depth",
  "budget",
  "recent-findings",
  "mcp-health",
  "dante-actions",
  "clock",
] as const;

const SIDES: readonly WidgetSide[] = ["left", "right", "top", "bottom"] as const;

export function isWidgetKind(v: unknown): v is WidgetKind {
  return typeof v === "string" && (WIDGET_KINDS as readonly string[]).includes(v);
}

export function isWidgetSide(v: unknown): v is WidgetSide {
  return typeof v === "string" && (SIDES as readonly string[]).includes(v);
}
