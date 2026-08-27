/** Default layout + (de)serialization for the widget subsystem (req 32).
 *
 * The persisted `layout_json` blob decodes to a `WidgetLayout`. The backend
 * stores the string verbatim (default `"{}"` for a user who never saved), so
 * all validation + defaulting lives here on the client. */

import type { WidgetKind, WidgetLayout, WidgetLayoutEntry } from "./types";
import { WIDGET_KINDS, isWidgetKind, isWidgetSide } from "./types";

/** Ships bound-case + queue-depth on the left, recent-findings + budget on the
 * right, clock bottom. mcp-health + dante-actions are catalogued but hidden by
 * default so the first-run screen stays uncluttered; the editor reveals them. */
export const DEFAULT_LAYOUT: WidgetLayout = {
  version: 1,
  widgets: [
    { id: "bound-case", kind: "bound-case", side: "left", order: 0 },
    { id: "queue-depth", kind: "queue-depth", side: "left", order: 1 },
    { id: "recent-findings", kind: "recent-findings", side: "right", order: 0 },
    { id: "budget", kind: "budget", side: "right", order: 1 },
    { id: "clock", kind: "clock", side: "bottom", order: 0, hidden: true },
    { id: "mcp-health", kind: "mcp-health", side: "right", order: 2, hidden: true },
    { id: "dante-actions", kind: "dante-actions", side: "left", order: 2, hidden: true },
  ],
};

function cloneDefault(): WidgetLayout {
  return { version: 1, widgets: DEFAULT_LAYOUT.widgets.map((w) => ({ ...w })) };
}

/** Coerce one unknown array element to a valid entry, or null if it cannot be
 * salvaged. Rect is tolerated but only kept when all four numbers are present.
 */
function coerceEntry(raw: unknown): WidgetLayoutEntry | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (!isWidgetKind(o.kind)) return null;
  const side = isWidgetSide(o.side) ? o.side : "left";
  const order = typeof o.order === "number" && Number.isFinite(o.order) ? o.order : 0;
  const id = typeof o.id === "string" && o.id.length > 0 ? o.id : o.kind;
  const entry: WidgetLayoutEntry = { id, kind: o.kind, side, order };
  if (typeof o.minimized === "boolean") entry.minimized = o.minimized;
  if (typeof o.hidden === "boolean") entry.hidden = o.hidden;
  const r = o.rect;
  if (r && typeof r === "object") {
    const rr = r as Record<string, unknown>;
    if (["x", "y", "w", "h"].every((k) => typeof rr[k] === "number")) {
      entry.rect = { x: rr.x as number, y: rr.y as number, w: rr.w as number, h: rr.h as number };
    }
  }
  return entry;
}

/** Parse the stored blob into a validated layout. Empty / malformed / kind-less
 * input falls back to the full default. A partial layout that omits some kinds
 * gets those kinds appended (hidden) so both the host and the editor always see
 * the complete catalog. First entry per kind wins (dedup). */
export function parseLayout(json: string | null | undefined): WidgetLayout {
  if (!json) return cloneDefault();
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return cloneDefault();
  }
  const rawWidgets = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>).widgets : undefined;
  if (!Array.isArray(rawWidgets)) return cloneDefault();

  const seen = new Set<WidgetKind>();
  const widgets: WidgetLayoutEntry[] = [];
  for (const raw of rawWidgets) {
    const entry = coerceEntry(raw);
    if (!entry || seen.has(entry.kind)) continue;
    seen.add(entry.kind);
    widgets.push(entry);
  }
  if (widgets.length === 0) return cloneDefault();

  for (const kind of WIDGET_KINDS) {
    if (seen.has(kind)) continue;
    const fallback = DEFAULT_LAYOUT.widgets.find((w) => w.kind === kind);
    widgets.push({ ...(fallback ?? { id: kind, kind, side: "left", order: widgets.length }), hidden: true });
  }
  return { version: 1, widgets };
}

export function serializeLayout(layout: WidgetLayout): string {
  return JSON.stringify({ version: 1, widgets: layout.widgets });
}
