import type { CSSProperties } from "react";

import { css } from "../../css";

// The five X-Ray layouts, switched by the status-bar buttons or number keys 1-5.
export type XRayView = "overview" | "records" | "graphs" | "oracle" | "finding";

export const VIEWS = [
  ["overview", "overview"],
  ["records", "records"],
  ["graphs", "graphs"],
  ["oracle", "oracle"],
  ["finding", "finding"],
] as const satisfies readonly (readonly [id: XRayView, label: string])[];

export const VIEW_INDEX = { overview: 1, records: 2, graphs: 3, oracle: 4, finding: 5 } as const satisfies Record<XRayView, number>;

export const KEY_TO_VIEW = { "1": "overview", "2": "records", "3": "graphs", "4": "oracle", "5": "finding" } as const satisfies Record<string, XRayView>;

export function isViewKey(key: string): key is keyof typeof KEY_TO_VIEW {
  return Object.hasOwn(KEY_TO_VIEW, key);
}

function isView(seg: string): seg is XRayView {
  return Object.hasOwn(VIEW_INDEX, seg);
}

// section may carry a registry-slug prefix ("xray" from openNamedPage, or a
// sub-intent like "xray:records"); validate the last segment against the
// view vocabulary and fall back to the default overview.
export function parseView(section: string | null): XRayView {
  const seg = (section ?? "overview").split(":").pop() ?? "overview";
  return isView(seg) ? seg : "overview";
}

// Ordered pane ids per layout -- h/k and l/j cycle focus through these.
export type LayoutPanes = Readonly<Record<XRayView, readonly string[]>>;

// The overview layout's collapsible drawer columns, in mock order (right of the
// wide turns panel). Each is a 30px vertical title strip that expands on hover.
export const OVERVIEW_DRAWERS = ["brief", "records", "engine", "activity"] as const satisfies readonly string[];
export type OverviewDrawer = (typeof OVERVIEW_DRAWERS)[number];

export function isOverviewDrawer(id: string): id is OverviewDrawer {
  return OVERVIEW_DRAWERS.some((d) => d === id);
}

export const SHORTCUTS = [
  ["1 - 5", "switch layout"],
  ["h / k", "focus previous pane"],
  ["l / j", "focus next pane"],
  ["f", "zoom / unzoom focused pane"],
  ["P", "pin / unpin a drawer"],
  ["p", "pause / resume the run"],
  ["?", "toggle this help"],
  ["/  \u00b7  \u2318K", "command palette"],
  ["Esc", "close zoom / help / palette"],
] as const satisfies readonly (readonly [key: string, action: string])[];

// Per-pane focus ring + zoom style, spread onto each Panel as {...pv(id)}.
export interface PaneProps {
  focused: boolean;
  style?: CSSProperties;
}
export type PaneView = (id: string) => PaneProps;

// Shared grid for the four-pane layouts.
export const grid2 = css("flex:1;min-height:0;display:grid;grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr;gap:10px;padding:12px;");
