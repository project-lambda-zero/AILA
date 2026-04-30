import type { ComponentType } from "react";

/**
 * Widget category — used for grouping in the picker dialog.
 */
export type WidgetCategory = "platform" | "vulnerability" | "sbd_nfr";

/**
 * Default grid dimensions for a widget.
 */
export interface WidgetSize {
  w: number;
  h: number;
  minW?: number;
  minH?: number;
  maxW?: number;
  maxH?: number;
}

/**
 * Core widget registry entry.
 * Every widget registered via widgetRegistry.ts must conform to this shape.
 */
export interface WidgetDefinition {
  /** Unique key, e.g. "platform.risk-score" */
  id: string;
  /** Display name shown in picker, e.g. "Risk Score" */
  name: string;
  /** Short description for picker card */
  description: string;
  /** Category for grouping in picker dialog */
  category: WidgetCategory;
  /** Default grid dimensions */
  defaultSize: WidgetSize;
  /** React component to render inside the widget slot */
  component: ComponentType;
}

/**
 * Serialized per-widget position — mirrors react-grid-layout's Layout item.
 * Stored in the backend layout_json.
 */
export interface DashboardLayoutItem {
  /** Widget id */
  i: string;
  /** Grid column position (0-based) */
  x: number;
  /** Grid row position (0-based) */
  y: number;
  /** Width in grid units */
  w: number;
  /** Height in grid units */
  h: number;
  minW?: number;
  minH?: number;
  maxW?: number;
  maxH?: number;
}

/**
 * The shape stored in the backend `layout_json` field.
 * version: 1 allows future migrations without breaking existing layouts.
 */
export interface SerializedLayout {
  version: 1;
  items: DashboardLayoutItem[];
}
