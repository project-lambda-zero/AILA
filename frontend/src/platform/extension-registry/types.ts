import type { ComponentType } from "react";

import type { AppRole, Capability } from "@platform/auth/roles";
import type { WidgetCategory } from "@platform/features/dashboard/types";

export interface NavContribution {
  id: string;
  slot: "sidebar.main";
  label: string;
  to: string;
  order: number;
  description?: string;
  minRole?: AppRole;
  requiresCapability?: Capability;
}

export interface RouteContribution {
  id: string;
  path: string;
  title: string;
  nav: boolean;
  slot: "page.full";
  page: ComponentType;
  minRole?: AppRole;
  requiresCapability?: Capability;
  /**
   * Label used in the header breadcrumb for this exact match. When
   * omitted, the header falls back to pathname-derived crumbs — which
   * can produce intermediate links to paths the module never
   * registered (e.g. `/forensics/projects` when only `/forensics` and
   * `/forensics/projects/:id` exist). Setting this turns the module's
   * registered routes into the only source of truth for crumbs.
   */
  breadcrumb?: string;
}

export interface PanelContribution {
  id: string;
  slot: "dashboard.primary" | "system.detail" | "task.detail" | "finding.detail" | "report.detail";
  order: number;
  label: string;
  render: ComponentType<{ systemId: number }>;
}

export interface WidgetContribution {
  id: string;
  slot: "dashboard.primary";
  order: number;
  render: ComponentType;
  /** Display name shown in the widget picker */
  name: string;
  /** Short description shown in the widget picker card */
  description: string;
  /** Category for grouping in picker dialog */
  category: WidgetCategory;
  /** Default grid dimensions */
  defaultSize: { w: number; h: number; minW?: number; minH?: number; maxW?: number; maxH?: number };
}

export interface ModuleFrontendSpec {
  moduleId: string;
  nav?: NavContribution[];
  routes?: RouteContribution[];
  panels?: PanelContribution[];
  widgets?: WidgetContribution[];
}
