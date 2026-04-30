import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";

import type { WidgetCategory, WidgetDefinition, SerializedLayout } from "./types";

const registry = new Map<string, WidgetDefinition>();

let initialized = false;

export function registerWidget(def: WidgetDefinition): void {
  if (registry.has(def.id)) {
    console.warn(`[widgetRegistry] Duplicate widget id "${def.id}" — skipping.`);
    return;
  }
  registry.set(def.id, def);
}

export function getWidgetById(id: string): WidgetDefinition | undefined {
  return registry.get(id);
}

export function getWidgetsByCategory(category: WidgetCategory): WidgetDefinition[] {
  return Array.from(registry.values()).filter((def) => def.category === category);
}

export function getAllWidgets(): WidgetDefinition[] {
  return Array.from(registry.values());
}

/**
 * Reads all module frontend specs loaded via import.meta.glob and registers
 * any widget contributions into the central registry.
 * Idempotent — safe to call multiple times (guarded by `initialized` flag).
 */
export function initModuleWidgets(): void {
  if (initialized) return;
  initialized = true;

  const specs = loadModuleFrontendSpecs();
  for (const spec of specs) {
    if (!spec.widgets) continue;
    for (const contrib of spec.widgets) {
      registerWidget({
        id: contrib.id,
        name: contrib.name,
        description: contrib.description,
        category: contrib.category,
        defaultSize: contrib.defaultSize,
        component: contrib.render,
      });
    }
  }
}

/**
 * Opinionated default layout for new users (D-08).
 * Pre-configured: risk score, fleet coverage, active scans, health status
 * in the top row; severity chart and top-5 findings spanning the bottom.
 */
export const DEFAULT_LAYOUT: SerializedLayout = {
  version: 1,
  items: [
    { i: "platform.risk-score",    x: 0, y: 0, w: 3, h: 2, minW: 2, minH: 2 },
    { i: "platform.fleet-coverage", x: 3, y: 0, w: 3, h: 2, minW: 2, minH: 2 },
    { i: "platform.active-scans",  x: 6, y: 0, w: 3, h: 2, minW: 2, minH: 2 },
    { i: "platform.health-status", x: 9, y: 0, w: 3, h: 2, minW: 2, minH: 2 },
    { i: "vuln.severity-chart",    x: 0, y: 2, w: 6, h: 3, minW: 4, minH: 2 },
    { i: "vuln.top-findings",      x: 6, y: 2, w: 6, h: 3, minW: 4, minH: 2 },
  ],
};
