/**
 * vizWidgets.ts — Dashboard widget contributions from the Viz feature.
 *
 * Registers platform.severity-donut and platform.findings-trend widgets.
 * Called from registerAllPlatformWidgets() in dashboard/widgets/index.ts.
 */
import type { WidgetDefinition } from "@platform/features/dashboard/types";

import { SeverityDonutChart } from "./SeverityDonutChart";
import { FindingsTrendChart } from "./FindingsTrendChart";

export const VIZ_WIDGETS: WidgetDefinition[] = [
  {
    id: "platform.severity-donut",
    name: "Severity Distribution",
    description: "Donut chart of findings by severity level",
    category: "platform",
    defaultSize: { w: 4, h: 3, minW: 3, minH: 2 },
    component: SeverityDonutChart,
  },
  {
    id: "platform.findings-trend",
    name: "Findings Trend",
    description: "Area chart showing findings over time",
    category: "platform",
    defaultSize: { w: 6, h: 3, minW: 4, minH: 2 },
    component: FindingsTrendChart,
  },
];
