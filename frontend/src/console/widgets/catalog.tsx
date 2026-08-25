/** Widget catalog (req 32): kind -> metadata + renderer.
 *
 * The single source of truth for which widget kinds exist, their chrome
 * affordances (fullscreen only where the body is not fixed-size), their default
 * floater size, and the component that renders each. The host reads this to
 * mount floaters; the admin editor reads it to list every kind with a title. */

import type { JSX } from "react";

import BoundCaseWidget from "./BoundCaseWidget";
import BudgetWidget from "./BudgetWidget";
import ClockWidget from "./ClockWidget";
import DanteActionsWidget from "./DanteActionsWidget";
import McpHealthWidget from "./McpHealthWidget";
import QueueDepthWidget from "./QueueDepthWidget";
import RecentFindingsWidget from "./RecentFindingsWidget";
import type { WidgetCatalogEntry, WidgetKind, WidgetProps } from "./types";

export const WIDGET_CATALOG: Record<WidgetKind, WidgetCatalogEntry> = {
  "bound-case": {
    kind: "bound-case",
    title: "bound case",
    canFullscreen: false,
    defaultSize: { w: 300, h: 190 },
    render: (p: WidgetProps): JSX.Element => <BoundCaseWidget {...p} />,
  },
  "queue-depth": {
    kind: "queue-depth",
    title: "queue depth",
    canFullscreen: true,
    defaultSize: { w: 300, h: 240 },
    render: (p: WidgetProps): JSX.Element => <QueueDepthWidget {...p} />,
  },
  budget: {
    kind: "budget",
    title: "budget",
    canFullscreen: false,
    defaultSize: { w: 290, h: 172 },
    render: (p: WidgetProps): JSX.Element => <BudgetWidget {...p} />,
  },
  "recent-findings": {
    kind: "recent-findings",
    title: "recent findings",
    canFullscreen: true,
    defaultSize: { w: 340, h: 300 },
    render: (p: WidgetProps): JSX.Element => <RecentFindingsWidget {...p} />,
  },
  "mcp-health": {
    kind: "mcp-health",
    title: "mcp health",
    canFullscreen: true,
    defaultSize: { w: 340, h: 280 },
    render: (p: WidgetProps): JSX.Element => <McpHealthWidget {...p} />,
  },
  "dante-actions": {
    kind: "dante-actions",
    title: "dante actions",
    canFullscreen: false,
    defaultSize: { w: 320, h: 240 },
    render: (p: WidgetProps): JSX.Element => <DanteActionsWidget {...p} />,
  },
  clock: {
    kind: "clock",
    title: "clock",
    canFullscreen: false,
    defaultSize: { w: 220, h: 112 },
    render: (p: WidgetProps): JSX.Element => <ClockWidget {...p} />,
  },
};
