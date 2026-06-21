import { registerWidget } from "../widgetRegistry";
import { RiskScoreWidget } from "./RiskScoreWidget";
import { FleetCoverageWidget } from "./FleetCoverageWidget";
import { ActiveScansWidget } from "./ActiveScansWidget";
import { HealthStatusWidget } from "./HealthStatusWidget";
import { SeverityChartWidget } from "./SeverityChartWidget";
import { TopFindingsWidget } from "./TopFindingsWidget";
import { MttrWidget } from "./MttrWidget";
import { TrendWidget } from "./TrendWidget";
import { VIZ_WIDGETS } from "@platform/features/viz/vizWidgets";

// Re-export all widget components for external use
export {
  RiskScoreWidget,
  FleetCoverageWidget,
  ActiveScansWidget,
  HealthStatusWidget,
  SeverityChartWidget,
  TopFindingsWidget,
  MttrWidget,
  TrendWidget,
};

let registered = false;

/**
 * Register all 9 built-in platform widgets into the widget registry.
 * Idempotent — safe to call multiple times (guarded by `registered` flag).
 * Call this on DashboardPage mount before initModuleWidgets().
 */
export function registerAllPlatformWidgets(): void {
  if (registered) return;
  registered = true;

  // Platform widgets (D-05)
  registerWidget({
    id: "platform.risk-score",
    name: "Risk Score",
    description: "Composite risk score gauge (0-10) based on finding severity distribution",
    category: "platform",
    defaultSize: { w: 3, h: 2, minW: 2, minH: 2 },
    component: RiskScoreWidget,
  });

  registerWidget({
    id: "platform.fleet-coverage",
    name: "Fleet Coverage",
    description: "System fleet online/total count with coverage percentage",
    category: "platform",
    defaultSize: { w: 3, h: 2, minW: 2, minH: 2 },
    component: FleetCoverageWidget,
  });

  registerWidget({
    id: "platform.active-scans",
    name: "Active Scans",
    description: "Currently running vulnerability scan count",
    category: "platform",
    defaultSize: { w: 3, h: 2, minW: 2, minH: 2 },
    component: ActiveScansWidget,
  });

  registerWidget({
    id: "platform.health-status",
    name: "Health Status",
    description: "Platform health checks overview with per-service status",
    category: "platform",
    defaultSize: { w: 3, h: 2, minW: 2, minH: 2 },
    component: HealthStatusWidget,
  });

  // Vulnerability widgets (D-06)
  registerWidget({
    id: "vuln.severity-chart",
    name: "Severity Distribution",
    description: "Donut chart showing finding count by severity level",
    category: "vulnerability",
    defaultSize: { w: 6, h: 3, minW: 4, minH: 2 },
    component: SeverityChartWidget,
  });

  registerWidget({
    id: "vuln.top-findings",
    name: "Top Critical Findings",
    description: "Top 5 most critical findings with CVE ID and system",
    category: "vulnerability",
    defaultSize: { w: 6, h: 3, minW: 4, minH: 2 },
    component: TopFindingsWidget,
  });

  registerWidget({
    id: "vuln.mttr",
    name: "Findings Closed (30d)",
    description: "Count of findings closed in the last 30 days",
    category: "vulnerability",
    defaultSize: { w: 3, h: 2, minW: 2, minH: 2 },
    component: MttrWidget,
  });

  registerWidget({
    id: "vuln.trend",
    name: "Findings Trend",
    description: "Time-series area chart of finding counts over time",
    category: "vulnerability",
    defaultSize: { w: 6, h: 3, minW: 4, minH: 2 },
    component: TrendWidget,
  });

  // Viz widgets (Phase 144 VIZ-01, VIZ-02)
  for (const def of VIZ_WIDGETS) {
    registerWidget(def);
  }
}
