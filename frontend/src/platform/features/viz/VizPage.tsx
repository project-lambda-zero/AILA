/**
 * VizPage — Data Visualization hub.
 *
 * Assembles all VIZ-01 through VIZ-04 charts on a single responsive grid page.
 * Available at /viz for any authenticated user.
 */
import * as React from "react";

import { SeverityDonutChart } from "./SeverityDonutChart";
import { FindingsTrendChart } from "./FindingsTrendChart";
import { SystemHeatmap } from "./SystemHeatmap";
import { GeographicMap } from "./GeographicMap";

export function VizPage() {
  const severityDonutRef = React.useRef<HTMLDivElement>(null);
  const trendRef = React.useRef<HTMLDivElement>(null);
  const heatmapRef = React.useRef<HTMLDivElement>(null);

  return (
    <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* VIZ-01: Severity donut */}
      <div ref={severityDonutRef}>
        <SeverityDonutChart exportRef={severityDonutRef} />
      </div>

      {/* VIZ-02: Findings trend */}
      <div ref={trendRef}>
        <FindingsTrendChart exportRef={trendRef} />
      </div>

      {/* VIZ-03: System heatmap — full width */}
      <div ref={heatmapRef} className="lg:col-span-2">
        <SystemHeatmap exportRef={heatmapRef} />
      </div>

      {/* VIZ-04: Geographic map — full width */}
      <div className="lg:col-span-2">
        <GeographicMap />
      </div>
    </div>
  );
}
