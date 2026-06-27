/**
 * VizPage -- Data Visualization hub.
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
    <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4 h-[calc(100vh-8rem)] min-h-[600px]">
      {/* VIZ-01: Severity donut */}
      <div ref={severityDonutRef} className="h-full">
        <SeverityDonutChart exportRef={severityDonutRef} />
      </div>

      {/* VIZ-02: Findings trend */}
      <div ref={trendRef} className="h-full">
        <FindingsTrendChart exportRef={trendRef} />
      </div>

          <div ref={heatmapRef} className="lg:col-span-2 h-full">
            <SystemHeatmap exportRef={heatmapRef} />
          </div>
    
          {/* VIZ-04: Geographic map -- full width */}
          <div className="lg:col-span-2 h-full">
            <GeographicMap />
          </div>
        </div>
      );
    }
