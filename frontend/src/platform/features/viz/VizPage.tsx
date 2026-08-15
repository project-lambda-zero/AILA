/**
 * VizPage -- mock rebuild.
 *
 * SectionHeader('visualization') + responsive grid of WindowPanels
 * hosting the chart .view components. Each chart wrapper (below)
 * owns its own WindowPanel now, so this page is purely layout.
 */
import * as React from "react";

import { SectionHeader } from "@/components/aila/mock";

import { SeverityDonutChart } from "./SeverityDonutChart";
import { FindingsTrendChart } from "./FindingsTrendChart";
import { SystemHeatmap } from "./SystemHeatmap";
import { GeographicMap } from "./GeographicMap";

export function VizPage() {
  const severityDonutRef = React.useRef<HTMLDivElement>(null);
  const trendRef = React.useRef<HTMLDivElement>(null);
  const heatmapRef = React.useRef<HTMLDivElement>(null);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20, minHeight: "100%" }}>
      <SectionHeader icon={"\u25CE"} title="visualization" />

      <div
        className="grid"
        style={{
          gap: 16,
          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
        }}
      >
        <div ref={severityDonutRef}>
          <SeverityDonutChart exportRef={severityDonutRef} />
        </div>
        <div ref={trendRef}>
          <FindingsTrendChart exportRef={trendRef} />
        </div>
      </div>

      <div
        className="grid"
        style={{ gap: 16, gridTemplateColumns: "1fr" }}
      >
        <div ref={heatmapRef}>
          <SystemHeatmap exportRef={heatmapRef} />
        </div>
        <GeographicMap />
      </div>
    </div>
  );
}
