/**
 * RadarNode.tsx — Custom ReactFlow node for the Network Radar (Phase 144).
 *
 * Renders as an SVG circle with:
 * - Fill color driven by the active colorBy mode (vulnerabilities/services/distro/connectivity)
 * - Severity count summary inside the circle
 * - System name label below the circle
 * - Stale indicator: dimmed opacity + dashed border ring when is_stale=true
 * - Hover glow effect via CSS filter
 *
 * Node data shape: { node: TopologyNode, fillColor: string, dominantSeverity: string }
 */
import * as React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

import { useThemeChartColors } from "@platform/features/viz/chartColors";
import type { TopologyNode } from "./types";

interface RadarNodeData {
  node: TopologyNode;
  fillColor: string;
  dominantSeverity: string;
}

/** Format severity counts as a compact summary string. */
function formatSeveritySummary(counts: TopologyNode["severity_counts"]): string {
  if (!counts) return "";
  const parts: string[] = [];
  if (counts.critical > 0) parts.push(`C:${counts.critical}`);
  if (counts.high > 0) parts.push(`H:${counts.high}`);
  if (counts.medium > 0) parts.push(`M:${counts.medium}`);
  if (counts.low > 0) parts.push(`L:${counts.low}`);
  return parts.join(" ");
}

export const RadarNode: React.FC<NodeProps> = ({ data, selected }) => {
  const { node, fillColor, dominantSeverity } = data as unknown as RadarNodeData;
  const isStale = node.is_stale;
  const severitySummary = formatSeveritySummary(node.severity_counts);
  const colors = useThemeChartColors();

  const circleSize = 60; // radius equivalent — total node is 120x120
  const nodeSize = 120;

  return (
    <div
      style={{
        width: nodeSize,
        height: nodeSize,
        position: "relative",
        cursor: "pointer",
        opacity: isStale ? 0.4 : 1,
        transition: "opacity 0.2s, filter 0.2s",
      }}
      title={`${node.name}\n${node.host}\n${isStale ? "[STALE]" : ""}`}
    >
      {/* ReactFlow connection handles — invisible, positioned at cardinal points */}
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      {/* SVG circle */}
      <svg
        width={nodeSize}
        height={nodeSize}
        style={{
          filter: selected
            ? `drop-shadow(0 0 8px ${fillColor})`
            : dominantSeverity === "critical"
            ? `drop-shadow(0 0 4px var(--color-critical))`
            : "none",
          transition: "filter 0.2s",
        }}
      >
        {/* Stale dashed ring */}
        {isStale && (
          <circle
            cx={nodeSize / 2}
            cy={nodeSize / 2}
            r={circleSize / 2 + 4}
            fill="none"
            stroke={colors.border}
            strokeWidth={1.5}
            strokeDasharray="4 4"
          />
        )}

        {/* Main circle */}
        <circle
          cx={nodeSize / 2}
          cy={nodeSize / 2}
          r={circleSize / 2}
          fill={fillColor}
          stroke={selected ? colors.accent : fillColor}
          strokeWidth={selected ? 2 : 1}
          fillOpacity={isStale ? 0.5 : 0.85}
        />

        {/* Severity summary text inside circle */}
        {severitySummary && (
          <text
            x={nodeSize / 2}
            y={nodeSize / 2}
            textAnchor="middle"
            dominantBaseline="middle"
            style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "9px",
              fill: "white",
              pointerEvents: "none",
            }}
          >
            {severitySummary}
          </text>
        )}

        {/* No-scan indicator */}
        {!severitySummary && !isStale && (
          <text
            x={nodeSize / 2}
            y={nodeSize / 2}
            textAnchor="middle"
            dominantBaseline="middle"
            style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "8px",
              fill: "var(--color-text-muted)",
              pointerEvents: "none",
            }}
          >
            no scan
          </text>
        )}
      </svg>

      {/* System name label below circle */}
      <div
        style={{
          position: "absolute",
          bottom: -22,
          left: 0,
          width: nodeSize,
          textAlign: "center",
          fontFamily: "var(--font-mono, monospace)",
          fontSize: "10px",
          color: "var(--color-text-muted)",
          overflow: "hidden",
          whiteSpace: "nowrap",
          textOverflow: "ellipsis",
          pointerEvents: "none",
        }}
        title={node.name}
      >
        {node.name}
      </div>

      {/* Stale label */}
      {isStale && (
        <div
          style={{
            position: "absolute",
            top: -18,
            left: 0,
            width: nodeSize,
            textAlign: "center",
            fontFamily: "var(--font-mono, monospace)",
            fontSize: "9px",
            color: "var(--color-critical)",
            pointerEvents: "none",
          }}
        >
          stale
        </div>
      )}
    </div>
  );
};
