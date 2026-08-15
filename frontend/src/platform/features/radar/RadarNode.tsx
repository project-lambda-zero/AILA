/**
 * RadarNode -- custom ReactFlow node for Network Radar.
 *
 * SVG circle sized by dominant severity, mono labels below. Selection
 * halo + stale ring preserved. Colors go through useThemeChartColors
 * so tokens resolve at runtime (SVG presentation attrs cannot resolve
 * `var(--*)`).
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

  const circleSize = 60;
  const nodeSize = 120;

  return (
    <div
      style={{
        width: nodeSize,
        height: nodeSize,
        position: "relative",
        cursor: "pointer",
        opacity: isStale ? 0.55 : 1,
        transition: "opacity 0.2s, filter 0.2s",
        fontFamily: "var(--font-mono, ui-monospace, monospace)",
      }}
      title={`${node.name}\n${node.host}${isStale ? "\n[STALE]" : ""}`}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      <svg
        width={nodeSize}
        height={nodeSize}
        style={{
          filter: selected
            ? `drop-shadow(0 0 6px ${fillColor})`
            : dominantSeverity === "critical"
            ? `drop-shadow(0 0 4px ${colors.critical})`
            : "none",
          transition: "filter 0.2s",
        }}
      >
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

        <circle
          cx={nodeSize / 2}
          cy={nodeSize / 2}
          r={circleSize / 2}
          fill={fillColor}
          stroke={selected ? colors.accent : fillColor}
          strokeWidth={selected ? 2 : 1}
          fillOpacity={isStale ? 0.55 : 0.9}
        />

        {severitySummary && (
          <text
            x={nodeSize / 2}
            y={nodeSize / 2}
            textAnchor="middle"
            dominantBaseline="middle"
            style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "9px",
              fill: "var(--text-on-accent)",
              pointerEvents: "none",
              fontWeight: 700,
              letterSpacing: "0.08em",
            }}
          >
            {severitySummary}
          </text>
        )}

        {!severitySummary && !isStale && (
          <text
            x={nodeSize / 2}
            y={nodeSize / 2}
            textAnchor="middle"
            dominantBaseline="middle"
            style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "8px",
              fill: colors.textMuted,
              pointerEvents: "none",
              textTransform: "uppercase",
              letterSpacing: "0.12em",
            }}
          >
            no scan
          </text>
        )}
      </svg>

      {/* Name label */}
      <div
        style={{
          position: "absolute",
          bottom: -22,
          left: 0,
          width: nodeSize,
          textAlign: "center",
          fontSize: 10,
          color: "var(--text-muted)",
          overflow: "hidden",
          whiteSpace: "nowrap",
          textOverflow: "ellipsis",
          pointerEvents: "none",
          letterSpacing: "0.06em",
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
            fontSize: 9,
            textTransform: "uppercase",
            letterSpacing: "0.14em",
            color: "var(--status-warn)",
            pointerEvents: "none",
          }}
        >
          STALE
        </div>
      )}
    </div>
  );
};
