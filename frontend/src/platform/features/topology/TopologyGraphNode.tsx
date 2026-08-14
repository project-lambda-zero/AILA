/**
 * TopologyGraphNode.tsx -- custom xyflow node for the Topology console.
 *
 * A compact hex-like tile: filled circle whose colour reflects the
 * dominant severity (via `data.fill`), the hostname beneath, and a
 * dashed halo when the node is stale. `data.faded` dims the node when
 * an overlay wants to spotlight a subset (stale-only / subnet focus).
 *
 * Node body is 140x110 -- keep in sync with the CELL_W/CELL_H constants
 * in topologyGraph.ts so the grid layout stays tight.
 */
import * as React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import type { TopologyNodeData } from "./topologyGraph";

const NODE_W = 140;
const NODE_H = 110;
const DISC_R = 22;

export function TopologyGraphNode({ data, selected }: NodeProps) {
  const { node, fill, severity, faded } = data as unknown as TopologyNodeData;
  const counts = node.severity_counts;
  const total = counts
    ? counts.critical + counts.high + counts.medium + counts.low
    : 0;

  return (
    <div
      style={{
        width: NODE_W,
        height: NODE_H,
        opacity: faded ? 0.28 : 1,
        transition: "opacity 120ms linear",
        fontFamily: "var(--font-mono, ui-monospace, monospace)",
        color: "var(--color-text)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "flex-start",
        padding: 6,
        cursor: "pointer",
      }}
      title={`${node.name} -- ${node.host}${node.is_stale ? " [STALE]" : ""}`}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      <svg
        width={DISC_R * 2 + 8}
        height={DISC_R * 2 + 8}
        viewBox={`0 0 ${DISC_R * 2 + 8} ${DISC_R * 2 + 8}`}
        aria-hidden="true"
      >
        {node.is_stale && (
          <circle
            cx={DISC_R + 4}
            cy={DISC_R + 4}
            r={DISC_R + 2}
            fill="none"
            stroke="var(--color-text-muted)"
            strokeWidth={1}
            strokeDasharray="3 3"
          />
        )}
        <circle
          cx={DISC_R + 4}
          cy={DISC_R + 4}
          r={DISC_R}
          fill={fill}
          stroke={
            selected
              ? "var(--color-accent)"
              : "color-mix(in srgb, var(--color-border) 80%, transparent)"
          }
          strokeWidth={selected ? 2 : 1}
          opacity={node.is_stale ? 0.55 : 1}
        />
        {total > 0 && (
          <text
            x={DISC_R + 4}
            y={DISC_R + 4}
            textAnchor="middle"
            dominantBaseline="central"
            fontSize={11}
            fontWeight={600}
            fill="var(--color-badge-text, #131313)"
          >
            {total}
          </text>
        )}
      </svg>

      <div
        style={{
          marginTop: 4,
          fontSize: 11,
          maxWidth: NODE_W - 12,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          textAlign: "center",
        }}
      >
        {node.name}
      </div>
      <div
        style={{
          fontSize: 9,
          color: "var(--color-text-muted)",
          maxWidth: NODE_W - 12,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          textAlign: "center",
        }}
      >
        {node.host}
      </div>
      {node.is_stale && (
        <div style={{ marginTop: 2 }}>
          <AilaBadge severity="medium" size="sm">STALE</AilaBadge>
        </div>
      )}
      {!node.is_stale && severity === "critical" && counts && counts.critical > 0 && (
        <div style={{ marginTop: 2 }}>
          <AilaBadge severity="critical" size="sm">
            {`C:${counts.critical}`}
          </AilaBadge>
        </div>
      )}
    </div>
  );
}
