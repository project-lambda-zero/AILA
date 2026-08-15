/**
 * TopologyGraphNode -- mock rebuild.
 *
 * Each node renders as a mini WindowPanel-like card: hatched-tone
 * title bar (mono host), body with a filled severity disc + finding
 * count, a MonoBadge for severity, and an optional STALE chip.
 *
 * Body stays 140x110 (matches CELL_W/CELL_H in topologyGraph.ts).
 */
import * as React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

import { MonoBadge, toneColor } from "@/components/aila/mock";
import type { TopologyNodeData } from "./topologyGraph";

const NODE_W = 140;
const NODE_H = 110;
const TITLE_H = 16;
const DISC_R = 18;

export function TopologyGraphNode({ data, selected }: NodeProps) {
  const { node, fill, severity, faded } = data as unknown as TopologyNodeData;
  const counts = node.severity_counts;
  const total = counts
    ? counts.critical + counts.high + counts.medium + counts.low
    : 0;
  const tone = severity === "none" ? "muted" : severity;
  const accent = toneColor(tone);

  return (
    <div
      style={{
        width: NODE_W,
        height: NODE_H,
        opacity: faded ? 0.32 : 1,
        transition: "opacity 120ms linear",
        fontFamily: "var(--font-mono, ui-monospace, monospace)",
        color: "var(--text-primary)",
        background: "var(--surface-card)",
        border: `1px solid ${selected ? "var(--accent)" : "var(--border-soft)"}`,
        borderRadius: 3,
        display: "flex",
        flexDirection: "column",
        cursor: "pointer",
        boxShadow: selected ? "0 0 0 1px var(--accent) inset" : "none",
      }}
      title={`${node.name} -- ${node.host}${node.is_stale ? " [STALE]" : ""}`}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      {/* Title bar */}
      <div
        className="flex items-center"
        style={{
          height: TITLE_H,
          borderBottom: "1px solid var(--border-faint)",
          background: "var(--surface-chrome)",
          padding: "0 6px",
          gap: 5,
        }}
      >
        <span
          aria-hidden="true"
          style={{
            width: 6,
            height: 6,
            borderRadius: 1,
            background: accent,
            flex: "0 0 auto",
          }}
        />
        <span
          className="uppercase"
          style={{
            fontSize: 8.5,
            letterSpacing: "0.12em",
            color: "var(--text-muted)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flex: 1,
          }}
        >
          {node.name}
        </span>
      </div>

      {/* Body */}
      <div
        className="flex flex-col items-center justify-center"
        style={{ flex: 1, padding: "4px 6px", gap: 3 }}
      >
        <svg
          width={DISC_R * 2 + 6}
          height={DISC_R * 2 + 6}
          viewBox={`0 0 ${DISC_R * 2 + 6} ${DISC_R * 2 + 6}`}
          aria-hidden="true"
        >
          {node.is_stale && (
            <circle
              cx={DISC_R + 3}
              cy={DISC_R + 3}
              r={DISC_R + 2}
              fill="none"
              stroke="var(--text-faint)"
              strokeWidth={1}
              strokeDasharray="3 3"
            />
          )}
          <circle
            cx={DISC_R + 3}
            cy={DISC_R + 3}
            r={DISC_R}
            fill={fill}
            stroke={accent}
            strokeWidth={1}
            opacity={node.is_stale ? 0.55 : 1}
          />
          {total > 0 && (
            <text
              x={DISC_R + 3}
              y={DISC_R + 3}
              textAnchor="middle"
              dominantBaseline="central"
              fontSize={11}
              fontWeight={700}
              fill="var(--text-on-accent)"
              style={{ fontFamily: "var(--font-mono, monospace)" }}
            >
              {total}
            </text>
          )}
        </svg>
        <div
          style={{
            fontSize: 9,
            color: "var(--text-muted)",
            maxWidth: NODE_W - 12,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            textAlign: "center",
          }}
        >
          {node.host}
        </div>
        {node.is_stale ? (
          <MonoBadge tone="warn">STALE</MonoBadge>
        ) : severity === "critical" && counts && counts.critical > 0 ? (
          <MonoBadge tone="critical">{`C:${counts.critical}`}</MonoBadge>
        ) : null}
      </div>
    </div>
  );
}
