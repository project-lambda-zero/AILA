import * as React from "react";

/**
 * PixelIcon -- the AILA design-system icon grammar.
 *
 * 16x16 unit canvas, pure rectangles (at most one diagonal per glyph, no
 * curves), rendered with `shape-rendering: crispEdges` so silhouettes stay
 * sharp at 16 / 24 / 32px. Colour follows `currentColor` -- set it via the
 * surrounding text colour (pink for live/accent, mint for ok). This is the
 * Workbench-era system iconography; keep Phosphor for dense app affordances,
 * reach for PixelIcon in chrome, status strips, and panel markers.
 */
export type PixelIconName =
  | "status"
  | "ok"
  | "close"
  | "arrow"
  | "down"
  | "grip"
  | "divider"
  | "spawn"
  | "cycle"
  | "emit"
  | "merge"
  | "folder"
  | "terminal";

type Rect = [x: number, y: number, w: number, h: number];

// Rect maps on a 16x16 grid. Kept deliberately blocky.
const GLYPHS: Record<PixelIconName, Rect[]> = {
  status: [[5, 5, 6, 6]],
  ok: [
    [3, 8, 2, 2],
    [5, 10, 2, 2],
    [7, 8, 2, 2],
    [9, 6, 2, 2],
    [11, 4, 2, 2],
  ],
  close: [
    [3, 3, 2, 2],
    [5, 5, 2, 2],
    [7, 7, 2, 2],
    [9, 9, 2, 2],
    [11, 11, 2, 2],
    [11, 3, 2, 2],
    [9, 5, 2, 2],
    [5, 9, 2, 2],
    [3, 11, 2, 2],
  ],
  arrow: [
    [3, 7, 6, 2],
    [7, 5, 2, 2],
    [9, 7, 2, 2],
    [7, 9, 2, 2],
  ],
  down: [
    [4, 5, 2, 2],
    [6, 7, 2, 2],
    [8, 7, 2, 2],
    [10, 5, 2, 2],
  ],
  grip: [
    [4, 4, 2, 2],
    [10, 4, 2, 2],
    [4, 10, 2, 2],
    [10, 10, 2, 2],
  ],
  divider: [[2, 7, 12, 2]],
  spawn: [
    [7, 2, 2, 5],
    [3, 9, 2, 5],
    [11, 9, 2, 5],
    [3, 7, 10, 2],
  ],
  cycle: [
    [4, 3, 8, 2],
    [4, 3, 2, 4],
    [10, 3, 2, 4],
    [4, 11, 8, 2],
    [10, 9, 2, 4],
    [12, 5, 2, 2],
  ],
  emit: [
    [7, 7, 2, 2],
    [2, 7, 2, 2],
    [12, 7, 2, 2],
    [7, 2, 2, 2],
    [7, 12, 2, 2],
  ],
  merge: [
    [3, 2, 2, 5],
    [11, 2, 2, 5],
    [3, 6, 10, 2],
    [7, 8, 2, 6],
  ],
  folder: [
    [2, 4, 5, 2],
    [2, 5, 12, 2],
    [2, 5, 2, 8],
    [12, 5, 2, 8],
    [2, 12, 12, 2],
  ],
  terminal: [
    [2, 3, 12, 2],
    [2, 11, 12, 2],
    [2, 3, 2, 10],
    [12, 3, 2, 10],
    [4, 6, 3, 2],
    [6, 8, 2, 2],
    [4, 10, 3, 2],
  ],
};

export interface PixelIconProps extends React.SVGProps<SVGSVGElement> {
  name: PixelIconName;
  /** Rendered pixel size (square). Default 16. */
  size?: number;
}

export function PixelIcon({ name, size = 16, className, style, ...props }: PixelIconProps) {
  const rects = GLYPHS[name];
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      role="img"
      aria-hidden="true"
      className={className}
      style={{ shapeRendering: "crispEdges", display: "inline-block", flex: "0 0 auto", ...style }}
      {...props}
    >
      {rects.map(([x, y, w, h], i) => (
        <rect key={i} x={x} y={y} width={w} height={h} fill="currentColor" />
      ))}
    </svg>
  );
}
