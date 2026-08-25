/** WidgetHost -- docks visible widgets around the chat panel as always-on-top
 * floaters (req 32). The host owns per-session close/minimize/fullscreen/focus
 * for each widget window; drag/resize is owned by the ConsoleWindow primitive
 * (its rect is seeded once from initialRect). Layout is read from
 * `useWidgetLayout` and NOT mutated here -- the editor page owns persistence.
 *
 * Geometry: the center column hosts the ~820px chat panel; we place `left`
 * widgets in the region between the 216px left rail (0 in basic mode) and the
 * chat's left edge, `right` widgets between the chat's right edge and the
 * viewport, and `bottom`/`top` widgets right-aligned against the viewport
 * edge. A viewport-resize listener updates a coarse geometry signature that is
 * mixed into every widget's React key so a resize remounts the floater with a
 * fresh initialRect (ConsoleWindow's internal rect is seeded once). */

import { useEffect, useMemo, useState, type CSSProperties, type JSX } from "react";

import { css } from "../css";
import { ConsoleWindow, type WindowRect } from "../window";
import { WIDGET_CATALOG } from "./catalog";
import { DEFAULT_LAYOUT, useWidgetLayout } from "./useWidgetLayout";
import type { WidgetLayoutEntry, WidgetSide } from "./types";

interface WidgetHostProps {
  moduleId: string;
  boundId: string | null;
  adv: boolean;
  onOpenPage: (module: string, section: string, label: string, investigationId?: string | null) => void;
}

const MENU_BAR_H = 40; // 32px bar + 8px breathing room
const STATUS_BAR_H = 30; // 24px bar + 6px breathing room
const GAP_PAD = 12;
const CHAT_HALF = 410; // ~820px chat panel
const MIN_WIDGET_W = 160;

interface Region {
  x: number;
  w: number;
}

function computeRects(
  entries: WidgetLayoutEntry[],
  vpW: number,
  vpH: number,
  railW: number,
): Record<string, WindowRect> {
  const top = MENU_BAR_H;
  const bottomLimit = Math.max(top + 120, vpH - STATUS_BAR_H);
  const sectionCenter = railW + (vpW - railW) / 2;
  const chatLeft = sectionCenter - CHAT_HALF;
  const chatRight = sectionCenter + CHAT_HALF;

  const leftStart = railW + GAP_PAD;
  const leftEnd = chatLeft - GAP_PAD;
  const rightStart = chatRight + GAP_PAD;
  const rightEnd = vpW - GAP_PAD;

  const leftRegion: Region = { x: leftStart, w: Math.max(0, leftEnd - leftStart) };
  const rightRegion: Region = { x: rightStart, w: Math.max(0, rightEnd - rightStart) };

  // Per-side cursors so entries stack top-to-bottom in their declared order.
  const cursor: Record<WidgetSide, number> = {
    left: top,
    right: top,
    top: top,
    bottom: bottomLimit,
  };

  const sorted = [...entries].sort((a, b) => a.order - b.order);
  const out: Record<string, WindowRect> = {};

  for (const entry of sorted) {
    const cat = WIDGET_CATALOG[entry.kind];
    if (!cat) continue;
    const { w: baseW, h } = cat.defaultSize;

    let x = 0;
    let w = baseW;
    if (entry.side === "left") {
      // Clamp to the real gap so a floater never crosses into the chat panel.
      // At 1280 with the rail the gap is ~98px, so the widget reads narrow
      // rather than overlapping; below ~30px there is no usable room at all.
      if (leftRegion.w < 30) continue;
      w = Math.min(baseW, leftRegion.w);
      x = leftRegion.x;
    } else if (entry.side === "right") {
      if (rightRegion.w < 30) continue;
      w = Math.min(baseW, rightRegion.w);
      x = rightStart + Math.max(0, rightRegion.w - w);
    } else {
      // top / bottom: right-align near the viewport edge (clock bottom-right)
      w = Math.min(baseW, Math.max(MIN_WIDGET_W, vpW - GAP_PAD - railW - GAP_PAD));
      x = Math.max(railW + GAP_PAD, vpW - GAP_PAD - w);
    }

    let y: number;
    if (entry.side === "bottom") {
      const nextTop = cursor.bottom - h;
      y = Math.max(top, nextTop);
      cursor.bottom = y - 10;
    } else {
      const startY = cursor[entry.side];
      const maxY = bottomLimit - h;
      y = Math.min(Math.max(top, startY), Math.max(top, maxY));
      cursor[entry.side] = y + h + 10;
    }

    out[entry.id] = { x, y, w, h };
  }

  return out;
}

const chipStripStyle: CSSProperties = css(
  "position:fixed;right:10px;top:42px;z-index:41;display:flex;flex-direction:column;gap:6px;pointer-events:none;",
);
const chipRowStyle: CSSProperties = css(
  "pointer-events:auto;display:flex;align-items:center;gap:6px;padding:3px 6px 3px 9px;background:var(--surface-card);border:1px solid var(--border-soft);border-radius:2px;box-shadow:0 4px 14px rgba(0,0,0,0.35);",
);
const chipDotStyle: CSSProperties = css(
  "width:7px;height:7px;background:var(--accent);box-shadow:0 0 7px var(--accent);flex:0 0 auto;",
);
const chipBtnStyle: CSSProperties = css(
  "background:transparent;border:0;color:var(--text-primary);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px;",
);
const chipCloseStyle: CSSProperties = css(
  "background:transparent;border:0;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;cursor:pointer;padding:0 3px;flex:0 0 auto;",
);

export default function WidgetHost(props: WidgetHostProps): JSX.Element | null {
  const { moduleId, boundId, adv, onOpenPage } = props;
  const { data: layout } = useWidgetLayout();
  const effective = layout ?? DEFAULT_LAYOUT;

  const [closed, setClosed] = useState<Set<string>>(() => new Set());
  const [minimized, setMinimized] = useState<Set<string>>(() => new Set());
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [fullscreenId, setFullscreenId] = useState<string | null>(null);
  const [vp, setVp] = useState(() => ({
    w: typeof window !== "undefined" ? window.innerWidth : 1440,
    h: typeof window !== "undefined" ? window.innerHeight : 900,
  }));

  useEffect(() => {
    const onResize = () => setVp({ w: window.innerWidth, h: window.innerHeight });
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const railW = adv ? 216 : 0;
  const geoSig = `${railW}:${Math.round(vp.w / 80)}:${Math.round(vp.h / 80)}`;

  const visible = useMemo(
    () => effective.widgets.filter((e) => !e.hidden && !closed.has(e.id) && !minimized.has(e.id)),
    [effective, closed, minimized],
  );
  const rects = useMemo(() => computeRects(visible, vp.w, vp.h, railW), [visible, vp.w, vp.h, railW]);

  const minimizedEntries = effective.widgets.filter((e) => !e.hidden && !closed.has(e.id) && minimized.has(e.id));

  const handleClose = (id: string) => {
    setClosed((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });
    setMinimized((prev) => {
      if (!prev.has(id)) return prev;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    if (focusedId === id) setFocusedId(null);
    if (fullscreenId === id) setFullscreenId(null);
  };

  const handleMinimize = (id: string) => {
    setMinimized((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });
    if (focusedId === id) setFocusedId(null);
    if (fullscreenId === id) setFullscreenId(null);
  };

  const restore = (id: string) => {
    setMinimized((prev) => {
      if (!prev.has(id)) return prev;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    setFocusedId(id);
  };

  return (
    <>
      {visible.map((entry) => {
        const cat = WIDGET_CATALOG[entry.kind];
        if (!cat) return null;
        const rect = rects[entry.id];
        if (!rect) return null;
        return (
          <ConsoleWindow
            key={`${entry.id}:${geoSig}`}
            id={entry.id}
            title={cat.title}
            kind="floater"
            initialRect={rect}
            minSize={{ w: Math.min(160, rect.w), h: Math.min(110, rect.h) }}
            canFullscreen={cat.canFullscreen}
            isFocused={focusedId === entry.id}
            isFullscreen={fullscreenId === entry.id}
            onFocus={() => setFocusedId(entry.id)}
            onClose={() => handleClose(entry.id)}
            onMinimize={() => handleMinimize(entry.id)}
            onToggleFullscreen={
              cat.canFullscreen
                ? () => setFullscreenId((cur) => (cur === entry.id ? null : entry.id))
                : undefined
            }
          >
            {cat.render({ moduleId, boundId, onOpenPage })}
          </ConsoleWindow>
        );
      })}
      {minimizedEntries.length > 0 ? (
        <div style={chipStripStyle}>
          {minimizedEntries.map((entry) => {
            const cat = WIDGET_CATALOG[entry.kind];
            const title = cat?.title ?? entry.kind;
            return (
              <div key={entry.id} style={chipRowStyle}>
                <span style={chipDotStyle} />
                <button
                  type="button"
                  onClick={() => restore(entry.id)}
                  title={`restore ${title}`}
                  style={chipBtnStyle}
                >
                  {title}
                </button>
                <button
                  type="button"
                  onClick={() => handleClose(entry.id)}
                  title={`close ${title}`}
                  style={chipCloseStyle}
                >
                  {"\u2715"}
                </button>
              </div>
            );
          })}
        </div>
      ) : null}
    </>
  );
}
