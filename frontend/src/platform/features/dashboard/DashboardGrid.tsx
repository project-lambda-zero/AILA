import * as React from "react";
import { Responsive, useContainerWidth, verticalCompactor } from "react-grid-layout";
import type { Layout } from "react-grid-layout";
import "react-grid-layout/css/styles.css";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { FeatureBoundary } from "@app/FeatureBoundary";
import { getWidgetById } from "./widgetRegistry";
import type { DashboardLayoutItem } from "./types";

export interface DashboardGridProps {
  layout: DashboardLayoutItem[];
  editMode: boolean;
  onLayoutChange: (newLayout: DashboardLayoutItem[]) => void;
  onRemoveWidget: (widgetId: string) => void;
}

const HANDLE_STRIP_STYLE: React.CSSProperties = {
  height: 22,
  padding: "0 8px",
  background: "var(--surface-chrome)",
  backgroundImage: "var(--hatch)",
  borderBottom: "1px solid var(--border-soft)",
  cursor: "grab",
};

const REMOVE_BUTTON_STYLE: React.CSSProperties = {
  height: 16,
  width: 16,
  borderRadius: 2,
  border: "1px solid var(--border-soft)",
  background: "transparent",
  color: "var(--text-muted)",
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  lineHeight: 1,
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
};

/**
 * DashboardGrid -- 12-column drag-drop resizable widget grid (D-01).
 *
 * Uses react-grid-layout v2. Every widget cell is wrapped in a WindowPanel
 * carrying the widget's display name in its hatched title bar. Edit mode
 * exposes a drag-handle strip and a remove control.
 */
export function DashboardGrid({
  layout,
  editMode,
  onLayoutChange,
  onRemoveWidget,
}: DashboardGridProps) {
  const { width, containerRef, mounted } = useContainerWidth();
  const [rowHeight, setRowHeight] = React.useState(80);

  React.useEffect(() => {
    function updateRowHeight() {
      // Calculate available height: viewport minus header (~64px) and padding (~96px)
      const availableHeight = window.innerHeight - 160;
      // Target 5 rows. 5 rows means 4 gaps of 16px (64px total margin).
      const calculated = Math.floor((availableHeight - 64) / 5);
      setRowHeight(Math.max(80, calculated)); // Floor of 80px
    }
    updateRowHeight();
    window.addEventListener("resize", updateRowHeight);
    return () => window.removeEventListener("resize", updateRowHeight);
  }, []);

  function handleLayoutChange(rglLayout: Layout) {
    const mapped: DashboardLayoutItem[] = rglLayout.map((item) => {
      const original = layout.find((l) => l.i === item.i);
      return {
        i: item.i,
        x: item.x,
        y: item.y,
        w: item.w,
        h: item.h,
        minW: original?.minW,
        minH: original?.minH,
        maxW: original?.maxW,
        maxH: original?.maxH,
      };
    });
    onLayoutChange(mapped);
  }

  const rglLayout: Layout = layout.map((item) => ({
    i: item.i,
    x: item.x,
    y: item.y,
    w: item.w,
    h: item.h,
    minW: item.minW,
    minH: item.minH,
    maxW: item.maxW,
    maxH: item.maxH,
    isDraggable: editMode,
    isResizable: editMode,
  }));

  const layouts = { lg: rglLayout };

  return (
    <>
      {/* Grid placeholder + item overrides -- tokenized to the mock palette */}
      <style>{`
        .react-grid-placeholder {
          background: var(--accent) !important;
          opacity: 0.15;
          border: 1px dashed var(--accent);
          border-radius: 3px;
        }
        .react-grid-item { transition: none !important; }
        .react-grid-item.react-grid-placeholder { transition: none !important; }
      `}</style>

      <div ref={containerRef} className="w-full">
        {mounted && (
          <Responsive
            layouts={layouts}
            breakpoints={{ lg: 1024, md: 768, sm: 640, xs: 480 }}
            cols={{ lg: 12, md: 8, sm: 4, xs: 2 }}
            rowHeight={rowHeight}
            margin={[16, 16]}
            containerPadding={[0, 0]}
            compactor={verticalCompactor}
            width={width}
            dragConfig={{ enabled: editMode, handle: ".widget-drag-handle" }}
            resizeConfig={{ enabled: editMode }}
            onLayoutChange={handleLayoutChange}
          >
            {layout.map((item) => {
              const widgetDef = getWidgetById(item.i);
              const WidgetComponent = widgetDef?.component;
              const label = widgetDef?.name ?? item.i;

              return (
                <div key={item.i} className="relative flex flex-col overflow-hidden">
                  {/* Edit-mode drag-handle strip -- sits above the WindowPanel
                      chrome so the OS-window title bar is not competing with
                      the grip. In locked mode the widget's own WindowPanel
                      title carries the name. */}
                  {editMode && (
                    <div
                      className="widget-drag-handle flex items-center justify-between shrink-0"
                      style={HANDLE_STRIP_STYLE}
                    >
                      <span
                        aria-hidden="true"
                        className="font-mono"
                        style={{
                          fontSize: 11,
                          color: "var(--text-faint)",
                          letterSpacing: "0.14em",
                        }}
                      >
                        {"\u2237"}
                      </span>
                      <span
                        className="font-mono uppercase truncate"
                        style={{
                          fontSize: 10.5,
                          letterSpacing: "0.14em",
                          color: "var(--text-muted)",
                          padding: "0 8px",
                        }}
                      >
                        {label.toLowerCase()}
                      </span>
                      <button
                        type="button"
                        onClick={() => onRemoveWidget(item.i)}
                        aria-label={`Remove ${label} widget`}
                        data-testid={`dashboard-remove-widget-${item.i}`}
                        style={REMOVE_BUTTON_STYLE}
                      >
                        {"\u2715"}
                      </button>
                    </div>
                  )}

                  {/* Widget content -- per-widget FeatureBoundary so one
                      failed widget renders a scoped retry surface instead
                      of blanking the entire grid (V-24 resilience). */}
                  <WindowPanel
                    flush
                    title={editMode ? undefined : label.toLowerCase()}
                    tone="muted"
                    className="flex-1 overflow-auto min-h-0"
                  >
                    {WidgetComponent ? (
                      <FeatureBoundary label={label}>
                        <WidgetComponent />
                      </FeatureBoundary>
                    ) : (
                      <div
                        className="flex items-center justify-center font-mono"
                        style={{
                          height: "100%",
                          padding: 16,
                          fontSize: 11,
                          color: "var(--text-muted)",
                        }}
                      >
                        widget not available
                      </div>
                    )}
                  </WindowPanel>
                </div>
              );
            })}
          </Responsive>
        )}
      </div>
    </>
  );
}
