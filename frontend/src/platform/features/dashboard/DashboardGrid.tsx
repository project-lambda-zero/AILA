import * as React from "react";
import { Responsive, useContainerWidth, verticalCompactor } from "react-grid-layout";
import type { Layout } from "react-grid-layout";
import { GripHorizontal, X } from "lucide-react";
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

/**
 * DashboardGrid -- 12-column drag-drop resizable widget grid (D-01).
 *
 * Uses react-grid-layout v2 with cyberpunk design token overrides.
 * Edit mode shows drag handles and remove buttons.
 * Locked mode is a clean read-only view.
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
      {/* Cyberpunk grid-placeholder override */}
      <style>{`
        .react-grid-placeholder {
          background: var(--color-accent) !important;
          opacity: 0.15;
          border: 1px dashed var(--color-accent);
          border-radius: 4px;
        }
        .react-grid-item {
          transition: none !important;
        }
        .react-grid-item.react-grid-placeholder {
          transition: none !important;
        }
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

              return (
                <div key={item.i} className="relative flex flex-col overflow-hidden">
                  {/* Edit mode drag handle bar */}
                  {editMode && (
                    <div
                      className="widget-drag-handle flex items-center justify-between px-2 py-1 border-b border-border cursor-grab active:cursor-grabbing shrink-0"
                      style={{ backgroundColor: "var(--color-chrome)", backgroundImage: "var(--hatch)" }}
                    >
                      <GripHorizontal className="h-4 w-4 text-muted-foreground" />
                      <span
                        className="font-mono uppercase text-muted-foreground truncate px-2"
                        style={{ fontSize: "10.5px", letterSpacing: "0.14em" }}
                      >
                        {widgetDef?.name ?? item.i}
                      </span>
                      <button
                        onClick={() => onRemoveWidget(item.i)}
                        className="flex items-center justify-center h-5 w-5 rounded-[2px] hover:bg-destructive/20 hover:text-destructive text-muted-foreground transition-colors"
                        aria-label={`Remove ${widgetDef?.name ?? item.i} widget`}
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </div>
                  )}

                  {/* Widget content -- per-widget FeatureBoundary so one
                      failed widget renders a scoped retry surface instead
                      of blanking the entire grid (V-24 resilience).
                      Non-edit mode carries the widget's display name in the
                      panel title bar; edit mode hoists the name into the
                      drag-handle strip above and leaves the panel flush so
                      the OS-window chrome doesn't compete with the grip. */}
                  <WindowPanel
                    flush
                    title={editMode ? undefined : widgetDef?.name}
                    tone="muted"
                    className="flex-1 overflow-auto min-h-0"
                  >{WidgetComponent ? (
                    <FeatureBoundary label={widgetDef?.name ?? "Widget"}>
                      <WidgetComponent />
                    </FeatureBoundary>
                  ) : (
                    <div className="flex items-center justify-center h-full p-4 text-sm text-muted-foreground">
                      Widget not available
                    </div>
                  )}</WindowPanel>
                </div>
              );
            })}
          </Responsive>
        )}
      </div>
    </>
  );
}
