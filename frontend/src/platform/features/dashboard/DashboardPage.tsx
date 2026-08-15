import * as React from "react";
import { SquaresFour } from "@phosphor-icons/react/dist/csr/SquaresFour";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { initModuleWidgets, getWidgetById } from "./widgetRegistry";
import { registerAllPlatformWidgets } from "./widgets";
import { useWidgetLayout, useSaveLayout } from "./useWidgetLayout";
import { DashboardGrid } from "./DashboardGrid";
import { EditModeToggle } from "./EditModeToggle";
import { WidgetPickerDialog } from "./WidgetPickerDialog";
import type { DashboardLayoutItem, SerializedLayout } from "./types";

/**
 * Finds the lowest y-position available to place a widget of the given size.
 * Packs to the bottom of the current layout.
 */
function findNextSlot(
  existingItems: DashboardLayoutItem[],
  _w: number,
): { x: number; y: number } {
  if (existingItems.length === 0) {
    return { x: 0, y: 0 };
  }
  const maxY = Math.max(...existingItems.map((item) => item.y + item.h));
  return { x: 0, y: maxY };
}

const MOCK_BUTTON_STYLE: React.CSSProperties = {
  height: 26,
  padding: "0 12px",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
  fontSize: 9.5,
  letterSpacing: "0.1em",
  textTransform: "uppercase",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

export function DashboardPage() {
  const [editMode, setEditMode] = React.useState(false);
  const [pickerOpen, setPickerOpen] = React.useState(false);
  const [localLayout, setLocalLayout] = React.useState<SerializedLayout | null>(null);

  // Register built-in platform widgets first, then module-contributed widgets (idempotent)
  React.useEffect(() => {
    registerAllPlatformWidgets();
    initModuleWidgets();
  }, []);

  const { layout: serverLayout, isLoading, isError, error } = useWidgetLayout();
  const saveLayout = useSaveLayout();

  // Initialize local layout once server layout arrives
  React.useEffect(() => {
    if (serverLayout && localLayout === null) {
      setLocalLayout(serverLayout);
    }
  }, [serverLayout, localLayout]);

  // Debounce timer ref for saves
  const saveTimerRef = React.useRef<number | null>(null);

  function triggerDebouncedSave(layout: SerializedLayout) {
    clearTimeout(saveTimerRef.current ?? undefined);
    saveTimerRef.current = window.setTimeout(() => {
      saveLayout.mutate(layout);
    }, 1000);
  }

  function handleLayoutChange(newItems: DashboardLayoutItem[]) {
    const updated: SerializedLayout = { version: 1, items: newItems };
    setLocalLayout(updated);
    triggerDebouncedSave(updated);
  }

  function handleRemoveWidget(widgetId: string) {
    const current = localLayout ?? serverLayout;
    const updated: SerializedLayout = {
      version: 1,
      items: current.items.filter((item) => item.i !== widgetId),
    };
    setLocalLayout(updated);
    triggerDebouncedSave(updated);
  }

  function handleAddWidget(widgetId: string) {
    const current = localLayout ?? serverLayout;
    const widgetDef = getWidgetById(widgetId);
    const size = widgetDef?.defaultSize ?? { w: 3, h: 2, minW: 2, minH: 2 };
    const { x, y } = findNextSlot(current.items, size.w);

    const newItem: DashboardLayoutItem = {
      i: widgetId,
      x,
      y,
      w: size.w,
      h: size.h,
      minW: size.minW,
      minH: size.minH,
      maxW: size.maxW,
      maxH: size.maxH,
    };

    const updated: SerializedLayout = {
      version: 1,
      items: [...current.items, newItem],
    };
    setLocalLayout(updated);
    triggerDebouncedSave(updated);
  }

  // Clean up debounce timer on unmount
  React.useEffect(() => {
    return () => {
      clearTimeout(saveTimerRef.current ?? undefined);
    };
  }, []);

  const currentLayout = localLayout ?? serverLayout;

  const actions = (
    <>
      {editMode && (
        <button
          type="button"
          onClick={() => setPickerOpen(true)}
          style={MOCK_BUTTON_STYLE}
          data-testid="dashboard-add-widget"
        >
          <span aria-hidden="true" style={{ fontSize: 11 }}>{"+"}</span>
          add widget
        </button>
      )}
      <EditModeToggle
        editMode={editMode}
        onToggle={() => setEditMode((prev) => !prev)}
      />
    </>
  );

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader icon={"\u25CE"} title="dashboard" actions={actions} />

      {/* Loading state */}
      {isLoading && (
        <WindowPanel title="dashboard" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {/* Error state */}
      {isError && (
        <WindowPanel title="dashboard" status="ERROR" tone="warn">
          <div
            className="font-mono"
            style={{
              color: "var(--status-warn)",
              fontSize: 11,
              padding: "6px 2px",
              letterSpacing: "0.02em",
            }}
          >
            Failed to load dashboard layout:{" "}
            {error instanceof Error ? error.message : "Unknown error"}
          </div>
        </WindowPanel>
      )}

      {/* Empty state -- mock-styled EmptyState replacement */}
      {!isLoading && !isError && currentLayout.items.length === 0 && (
        <WindowPanel title="dashboard" tone="muted">
          <div
            className="flex flex-col items-center justify-center"
            style={{ gap: 12, padding: "40px 16px", textAlign: "center" }}
          >
            <SquaresFour size={40} style={{ color: "var(--text-faint)" }} aria-hidden="true" />
            <div
              className="font-mono"
              style={{
                fontSize: 12,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "var(--text-primary)",
              }}
            >
              your dashboard is empty
            </div>
            <div
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                maxWidth: 380,
              }}
            >
              Add widgets to build your personalized security overview.
            </div>
            <button
              type="button"
              onClick={() => setPickerOpen(true)}
              style={{
                ...MOCK_BUTTON_STYLE,
                border: "1px solid var(--accent)",
                color: "var(--accent)",
                marginTop: 4,
              }}
              data-testid="dashboard-empty-add-widget"
            >
              add widget
            </button>
          </div>
        </WindowPanel>
      )}

      {/* Grid */}
      {!isLoading && currentLayout.items.length > 0 && (
        <DashboardGrid
          layout={currentLayout.items}
          editMode={editMode}
          onLayoutChange={handleLayoutChange}
          onRemoveWidget={handleRemoveWidget}
        />
      )}

      {/* Widget picker dialog */}
      <WidgetPickerDialog
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        activeWidgetIds={currentLayout.items.map((item) => item.i)}
        onAddWidget={handleAddWidget}
      />
    </div>
  );
}
