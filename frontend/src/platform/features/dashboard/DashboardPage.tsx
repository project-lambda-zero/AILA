import * as React from "react";
import { Plus } from "lucide-react";
import { SquaresFour } from "@phosphor-icons/react/dist/csr/SquaresFour";

import { Button } from "@/components/ui/button";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
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
  w: number,
): { x: number; y: number } {
  if (existingItems.length === 0) {
    return { x: 0, y: 0 };
  }
  const maxY = Math.max(...existingItems.map((item) => item.y + item.h));
  return { x: 0, y: maxY };
}

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
  const saveTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  function triggerDebouncedSave(layout: SerializedLayout) {
    if (saveTimerRef.current !== null) {
      clearTimeout(saveTimerRef.current);
    }
    saveTimerRef.current = setTimeout(() => {
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
      if (saveTimerRef.current !== null) {
        clearTimeout(saveTimerRef.current);
      }
    };
  }, []);

  const currentLayout = localLayout ?? serverLayout;

  // Hoist the page-level actions (Add Widget when editing + EditModeToggle)
  // into the PageShell sticky header via useUpdatePageHeader, so the
  // controls sit alongside the page title in the global cyber-tech bar.
  //
  // MUST be memoized: useUpdatePageHeader stores `actions` in a useEffect
  // dep array (reference equality). An inline JSX fragment here is a fresh
  // object every render → effect fires → setOverrides → context update →
  // re-render → "Maximum update depth exceeded".
  const headerActions = React.useMemo(
    () => (
      <>
        {editMode && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPickerOpen(true)}
          >
            <Plus className="h-4 w-4 mr-1" />
            Add Widget
          </Button>
        )}
        <EditModeToggle
          editMode={editMode}
          onToggle={() => setEditMode((prev) => !prev)}
        />
      </>
    ),
    [editMode],
  );
  useUpdatePageHeader({ actions: headerActions });
  return (
    <div className="depth-mesh space-y-4">
      {/* Loading state */}
      {isLoading && (
        <div className="p-4">
          <LoadingSkeletonGroup lines={6} />
        </div>
      )}

      {/* Error state */}
      {isError && (
        <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load dashboard layout:{" "}
          {error instanceof Error ? error.message : "Unknown error"}
        </div>
      )}

      {/* Grid — or empty state when no widgets */}
      {!isLoading && currentLayout.items.length === 0 && (
        <EmptyState
          icon={<SquaresFour size={40} />}
          title="Your dashboard is empty"
          description="Add widgets to build your personalized security overview."
          action={{ label: "Add Widget", onClick: () => setPickerOpen(true) }}
        />
      )}
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
