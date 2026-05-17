import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { AilaCard } from "@/components/aila/AilaCard";
import { getAllWidgets } from "./widgetRegistry";
import type { WidgetCategory } from "./types";

const CATEGORY_LABELS: Record<WidgetCategory, string> = {
  platform: "Platform",
  vulnerability: "Vulnerability",
  sbd_nfr: "SbD NFR",
  vr: "Vulnerability Research",
};

const CATEGORY_ORDER: WidgetCategory[] = ["platform", "vulnerability", "vr", "sbd_nfr"];

export interface WidgetPickerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeWidgetIds: string[];
  onAddWidget: (widgetId: string) => void;
}

/**
 * WidgetPickerDialog — categorized widget card grid for adding widgets (D-03).
 *
 * Opens as a Dialog, lists all registered widgets grouped by category.
 * Cards are disabled for widgets already on the dashboard.
 * Clicking a card adds it to the grid and closes the dialog.
 */
export function WidgetPickerDialog({
  open,
  onOpenChange,
  activeWidgetIds,
  onAddWidget,
}: WidgetPickerDialogProps) {
  const allWidgets = getAllWidgets();

  function handleAdd(widgetId: string) {
    onAddWidget(widgetId);
    onOpenChange(false);
  }

  const widgetsByCategory = CATEGORY_ORDER.map((category) => ({
    category,
    label: CATEGORY_LABELS[category],
    widgets: allWidgets.filter((w) => w.category === category),
  })).filter((group) => group.widgets.length > 0);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add Widget</DialogTitle>
        </DialogHeader>

        {widgetsByCategory.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4 text-center">
            No widgets are registered yet. Widgets will appear here once modules are loaded.
          </p>
        ) : (
          <div className="space-y-6 mt-2">
            {widgetsByCategory.map(({ category, label, widgets }) => (
              <section key={category}>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                  {label}
                </h3>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  {widgets.map((widget) => {
                    const isActive = activeWidgetIds.includes(widget.id);
                    return (
                      <AilaCard
                        key={widget.id}
                        variant={isActive ? "default" : "interactive"}
                        padding="sm"
                        className={isActive ? "opacity-50 cursor-not-allowed" : ""}
                        onClick={isActive ? undefined : () => handleAdd(widget.id)}
                        role={isActive ? undefined : "button"}
                        tabIndex={isActive ? -1 : 0}
                        onKeyDown={
                          isActive
                            ? undefined
                            : (e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  e.preventDefault();
                                  handleAdd(widget.id);
                                }
                              }
                        }
                        aria-disabled={isActive}
                        aria-label={isActive ? `${widget.name} — already added` : `Add ${widget.name}`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-foreground truncate">
                              {widget.name}
                            </p>
                            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                              {widget.description}
                            </p>
                          </div>
                          {isActive && (
                            <span className="shrink-0 text-xs text-muted-foreground border border-border rounded px-1.5 py-0.5 mt-0.5">
                              Added
                            </span>
                          )}
                        </div>
                      </AilaCard>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
