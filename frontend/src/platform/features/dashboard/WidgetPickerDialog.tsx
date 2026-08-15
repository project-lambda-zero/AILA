import * as React from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";
import { getAllWidgets } from "./widgetRegistry";
import type { WidgetCategory } from "./types";

const CATEGORY_LABELS: Record<WidgetCategory, string> = {
  platform: "platform",
  vulnerability: "vulnerability",
  vr: "vulnerability research",
  malware: "malware analysis",
};

const CATEGORY_ORDER: WidgetCategory[] = ["platform", "vulnerability", "vr", "malware"];

export interface WidgetPickerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeWidgetIds: string[];
  onAddWidget: (widgetId: string) => void;
}

const BACKDROP_STYLE: React.CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "color-mix(in srgb, var(--surface-page) 78%, transparent)",
  backdropFilter: "blur(2px)",
  zIndex: 60,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 24,
};

const DIALOG_WRAP_STYLE: React.CSSProperties = {
  width: "100%",
  maxWidth: 720,
  maxHeight: "80vh",
  display: "flex",
  flexDirection: "column",
};

const CLOSE_BUTTON_STYLE: React.CSSProperties = {
  height: 22,
  padding: "0 10px",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  letterSpacing: "0.1em",
  textTransform: "uppercase",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-muted)",
  cursor: "pointer",
};

/**
 * WidgetPickerDialog -- categorized widget list for adding widgets (D-03).
 *
 * Mono modal: fixed backdrop + centered WindowPanel titled "add widget".
 * Each widget is a mono row; already-added widgets are marked ADDED via
 * MonoBadge and disabled.
 */
export function WidgetPickerDialog({
  open,
  onOpenChange,
  activeWidgetIds,
  onAddWidget,
}: WidgetPickerDialogProps) {
  const allWidgets = getAllWidgets();

  // ESC to close (matches shadcn Dialog UX).
  React.useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onOpenChange(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  if (!open) return null;

  function handleAdd(widgetId: string) {
    onAddWidget(widgetId);
    onOpenChange(false);
  }

  const widgetsByCategory = CATEGORY_ORDER.map((category) => ({
    category,
    label: CATEGORY_LABELS[category],
    widgets: allWidgets.filter((w) => w.category === category),
  })).filter((group) => group.widgets.length > 0);

  const closeAction = (
    <button
      type="button"
      onClick={() => onOpenChange(false)}
      style={CLOSE_BUTTON_STYLE}
      aria-label="Close widget picker"
      data-testid="dashboard-picker-close"
    >
      close
    </button>
  );

  return (
    <div
      role="presentation"
      style={BACKDROP_STYLE}
      onClick={(e) => {
        if (e.target === e.currentTarget) onOpenChange(false);
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Add Widget"
        style={DIALOG_WRAP_STYLE}
        onClick={(e) => e.stopPropagation()}
      >
        <WindowPanel
          title="add widget"
          actions={closeAction}
          className="flex flex-col overflow-hidden"
        >
          <div
            className="flex flex-col overflow-auto"
            style={{ gap: 20, maxHeight: "68vh" }}
          >
            {widgetsByCategory.length === 0 ? (
              <div
                className="font-mono"
                style={{
                  fontSize: 11,
                  color: "var(--text-muted)",
                  padding: "24px 0",
                  textAlign: "center",
                }}
              >
                No widgets are registered yet. Widgets will appear here once modules are loaded.
              </div>
            ) : (
              widgetsByCategory.map(({ category, label, widgets }) => (
                <section key={category} className="flex flex-col" style={{ gap: 6 }}>
                  <h3
                    className="font-mono uppercase"
                    style={{
                      fontSize: 10,
                      letterSpacing: "0.16em",
                      color: "var(--text-faint)",
                      borderBottom: "1px solid var(--border-faint)",
                      paddingBottom: 4,
                      margin: 0,
                    }}
                  >
                    {label}
                  </h3>
                  <div className="flex flex-col" style={{ gap: 4 }}>
                    {widgets.map((widget) => {
                      const isActive = activeWidgetIds.includes(widget.id);
                      const row = (
                        <div
                          className="flex items-start justify-between"
                          style={{ gap: 12, minWidth: 0 }}
                        >
                          <div className="min-w-0" style={{ flex: 1 }}>
                            <div
                              className="font-mono truncate"
                              style={{
                                fontSize: 12,
                                color: isActive
                                  ? "var(--text-muted)"
                                  : "var(--text-primary)",
                                letterSpacing: "0.02em",
                              }}
                            >
                              {widget.name}
                            </div>
                            <div
                              className="font-mono"
                              style={{
                                fontSize: 10.5,
                                color: "var(--text-faint)",
                                marginTop: 2,
                                lineHeight: 1.4,
                              }}
                            >
                              {widget.description}
                            </div>
                          </div>
                          {isActive && (
                            <MonoBadge tone="muted">added</MonoBadge>
                          )}
                        </div>
                      );

                      const rowStyle: React.CSSProperties = {
                        padding: "8px 10px",
                        borderRadius: 3,
                        border: "1px solid var(--border-faint)",
                        background: "var(--surface-sunk)",
                        opacity: isActive ? 0.55 : 1,
                        cursor: isActive ? "not-allowed" : "pointer",
                        textAlign: "left",
                        width: "100%",
                        color: "inherit",
                      };

                      if (isActive) {
                        return (
                          <div
                            key={widget.id}
                            style={rowStyle}
                            aria-disabled="true"
                            aria-label={`${widget.name} -- already added`}
                          >
                            {row}
                          </div>
                        );
                      }

                      return (
                        <button
                          key={widget.id}
                          type="button"
                          style={rowStyle}
                          onClick={() => handleAdd(widget.id)}
                          aria-label={`Add ${widget.name}`}
                          data-testid={`dashboard-picker-widget-${widget.id}`}
                        >
                          {row}
                        </button>
                      );
                    })}
                  </div>
                </section>
              ))
            )}
          </div>
        </WindowPanel>
      </div>
    </div>
  );
}
