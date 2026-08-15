import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * WindowPanel -- the AILA design-system signature surface primitive.
 *
 * An OS-window chrome card: a hatched title bar carrying a system "light"
 * square + a mono uppercase title (and optional trailing actions), a body,
 * and an optional one-line mono status footer. Inset-first bevel makes the
 * panel read as sunk into the midnight page rather than floating on it.
 *
 * All design values come from the AILA tokens in globals.css so the panel
 * stays coherent with the single midnight-cloud-8 theme. Prefer this over a
 * bare rounded card for any titled content region.
 */
export type WindowPanelTone = "accent" | "ok" | "info" | "warn" | "muted";

const TONE_VAR: Record<WindowPanelTone, string> = {
  accent: "var(--color-accent)",
  ok: "var(--color-mint)",
  info: "var(--color-lavender)",
  warn: "var(--color-amber)",
  muted: "var(--color-text-faint)",
};

export interface WindowPanelProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, "title"> {
  /** Mono uppercase label shown in the hatched title bar. Omit for a bare panel. */
  title?: React.ReactNode;
  /** Trailing controls rendered at the right edge of the title bar. */
  actions?: React.ReactNode;
  /** One-line mono status footer. */
  status?: React.ReactNode;
  /** Colour of the system light square + footer dot. */
  tone?: WindowPanelTone;
  /** Drop body padding (tables, full-bleed content). */
  flush?: boolean;
}

export function WindowPanel({
  title,
  actions,
  status,
  tone = "accent",
  flush = false,
  className,
  children,
  ...props
}: WindowPanelProps) {
  const dot = TONE_VAR[tone];
  return (
    <div
      data-slot="window-panel"
      className={cn("flex min-w-0 flex-col border bg-surface text-foreground", className)}
      style={{
        borderColor: "var(--color-border-bright)",
        borderRadius: "var(--radius-md)",
        boxShadow: "var(--bevel-raised)",
      }}
      {...props}
    >
      {title != null && (
        <div
          data-slot="window-panel-title"
          className="flex flex-none items-center gap-2 border-b px-3"
          style={{
            height: "var(--panel-title-h)",
            borderColor: "var(--color-border)",
            backgroundColor: "var(--color-chrome)",
            backgroundImage: "var(--hatch)",
          }}
        >
          <span
            aria-hidden="true"
            style={{ width: 8, height: 8, flex: "0 0 auto", background: dot, boxShadow: `0 0 6px ${dot}` }}
          />
          <span
            className="truncate font-mono uppercase text-muted-foreground"
            style={{ fontSize: "10.5px", letterSpacing: "0.14em" }}
          >
            {title}
          </span>
          {actions != null && <span className="ml-auto flex items-center gap-1">{actions}</span>}
        </div>
      )}
      <div data-slot="window-panel-body" className={cn("min-h-0 min-w-0 flex-1", flush ? "" : "p-4")}>
        {children}
      </div>
      {status != null && (
        <div
          data-slot="window-panel-status"
          className="flex flex-none items-center gap-2 border-t px-3 font-mono"
          style={{
            height: "var(--panel-status-h)",
            borderColor: "var(--color-border)",
            backgroundColor: "var(--color-chrome)",
            fontSize: "10.5px",
            letterSpacing: "0.06em",
            color: "var(--color-text-faint)",
          }}
        >
          <span aria-hidden="true" style={{ width: 5, height: 5, flex: "0 0 auto", background: dot }} />
          <span className="truncate">{status}</span>
        </div>
      )}
    </div>
  );
}
