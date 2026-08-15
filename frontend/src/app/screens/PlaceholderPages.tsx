/**
 * Placeholder pages for routes that will be fully implemented in later plans.
 * Plan 03 will replace SessionsPlaceholder with the real session management page.
 *
 * A centered `WindowPanel` gives the placeholder the same OS-window chrome as
 * every other page, so a not-yet-shipped route still reads as part of the
 * workbench and not as a bare div.
 */
import * as React from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";

const PLACEHOLDER_BODY = (
  <p className="font-mono text-xs text-text-muted">
    This surface is queued for a later phase.
  </p>
);

function PlaceholderShell({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-64 items-center justify-center p-6">
      <WindowPanel
        title={title}
        tone="muted"
        status="coming soon"
        className="w-full max-w-md"
      >
        <div className="flex flex-col items-center gap-3 py-6 text-center">
          <p
            className="font-mono uppercase text-text-muted"
            style={{ fontSize: "10.5px", letterSpacing: "0.14em" }}
          >
            {title}
          </p>
          {children}
        </div>
      </WindowPanel>
    </div>
  );
}

export function SettingsPlaceholder() {
  return <PlaceholderShell title="SETTINGS">{PLACEHOLDER_BODY}</PlaceholderShell>;
}

export function SessionsPlaceholder() {
  return <PlaceholderShell title="SESSIONS">{PLACEHOLDER_BODY}</PlaceholderShell>;
}
