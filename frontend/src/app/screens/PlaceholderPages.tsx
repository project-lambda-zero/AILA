/**
 * Placeholder pages for routes that will be fully implemented in later plans.
 * Plan 03 will replace SessionsPlaceholder with the real session management
 * page.
 *
 * A centred `WindowPanel` with a mock `SectionHeader` gives the placeholder
 * the same OS-window chrome as every other page, so a not-yet-shipped route
 * still reads as part of the workbench and not as a bare div.
 */
import * as React from "react";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

function PlaceholderShell({ title }: { title: string }) {
  return (
    <div className="flex min-h-64 items-center justify-center p-6">
      <WindowPanel
        title={title.toLowerCase()}
        tone="muted"
        status="coming soon"
        className="w-full max-w-md"
      >
        <div className="flex flex-col" style={{ gap: 14, padding: "6px 2px 4px" }}>
          <SectionHeader icon={"\u25ce"} title={title.toLowerCase()} size={20} />
          <p
            className="font-mono"
            style={{
              color: "var(--text-muted)",
              fontSize: 11,
              lineHeight: 1.55,
              letterSpacing: "0.02em",
            }}
          >
            This surface is queued for a later phase.
          </p>
        </div>
      </WindowPanel>
    </div>
  );
}

export function SettingsPlaceholder(): React.ReactElement {
  return <PlaceholderShell title="SETTINGS" />;
}

export function SessionsPlaceholder(): React.ReactElement {
  return <PlaceholderShell title="SESSIONS" />;
}
