import type { ReactNode } from "react";

import { type ModuleFrontendSpec } from "@platform/extension-registry/types";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { OfflineBanner } from "@/components/shell/OfflineBanner";
import { OnboardingWizard } from "@platform/features/onboarding";
import { AppSidebar } from "./AppSidebar";
import { AppHeader } from "./AppHeader";

interface AppShellProps {
  children: ReactNode;
  moduleSpecs: ModuleFrontendSpec[];
}

function getStoredSidebarOpen(): boolean {
  try {
    return localStorage.getItem("aila-sidebar-open") !== "false";
  } catch {
    return true;
  }
}

function getDefaultSidebarOpen(): boolean {
  // Tablet breakpoint (768-1024px): default to collapsed rail (D-08)
  if (typeof window !== "undefined" && window.innerWidth < 1024) {
    return false;
  }
  // Desktop (>1024px): read from localStorage
  return getStoredSidebarOpen();
}

export function AppShell({ children, moduleSpecs }: AppShellProps) {
  return (
    <SidebarProvider
      defaultOpen={getDefaultSidebarOpen()}
      onOpenChange={(open) => {
        try {
          localStorage.setItem("aila-sidebar-open", String(open));
        } catch {
          // localStorage unavailable — ignore
        }
      }}
    >
      <AppSidebar moduleSpecs={moduleSpecs} />
      <SidebarInset>
        <AppHeader />
        <OfflineBanner />
        <main className="flex-1 overflow-y-auto overflow-x-hidden p-3 sm:p-4 lg:p-6">
          {children}
        </main>
      </SidebarInset>
      {/* CommandPalette renders via portal — outside layout flow (D-09, D-10) */}
      <CommandPalette />

      {/*
        App-level cyber-tech overlay — corner brackets + top hairline
        rendered ONCE here so every route gets the treatment without
        each page having to opt in. All decoration uses
        --color-accent so it theme-adapts (synthwave pink, vaporwave
        teal, ps2 cyan, vendetta red, midnight-cloud-8 hot pink).
        Fixed-positioned + z-50 + pointer-events-none so they sit
        above content but don't intercept clicks.
      */}
      <span
        aria-hidden
        className="pointer-events-none fixed inset-x-0 top-0 h-px z-50"
        style={{
          background:
            "linear-gradient(90deg, transparent, color-mix(in srgb, var(--color-accent) 60%, transparent), transparent)",
        }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed top-2 left-2 z-50 h-4 w-4 border-t-2 border-l-2"
        style={{ borderColor: "color-mix(in srgb, var(--color-accent) 50%, transparent)" }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed top-2 right-2 z-50 h-4 w-4 border-t-2 border-r-2"
        style={{ borderColor: "color-mix(in srgb, var(--color-accent) 50%, transparent)" }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed bottom-2 left-2 z-50 h-4 w-4 border-b-2 border-l-2"
        style={{ borderColor: "color-mix(in srgb, var(--color-accent) 50%, transparent)" }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed bottom-2 right-2 z-50 h-4 w-4 border-b-2 border-r-2"
        style={{ borderColor: "color-mix(in srgb, var(--color-accent) 50%, transparent)" }}
      />
    </SidebarProvider>
  );
}
