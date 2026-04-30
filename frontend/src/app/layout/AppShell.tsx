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
        <main className="flex-1 overflow-auto p-3 sm:p-4 lg:p-6">
          {children}
        </main>
      </SidebarInset>
      {/* CommandPalette renders via portal — outside layout flow (D-09, D-10) */}
      <CommandPalette />
      {/* OnboardingWizard removed — usage docs will be a dedicated tab */}
    </SidebarProvider>
  );
}
