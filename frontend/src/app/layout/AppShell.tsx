import { useCallback } from "react";
import type { ReactNode } from "react";

import { type ModuleFrontendSpec } from "@platform/extension-registry/types";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { KeyboardShortcutsController } from "@/components/shell/KeyboardShortcutsController";
import { OfflineBanner } from "@/components/shell/OfflineBanner";
import { ShortcutsCheatsheet } from "@/components/shell/ShortcutsCheatsheet";
import { StatusBar } from "@/components/shell/StatusBar";
import { OnboardingWizard } from "@platform/features/onboarding";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { useIdleTimeout } from "@/hooks/useIdleTimeout";
import { usePreferences } from "@/providers/PreferencesProvider";
import { AppSidebar } from "./AppSidebar";
import { AppHeader } from "./AppHeader";

interface AppShellProps {
  children: ReactNode;
  moduleSpecs: ModuleFrontendSpec[];
}

export function AppShell({ children, moduleSpecs }: AppShellProps) {
  // Sidebar open/collapsed state now flows through PreferencesProvider so
  // the operator's choice survives reloads and is settable from the
  // Settings page. The tablet-breakpoint default (D-08) is preserved by
  // PreferencesProvider.getInitialSidebarCollapsed when no explicit
  // preference is stored.
  const { sidebarCollapsed, setSidebarCollapsed } = usePreferences();
  // #47 -- clear the session after 15 minutes of inactivity so a signed-in
  // console left open on a shared workstation does not stay authenticated
  // indefinitely. The shell only renders behind ProtectedRoute, so once
  // logout() sets status="unauthenticated" the routing layer immediately
  // redirects to /login. Any presence event (pointer, keyboard, scroll,
  // visibilitychange) resets the timer.
  const onIdle = useCallback(() => {
    useAuthStore.getState().logout();
  }, []);
  useIdleTimeout({ onIdle });

  return (
    <SidebarProvider
      open={!sidebarCollapsed}
      onOpenChange={(open) => setSidebarCollapsed(!open)}
    >
      {/*
        Skip-to-main-content link (B8). First focusable element in the
        DOM so a keyboard user lands here on initial Tab. Visually
        hidden until focused (sr-only → focus:not-sr-only). The href
        target -- <main id="main" tabIndex={-1}> below -- is made
        programmatically focusable so activation moves focus into the
        content region, not just the scroll position.
      */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[60] focus:rounded-md focus:border focus:border-border focus:bg-elevated focus:px-4 focus:py-2 focus:font-sans focus:text-sm focus:font-medium focus:text-text focus:shadow-lg"
      >
        Skip to main content
      </a>
      <AppSidebar moduleSpecs={moduleSpecs} />
      <SidebarInset>
        <AppHeader />
        <OfflineBanner />
        <main
          id="main"
          tabIndex={-1}
          className="flex-1 overflow-y-auto overflow-x-hidden p-3 sm:p-4 lg:p-6 focus:outline-none focus-visible:outline-none"
        >
          {children}
        </main>
        {/*
          Issue #211 -- pinned 24px console status bar. Renders the
          live engine dot (from GET /health), queue depth (from
          GET /tasks/queue-depth, hidden on 4xx/5xx), active module,
          online/offline, build tag (v<version> <short-sha>), and a
          ticking clock. Replaces the earlier `<footer>` that only
          showed the build identity -- the version+SHA now lives in
          the status bar's build-tag segment.
        */}
        <StatusBar />
      </SidebarInset>
      {/* CommandPalette renders via portal -- outside layout flow (D-09, D-10) */}
      <CommandPalette />

      {/*
        Platform-wide keyboard shortcut layer. The controller attaches
        the document keydown listener and calls `useNavigate` (so it
        MUST live inside the RouterProvider tree -- AppShell qualifies);
        the cheatsheet is a portalled dialog driven by the shared
        KeyboardShortcutsProvider context. Mounted here (not in
        providers.tsx) so shortcuts only fire behind ProtectedRoute
        and never on /login, /auth/callback, /403, or /500.
      */}
      <KeyboardShortcutsController />
      <ShortcutsCheatsheet />

      {/*
        App-level cyber-tech overlay -- corner brackets + top hairline
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
