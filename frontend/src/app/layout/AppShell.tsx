import { useCallback } from "react";
import type { ReactNode } from "react";

import { type ModuleFrontendSpec } from "@platform/extension-registry/types";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { KeyboardShortcutsController } from "@/components/shell/KeyboardShortcutsController";
import { OfflineBanner } from "@/components/shell/OfflineBanner";
import { ShortcutsCheatsheet } from "@/components/shell/ShortcutsCheatsheet";
import { StatusBar } from "@/components/shell/StatusBar";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { useIdleTimeout } from "@/hooks/useIdleTimeout";
import { usePreferences } from "@/providers/PreferencesProvider";
import { FaultyTerminal } from "@/components/aila/FaultyTerminal";
import { AppSidebar } from "./AppSidebar";
import { AppHeader } from "./AppHeader";

interface AppShellProps {
  children: ReactNode;
  moduleSpecs: ModuleFrontendSpec[];
}

/**
 * AppShell -- the AILA workbench OS-frame.
 *
 * A fixed full-viewport frame drawn directly from the design system mockup:
 * a FaultyTerminal CRT hero behind everything, a 32px MenuBar on top, a left
 * module/investigation rail, the routed content in the center, and a 24px
 * status strip pinned to the bottom. The former shadcn SidebarProvider
 * dashboard is gone -- this is the mockup architecture, not a reskin.
 */
export function AppShell({ children, moduleSpecs }: AppShellProps) {
  // Rail open/collapsed flows through PreferencesProvider so the operator's
  // choice survives reloads and is settable from Settings.
  const { sidebarCollapsed, setSidebarCollapsed } = usePreferences();

  // #47 -- clear the session after 15 minutes of inactivity. The shell only
  // renders behind ProtectedRoute, so logout() -> unauthenticated redirects
  // to /login. Any presence event resets the timer.
  const onIdle = useCallback(() => {
    useAuthStore.getState().logout();
  }, []);
  useIdleTimeout({ onIdle });

  return (
    <>
      {/*
        AILA hero motif -- the FaultyTerminal CRT digit-rain behind the whole
        workbench, screen-blended over the midnight page so it reads in the
        content negative space while the opaque chrome (menubar, rail,
        statusbar) and panels float on top. One instance, fixed, inert;
        honors prefers-reduced-motion (single static frame).
      */}
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
        <FaultyTerminal
          style={{ position: "absolute", inset: 0, mixBlendMode: "screen", opacity: 0.55 }}
          options={{ brightness: 0.32, scanline: 0.4, glitch: 1, flicker: 0.22, chroma: 1.2, curvature: 0.12 }}
        />
        <div
          style={{
            position: "absolute",
            left: "50%",
            top: "-12%",
            width: "80%",
            height: "60%",
            transform: "translateX(-50%)",
            background:
              "radial-gradient(ellipse at center, color-mix(in srgb, var(--color-accent) 12%, transparent), transparent 68%)",
          }}
        />
      </div>

      {/* OS-frame: menubar / [rail | content] / statusbar. Transparent so the
          hero shows through the content negative space; chrome tiers are opaque. */}
      <div className="fixed inset-0 z-10 flex flex-col" style={{ fontFamily: "var(--font-mono)" }}>
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[60] focus:rounded focus:border focus:border-border focus:bg-elevated focus:px-4 focus:py-2 focus:font-sans focus:text-sm focus:font-medium focus:text-text"
        >
          Skip to main content
        </a>

        <AppHeader onToggleRail={() => setSidebarCollapsed(!sidebarCollapsed)} />
        <OfflineBanner />

        <div className="flex min-h-0 flex-1">
          {!sidebarCollapsed && <AppSidebar moduleSpecs={moduleSpecs} />}
          <main
            id="main"
            tabIndex={-1}
            className="min-w-0 flex-1 overflow-y-auto overflow-x-hidden p-3 focus:outline-none focus-visible:outline-none sm:p-4 lg:p-6"
          >
            {/* Workbench content measure -- centered, capped at content-max. */}
            <div className="mx-auto w-full" style={{ maxWidth: "var(--content-max)" }}>
              {children}
            </div>
          </main>
        </div>

        <StatusBar />
      </div>

      {/* CommandPalette renders via portal -- outside layout flow. */}
      <CommandPalette />
      {/* Platform-wide keyboard shortcut layer + cheatsheet (behind ProtectedRoute). */}
      <KeyboardShortcutsController />
      <ShortcutsCheatsheet />
    </>
  );
}
