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
 * AppShell -- the AILA workbench OS-frame, rebuilt from the design mock
 * (`AILA Console.dc.html`).
 *
 * Fixed full-viewport frame: FaultyTerminal CRT digit-rain hero behind
 * everything, a 32px MenuBar on top, a 216px module rail on the left, the
 * routed content in the centre, and a 24px status strip pinned to the bottom.
 * There is NO shadcn SidebarProvider anywhere in this tree -- this is the
 * mock's OS-frame architecture, wired to the same routing, auth, and idle
 * timers as before.
 */
export function AppShell({ children, moduleSpecs }: AppShellProps) {
  // Rail open/collapsed persists through PreferencesProvider (survives reload,
  // settable from Settings) -- same wiring as before, no shadcn context.
  const { sidebarCollapsed, setSidebarCollapsed } = usePreferences();

  // #47 -- clear the session after 15 minutes of inactivity. AppShell only
  // renders behind ProtectedRoute, so logout() -> unauthenticated redirects
  // to /login. Any presence event resets the timer.
  const onIdle = useCallback(() => {
    useAuthStore.getState().logout();
  }, []);
  useIdleTimeout({ onIdle });

  return (
    <>
      {/*
        Hero motif -- FaultyTerminal shader tinted by --accent, behind the
        whole shell. z-0, screen-blended, inert; honours prefers-reduced-motion
        (the shader renders a single static frame). Scanline field + radial
        accent bloom mirror the mock's `terminalStyle` + `scanStyle` + top-
        centre gradient trick.
      */}
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
        <FaultyTerminal
          style={{ position: "absolute", inset: 0, mixBlendMode: "screen", opacity: 0.32 }}
          options={{ brightness: 0.55, scanline: 0.5, glitch: 1, chroma: 1.0, curvature: 0.05 }}
        />
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage:
              "repeating-linear-gradient(0deg, rgba(0,0,0,0.16) 0 1px, transparent 1px 3px)",
            opacity: 0.4,
          }}
        />
        <div
          style={{
            position: "absolute",
            left: "50%",
            top: "-12%",
            width: "78%",
            height: "60%",
            transform: "translateX(-50%)",
            background:
              "radial-gradient(ellipse at center, color-mix(in srgb, var(--accent) 12%, transparent), transparent 68%)",
          }}
        />
      </div>

      {/* OS-frame: menubar / [rail | content] / statusbar. Transparent so the
          hero shows through content negative space; chrome tiers are opaque. */}
      <div
        className="fixed inset-0 z-10 flex flex-col"
        style={{
          fontFamily: "var(--font-mono)",
          color: "var(--text-primary)",
          background: "transparent",
        }}
      >
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[60] focus:rounded focus:px-4 focus:py-2 focus:font-sans focus:text-sm focus:font-medium"
          style={{
            background: "var(--surface-card)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
          }}
        >
          Skip to main content
        </a>

        <AppHeader onToggleRail={() => setSidebarCollapsed(!sidebarCollapsed)} />
        <OfflineBanner />

        <div className="flex min-h-0 flex-1" style={{ position: "relative", zIndex: 10 }}>
          {!sidebarCollapsed && <AppSidebar moduleSpecs={moduleSpecs} />}
          {/* No padding / max-width here -- pages own their layout so the
              rebuilt mock surfaces (CONSOLE / VR X-RAY / VULN) render
              flush against the OS-frame chrome, just like the mock. */}
          <main
            id="main"
            tabIndex={-1}
            className="min-w-0 flex-1 overflow-auto focus:outline-none focus-visible:outline-none"
            style={{ position: "relative" }}
          >
            {children}
          </main>
        </div>

        <StatusBar />
      </div>

      {/* CommandPalette renders via portal -- outside layout flow. */}
      <CommandPalette />
      <KeyboardShortcutsController />
      <ShortcutsCheatsheet />
    </>
  );
}
