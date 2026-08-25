/**
 * SystemsRegistryPage -- platform-owned admin/systems page (req 11 of
 * system-registry-platform.md). Re-homes the SSH host registry off the
 * vulnerability module so a single page owns creation, edit, deletion,
 * tagging, and the live connectivity probe. Mirrors DocsPage's shape:
 * self-wraps ConsoleWindow with a display-font header and a body that
 * renders SystemsPanel's rich registry surface.
 */
import type { JSX } from "react";

import type { ModulePageProps } from "../contract";
import { ConsoleWindow } from "../window";

import SystemsSection from "./systems/SystemsPanel";

export default function SystemsRegistryPage(props: ModulePageProps): JSX.Element {
  const {
    windowId,
    title,
    isFocused,
    isFullscreen,
    onFocus,
    onBack,
    onMinimize,
    onToggleFullscreen,
  } = props;

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
    >
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: 1,
            background: "var(--accent)",
            boxShadow: "0 0 7px var(--accent)",
          }}
        />
        <span
          style={{
            fontFamily: "var(--font-display)",
            color: "var(--text-primary)",
            fontWeight: 700,
            letterSpacing: "0.16em",
          }}
        >
          systems registry
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          platform-owned SSH host registry
        </span>
      </header>
      <main
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          position: "relative",
        }}
      >
        <SystemsSection />
      </main>
    </ConsoleWindow>
  );
}
