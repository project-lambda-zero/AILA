import { useEffect, useRef } from "react";

import {
  SHORTCUT_GROUPS,
  useKeyboardShortcuts,
} from "@/providers/KeyboardShortcutsProvider";
import { WindowPanel } from "@/components/aila/WindowPanel";

/**
 * Cheatsheet overlay listing every registered global shortcut.
 *
 * Rendered once at the app root (inside the AppShell). Open/close state
 * lives in the shared {@link useKeyboardShortcuts} context so the "?" key
 * handler in {@link KeyboardShortcutsController} and any future in-app
 * trigger drive the same modal.
 *
 * Presentation follows the OS-window mock kit: a fixed backdrop covers the
 * viewport and a centered <WindowPanel> holds the shortcut list. Escape or
 * a click on the backdrop dismisses.
 */

const KBD_STYLE: React.CSSProperties = {
  display: "inline-flex",
  minWidth: 22,
  height: 20,
  alignItems: "center",
  justifyContent: "center",
  padding: "0 6px",
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  letterSpacing: "0.06em",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
};

function ChordKey({ children }: { children: string }) {
  return <kbd style={KBD_STYLE}>{children}</kbd>;
}

function renderChord(chord: string) {
  // Space-separated chord tokens ("g d") render as two keys with a
  // "then" separator; "+"-separated tokens ("Cmd/Ctrl + K") render as
  // simultaneous keys joined by "+".
  if (chord.includes(" + ")) {
    const parts = chord.split(" + ");
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
        {parts.map((part, i) => (
          <span
            key={`${part}-${i}`}
            style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
          >
            {i > 0 && (
              <span
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-muted)" }}
              >
                +
              </span>
            )}
            <ChordKey>{part}</ChordKey>
          </span>
        ))}
      </span>
    );
  }
  if (chord.includes(" ")) {
    const parts = chord.split(" ");
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
        {parts.map((part, i) => (
          <span
            key={`${part}-${i}`}
            style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
          >
            {i > 0 && (
              <span
                className="font-mono uppercase"
                style={{
                  fontSize: 8.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                }}
              >
                then
              </span>
            )}
            <ChordKey>{part}</ChordKey>
          </span>
        ))}
      </span>
    );
  }
  return <ChordKey>{chord}</ChordKey>;
}

export function ShortcutsCheatsheet() {
  const { isCheatsheetOpen, closeCheatsheet } = useKeyboardShortcuts();
  const panelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!isCheatsheetOpen) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        closeCheatsheet();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isCheatsheetOpen, closeCheatsheet]);

  if (!isCheatsheetOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard shortcuts"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) closeCheatsheet();
      }}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        padding: "10vh 16px 16px",
        background: "color-mix(in srgb, var(--surface-page) 82%, transparent)",
        backdropFilter: "blur(2px)",
      }}
    >
      <div
        ref={panelRef}
        style={{ width: "100%", maxWidth: 520 }}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <WindowPanel title="keyboard shortcuts" tone="info">
          <div
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.02em",
              marginBottom: 12,
            }}
          >
            Press <ChordKey>?</ChordKey> anywhere to open this list.
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {SHORTCUT_GROUPS.map((group) => (
              <section
                key={group.title}
                style={{ display: "flex", flexDirection: "column", gap: 8 }}
              >
                <h2
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9.5,
                    letterSpacing: "0.14em",
                    color: "var(--text-faint)",
                    margin: 0,
                  }}
                >
                  {group.title}
                </h2>
                <ul
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 6,
                    margin: 0,
                    padding: 0,
                    listStyle: "none",
                  }}
                >
                  {group.entries.map((entry) => (
                    <li
                      key={`${group.title}-${entry.chord}`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        gap: 12,
                      }}
                    >
                      <span style={{ display: "flex", flexDirection: "column" }}>
                        <span
                          style={{
                            fontFamily: "var(--font-mono)",
                            fontSize: 11,
                            color: "var(--text-primary)",
                            letterSpacing: "0.02em",
                          }}
                        >
                          {entry.label}
                        </span>
                        {entry.hint && (
                          <span
                            className="font-mono"
                            style={{
                              fontSize: 9.5,
                              color: "var(--text-faint)",
                              letterSpacing: "0.04em",
                            }}
                          >
                            {entry.hint}
                          </span>
                        )}
                      </span>
                      {renderChord(entry.chord)}
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </WindowPanel>
      </div>
    </div>
  );
}
