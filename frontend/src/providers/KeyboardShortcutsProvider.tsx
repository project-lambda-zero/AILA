import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/**
 * Platform-wide keyboard shortcut layer.
 *
 * This provider only owns the cheatsheet-open state -- it does NOT bind
 * the document keydown listener itself, because navigation shortcuts need
 * `useNavigate` from react-router which is only valid inside the
 * `<RouterProvider>` tree. See {@link KeyboardShortcutsController} for
 * the actual keydown wiring; mount that component somewhere inside the
 * router (the AppShell is the canonical spot).
 *
 * The cheatsheet overlay ({@link ShortcutsCheatsheet}) also lives inside
 * the router-aware tree so that navigation triggered from within it (if
 * ever added) has a router context; the overlay itself only reads the
 * open flag from this context and calls `closeCheatsheet`.
 *
 * The existing Cmd/Ctrl+K palette shortcut (wired in AppHeader.tsx +
 * CommandPalette.tsx) is intentionally NOT re-bound here -- this layer
 * cooperates by ignoring any keydown with a Cmd/Ctrl/Alt modifier, and
 * the palette itself keeps ownership of that combo.
 */

interface KeyboardShortcutsContextValue {
  isCheatsheetOpen: boolean;
  openCheatsheet: () => void;
  closeCheatsheet: () => void;
  toggleCheatsheet: () => void;
}

const KeyboardShortcutsContext =
  createContext<KeyboardShortcutsContextValue | null>(null);

interface KeyboardShortcutsProviderProps {
  children: ReactNode;
}

export function KeyboardShortcutsProvider({
  children,
}: KeyboardShortcutsProviderProps) {
  const [isCheatsheetOpen, setIsCheatsheetOpen] = useState(false);

  const openCheatsheet = useCallback(() => setIsCheatsheetOpen(true), []);
  const closeCheatsheet = useCallback(() => setIsCheatsheetOpen(false), []);
  const toggleCheatsheet = useCallback(
    () => setIsCheatsheetOpen((prev) => !prev),
    [],
  );

  const value = useMemo<KeyboardShortcutsContextValue>(
    () => ({
      isCheatsheetOpen,
      openCheatsheet,
      closeCheatsheet,
      toggleCheatsheet,
    }),
    [isCheatsheetOpen, openCheatsheet, closeCheatsheet, toggleCheatsheet],
  );

  return (
    <KeyboardShortcutsContext.Provider value={value}>
      {children}
    </KeyboardShortcutsContext.Provider>
  );
}

export function useKeyboardShortcuts(): KeyboardShortcutsContextValue {
  const ctx = useContext(KeyboardShortcutsContext);
  if (!ctx) {
    throw new Error(
      "useKeyboardShortcuts must be used within a <KeyboardShortcutsProvider>",
    );
  }
  return ctx;
}

/**
 * Static shortcut catalog rendered by the cheatsheet overlay. Kept next
 * to the keydown handler so a chord added in one place shows up in the
 * other. `chord` is a display string; the handler resolves keys itself.
 */
export interface ShortcutEntry {
  chord: string;
  label: string;
  hint?: string;
}

export interface ShortcutGroup {
  title: string;
  entries: ShortcutEntry[];
}

export const SHORTCUT_GROUPS: readonly ShortcutGroup[] = [
  {
    title: "Navigation",
    entries: [
      { chord: "g d", label: "Go to Dashboard", hint: "/dashboard" },
      { chord: "g o", label: "Go to War Room", hint: "/ops" },
      { chord: "g c", label: "Go to Chat", hint: "/" },
      { chord: "g t", label: "Go to Topology", hint: "/topology" },
    ],
  },
  {
    title: "Palette",
    entries: [
      { chord: "Cmd/Ctrl + K", label: "Open command palette" },
      { chord: "Cmd/Ctrl + B", label: "Toggle sidebar" },
    ],
  },
  {
    title: "Help",
    entries: [
      { chord: "?", label: "Toggle this cheatsheet" },
      { chord: "Esc", label: "Close cheatsheet or dialogs" },
    ],
  },
] as const;
