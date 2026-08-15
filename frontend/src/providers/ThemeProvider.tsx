import { createContext, useContext, useEffect, type ReactNode } from "react";

/**
 * AILA theme system -- single canonical design.
 *
 * AILA ships ONE design: "midnight-cloud-8" (dark) -- the AILA design
 * system. The former multi-theme switcher and its 12 alternate themes were
 * removed with the design-system overhaul. This provider now only guarantees
 * the theme attributes are on <html> (theme-init.js sets them pre-paint; this
 * re-applies idempotently for hydration safety) and exposes a stable, inert
 * `useTheme()` surface so any remaining reader keeps compiling.
 */

const THEMES = ["midnight-cloud-8"] as const;

type Theme = (typeof THEMES)[number];
type Mode = "dark" | "light";

const DEFAULT_THEME: Theme = "midnight-cloud-8";

/** No AILA theme is naturally light -- retained as an empty set for callers. */
const NATURALLY_LIGHT: ReadonlySet<Theme> = new Set<Theme>();

interface ThemeContextValue {
  theme: Theme;
  mode: Mode;
  setTheme: (theme: Theme) => void;
  cycleTheme: () => void;
  setMode: (mode: Mode) => void;
  toggleMode: () => void;
}

const noop = () => {};

const VALUE: ThemeContextValue = {
  theme: DEFAULT_THEME,
  mode: "dark",
  setTheme: noop,
  cycleTheme: noop,
  setMode: noop,
  toggleMode: noop,
};

const ThemeContext = createContext<ThemeContextValue>(VALUE);

function applyTheme(): void {
  if (typeof document === "undefined") return;
  const el = document.documentElement;
  el.setAttribute("data-theme", DEFAULT_THEME);
  el.setAttribute("data-mode", "dark");
  el.classList.add("dark");
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    applyTheme();
  }, []);
  return <ThemeContext.Provider value={VALUE}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}

export { THEMES, DEFAULT_THEME, NATURALLY_LIGHT, type Theme, type Mode };
