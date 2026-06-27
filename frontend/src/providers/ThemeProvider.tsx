import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

/**
 * AILA theme system -- extended pack.
 *
 * Twelve themes, each a named era / cultural moment, engineered to be
 * recognizable within a second of opening the app:
 *
 *   - midnight-cloud-8: 2022 Istanbul-at-dusk neovim palette
 *                       (echel0n/midnight-cloud-8). Warm charcoal base,
 *                       cream foreground, hot-pink + lavender accents,
 *                       mint highlights. Distinct from synthwave's pure
 *                       neon -- softer, atmospheric, vaguely melancholic.
 *                       Default theme.
 *   - frutiger-aero:  2004-2012 iPod/Vista aqua glass, Bliss sky, bokeh
 *   - synthwave:      1984 neon grid + chromatic aberration
 *   - vaporwave:      1995 Windows 98 + pastel mall aesthetic
 *   - ps1:            1994 Sony PlayStation gray console, RGBY PS logo
 *   - ps2:            2000 PlayStation 2 -- deep black + cyan dot field
 *   - cyberpunk-2077: 2077 NCPD yellow/cyan/magenta, Rage Italic glitch
 *   - matrix:         1999 green digital rain, phosphor CRT
 *   - truman-show:    1998 pastel 50s suburbia, hidden camera vignette
 *   - half-life-1:    1998 Black Mesa -- lambda orange, industrial gray
 *   - y2k-fever:      1999-2001 holographic chrome + iMac blueberry
 *   - vendetta:       V-for-Vendetta blood-red on black, Fawkes propaganda
 *
 * Each theme has a natural mode; toggling mode flips the token surface colors
 * but the signature decorative CSS (body atmospherics, card treatments, button
 * styles) remains unambiguous so the theme is always identifiable at a glance.
 */

const THEMES = [
  "midnight-cloud-8",
  "frutiger-aero",
  "synthwave",
  "vaporwave",
  "ps1",
  "ps2",
  "cyberpunk-2077",
  "matrix",
  "truman-show",
  "half-life-1",
  "y2k-fever",
  "vendetta",
  "specimen-index",
] as const;

type Theme = (typeof THEMES)[number];
type Mode = "dark" | "light";

/** Themes whose natural default is light mode */
const NATURALLY_LIGHT: ReadonlySet<Theme> = new Set<Theme>([
  "frutiger-aero",
  "ps1",
  "truman-show",
  "y2k-fever",
  "specimen-index",
]);

const DEFAULT_THEME: Theme = "midnight-cloud-8";
const THEME_KEY = "aila-theme";
const MODE_KEY = "aila-mode";

interface ThemeContextValue {
  theme: Theme;
  mode: Mode;
  setTheme: (theme: Theme) => void;
  setMode: (mode: Mode) => void;
  toggleMode: () => void;
  cycleTheme: () => void;
  isDark: boolean;
  themes: readonly Theme[];
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function isValidTheme(value: unknown): value is Theme {
  return typeof value === "string" && (THEMES as readonly string[]).includes(value);
}

function isValidMode(value: unknown): value is Mode {
  return value === "dark" || value === "light";
}

function naturalMode(theme: Theme): Mode {
  return NATURALLY_LIGHT.has(theme) ? "light" : "dark";
}

function getInitialTheme(): Theme {
  if (typeof window === "undefined") return DEFAULT_THEME;
  const stored = localStorage.getItem(THEME_KEY);
  if (isValidTheme(stored)) return stored;
  localStorage.setItem(THEME_KEY, DEFAULT_THEME);
  return DEFAULT_THEME;
}

function getInitialMode(theme: Theme): Mode {
  if (typeof window === "undefined") return naturalMode(theme);
  const stored = localStorage.getItem(MODE_KEY);
  if (isValidMode(stored)) return stored;
  const fallback = naturalMode(theme);
  localStorage.setItem(MODE_KEY, fallback);
  return fallback;
}

function applyTheme(theme: Theme, mode: Mode): void {
  const html = document.documentElement;
  html.setAttribute("data-theme", theme);
  html.setAttribute("data-mode", mode);
  if (mode === "dark") {
    html.classList.add("dark");
  } else {
    html.classList.remove("dark");
  }
}

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [theme, setThemeState] = useState<Theme>(() => getInitialTheme());
  const [mode, setModeState] = useState<Mode>(() => {
    const t = getInitialTheme();
    const m = getInitialMode(t);
    if (typeof window !== "undefined") applyTheme(t, m);
    return m;
  });

  const setTheme = useCallback((next: Theme) => {
    if (!isValidTheme(next)) return;
    const m = naturalMode(next);
    localStorage.setItem(THEME_KEY, next);
    localStorage.setItem(MODE_KEY, m);
    setThemeState(next);
    setModeState(m);
    applyTheme(next, m);
  }, []);

  const setMode = useCallback((next: Mode) => {
    if (!isValidMode(next)) return;
    localStorage.setItem(MODE_KEY, next);
    setModeState(next);
    setThemeState((currentTheme) => {
      applyTheme(currentTheme, next);
      return currentTheme;
    });
  }, []);

  const toggleMode = useCallback(() => {
    setModeState((prev) => {
      const next: Mode = prev === "dark" ? "light" : "dark";
      localStorage.setItem(MODE_KEY, next);
      setThemeState((currentTheme) => {
        applyTheme(currentTheme, next);
        return currentTheme;
      });
      return next;
    });
  }, []);

  const cycleTheme = useCallback(() => {
    setThemeState((prev) => {
      const idx = THEMES.indexOf(prev);
      const next = THEMES[(idx + 1) % THEMES.length];
      const m = naturalMode(next);
      localStorage.setItem(THEME_KEY, next);
      localStorage.setItem(MODE_KEY, m);
      setModeState(m);
      applyTheme(next, m);
      return next;
    });
  }, []);

  return (
    <ThemeContext.Provider
      value={{
        theme,
        mode,
        setTheme,
        setMode,
        toggleMode,
        cycleTheme,
        isDark: mode === "dark",
        themes: THEMES,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return ctx;
}

export { THEMES, DEFAULT_THEME, NATURALLY_LIGHT, type Theme, type Mode };
