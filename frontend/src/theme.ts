/**
 * Theme registry + runtime theme switching.
 *
 * The canonical theme list lives here so the Settings UI and the load-time
 * applier never drift. Each theme name maps to a slug that selects a
 * `[data-theme="<slug>"]` block in styles/globals.css; that block overrides the
 * base design-system tokens, so switching the slug on <html> restyles the whole
 * app. The default (`:root`) equals the first theme, Midnight Cloud 8.
 */

export type Theme = readonly [name: string, sub: string, mode: string, gradient: string];

export const THEMES: readonly Theme[] = [
  ["Midnight Cloud 8", "istanbul at dusk. cream on charcoal.", "dark", "linear-gradient(135deg,#0d0d0d,#2a1a20)"],
  ["Frutiger Aero", "bliss sky + wet glass. 2006 is back.", "light", "linear-gradient(135deg,#bfe6ff,#e9f7e0)"],
  ["Synthwave", "1984 neon grid. chromatic horizon.", "dark", "linear-gradient(160deg,#1a0a2a 30%,#ff5f87)"],
  ["Vaporwave", "win95 pastel mall.", "dark", "linear-gradient(135deg,#2a1a40,#a0d8d0)"],
  ["PlayStation 1", "console-gray chassis. rgby logo.", "light", "linear-gradient(135deg,#cfcfcf,#9aa0b0)"],
  ["PlayStation 2", "black + cyan. rising boot cubes.", "dark", "linear-gradient(160deg,#050510,#1a6cff)"],
  ["Cyberpunk 2077", "ncpo yellow / cyan / red.", "dark", "linear-gradient(135deg,#0a0a0a,#f5e000)"],
  ["The Matrix", "phosphor green rain on black.", "dark", "linear-gradient(160deg,#000,#00d000)"],
  ["Truman Show", "pastel dome. hidden-camera vignette.", "light", "linear-gradient(135deg,#cfe0d8,#eef0e0)"],
  ["Half-Life 1", "hev orange. black mesa hazard bay.", "dark", "linear-gradient(135deg,#0d0d0d,#ff8a00)"],
  ["Y2K Fever", "holographic chrome. imac blueberry.", "light", "linear-gradient(135deg,#e8d0ff,#bfe6ff)"],
  ["Vendetta", "blood-red on black. remember.", "dark", "linear-gradient(160deg,#0a0000,#c00018)"],
];

export const THEME_NAMES: readonly string[] = THEMES.map((t) => t[0]);

const DEFAULT_THEME_NAME = THEMES[0][0];
const STORAGE_KEY = "aila-theme";

/**
 * Theme name -> data-theme slug. "PlayStation 1" -> "playstation-1",
 * "Cyberpunk 2077" -> "cyberpunk-2077". Non-alphanumeric runs collapse to a
 * single hyphen; leading/trailing hyphens are trimmed. globals.css authors the
 * exact same slugs.
 */
export function slugifyTheme(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Apply a theme immediately: set the slug on <html> (so the matching
 * `[data-theme]` token block wins the cascade) and persist the name.
 */
export function applyTheme(name: string): void {
  document.documentElement.dataset.theme = slugifyTheme(name);
  localStorage.setItem(STORAGE_KEY, name);
}

/**
 * Resolve the persisted theme (falling back to the default when absent or
 * unknown), apply it, and return the resolved name. Call once at startup.
 */
export function loadTheme(): string {
  const stored = localStorage.getItem(STORAGE_KEY);
  const name = stored && THEME_NAMES.includes(stored) ? stored : DEFAULT_THEME_NAME;
  applyTheme(name);
  return name;
}
