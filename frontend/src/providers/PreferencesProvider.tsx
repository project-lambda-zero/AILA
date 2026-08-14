import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/**
 * PreferencesProvider -- operator-level UI preferences persisted to
 * localStorage. Mirrors the ThemeProvider pattern: read synchronously on
 * init (no flash), apply DOM side effects (data-density attribute on
 * <html>) inside the state initializer, and expose a small context with
 * typed setters.
 *
 * Scope:
 *   - density: comfortable | compact -- reflected as data-density on <html>;
 *     CSS rules in globals.css scoped under [data-density="compact"]
 *     tighten table cell padding + row line-height without altering the
 *     comfortable baseline.
 *   - sidebarCollapsed: authoritative source of truth for the shell
 *     SidebarProvider's open state (AppShell wires it as controlled).
 *     Preserves the pre-existing tablet-collapsed-by-default heuristic
 *     when no explicit user choice is stored.
 *   - defaultPageSize: the row count list screens should render when the
 *     operator has not explicitly overridden it. Exposed here so any
 *     list screen can adopt it without duplicating the storage layer.
 *
 * All keys are namespaced under `aila-pref-*` so nothing collides with
 * theme (`aila-theme`, `aila-mode`) or the legacy `aila-sidebar-open`
 * bootstrap key -- which is still honoured on first read so returning
 * operators keep their sidebar state after this ship.
 */

type Density = "comfortable" | "compact";

const DEFAULT_DENSITY: Density = "comfortable";
const DEFAULT_PAGE_SIZE = 25;
const ALLOWED_PAGE_SIZES: readonly number[] = [10, 25, 50, 100] as const;
const TABLET_MAX_WIDTH_PX = 1024;

const DENSITY_KEY = "aila-pref-density";
const SIDEBAR_COLLAPSED_KEY = "aila-pref-sidebar-collapsed";
const PAGE_SIZE_KEY = "aila-pref-default-page-size";
const LEGACY_SIDEBAR_OPEN_KEY = "aila-sidebar-open";

function isDensity(value: unknown): value is Density {
  return value === "comfortable" || value === "compact";
}

function applyDensity(density: Density): void {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-density", density);
}

function getInitialDensity(): Density {
  if (typeof window === "undefined") return DEFAULT_DENSITY;
  try {
    const stored = localStorage.getItem(DENSITY_KEY);
    if (isDensity(stored)) return stored;
  } catch {
    // localStorage unavailable -- fall back to default
  }
  return DEFAULT_DENSITY;
}

function getInitialSidebarCollapsed(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const stored = localStorage.getItem(SIDEBAR_COLLAPSED_KEY);
    if (stored === "true") return true;
    if (stored === "false") return false;
    // Backwards compatibility: honour the pre-existing key so operators
    // who set their sidebar state before this landed don't get reset.
    const legacy = localStorage.getItem(LEGACY_SIDEBAR_OPEN_KEY);
    if (legacy === "true") return false;
    if (legacy === "false") return true;
  } catch {
    // fall through to viewport heuristic
  }
  // Tablet breakpoint default -- matches the previous AppShell behaviour.
  if (window.innerWidth < TABLET_MAX_WIDTH_PX) return true;
  return false;
}

function getInitialPageSize(): number {
  if (typeof window === "undefined") return DEFAULT_PAGE_SIZE;
  try {
    const stored = localStorage.getItem(PAGE_SIZE_KEY);
    if (stored !== null) {
      const parsed = Number.parseInt(stored, 10);
      if (Number.isFinite(parsed) && ALLOWED_PAGE_SIZES.includes(parsed)) {
        return parsed;
      }
    }
  } catch {
    // fall back to default
  }
  return DEFAULT_PAGE_SIZE;
}

interface PreferencesContextValue {
  density: Density;
  sidebarCollapsed: boolean;
  defaultPageSize: number;
  setDensity: (next: Density) => void;
  setSidebarCollapsed: (next: boolean) => void;
  setDefaultPageSize: (next: number) => void;
  resetPreferences: () => void;
  allowedPageSizes: readonly number[];
}

const PreferencesContext = createContext<PreferencesContextValue | null>(null);

interface PreferencesProviderProps {
  children: ReactNode;
}

export function PreferencesProvider({ children }: PreferencesProviderProps) {
  const [density, setDensityState] = useState<Density>(() => {
    const initial = getInitialDensity();
    applyDensity(initial);
    return initial;
  });
  const [sidebarCollapsed, setSidebarCollapsedState] = useState<boolean>(
    getInitialSidebarCollapsed,
  );
  const [defaultPageSize, setDefaultPageSizeState] =
    useState<number>(getInitialPageSize);

  // Guard against a hydration path where the provider mounts before the
  // very first paint on some environments -- re-assert data-density so
  // the attribute is always present.
  useEffect(() => {
    applyDensity(density);
  }, [density]);

  const setDensity = useCallback((next: Density) => {
    if (!isDensity(next)) return;
    try {
      localStorage.setItem(DENSITY_KEY, next);
    } catch {
      // ignore
    }
    applyDensity(next);
    setDensityState(next);
  }, []);

  const setSidebarCollapsed = useCallback((next: boolean) => {
    try {
      localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(next));
      // Keep the legacy key in sync so any code path still reading it
      // gets a coherent answer during the transition.
      localStorage.setItem(LEGACY_SIDEBAR_OPEN_KEY, String(!next));
    } catch {
      // ignore
    }
    setSidebarCollapsedState(next);
  }, []);

  const setDefaultPageSize = useCallback((next: number) => {
    if (!Number.isFinite(next)) return;
    const clamped = ALLOWED_PAGE_SIZES.includes(next) ? next : DEFAULT_PAGE_SIZE;
    try {
      localStorage.setItem(PAGE_SIZE_KEY, String(clamped));
    } catch {
      // ignore
    }
    setDefaultPageSizeState(clamped);
  }, []);

  const resetPreferences = useCallback(() => {
    try {
      localStorage.removeItem(DENSITY_KEY);
      localStorage.removeItem(SIDEBAR_COLLAPSED_KEY);
      localStorage.removeItem(PAGE_SIZE_KEY);
    } catch {
      // ignore
    }
    applyDensity(DEFAULT_DENSITY);
    setDensityState(DEFAULT_DENSITY);
    setSidebarCollapsedState(false);
    setDefaultPageSizeState(DEFAULT_PAGE_SIZE);
  }, []);

  const value = useMemo<PreferencesContextValue>(
    () => ({
      density,
      sidebarCollapsed,
      defaultPageSize,
      setDensity,
      setSidebarCollapsed,
      setDefaultPageSize,
      resetPreferences,
      allowedPageSizes: ALLOWED_PAGE_SIZES,
    }),
    [
      density,
      sidebarCollapsed,
      defaultPageSize,
      setDensity,
      setSidebarCollapsed,
      setDefaultPageSize,
      resetPreferences,
    ],
  );

  return (
    <PreferencesContext.Provider value={value}>
      {children}
    </PreferencesContext.Provider>
  );
}

export function usePreferences(): PreferencesContextValue {
  const ctx = useContext(PreferencesContext);
  if (!ctx) {
    throw new Error("usePreferences must be used within a PreferencesProvider");
  }
  return ctx;
}

export {
  DEFAULT_DENSITY,
  DEFAULT_PAGE_SIZE,
  ALLOWED_PAGE_SIZES,
  type Density,
};
