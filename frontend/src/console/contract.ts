/** Prop contracts shared between App.tsx and the console panels. */

import type { User } from "../api/types";

export interface BoundInvestigation {
  id: string;
  title: string;
}

export interface LeftRailProps {
  moduleId: string;
  onSelectModule: (id: string) => void;
  bound: BoundInvestigation | null;
  onBind: (inv: BoundInvestigation) => void;
  pagesOpen: boolean;
  onTogglePages: () => void;
  adminOpen: boolean;
  onToggleAdmin: () => void;
  onOpenIntake: (opts?: { moduleId?: string; targetId?: string }) => void;
  onOpenSettings: () => void;
  onOpenPage: (moduleId: string, pageId: string, label: string) => void;
}

/** A module page (Vulnerability, VR X-Ray, ...) opened from the left-rail PAGES
 * section or an investigation row. It renders as an overlay window in the
 * console's center column (keeping the menu bar, left rail and status bar), with
 * minimize / close controls supplied by the console shell. Each page carries its
 * own top nav whose `< AILA` affordance calls onBack to close the window. */
export interface ModulePageProps {
  section: string | null;
  investigationId?: string | null;
  /** Host-assigned window id; a page spreads it into its `<ConsoleWindow id>`
   * so the shell can track z-order, focus, and the minimize dock. */
  windowId: string;
  /** Window title the shell computed for this page; passed to `<ConsoleWindow
   * title>` (used by the dock chip + aria labelling). */
  title: string;
  /** True when this is the focused (z-top) window; gates the primitive's
   * keyboard shortcuts so only one window responds. */
  isFocused?: boolean;
  /** Raise this window in z-order + pass it keyboard focus (wired to
   * `<ConsoleWindow onFocus>`). */
  onFocus?: () => void;
  /** Close the window (back to the console). */
  onBack: () => void;
  /** Collapse the window to the dock, revealing the console behind it. */
  onMinimize: () => void;
  onNavigate: (section: string) => void;
  /** True when the window covers the whole viewport. */
  isFullscreen?: boolean;
  /** Toggle between the contained window and full-viewport. */
  onToggleFullscreen?: () => void;
  /** Open another registered window (registry key `${moduleKey}:${section}`),
   * optionally bound to a selected entity id. Used by DataPage to hand a
   * targets row off to the upload wizard or a project row to its detail. */
  onOpenPage?: (moduleKey: string, section: string, label: string, investigationId?: string | null) => void;
}

export interface ChatConsoleProps {
  mode: "basic" | "advanced";
  moduleId: string;
  investigationId: string | null;
  investigationTitle: string | null;
  onToggleMode: () => void;
  onOpenIntake: (opts?: { moduleId?: string; targetId?: string }) => void;
  /** Open a wizard by its registry id (see console/wizards). Chat's picker
   * uses `wizardsForModule` to enumerate; dante's `open_wizard` action
   * resolves through `primaryWizardIdForModule` before calling this. */
  onOpenWizard: (wizardId: string, opts?: { targetId?: string }) => void;
  onOpenXray?: () => void;
  /** True while a minimized page dock occupies the bottom of the center column.
   * The composer reserves space for it so it stays clickable. */
  dockOpen?: boolean;
}

export interface IntakeWizardProps {
  moduleId: string;
  onClose: () => void;
  onBind: (inv: BoundInvestigation) => void;
  /** Optional -- when set the wizard renders a "+ upload new target" button
   * in its target picker; clicking it hands off to the shell (which should
   * close the wizard and open the UploadForm window for this module). */
  onRequestUpload?: () => void;
  /** Optional -- when a targetId is supplied and matches a loaded target
   *  for the wizard's module, the picker preselects that target. Best-effort;
   *  a miss silently falls back to the normal empty picker. */
  prefill?: { targetId?: string };
}

export interface SettingsOverlayProps {
  user: User | null;
  onClose: () => void;
  onOpenPage?: (moduleId: string, pageId: string, title?: string) => void;
}
