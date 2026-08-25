/** Shared window-system types.
 *
 * `ConsoleWindow` (the primitive) owns chrome + shortcuts + z-order + focus for
 * a single surface. `WindowState` is the host-side (App.tsx) record for one
 * open window; the host holds an ordered `WindowState[]` + a `focusedId`. */

import type { ReactNode } from "react";

export type WindowKind = "page" | "overlay" | "floater";

export interface WindowRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Host-side record of one open window. `page`/`overlay` surfaces form the
 * center-column drill stack (only the top non-minimized one renders);
 * `floater` surfaces render concurrently as always-on-top rectangles. */
export interface WindowState {
  id: string;
  kind: WindowKind;
  title: string;
  /** Owning module id (e.g. "vr", "malware", "admin"). */
  module: string;
  /** Page-registry key that resolves the renderer (e.g. "vr:targets", "xray",
   * "malware:xray"). Not always `module:section` -- X-Ray keys are bare. */
  registryKey: string;
  /** Registry sub-intent past the module prefix (e.g. "overview", "systems:new"). */
  section: string | null;
  /** Selected-entity id threaded through ModulePageProps.investigationId. */
  investigationId: string | null;
  /** Geometry for `floater` windows; ignored for `page`/`overlay`. */
  rect?: WindowRect;
  minimized: boolean;
  fullscreen: boolean;
}

/** Props for the `ConsoleWindow` primitive. Host-controlled flags
 * (`isFullscreen`/`isMinimized`/`isFocused`) drive rendering; the primitive
 * never mutates them, it only calls back the `on*` handlers. */
export interface ConsoleWindowProps {
  /** Stable window id: z-order + focus + dock identity + shortcut targeting. */
  id: string;
  /** Rendered in the footer / dock strip; no filler suffix is appended. */
  title: string;
  kind: WindowKind;
  /** Initial geometry for `floater`; ignored otherwise. */
  initialRect?: WindowRect;
  /** Minimum floater size (default 320x200). */
  minSize?: { w: number; h: number };
  /** Default true; false hides the fullscreen button + F shortcut. */
  canFullscreen?: boolean;
  /** Default true; false hides the minimize button + M shortcut. */
  canMinimize?: boolean;
  /** Default true; false hides the close button + Esc shortcut. */
  canClose?: boolean;
  onClose: () => void;
  onMinimize: () => void;
  onToggleFullscreen?: () => void;
  /** Raise this window in z-order + pass it keyboard focus. */
  onFocus?: () => void;
  isFullscreen?: boolean;
  isMinimized?: boolean;
  isFocused?: boolean;
  /** Consumer-owned left-side status + tab strip; the primitive appends the
   * three control buttons on the right. */
  footerExtras?: ReactNode;
  children: ReactNode;
}
