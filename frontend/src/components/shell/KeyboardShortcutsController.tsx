import { useEffect, useRef } from "react";
import { useNavigate } from "react-router";

import { useKeyboardShortcuts } from "@/providers/KeyboardShortcutsProvider";

/**
 * Document-level keydown listener for the platform-wide shortcut layer.
 *
 * MUST be mounted INSIDE the react-router `<RouterProvider>` tree
 * because it calls `useNavigate`. The canonical mount point is the
 * AppShell (behind `<ProtectedRoute>`), so shortcuts only fire for a
 * signed-in operator and never on the login / OIDC-callback / error
 * pages.
 *
 * Cooperation with the existing Cmd/Ctrl+K palette wiring
 * (AppHeader.tsx + CommandPalette.tsx) is enforced by an early return
 * on any keydown that carries a Cmd, Ctrl, or Alt modifier -- the
 * palette owns those combos.
 *
 * Editable targets (input, textarea, select, [contenteditable]) are
 * skipped so typing "?" or "g" into a search box never navigates or
 * pops the cheatsheet.
 */

const G_CHORD_TIMEOUT_MS = 1200;

const G_CHORD_TARGETS: Record<string, string> = {
  d: "/dashboard",
  o: "/ops",
  c: "/",
  t: "/topology",
};

function isEditableEventTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (target.isContentEditable) return true;
  // base-ui / role-based composers sometimes forward keys to a hidden
  // input; treat any element flagged as combobox/searchbox/textbox as
  // editable for chord suppression.
  const role = target.getAttribute("role");
  if (role === "textbox" || role === "combobox" || role === "searchbox") {
    return true;
  }
  return false;
}

export function KeyboardShortcutsController() {
  const navigate = useNavigate();
  const { toggleCheatsheet, closeCheatsheet } = useKeyboardShortcuts();

  // Ref, not state -- we do NOT want a re-render every keystroke and we
  // do NOT want the effect to re-subscribe when the chord state flips.
  const pendingGRef = useRef<{ timerId: number } | null>(null);

  useEffect(() => {
    function clearPending() {
      const pending = pendingGRef.current;
      if (pending) {
        window.clearTimeout(pending.timerId);
        pendingGRef.current = null;
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      // The palette owns modifier combos -- Cmd/Ctrl+K, Cmd/Ctrl+B, and
      // any other modifier chord. Stay out of their way entirely.
      if (event.metaKey || event.ctrlKey || event.altKey) return;

      // Never intercept keys destined for a text field.
      if (isEditableEventTarget(event.target)) return;

      // Escape closes the cheatsheet from anywhere. base-ui's Dialog
      // handles Escape internally when the dialog itself has focus, but
      // if focus escaped for any reason we still want a way out.
      if (event.key === "Escape") {
        closeCheatsheet();
        clearPending();
        return;
      }

      // "?" is Shift+/ on US layouts; base it on `event.key` so other
      // layouts that produce "?" via a different physical key work too.
      if (event.key === "?") {
        event.preventDefault();
        clearPending();
        toggleCheatsheet();
        return;
      }

      const key = event.key.length === 1 ? event.key.toLowerCase() : event.key;

      // Second half of the "g" chord.
      if (pendingGRef.current) {
        const target = G_CHORD_TARGETS[key];
        clearPending();
        if (target) {
          event.preventDefault();
          navigate(target);
        }
        return;
      }

      // First half: arm the "g" chord.
      if (key === "g") {
        event.preventDefault();
        const timerId = window.setTimeout(() => {
          pendingGRef.current = null;
        }, G_CHORD_TIMEOUT_MS);
        pendingGRef.current = { timerId };
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      clearPending();
    };
  }, [navigate, toggleCheatsheet, closeCheatsheet]);

  return null;
}
