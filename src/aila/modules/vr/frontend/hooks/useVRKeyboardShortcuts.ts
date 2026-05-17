import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router";

/** VR module keyboard shortcuts (08_FRONTEND_UX.md §6.6).
 *
 *  Three shortcuts only — heavy keyboard vocabularies create onboarding
 *  cost that the spec explicitly rejects.
 *
 *    Cmd+P (Ctrl+P on non-mac) — quick-jump search across project entities
 *    Cmd+/ (Ctrl+/)            — open steering drawer on pages that support it
 *    J / K                     — when on the investigation timeline,
 *                                jump to next / previous turn
 *
 *  Mount once at the platform shell or per-page. We mount at the VR
 *  module's route boundary by calling this hook from any page in the
 *  VR module — the listeners are global window listeners but unmount
 *  cleanly when the VR route unmounts.
 *
 *  The hook supports a `onOpenSteering` callback so per-page drawer
 *  state can be opened by Cmd+/. */

export interface VRShortcutHandlers {
  onOpenSteering?: () => void;
}

const QUICK_JUMP_EVENT = "vr-quick-jump";

/** Bus event for the quick-jump dialog — any page can listen and open
 *  its own command palette. For v0.5 we just fire the event; pages can
 *  attach `window.addEventListener('vr-quick-jump', …)`. */
export function emitQuickJumpRequest(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(QUICK_JUMP_EVENT));
  }
}

export function useVRKeyboardShortcuts({
  onOpenSteering,
}: VRShortcutHandlers = {}) {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    function isTypingTarget(t: EventTarget | null): boolean {
      if (!(t instanceof HTMLElement)) return false;
      const tag = t.tagName;
      return (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        t.isContentEditable
      );
    }

    function handler(e: KeyboardEvent) {
      // Don't hijack keys while the operator is typing in a form
      if (isTypingTarget(e.target)) return;

      const mod = e.metaKey || e.ctrlKey;

      // Cmd+P — quick-jump
      if (mod && (e.key === "p" || e.key === "P")) {
        e.preventDefault();
        emitQuickJumpRequest();
        return;
      }

      // Cmd+/ — open steering drawer
      if (mod && e.key === "/") {
        e.preventDefault();
        if (onOpenSteering) onOpenSteering();
        return;
      }

      // J / K — jump turn (only on timeline pages)
      const onTimeline = /\/vr\/investigations\/[^/]+$/.test(location.pathname);
      if (!onTimeline || mod || e.shiftKey || e.altKey) return;

      if (e.key === "j" || e.key === "k") {
        e.preventDefault();
        const dir = e.key === "j" ? 1 : -1;
        jumpTurn(dir);
      }
    }

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [navigate, location.pathname, onOpenSteering]);
}

function jumpTurn(direction: 1 | -1) {
  // TurnCards render with id=`turn-${index}`. Find the one closest to
  // the current viewport and scroll the next/prev one into view.
  const cards = Array.from(document.querySelectorAll<HTMLElement>("[id^='turn-']"));
  if (cards.length === 0) return;
  const viewportMid = window.innerHeight / 2;
  let closestIdx = 0;
  let closestDist = Infinity;
  cards.forEach((el, i) => {
    const dist = Math.abs(el.getBoundingClientRect().top - viewportMid);
    if (dist < closestDist) {
      closestDist = dist;
      closestIdx = i;
    }
  });
  const targetIdx = Math.max(0, Math.min(cards.length - 1, closestIdx + direction));
  cards[targetIdx]?.scrollIntoView({ behavior: "smooth", block: "center" });
}
