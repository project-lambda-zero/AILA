/**
 * #47 -- idle-timeout hook.
 *
 * Watches the DOM for signs of live user presence (pointer, keyboard,
 * scroll, touch, and window focus) and fires `onIdle` after
 * `timeoutMs` of continuous inactivity. Wired at the app shell so a
 * signed-in operator who walks away from a shared workstation is
 * logged out instead of leaving an authenticated session open.
 *
 * The hook does NOT itself log the user out -- callers pass the logout
 * closure via `onIdle` so tests can stub it without a real store.
 * Presence events are attached via a single `addEventListener` per
 * event, `passive: true`, and cleaned up on unmount so the hook is
 * safe to leave mounted for the entire authenticated session.
 *
 * `enabled` gates the whole subscription so the hook is a no-op on
 * public pages (login, OIDC callback, 403) where an idle timer would
 * fire without a session to invalidate.
 */
import { useEffect, useRef } from "react";

/** Default idle window (15 minutes) balanced against long-running scan
 * screens where the operator legitimately watches for progress. */
export const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000;

/** Presence events the hook listens for. Pointer covers mouse and pen,
 * touchstart covers touch devices, keydown covers keyboard-only nav,
 * scroll covers scroll-wheel + trackpad, and visibilitychange lets a
 * returning tab reset the timer without needing a bounce. */
const PRESENCE_EVENTS = [
  "pointerdown",
  "pointermove",
  "keydown",
  "scroll",
  "touchstart",
  "visibilitychange",
] as const;

export interface UseIdleTimeoutOptions {
  /** Callback fired once when the idle window elapses. */
  onIdle: () => void;
  /** Idle window in milliseconds. Defaults to 15 minutes. */
  timeoutMs?: number;
  /** When false, the hook does not attach listeners or schedule a
   * timer. Defaults to true. */
  enabled?: boolean;
}

export function useIdleTimeout(options: UseIdleTimeoutOptions): void {
  const { onIdle, timeoutMs = DEFAULT_IDLE_TIMEOUT_MS, enabled = true } = options;

  // Callback ref so a parent that re-renders with a new `onIdle`
  // closure does not tear down and reinstall the listeners.
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;

  useEffect(() => {
    if (!enabled) return;
    if (typeof window === "undefined") return;
    if (timeoutMs <= 0) return;

    let timerId: ReturnType<typeof setTimeout> | null = null;
    let fired = false;

    function scheduleFire(): void {
      clearTimeout(timerId ?? undefined);
      timerId = setTimeout(() => {
        if (fired) return;
        fired = true;
        onIdleRef.current();
      }, timeoutMs);
    }

    function onPresence(): void {
      // If the timer already fired we NEVER re-schedule -- the caller
      // has taken an unrecoverable action (logout) and any further
      // presence event should be handled by the fresh session.
      if (fired) return;
      scheduleFire();
    }

    for (const eventName of PRESENCE_EVENTS) {
      window.addEventListener(eventName, onPresence, { passive: true });
    }
    scheduleFire();

    return () => {
      for (const eventName of PRESENCE_EVENTS) {
        window.removeEventListener(eventName, onPresence);
      }
      clearTimeout(timerId ?? undefined);
    };
  }, [enabled, timeoutMs]);
}
