import { useEffect, useRef } from "react";

declare global {
  interface Window {
    mountFaultyTerminal?: (
      el: HTMLElement,
      opts?: Record<string, unknown>,
    ) => (() => void) | void;
  }
}

/**
 * FaultyTerminal -- the signature AILA WebGL hero (pink CRT digit-rain), loaded
 * once from the self-hosted /faulty-terminal.js (CSP script-src 'self'). Sits
 * behind the desktop at low brightness with screen blend.
 */
export function FaultyTerminal({ opts }: { opts?: Record<string, unknown> }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cleanup: (() => void) | void;
    let cancelled = false;

    const mount = () => {
      if (!cancelled && ref.current && window.mountFaultyTerminal) {
        cleanup = window.mountFaultyTerminal(ref.current, opts);
      }
    };

    if (window.mountFaultyTerminal) {
      mount();
    } else {
      const existing = document.querySelector<HTMLScriptElement>("script[data-faulty]");
      if (existing) {
        existing.addEventListener("load", mount, { once: true });
      } else {
        const s = document.createElement("script");
        s.src = "/faulty-terminal.js";
        s.dataset.faulty = "1";
        s.addEventListener("load", mount, { once: true });
        document.head.appendChild(s);
      }
    }

    return () => {
      cancelled = true;
      if (typeof cleanup === "function") cleanup();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      ref={ref}
      aria-hidden="true"
      style={{
        position: "absolute",
        inset: 0,
        mixBlendMode: "screen",
        opacity: 0.5,
        filter: "brightness(0.32)",
        pointerEvents: "none",
      }}
    />
  );
}
