import * as React from "react";

/**
 * FaultyTerminal -- the AILA design-system hero motif.
 *
 * Drives the self-contained raw-WebGL shader shipped at
 * `/faulty-terminal.js` (a CRT "digit rain" tinted by `--accent`, with
 * scanlines, glitch, chromatic aberration and gentle barrel curvature).
 * The script is loaded once from our own origin (CSP `script-src 'self'`)
 * and exposes `window.mountFaultyTerminal(container, opts) -> cleanup`.
 *
 * Use ONCE, large, behind a hero surface -- never as repeated decoration.
 * Honors `prefers-reduced-motion` (the shader renders a single static frame).
 */

declare global {
  interface Window {
    mountFaultyTerminal?: (
      container: HTMLElement,
      opts?: Record<string, number | number[] | string>,
    ) => () => void;
  }
}

const SCRIPT_SRC = "/faulty-terminal.js";
let scriptPromise: Promise<void> | null = null;

function loadScript(): Promise<void> {
  if (typeof window === "undefined") return Promise.resolve();
  if (window.mountFaultyTerminal) return Promise.resolve();
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(
      `script[src="${SCRIPT_SRC}"]`,
    );
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () => reject(new Error("faulty-terminal failed")));
      if (window.mountFaultyTerminal) resolve();
      return;
    }
    const s = document.createElement("script");
    s.src = SCRIPT_SRC;
    s.async = true;
    s.addEventListener("load", () => resolve());
    s.addEventListener("error", () => reject(new Error("faulty-terminal failed")));
    document.head.appendChild(s);
  });
  return scriptPromise;
}

export interface FaultyTerminalProps {
  /** Shader tuning overrides (brightness, tint, scanline, glitch, curvature, ...). */
  options?: Record<string, number | number[] | string>;
  className?: string;
  style?: React.CSSProperties;
}

export function FaultyTerminal({ options, className, style }: FaultyTerminalProps) {
  const ref = React.useRef<HTMLDivElement>(null);
  const optionsRef = React.useRef(options);
  optionsRef.current = options;

  React.useEffect(() => {
    let cleanup: (() => void) | undefined;
    let cancelled = false;
    void loadScript()
      .then(() => {
        if (cancelled || !ref.current || !window.mountFaultyTerminal) return;
        cleanup = window.mountFaultyTerminal(ref.current, optionsRef.current);
      })
      .catch(() => {
        /* WebGL unavailable or blocked -- the midnight background stands alone */
      });
    return () => {
      cancelled = true;
      if (cleanup) cleanup();
    };
  }, []);

  return <div ref={ref} aria-hidden="true" className={className} style={style} />;
}
