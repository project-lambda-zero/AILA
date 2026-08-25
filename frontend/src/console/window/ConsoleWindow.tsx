/** ConsoleWindow -- the one reusable window primitive for every console
 * surface (module pages, admin sub-views, sandbox terminal, LLM-log viewer,
 * chat widgets). It owns the footer chrome (fullscreen / minimize / close),
 * the window-scoped keyboard shortcuts, and -- for `floater` kind -- drag +
 * resize. Consumers keep their own body content and hand their status strip
 * through `footerExtras`; the primitive appends the three control buttons.
 *
 * Chrome matches the historical hand-duplicated footers exactly: one 28px
 * strip, `--surface-chrome` background, 2px `--border` top rule, three 30px
 * buttons divided by `--border-soft`, glyphs U+2921/U+2922 (fullscreen),
 * U+2014 (minimize), U+2715 (close). A `can*` flag set false HIDES its button
 * rather than rendering an inert one.
 *
 * Keyboard (focused window only, captured on `window` but gated so it never
 * fires while typing in a field or when a child already consumed the key):
 *   - `F` toggles fullscreen (when allowed),
 *   - `M` minimizes (when allowed),
 *   - `Esc` closes (when allowed and no in-window modal owns the key).
 * `F`/`M` are the SHIFTED letters, so a page's own lowercase `f`/`m` handlers
 * (X-Ray pane-zoom) never collide. `Esc` overlaps: a consumer that owns Esc
 * (an open palette/help) must stop it in the capture phase so the fallback
 * close does not fire (see XRayPage). Cross-window focus cycling (Ctrl+`) is a
 * host concern and lives in App.tsx, not here. */

import { useEffect, useRef, useState } from "react";
import type { CSSProperties, JSX, MouseEvent as ReactMouseEvent, ReactNode } from "react";

import type { ConsoleWindowProps } from "./types";

export type { ConsoleWindowProps } from "./types";
export type { WindowKind, WindowRect, WindowState } from "./types";

const DEFAULT_MIN = { w: 320, h: 200 };
const DEFAULT_FLOATER_RECT = { x: 140, y: 96, w: 560, h: 380 };

const ctlBtnStyle: CSSProperties = {
  width: 30,
  flex: "0 0 auto",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  border: 0,
  borderLeft: "1px solid var(--border-soft)",
  background: "transparent",
  color: "var(--text-muted)",
  cursor: "pointer",
  fontFamily: "inherit",
  fontSize: 12,
};

function isEditableTarget(t: EventTarget | null): boolean {
  return (
    t instanceof HTMLInputElement ||
    t instanceof HTMLTextAreaElement ||
    t instanceof HTMLSelectElement ||
    (t instanceof HTMLElement && t.isContentEditable)
  );
}

export default function ConsoleWindow(props: ConsoleWindowProps): JSX.Element | null {
  const {
    kind,
    title,
    initialRect,
    minSize = DEFAULT_MIN,
    canFullscreen = true,
    canMinimize = true,
    canClose = true,
    onClose,
    onMinimize,
    onToggleFullscreen,
    onFocus,
    isFullscreen = false,
    isMinimized = false,
    isFocused = true,
    footerExtras,
    children,
  } = props;

  const [rect, setRect] = useState(initialRect ?? DEFAULT_FLOATER_RECT);
  const dragRef = useRef<{
    mode: "move" | "resize";
    sx: number;
    sy: number;
    ox: number;
    oy: number;
    ow: number;
    oh: number;
  } | null>(null);

  const showFullscreen = canFullscreen && !!onToggleFullscreen;

  // Window-scoped shortcuts. Only the focused window listens. Skips editable
  // targets and any event a child already consumed (e.defaultPrevented), so a
  // modal/palette Esc handled in the capture phase wins over the window close.
  useEffect(() => {
    if (!isFocused) return undefined;
    const onKey = (e: KeyboardEvent): void => {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      if (isEditableTarget(e.target)) return;
      if (e.defaultPrevented) return;
      if (e.key === "Escape") {
        if (canClose) onClose();
        return;
      }
      if (e.key === "F") {
        if (showFullscreen && onToggleFullscreen) {
          e.preventDefault();
          onToggleFullscreen();
        }
        return;
      }
      if (e.key === "M") {
        if (canMinimize) {
          e.preventDefault();
          onMinimize();
        }
        return;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isFocused, canClose, canMinimize, showFullscreen, onClose, onMinimize, onToggleFullscreen]);

  // Floater drag + resize. The pointer capture lives on `window` so a fast drag
  // that outruns the handle keeps tracking. Non-floater kinds never register.
  useEffect(() => {
    if (kind !== "floater") return undefined;
    const onMove = (e: MouseEvent): void => {
      const d = dragRef.current;
      if (!d) return;
      if (d.mode === "move") {
        setRect((r) => ({ ...r, x: d.ox + (e.clientX - d.sx), y: d.oy + (e.clientY - d.sy) }));
      } else {
        setRect((r) => ({
          ...r,
          w: Math.max(minSize.w, d.ow + (e.clientX - d.sx)),
          h: Math.max(minSize.h, d.oh + (e.clientY - d.sy)),
        }));
      }
    };
    const onUp = (): void => {
      dragRef.current = null;
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [kind, minSize.w, minSize.h]);

  if (isMinimized) return null;

  const raise = (): void => {
    if (onFocus && !isFocused) onFocus();
  };

  const startDrag = (e: ReactMouseEvent, mode: "move" | "resize"): void => {
    if (mode === "move" && (e.target as HTMLElement).closest("button")) return;
    e.preventDefault();
    dragRef.current = { mode, sx: e.clientX, sy: e.clientY, ox: rect.x, oy: rect.y, ow: rect.w, oh: rect.h };
    raise();
  };

  const fixedZ = kind === "overlay" ? 45 : isFullscreen ? 45 : kind === "floater" ? 40 : 30;
  const wrapStyle: CSSProperties =
    kind === "floater" && !isFullscreen
      ? {
          position: "fixed",
          left: rect.x,
          top: rect.y,
          width: rect.w,
          height: rect.h,
          zIndex: fixedZ,
          display: "flex",
          flexDirection: "column",
          background: "var(--surface-page)",
          border: "1px solid var(--border)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.55)",
        }
      : kind === "overlay" || isFullscreen
        ? {
            position: "fixed",
            inset: 0,
            zIndex: fixedZ,
            display: "flex",
            flexDirection: "column",
            background: "var(--surface-page)",
          }
        : { position: "absolute", inset: 0, zIndex: fixedZ, display: "flex", flexDirection: "column", background: "transparent" };

  const body: ReactNode = <div style={{ flex: 1, minHeight: 0, position: "relative", display: "flex", flexDirection: "column" }}>{children}</div>;

  return (
    <div style={wrapStyle} onMouseDownCapture={raise}>
      {body}
      <footer
        onMouseDown={kind === "floater" && !isFullscreen ? (e) => startDrag(e, "move") : undefined}
        style={{
          flex: "0 0 28px",
          height: 28,
          display: "flex",
          alignItems: "stretch",
          background: "var(--surface-chrome)",
          borderTop: "2px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--text-faint)",
          cursor: kind === "floater" && !isFullscreen ? "move" : "default",
        }}
      >
        {footerExtras ?? (
          <>
            <span style={{ display: "flex", alignItems: "center", padding: "0 12px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{title}</span>
            <span style={{ flex: 1 }} />
          </>
        )}
        {showFullscreen ? (
          <button type="button" onClick={onToggleFullscreen} title={isFullscreen ? "exit fullscreen" : "fullscreen"} style={ctlBtnStyle}>
            {isFullscreen ? "\u2921" : "\u2922"}
          </button>
        ) : null}
        {canMinimize ? (
          <button type="button" onClick={onMinimize} title="minimize" style={ctlBtnStyle}>
            {"\u2014"}
          </button>
        ) : null}
        {canClose ? (
          <button type="button" onClick={onClose} title="close" style={{ ...ctlBtnStyle, fontSize: 11 }}>
            {"\u2715"}
          </button>
        ) : null}
      </footer>
      {kind === "floater" && !isFullscreen ? (
        <div
          onMouseDown={(e) => startDrag(e, "resize")}
          title="resize"
          style={{ position: "absolute", right: 0, bottom: 28, width: 16, height: 16, cursor: "nwse-resize", zIndex: fixedZ + 1 }}
        />
      ) : null}
    </div>
  );
}
