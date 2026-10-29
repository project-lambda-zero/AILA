import type { Dispatch, JSX, MouseEvent as ReactMouseEvent, ReactNode, SetStateAction } from "react";

import { css } from "../../css";
import { OVERVIEW_DRAWERS, VIEWS, type OverviewDrawer, type XRayView } from "./layout";
import { H } from "./theme";
import type { XRayShell } from "./useXRayShell";

// Turns-header operator control button.
export function CtlButton({ label, onClick, enabled }: { label: string; onClick: () => void; enabled: boolean }): JSX.Element {
  return (
    <button
      type="button"
      onClick={enabled ? onClick : undefined}
      disabled={!enabled}
      style={css(
        `flex:0 0 auto;font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;padding:4px 10px;height:26px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);cursor:${enabled ? "pointer" : "default"};${enabled ? "" : "opacity:0.4;"}`,
      )}
    >
      {label}
    </button>
  );
}

// Window footer: run status, the five layout tabs and the focus / zoom / pin
// readout; `children` render after the flexible spacer.
export function StatusStrip({
  status,
  view,
  onNavigate,
  shell,
  children,
}: {
  status: string | undefined;
  view: XRayView;
  onNavigate: (section: string) => void;
  shell: XRayShell;
  children: ReactNode;
}): JSX.Element {
  const { focus, zoom, pinned } = shell;
  return (
    <>
      <span style={{ display: "flex", alignItems: "center", padding: "0 12px", background: "var(--status-ok)", color: "var(--text-on-accent)", fontWeight: 700, letterSpacing: "0.14em" }}>{status ?? "running"}</span>
      {VIEWS.map(([id, label], i) => {
        const on = id === view;
        return (
          <button key={id} type="button" onClick={() => onNavigate(id)} style={css(`display:flex;align-items:center;padding:0 11px;background:${on ? "color-mix(in srgb,var(--accent) 16%,transparent)" : "transparent"};color:${on ? "var(--accent)" : "var(--text-faint)"};border:0;border-right:1px solid var(--border-soft);font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;`)}>{i + 1} {label}</button>
        );
      })}
      <span style={{ display: "flex", alignItems: "center", padding: "0 10px", color: "var(--accent)", letterSpacing: "0.1em" }}>focus {focus}{zoom ? " \u00b7 zoom" : ""}{pinned.length ? ` \u00b7 pin ${pinned.join("+")}` : ""}</span>
      <span style={{ flex: 1 }} />
      {children}
    </>
  );
}

// The overview layout's collapsible drawer columns. A drawer opens on hover,
// when pane focus lands on it (hjkl), or when it is pinned (P / the pin
// button). Focus rings it in accent, a pin rings it in signal -- mirroring the
// mock's foc / pin outlines.
export function OverviewDrawers({
  shell,
  openDrawer,
  setOpenDrawer,
  renderBody,
}: {
  shell: XRayShell;
  openDrawer: string | null;
  setOpenDrawer: Dispatch<SetStateAction<string | null>>;
  renderBody: (id: OverviewDrawer) => ReactNode;
}): JSX.Element {
  const { focus, setFocus, pinned, setPinned } = shell;
  return (
    <>
      {OVERVIEW_DRAWERS.map((id) => {
        const drawerFocused = focus === id;
        const drawerPinned = pinned.includes(id);
        const open = openDrawer === id || drawerFocused || drawerPinned;
        const ring = drawerFocused ? "var(--accent)" : drawerPinned ? H.sig : open ? "var(--border)" : "var(--border-soft)";
        const glow = drawerFocused
          ? "box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 30%,transparent),0 0 20px color-mix(in srgb,var(--accent) 12%,transparent);"
          : drawerPinned
            ? `box-shadow:0 0 0 1px color-mix(in srgb,${H.sig} 34%,transparent);`
            : "";
        const togglePin = (e: ReactMouseEvent): void => {
          e.stopPropagation();
          setPinned((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2)));
        };
        return (
          <div
            key={id}
            onMouseEnter={() => setOpenDrawer(id)}
            onMouseLeave={() => setOpenDrawer((cur) => (cur === id ? null : cur))}
            onClick={() => { setOpenDrawer(id); setFocus(id); }}
            style={css(
              `flex:${open ? "0 0 320px" : "0 0 30px"};min-width:0;display:flex;flex-direction:column;border:1px solid ${ring};border-radius:3px;background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;cursor:pointer;transition:flex-basis 220ms cubic-bezier(0.22,1,0.36,1);${glow}`,
            )}
          >
            {open ? (
              <>
                <div style={css("flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);")}>
                  <span style={css(`width:6px;height:6px;background:${drawerFocused ? "var(--accent)" : drawerPinned ? H.sig : "var(--accent)"};box-shadow:0 0 6px var(--accent);flex:0 0 auto;`)} />
                  <span style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>{id}</span>
                  <span style={css("flex:1;")} />
                  <button
                    type="button"
                    onClick={togglePin}
                    title={drawerPinned ? "unpin (P)" : "pin (P)"}
                    style={css(`min-height:28px;flex:0 0 auto;background:transparent;border:1px solid ${drawerPinned ? H.sig : "var(--border-soft)"};color:${drawerPinned ? H.sig : "var(--text-faint)"};font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;padding:1px 6px;border-radius:2px;cursor:pointer;`)}
                  >
                    {drawerPinned ? "pinned" : "pin"}
                  </button>
                </div>
                <div style={css("flex:1;min-height:0;overflow:auto;")}>{renderBody(id)}</div>
              </>
            ) : (
              <div style={css("flex:1;min-width:0;display:flex;align-items:center;justify-content:flex-start;gap:9px;writing-mode:vertical-rl;text-orientation:mixed;padding:9px 0;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;white-space:nowrap;overflow:hidden;background:var(--surface-chrome);color:var(--text-muted);")}>
                <span style={css("width:6px;height:6px;background:var(--accent);flex:0 0 auto;")} />
                {id}
              </div>
            )}
          </div>
        );
      })}
    </>
  );
}
