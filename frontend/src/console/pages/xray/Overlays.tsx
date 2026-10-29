import type { ChangeEvent, JSX, KeyboardEvent, MouseEvent as ReactMouseEvent } from "react";

import { css } from "../../css";
import { SHORTCUTS, VIEWS, VIEW_INDEX, type LayoutPanes, type XRayView } from "./layout";
import { emptyNote } from "./theme";
import type { XRayShell } from "./useXRayShell";

export interface PalCmd {
  group: string;
  label: string;
  hint?: string;
  run: () => void;
}

// Layout switches, pane focus, zoom and keymap: the palette commands every
// X-Ray page shares ahead of its own run controls.
export function shellCommands(view: XRayView, panes: LayoutPanes, shell: XRayShell, onNavigate: (section: string) => void): PalCmd[] {
  const cmds: PalCmd[] = [];
  for (const [id, label] of VIEWS) {
    cmds.push({ group: "layout", label: `layout \u00b7 ${label}`, hint: String(VIEW_INDEX[id]), run: () => onNavigate(id) });
  }
  for (const pane of panes[view]) {
    cmds.push({ group: "focus", label: `focus \u00b7 ${pane}`, hint: "\u21b5", run: () => { shell.setFocus(pane); shell.setZoom(null); } });
  }
  cmds.push({ group: "view", label: "zoom focused pane", hint: "f", run: () => shell.setZoom((z) => (z ? null : shell.focus)) });
  cmds.push({ group: "view", label: "keymap", hint: "?", run: () => shell.setHelp(true) });
  return cmds;
}

// Command palette (/ or Ctrl-K; Esc / click-away closes). Every command is a
// real action -- nothing here is a demo no-op.
export function CommandPalette({ commands, shell }: { commands: readonly PalCmd[]; shell: XRayShell }): JSX.Element {
  const { palQuery, setPalQuery, palSel, setPalSel, setPalette } = shell;
  const palQ = palQuery.trim().toLowerCase();
  const palFiltered = (palQ ? commands.filter((c) => c.label.toLowerCase().includes(palQ)) : commands).slice(0, 40);
  const palIdx = palFiltered.length ? Math.min(palSel, palFiltered.length - 1) : 0;
  const runPal = (c: PalCmd): void => {
    setPalette(false);
    setPalQuery("");
    c.run();
  };
  return (
    <div
      onClick={() => setPalette(false)}
      style={{ position: "absolute", inset: 0, zIndex: 70, display: "flex", alignItems: "flex-start", justifyContent: "center", paddingTop: "12vh", background: "rgba(9,9,9,0.62)" }}
    >
      <div
        onClick={(e: ReactMouseEvent) => e.stopPropagation()}
        style={css("width:min(560px,88%);max-height:64vh;display:flex;flex-direction:column;background:var(--surface-card);border:1px solid var(--accent);border-radius:4px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,0.6);")}
      >
        <div style={css("display:flex;align-items:center;gap:9px;padding:10px 12px;border-bottom:1px solid var(--border);background:var(--surface-chrome);")}>
          <span style={css("color:var(--accent);font-size:13px;")}>:</span>
          <input
            autoFocus
            value={palQuery}
            onChange={(e: ChangeEvent<HTMLInputElement>) => { setPalQuery(e.target.value); setPalSel(0); }}
            onKeyDown={(e: KeyboardEvent<HTMLInputElement>) => {
              if (e.key === "Escape") { e.preventDefault(); setPalette(false); }
              else if (e.key === "Enter") { e.preventDefault(); const c = palFiltered[palIdx]; if (c) runPal(c); }
              else if (e.key === "ArrowDown") { e.preventDefault(); setPalSel((s) => Math.min(s + 1, palFiltered.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setPalSel((s) => Math.max(s - 1, 0)); }
            }}
            placeholder={"layout, pane, action\u2026"}
            style={css("flex:1;min-width:0;background:transparent;border:0;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:13px;")}
          />
          <span style={css("font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>esc</span>
        </div>
        <div style={css("flex:1;min-height:0;overflow:auto;")}>
          {palFiltered.length === 0 ? (
            <div style={emptyNote}>no command matches.</div>
          ) : (
            palFiltered.map((c, i) => (
              <div
                key={`${c.group}-${c.label}`}
                onClick={() => runPal(c)}
                onMouseEnter={() => setPalSel(i)}
                style={css(
                  `display:flex;align-items:center;gap:10px;padding:7px 12px;cursor:pointer;border-bottom:1px solid var(--border-faint);${i === palIdx ? "background:color-mix(in srgb,var(--accent) 14%,transparent);" : ""}`,
                )}
              >
                <span style={css("flex:0 0 52px;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>{c.group}</span>
                <span style={css(`flex:1;min-width:0;font-size:12px;color:${i === palIdx ? "var(--accent)" : "var(--text-primary)"};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;`)}>{c.label}</span>
                {c.hint ? <span style={css("flex:0 0 auto;font-size:11px;font-family:var(--font-mono);color:var(--text-faint);border:1px solid var(--border-soft);padding:0 5px;border-radius:2px;")}>{c.hint}</span> : null}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// Keymap help (? toggles, Esc / click-away closes).
export function KeymapHelp({ onClose }: { onClose: () => void }): JSX.Element {
  return (
    <div
      onClick={onClose}
      style={{ position: "absolute", inset: 0, zIndex: 60, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(9,9,9,0.62)" }}
    >
      <div
        onClick={(e: ReactMouseEvent) => e.stopPropagation()}
        style={css("width:min(520px,86%);background:var(--surface-card);border:1px solid var(--accent);border-radius:4px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,0.6);")}
      >
        <div style={css("display:flex;align-items:center;gap:10px;padding:10px 13px;border-bottom:1px solid var(--border);background:var(--surface-chrome);font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-primary);")}>
          <span style={css("width:8px;height:8px;background:var(--accent);flex:0 0 auto;")} />
          <span>keymap</span>
          <span style={css("flex:1;")} />
          <button type="button" onClick={onClose} style={css("background:transparent;border:0;color:var(--text-muted);font-family:inherit;font-size:14px;cursor:pointer;min-height:28px;display:inline-flex;align-items:center;")}>{"\u2715"}</button>
        </div>
        <div style={css("padding:14px;display:flex;flex-direction:column;gap:6px;")}>
          {SHORTCUTS.map(([k, v]) => (
            <div key={k} style={css("display:flex;align-items:center;gap:12px;font-size:11px;")}>
              <span style={css("flex:0 0 76px;border:1px solid var(--border);padding:1px 6px;text-align:center;color:var(--accent);font-family:var(--font-mono);font-size:11px;")}>{k}</span>
              <span style={css("color:var(--text-muted);letter-spacing:0.02em;")}>{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
