import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";

import { pad2 } from "./parsers";
import { KEY_TO_VIEW, isOverviewDrawer, isViewKey, type LayoutPanes, type PaneView, type XRayView } from "./layout";
import { PV_HIDE, PV_ZOOM } from "./theme";

// The pause / resume half of an investigation control mutation.
export interface PauseControl {
  mutate: (action: "pause" | "resume") => void;
}

export interface XRayShell {
  focus: string;
  setFocus: Dispatch<SetStateAction<string>>;
  zoom: string | null;
  setZoom: Dispatch<SetStateAction<string | null>>;
  pinned: string[];
  setPinned: Dispatch<SetStateAction<string[]>>;
  help: boolean;
  setHelp: Dispatch<SetStateAction<boolean>>;
  palette: boolean;
  setPalette: Dispatch<SetStateAction<boolean>>;
  palQuery: string;
  setPalQuery: Dispatch<SetStateAction<string>>;
  palSel: number;
  setPalSel: Dispatch<SetStateAction<number>>;
  pv: PaneView;
}

// Pane focus, f-key zoom, drawer pins, keymap help and the command palette,
// plus the window keyboard model (mirrors the mock's handleKey): 1-5 switch
// layout, h/k and l/j move pane focus, f zooms the focused pane, P pins an
// overview drawer, p pauses / resumes, ? toggles the keymap, / or Ctrl-K opens
// the palette, Esc closes zoom / help. Refs hold the live values so the window
// listener registers exactly once.
export function useXRayShell({
  view,
  panes: layoutPanes,
  status,
  control,
  onNavigate,
}: {
  view: XRayView;
  panes: LayoutPanes;
  status: string; // lower-cased investigation status
  control: PauseControl;
  onNavigate: (section: string) => void;
}): XRayShell {
  const [focus, setFocus] = useState("transcript");
  const [zoom, setZoom] = useState<string | null>(null);
  const [pinned, setPinned] = useState<string[]>([]);
  const [help, setHelp] = useState(false);
  const [palette, setPalette] = useState(false);
  const [palQuery, setPalQuery] = useState("");
  const [palSel, setPalSel] = useState(0);

  const focusRef = useRef(focus);
  const viewRef = useRef(view);
  const navRef = useRef(onNavigate);
  const controlRef = useRef(control);
  const statusRef = useRef("");
  const zoomRef = useRef(zoom);
  const helpRef = useRef(help);
  const panesRef = useRef(layoutPanes);
  focusRef.current = focus;
  viewRef.current = view;
  navRef.current = onNavigate;
  controlRef.current = control;
  statusRef.current = status;
  zoomRef.current = zoom;
  helpRef.current = help;
  panesRef.current = layoutPanes;

  // Reset pane focus to the first pane whenever the layout changes.
  useEffect(() => {
    const panes = panesRef.current[view];
    setFocus((prev) => (panes.includes(prev) ? prev : panes[0] ?? "transcript"));
    setZoom(null);
  }, [view]);

  useEffect(() => {
    const move = (d: number): void => {
      const panes = panesRef.current[viewRef.current];
      if (!panes.length) return;
      setFocus((prev) => panes[(panes.indexOf(prev) + d + panes.length) % panes.length] ?? prev);
      setZoom(null);
    };
    const onKeyDown = (e: globalThis.KeyboardEvent): void => {
      const tgt = e.target;
      if (
        tgt instanceof HTMLInputElement ||
        tgt instanceof HTMLTextAreaElement ||
        tgt instanceof HTMLSelectElement ||
        (tgt instanceof HTMLElement && tgt.isContentEditable)
      )
        return;
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setPalette(true);
        setPalQuery("");
        setPalSel(0);
        return;
      }
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === "Escape") {
        // Only consume Esc when a local overlay owns it; otherwise let it reach
        // the window primitive (which closes the window). Capture phase +
        // stopImmediatePropagation guarantees this handler wins when it fires.
        if (zoomRef.current || helpRef.current) {
          e.preventDefault();
          e.stopImmediatePropagation();
          setZoom(null);
          setHelp(false);
        }
        return;
      }
      if (e.key === "/") {
        e.preventDefault();
        setPalette(true);
        setPalQuery("");
        setPalSel(0);
        return;
      }
      if (isViewKey(e.key)) {
        e.preventDefault();
        navRef.current(KEY_TO_VIEW[e.key]);
        return;
      }
      if (e.key === "l" || e.key === "j") {
        e.preventDefault();
        move(1);
        return;
      }
      if (e.key === "h" || e.key === "k") {
        e.preventDefault();
        move(-1);
        return;
      }
      if (e.key === "f") {
        e.preventDefault();
        setZoom((z) => (z ? null : focusRef.current));
        return;
      }
      if (e.key === "?") {
        e.preventDefault();
        setHelp((h) => !h);
        return;
      }
      if (e.key === "P") {
        e.preventDefault();
        const id = focusRef.current;
        if (viewRef.current === "overview" && isOverviewDrawer(id)) {
          setPinned((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2)));
        }
        return;
      }
      if (e.key === "p") {
        e.preventDefault();
        const st = statusRef.current;
        if (st === "paused") controlRef.current.mutate("resume");
        else if (!["completed", "failed", "cancelled"].includes(st)) controlRef.current.mutate("pause");
        return;
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, []);

  const pv: PaneView = (id) => {
    if (zoom) return zoom === id ? { focused: true, style: PV_ZOOM } : { focused: false, style: PV_HIDE };
    return { focused: focus === id };
  };

  return { focus, setFocus, zoom, setZoom, pinned, setPinned, help, setHelp, palette, setPalette, palQuery, setPalQuery, palSel, setPalSel, pv };
}

// Local HH:MM:SS wall clock, ticking once a second.
export function useWallClock(): string {
  const [clock, setClock] = useState("");
  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setClock(`${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return clock;
}
