import { useCallback, useEffect, useRef, useState } from "react";

import { FaultyTerminal } from "./desktop/FaultyTerminal";

// ---------------------------------------------------------------------------
// Navigation model -- the left pane. Each module owns pages; opening a page
// spawns a window on the desktop. (Window content is wired to real module
// screens + data in the next build phase.)
// ---------------------------------------------------------------------------

interface PageDef {
  id: string;
  label: string;
}
interface ModuleDef {
  id: string;
  label: string;
  tone: string;
  pages: PageDef[];
}

const MODULES: ModuleDef[] = [
  {
    id: "vr",
    label: "vr",
    tone: "var(--accent)",
    pages: [
      { id: "investigations", label: "investigations" },
      { id: "targets", label: "targets" },
      { id: "workspaces", label: "workspaces" },
      { id: "patterns", label: "patterns" },
      { id: "findings", label: "findings" },
      { id: "disclosures", label: "disclosures" },
      { id: "fuzz", label: "fuzz campaigns" },
    ],
  },
  {
    id: "vulnerability",
    label: "vulnerability",
    tone: "var(--status-warn)",
    pages: [
      { id: "scan", label: "launch scan" },
      { id: "findings", label: "findings" },
      { id: "radar", label: "network radar" },
      { id: "viz", label: "data visualization" },
      { id: "reports", label: "reports" },
    ],
  },
  {
    id: "forensics",
    label: "forensics",
    tone: "var(--status-info)",
    pages: [
      { id: "projects", label: "projects" },
      { id: "investigations", label: "investigations" },
      { id: "evidence", label: "evidence" },
      { id: "timeline", label: "timeline" },
    ],
  },
  {
    id: "malware",
    label: "malware",
    tone: "var(--status-ok)",
    pages: [
      { id: "targets", label: "targets" },
      { id: "investigations", label: "investigations" },
      { id: "families", label: "families" },
      { id: "patterns", label: "patterns" },
    ],
  },
];

const INVESTIGATIONS = [
  { id: "VR-2291", label: "VR-2291", sub: "rtsp-core \u00b7 scada", state: "running", tone: "var(--accent)" },
  { id: "VR-2288", label: "VR-2288", sub: "libav demux fuzz", state: "review", tone: "var(--status-info)" },
  { id: "VR-2280", label: "VR-2280", sub: "openssl n-day triage", state: "shipped", tone: "var(--status-ok)" },
  { id: "VR-2263", label: "VR-2263", sub: "banking apk masvs", state: "paused", tone: "var(--status-warn)" },
];

// ---------------------------------------------------------------------------
// Window manager
// ---------------------------------------------------------------------------

interface WinState {
  id: string;
  title: string;
  sub: string;
  tone: string;
  x: number;
  y: number;
  w: number;
  h: number;
  z: number;
  minimized: boolean;
}

let SEQ = 0;

export default function App() {
  const [activeModule, setActiveModule] = useState<string>("vr");
  const [wins, setWins] = useState<WinState[]>([]);
  const [topZ, setTopZ] = useState(10);
  const [clock, setClock] = useState("");
  const dragRef = useRef<{ id: string; dx: number; dy: number } | null>(null);

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      const p = (n: number) => (n < 10 ? "0" : "") + n;
      setClock(`${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  const focus = useCallback((id: string) => {
    setTopZ((z) => {
      const nz = z + 1;
      setWins((ws) => ws.map((w) => (w.id === id ? { ...w, z: nz, minimized: false } : w)));
      return nz;
    });
  }, []);

  const openWindow = useCallback(
    (moduleId: string, page: PageDef, tone: string) => {
      const winId = `${moduleId}:${page.id}`;
      setWins((ws) => {
        const existing = ws.find((w) => w.id === winId);
        if (existing) {
          return ws.map((w) => (w.id === winId ? { ...w, minimized: false, z: topZ + 1 } : w));
        }
        const n = SEQ++;
        const nz = topZ + 1;
        return [
          ...ws,
          {
            id: winId,
            title: `${moduleId} / ${page.label}`,
            sub: `module page \u00b7 ${page.id}`,
            tone,
            x: 80 + (n % 6) * 34,
            y: 60 + (n % 6) * 30,
            w: 720,
            h: 460,
            z: nz,
            minimized: false,
          },
        ];
      });
      setTopZ((z) => z + 1);
    },
    [topZ],
  );

  const closeWindow = useCallback((id: string) => {
    setWins((ws) => ws.filter((w) => w.id !== id));
  }, []);
  const minimize = useCallback((id: string) => {
    setWins((ws) => ws.map((w) => (w.id === id ? { ...w, minimized: true } : w)));
  }, []);

  // dragging
  useEffect(() => {
    const move = (e: MouseEvent) => {
      const d = dragRef.current;
      if (!d) return;
      setWins((ws) =>
        ws.map((w) =>
          w.id === d.id
            ? { ...w, x: Math.max(0, e.clientX - d.dx), y: Math.max(0, e.clientY - d.dy) }
            : w,
        ),
      );
    };
    const up = () => {
      dragRef.current = null;
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
  }, []);

  const startDrag = (e: React.MouseEvent, w: WinState) => {
    dragRef.current = { id: w.id, dx: e.clientX - w.x, dy: e.clientY - w.y };
    focus(w.id);
  };

  const activePages = MODULES.find((m) => m.id === activeModule);
  const dockWins = wins.filter((w) => w.minimized);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        display: "flex",
        flexDirection: "column",
        background: "var(--surface-page)",
        color: "var(--text-primary)",
        fontFamily: "var(--font-mono)",
      }}
    >
      {/* hero */}
      <FaultyTerminal />

      {/* menubar */}
      <header
        style={{
          position: "relative",
          zIndex: 30,
          flex: "0 0 var(--menubar-h)",
          height: "var(--menubar-h)",
          display: "flex",
          alignItems: "stretch",
          background: "var(--surface-chrome)",
          borderBottom: "2px solid var(--border)",
          fontSize: 11,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "0 12px", borderRight: "1px solid var(--border-soft)" }}>
          <span style={{ width: 9, height: 9, background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />
          <span style={{ fontWeight: 700 }}>AILA</span>
        </div>
        {["console", "workspace", "docs"].map((t, i) => (
          <button
            key={t}
            type="button"
            style={{
              padding: "0 14px",
              background: i === 0 ? "var(--accent)" : "transparent",
              color: i === 0 ? "var(--text-on-accent)" : "var(--text-muted)",
              border: 0,
              borderRight: "1px solid var(--border-soft)",
              fontSize: 11,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              cursor: "pointer",
              fontWeight: i === 0 ? 700 : 400,
            }}
          >
            {t}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "0 12px", borderLeft: "1px solid var(--border-soft)", color: "var(--text-faint)" }}>
          <span style={{ width: 8, height: 8, background: "var(--status-ok)", boxShadow: "0 0 7px var(--status-ok)" }} />
          <span style={{ color: "var(--text-muted)" }}>engine ok</span>
          <span>·</span>
          <span>{clock}</span>
        </div>
      </header>

      {/* main: left pane | desktop */}
      <main style={{ position: "relative", zIndex: 10, flex: 1, minHeight: 0, display: "flex" }}>
        {/* left pane */}
        <aside
          style={{
            flex: "0 0 216px",
            display: "flex",
            flexDirection: "column",
            background: "color-mix(in srgb, var(--surface-page) 86%, transparent)",
            borderRight: "1px solid var(--border-soft)",
            overflow: "auto",
          }}
        >
          <PaneSection title="module">
            {MODULES.map((m) => (
              <PaneRow
                key={m.id}
                label={m.label}
                dot={m.tone}
                active={m.id === activeModule}
                onClick={() => setActiveModule(m.id)}
              />
            ))}
          </PaneSection>

          <PaneSection title="pages">
            {activePages?.pages.map((p) => (
              <PaneRow
                key={p.id}
                label={p.label}
                dot="var(--text-faint)"
                onClick={() => openWindow(activePages.id, p, activePages.tone)}
              />
            ))}
          </PaneSection>

          <PaneSection title="investigations">
            {INVESTIGATIONS.map((inv) => (
              <button
                key={inv.id}
                type="button"
                onClick={() =>
                  openWindow(activeModule, { id: inv.id, label: inv.id }, inv.tone)
                }
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  padding: "6px 12px",
                  background: "transparent",
                  border: 0,
                  borderBottom: "1px solid var(--border-faint)",
                  cursor: "pointer",
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
                  <span style={{ width: 6, height: 6, background: inv.tone, flex: "0 0 auto" }} />
                  <span style={{ fontSize: 11, color: "var(--text-primary)" }}>{inv.label}</span>
                  <span style={{ flex: 1 }} />
                  <span style={{ fontSize: 8, letterSpacing: "0.1em", textTransform: "uppercase", color: inv.tone }}>{inv.state}</span>
                </span>
                <span style={{ display: "block", marginTop: 2, marginLeft: 13, fontSize: 9.5, color: "var(--text-faint)" }}>{inv.sub}</span>
              </button>
            ))}
          </PaneSection>
        </aside>

        {/* desktop -- window canvas */}
        <section style={{ position: "relative", flex: 1, minWidth: 0, overflow: "hidden" }}>
          {wins.filter((w) => !w.minimized).length === 0 && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexDirection: "column",
                gap: 10,
                color: "var(--text-faint)",
              }}
            >
              <div style={{ fontFamily: "var(--font-display)", fontWeight: 300, fontSize: 30, color: "var(--text-muted)" }}>
                AILA workbench
              </div>
              <div style={{ fontSize: 11, letterSpacing: "0.1em", textTransform: "uppercase" }}>
                pick a page from the left rail to open a window
              </div>
            </div>
          )}

          {wins
            .filter((w) => !w.minimized)
            .map((w) => (
              <Window
                key={w.id}
                w={w}
                onFocus={() => focus(w.id)}
                onDragStart={(e) => startDrag(e, w)}
                onMinimize={() => minimize(w.id)}
                onClose={() => closeWindow(w.id)}
              />
            ))}

          {/* page dock */}
          {dockWins.length > 0 && (
            <div
              style={{
                position: "absolute",
                left: 8,
                right: 8,
                bottom: 8,
                display: "flex",
                gap: 6,
                flexWrap: "wrap",
                zIndex: 9999,
              }}
            >
              {dockWins.map((w) => (
                <button
                  key={w.id}
                  type="button"
                  onClick={() => focus(w.id)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 7,
                    height: 24,
                    padding: "0 10px",
                    background: "var(--surface-chrome)",
                    border: "1px solid var(--border-soft)",
                    borderRadius: "var(--radius-sm)",
                    color: "var(--text-muted)",
                    fontSize: 10,
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    cursor: "pointer",
                  }}
                >
                  <span style={{ width: 6, height: 6, background: w.tone }} />
                  {w.title}
                </button>
              ))}
            </div>
          )}
        </section>
      </main>

      {/* status bar */}
      <footer
        style={{
          position: "relative",
          zIndex: 30,
          flex: "0 0 var(--statusbar-h)",
          height: "var(--statusbar-h)",
          display: "flex",
          alignItems: "center",
          gap: 14,
          padding: "0 12px",
          background: "var(--surface-chrome)",
          borderTop: "1px solid var(--border)",
          fontSize: 10,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          color: "var(--text-faint)",
        }}
      >
        <span style={{ color: "var(--text-on-accent)", background: "var(--accent)", padding: "2px 8px", borderRadius: 2 }}>desktop</span>
        <span>{wins.length} windows</span>
        <span>module {activeModule}</span>
        <span style={{ flex: 1 }} />
        <span>aila.sh</span>
        <span>{clock}</span>
      </footer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Left-pane primitives
// ---------------------------------------------------------------------------

function PaneSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ paddingTop: 6 }}>
      <div
        style={{
          padding: "6px 12px 4px",
          fontSize: 9,
          letterSpacing: "0.16em",
          textTransform: "uppercase",
          color: "var(--text-faint)",
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function PaneRow({
  label,
  dot,
  active,
  onClick,
}: {
  label: string;
  dot: string;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        width: "100%",
        textAlign: "left",
        padding: "6px 12px",
        background: active ? "color-mix(in srgb, var(--accent) 12%, transparent)" : "transparent",
        border: 0,
        borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
        color: active ? "var(--accent)" : "var(--text-muted)",
        fontSize: 11.5,
        letterSpacing: "0.02em",
        cursor: "pointer",
      }}
    >
      <span style={{ width: 6, height: 6, background: dot, flex: "0 0 auto" }} />
      {label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

function Window({
  w,
  onFocus,
  onDragStart,
  onMinimize,
  onClose,
}: {
  w: WinState;
  onFocus: () => void;
  onDragStart: (e: React.MouseEvent) => void;
  onMinimize: () => void;
  onClose: () => void;
}) {
  return (
    <div
      onMouseDown={onFocus}
      style={{
        position: "absolute",
        left: w.x,
        top: w.y,
        width: w.w,
        height: w.h,
        zIndex: w.z,
        display: "flex",
        flexDirection: "column",
        background: "var(--surface-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        boxShadow: "var(--shadow-window)",
        overflow: "hidden",
      }}
    >
      {/* title bar */}
      <div
        onMouseDown={onDragStart}
        style={{
          flex: "0 0 var(--panel-title-h)",
          height: "var(--panel-title-h)",
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "0 8px 0 10px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          backgroundImage: "var(--hatch)",
          cursor: "move",
          userSelect: "none",
        }}
      >
        <span style={{ width: 7, height: 7, background: w.tone, flex: "0 0 auto" }} />
        <span style={{ fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--text-primary)" }}>
          {w.title}
        </span>
        <span style={{ flex: 1 }} />
        <WinBtn label="–" onClick={onMinimize} title="minimize" />
        <WinBtn label="✕" onClick={onClose} title="close" accent />
      </div>
      {/* body -- window content wires to real module screens + data next phase */}
      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        <div
          style={{
            border: "1px solid var(--border-soft)",
            background: "var(--surface-sunk)",
            borderRadius: "var(--radius-md)",
            padding: 16,
            fontSize: 12,
            color: "var(--text-muted)",
            lineHeight: 1.6,
          }}
        >
          <div style={{ fontFamily: "var(--font-display)", fontWeight: 300, fontSize: 20, color: "var(--text-primary)", marginBottom: 8 }}>
            {w.title}
          </div>
          <div style={{ letterSpacing: "0.04em" }}>{w.sub}</div>
          <div style={{ marginTop: 12, fontSize: 11, color: "var(--text-faint)" }}>
            window open · drag the title bar · minimize to the dock · close with ✕
          </div>
        </div>
      </div>
    </div>
  );
}

function WinBtn({
  label,
  onClick,
  title,
  accent,
}: {
  label: string;
  onClick: () => void;
  title: string;
  accent?: boolean;
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      onMouseDown={(e) => e.stopPropagation()}
      style={{
        width: 18,
        height: 18,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "transparent",
        border: "1px solid var(--border-soft)",
        borderRadius: 2,
        color: accent ? "var(--accent)" : "var(--text-muted)",
        fontSize: 11,
        cursor: "pointer",
        lineHeight: 1,
      }}
    >
      {label}
    </button>
  );
}
