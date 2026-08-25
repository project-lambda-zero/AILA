import { useEffect, useRef, useState } from "react";

import { useAuth } from "./api/auth";
import { useInvestigations } from "./api/hooks";
import type { BoundInvestigation, ModulePageProps } from "./console/contract";
import type { WindowKind, WindowState } from "./console/window";
import { shortCaseId } from "./console/ids";
import IntakeWizard from "./console/IntakeWizard";
import LeftRail from "./console/LeftRail";
import Login from "./console/Login";
import { MODULES } from "./console/nav";
import NotificationsCenter from "./console/NotificationsCenter";
import { resolvePage } from "./console/pages/registry";
import SettingsOverlay from "./console/SettingsOverlay";
import ChatConsole from "./console/ChatConsole";
import WidgetHost from "./console/widgets/WidgetHost";
import { ConsoleWindow } from "./console/window";
import { resolveWizard } from "./console/wizards";
import { FaultyTerminal } from "./desktop/FaultyTerminal";

// Faithful port of the `AILA Console` design page. Two modes: basic (console
// tab -- general assistant, rail collapsed) and advanced (workspace tab -- full
// left rail + bound investigation). The right rail is display:none in the mock;
// module pages / x-ray open as an overlay in the center column. All data is live.

const pad = (n: number): string => (n < 10 ? "0" : "") + n;

export default function App() {
  const status = useAuth((s) => s.status);
  if (status !== "authed") {
    return <Login />;
  }
  return <Console />;
}

function Console() {
  const user = useAuth((s) => s.user);

  const [mode, setMode] = useState<"basic" | "advanced">("advanced");
  const [moduleId, setModuleId] = useState("vr");
  const [bound, setBound] = useState<BoundInvestigation | null>(null);
  const [pagesOpen, setPagesOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  // Multi-window host: an ordered back-to-front stack plus the focused id.
  // `page`/`overlay` surfaces form the center-column drill stack (only the top
  // non-minimized one renders); `floater` surfaces (added by later reqs) render
  // concurrently. Closing a window falls back to the previously focused one.
  const [windows, setWindows] = useState<WindowState[]>([]);
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const winSeq = useRef(0);
  const [clock, setClock] = useState("");

  // Open on the case that best fills the design: the most branches, which give
  // a rich x-ray (multiple persona lanes, ledger, hypotheses, hundreds of MCP
  // calls). Tie-break by the fewest turns so the console still opens at a
  // readable length. The thread opens at the top (greeting first), so a longer
  // case still reads cleanly from its start. Fall back to the richest by
  // messages when nothing is branched.
  const { data: invList } = useInvestigations();
  useEffect(() => {
    if (bound || !invList || invList.length === 0) return;
    let pick = invList[0];
    let best: { branches: number; msgs: number } | null = null;
    for (const inv of invList) {
      const branches = inv.branch_count ?? 0;
      const msgs = inv.message_count ?? 0;
      if (msgs < 4) continue;
      if (!best || branches > best.branches || (branches === best.branches && msgs < best.msgs)) {
        best = { branches, msgs };
        pick = inv;
      }
    }
    setBound({ id: pick.id, title: pick.title });
  }, [invList, bound]);

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setClock(`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const adv = mode === "advanced";
  const modDef = MODULES.find((m) => m.id === moduleId) ?? MODULES[0];
  const boundLabel = bound ? shortCaseId(moduleId, bound.id) : modDef.id;
  const engineLabel = adv ? `${boundLabel} \u00b7 ${moduleId}` : "idle \u00b7 ready";

  const nav: { label: string; on: boolean; onClick: () => void }[] = [
    { label: "console", on: !adv, onClick: () => setMode("basic") },
    { label: "workspace", on: adv, onClick: () => setMode("advanced") },
    { label: "docs", on: windows.some((w) => w.id === focusedId && w.registryKey === "platform:docs" && !w.minimized), onClick: () => openNamedPage("platform", "docs", "docs") },
  ];

  // Open any registered page (left-rail page / admin item) as a window. An
  // optional entity id binds the window to a selected row (e.g. a forensics
  // project detail), reusing the ModulePageProps.investigationId channel.
  //
  // A `section` may carry an in-page sub-intent past a colon (e.g.
  // "scan:<run_id>", "reports:<run_id>"). The registry key is derived from the
  // base slug (part before the colon) so the same registered renderer serves
  // both the base view and its sub-intents; the full section string is
  // handed through to the page so it can react to the intent.
  // Raise a page window, pushing whatever page is currently open onto the
  // history trail first (only when the target is a genuinely different page,
  // so an in-place section change never self-stacks). "back" walks this trail.
  const focused = windows.find((w) => w.id === focusedId) ?? null;

  // Raise a window to the top of the z-stack and give it keyboard focus.
  const focusWindow = (id: string) => {
    setWindows((cur) => {
      const w = cur.find((x) => x.id === id);
      return w ? [...cur.filter((x) => x.id !== id), w] : cur;
    });
    setFocusedId(id);
  };

  // Open a registered surface as a window. Re-opening the focused page surface
  // (same registry key + entity) updates it in place instead of stacking a
  // duplicate; anything else pushes a new window and focuses it.
  const openWindow = (spec: { kind: WindowKind; module: string; registryKey: string; title: string; section: string | null; investigationId: string | null }) => {
    if (
      focused &&
      (focused.kind === "page" || focused.kind === "overlay") &&
      !focused.minimized &&
      focused.registryKey === spec.registryKey &&
      (focused.investigationId ?? null) === spec.investigationId
    ) {
      setWindows(windows.map((w) => (w.id === focused.id ? { ...w, title: spec.title, section: spec.section } : w)));
      return;
    }
    const id = `w${(winSeq.current += 1)}`;
    setWindows([...windows, { id, minimized: false, fullscreen: false, ...spec }]);
    setFocusedId(id);
  };

  const openNamedPage = (moduleKey: string, section: string, label: string, investigationId: string | null = null) => {
    const colon = section.indexOf(":");
    const baseSection = colon >= 0 ? section.slice(0, colon) : section;
    const key = `${moduleKey}:${baseSection}`;
    if (!resolvePage(key)) return;
    openWindow({ kind: "page", module: moduleKey, registryKey: key, title: `${moduleKey} \u00b7 ${label}`, section, investigationId });
  };

  // Intake wizards live in the same windows[] stack as every other page, as
  // `overlay` windows keyed on "wizard:intake". Reusing WindowState means the
  // intake participates in the dock, z-order, and fullscreen chrome instead
  // of floating as a bespoke overlay outside the host.
  const openIntakeWindow = (module: string, targetId: string | null): void => {
    openWindow({
      kind: "overlay",
      module,
      registryKey: "wizard:intake",
      title: `${module} \u00b7 new investigation`,
      section: null,
      investigationId: targetId,
    });
  };

  // Registry-driven wizard opener. Intake wizards hit `openIntakeWindow`; page
  // wizards route through `openNamedPage`. Chat's picker + dante's open_wizard
  // action both funnel through here so the console never offers a wizard the
  // registry doesn't back with a real surface.
  const openWizard = (wizardId: string, opts?: { targetId?: string }): void => {
    const w = resolveWizard(wizardId);
    if (!w) return;
    if (w.open.kind === "intake") {
      openIntakeWindow(w.module, opts?.targetId ?? null);
      return;
    }
    openNamedPage(w.open.moduleKey, w.open.section, w.label, null);
  };

  // LeftRail's "+" is module-aware: for vulnerability it raises the
  // platform-owned admin systems registry (there is no duplicate
  // IntakeWizard variant for that module). Every other module opens its
  // IntakeWizard as an overlay window.
  const requestIntake = (opts?: { moduleId?: string; targetId?: string }): void => {
    const effectiveModule = opts?.moduleId ?? moduleId;
    const targetId = opts?.targetId ?? null;
    if (effectiveModule === "vulnerability") {
      // Systems registry is platform-owned (system-registry-platform.md
      // req 11): the vulnerability module's "+" jumps to the admin systems
      // page, where "+ register system" inside opens the create form.
      openNamedPage("admin", "systems", "admin \u00b7 systems");
      return;
    }
    openIntakeWindow(effectiveModule, targetId);
  };

  // Opening a rail row binds it and raises the module's detail window. For
  // vr/malware that's the X-Ray; for forensics the row is a project, so we
  // route through the shared ForensicsProjectPage via the page registry.
  const openInvestigation = (inv: BoundInvestigation) => {
    setBound(inv);
    if (moduleId === "vr") {
      openWindow({ kind: "page", module: "vr", registryKey: "xray", title: `vr \u00b7 ${shortCaseId("vr", inv.id)} \u00b7 x-ray`, section: "overview", investigationId: inv.id });
    } else if (moduleId === "malware") {
      openWindow({ kind: "page", module: "malware", registryKey: "malware:xray", title: `malware \u00b7 ${shortCaseId("malware", inv.id)} \u00b7 x-ray`, section: "overview", investigationId: inv.id });
    } else if (moduleId === "forensics") {
      openNamedPage("forensics", "project", inv.title, inv.id);
    }
  };

  const closeWindow = (id: string) => {
    const remaining = windows.filter((w) => w.id !== id);
    setWindows(remaining);
    if (focusedId === id) {
      const next = [...remaining].reverse().find((w) => !w.minimized) ?? null;
      setFocusedId(next ? next.id : null);
    }
  };

  const setMinimized = (id: string, minimized: boolean) => {
    setWindows(windows.map((w) => (w.id === id ? { ...w, minimized } : w)));
    if (minimized) {
      if (focusedId === id) {
        const next = [...windows].reverse().find((w) => w.id !== id && !w.minimized) ?? null;
        setFocusedId(next ? next.id : null);
      }
    } else {
      setFocusedId(id);
    }
  };

  const toggleFullscreen = (id: string) => setWindows(windows.map((w) => (w.id === id ? { ...w, fullscreen: !w.fullscreen } : w)));
  const updateSection = (id: string, section: string) => setWindows(windows.map((w) => (w.id === id ? { ...w, section } : w)));

  // The focused non-minimized page/overlay renders in the center column; the
  // page's own ConsoleWindow owns the chrome + fullscreen. Minimized windows
  // collapse to the dock strip. Floater surfaces (later reqs) render
  // concurrently on top -- their render branch lands with their consumer.
  const pageWindows = windows.filter((w) => w.kind === "page" || w.kind === "overlay");
  const activePage = [...pageWindows].reverse().find((w) => !w.minimized) ?? null;
  const minimizedWindows = windows.filter((w) => w.minimized);

  // A drill window (or full viewport when fullscreen). Intake-wizard windows
  // are hosted inline (wrapped in <ConsoleWindow> so they share the dock /
  // z-order / fullscreen chrome); every other key resolves through the page
  // registry, where the page returns its own <ConsoleWindow>.
  const renderPage = (w: WindowState) => {
    if (w.registryKey === "wizard:intake") {
      return (
        <ConsoleWindow
          id={w.id}
          title={w.title}
          kind="overlay"
          isFocused={focusedId === w.id}
          isFullscreen={w.fullscreen}
          isMinimized={w.minimized}
          onFocus={() => focusWindow(w.id)}
          onClose={() => closeWindow(w.id)}
          onMinimize={() => setMinimized(w.id, true)}
          onToggleFullscreen={() => toggleFullscreen(w.id)}
        >
          <IntakeWizard
            moduleId={w.module}
            prefill={{ targetId: w.investigationId ?? undefined }}
            onClose={() => closeWindow(w.id)}
            onBind={(inv) => {
              closeWindow(w.id);
              openInvestigation(inv);
            }}
            onRequestUpload={() => {
              closeWindow(w.id);
              openNamedPage(w.module, "new-target", "upload target");
            }}
          />
        </ConsoleWindow>
      );
    }
    const entry = resolvePage(w.registryKey);
    const shared: ModulePageProps = {
      section: w.section,
      investigationId: w.investigationId,
      windowId: w.id,
      title: w.title,
      isFocused: focusedId === w.id,
      onFocus: () => focusWindow(w.id),
      onBack: () => closeWindow(w.id),
      onMinimize: () => setMinimized(w.id, true),
      onNavigate: (section: string) => updateSection(w.id, section),
      isFullscreen: w.fullscreen,
      onToggleFullscreen: () => toggleFullscreen(w.id),
      onOpenPage: (m: string, s: string, l: string, invId?: string | null) => openNamedPage(m, s, l, invId ?? null),
    };
    if (!entry) {
      return (
        <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
          page not available: {w.registryKey}
        </div>
      );
    }
    return entry.render(shared);
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        display: "flex",
        flexDirection: "column",
        background: "var(--surface-page)",
        fontFamily: "var(--font-mono)",
        color: "var(--text-primary)",
      }}
    >
      <FaultyTerminal opts={{ brightness: 0.55, scanlineIntensity: 0.5, glitchAmount: 1 }} />
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: 0,
          pointerEvents: "none",
          zIndex: 15,
          background: "repeating-linear-gradient(0deg,rgba(0,0,0,0.16) 0 1px,transparent 1px 3px)",
          opacity: 0.4,
        }}
      />
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "50%",
          top: "-12%",
          width: "78%",
          height: "60%",
          transform: "translateX(-50%)",
          pointerEvents: "none",
          zIndex: 0,
          background:
            "radial-gradient(ellipse at center,color-mix(in srgb,var(--accent) 12%,transparent),transparent 68%)",
        }}
      />

      {/* menu bar */}
      <header
        style={{
          flex: "0 0 var(--menubar-h,32px)",
          height: "var(--menubar-h,32px)",
          display: "flex",
          alignItems: "stretch",
          background: "var(--surface-chrome)",
          borderBottom: "2px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          position: "relative",
          zIndex: 20,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "0 12px", borderRight: "1px solid var(--border-soft)" }}>
          <img src="/aila-monogram.svg" alt="" style={{ height: 16, width: "auto", display: "block" }} />
          <span style={{ fontFamily: "var(--font-display)", letterSpacing: "0.2em" }}>AILA</span>
        </div>
        <nav style={{ display: "flex", alignItems: "stretch" }}>
          {nav.map((n) => (
            <button
              key={n.label}
              type="button"
              onClick={n.onClick}
              style={{
                padding: "0 12px",
                background: n.on ? "var(--accent)" : "transparent",
                color: n.on ? "var(--text-on-accent)" : "var(--text-muted)",
                border: 0,
                borderRight: "1px solid var(--border-soft)",
                fontFamily: "var(--font-mono)",
                fontSize: 10.5,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                cursor: "pointer",
                fontWeight: n.on ? 700 : 400,
              }}
            >
              {n.label}
            </button>
          ))}
        </nav>
        {activePage ? (
          <button
            type="button"
            onClick={() => closeWindow(activePage.id)}
            title="close this window"
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "0 14px",
              background: "transparent",
              color: "var(--accent)",
              border: 0,
              borderRight: "1px solid var(--border-soft)",
              fontFamily: "var(--font-mono)",
              fontSize: 10.5,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              cursor: "pointer",
              fontWeight: 700,
            }}
          >
            {"\u2039 back"}
          </button>
        ) : null}
        <div style={{ flex: 1 }} />
        <NotificationsCenter />
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            padding: "0 12px",
            borderLeft: "1px solid var(--border-soft)",
            color: "var(--text-muted)",
            textTransform: "none",
            letterSpacing: "0.05em",
            maxWidth: 320,
            overflow: "hidden",
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              background: adv ? "var(--status-ok)" : "var(--text-muted)",
              boxShadow: adv ? "0 0 7px var(--status-ok)" : "none",
            }}
          />
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{engineLabel}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", padding: "0 12px", borderLeft: "1px solid var(--border-soft)", color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.06em" }}>
          {clock}
        </div>
      </header>

      {/* body */}
      <main style={{ flex: 1, minHeight: 0, display: "flex", position: "relative" }}>
        <aside
          style={{
            flex: `0 0 ${adv ? "216px" : "0px"}`,
            width: adv ? 216 : 0,
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
            borderRight: adv ? "1px solid var(--border-soft)" : "1px solid transparent",
            background: "color-mix(in srgb, var(--surface-card) 72%, transparent)",
            transition: "flex-basis 260ms cubic-bezier(0.22,1,0.36,1),width 260ms cubic-bezier(0.22,1,0.36,1)",
          }}
        >
          {adv ? (
            <LeftRail
              moduleId={moduleId}
              onSelectModule={setModuleId}
              bound={bound}
              onBind={openInvestigation}
              pagesOpen={pagesOpen}
              onTogglePages={() => setPagesOpen((v) => !v)}
              adminOpen={adminOpen}
              onToggleAdmin={() => setAdminOpen((v) => !v)}
              onOpenIntake={requestIntake}
              onOpenSettings={() => setSettingsOpen(true)}
              onOpenPage={openNamedPage}
            />
          ) : null}
        </aside>

        <section style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", alignItems: "center", position: "relative" }}>
          {settingsOpen ? (
            <SettingsOverlay
              user={user}
              onClose={() => setSettingsOpen(false)}
              onOpenPage={(mod, page, title) => openNamedPage(mod, page, title ?? page)}
            />
          ) : null}
          {!activePage ? (
            <ChatConsole
              mode={mode}
              moduleId={moduleId}
              investigationId={bound?.id ?? null}
              investigationTitle={bound?.title ?? null}
              onToggleMode={() => setMode(adv ? "basic" : "advanced")}
              onOpenIntake={requestIntake}
              onOpenWizard={openWizard}
              onOpenXray={bound ? () => openInvestigation(bound) : undefined}
              dockOpen={minimizedWindows.length > 0}
            />
          ) : null}
          {!activePage ? (
            <WidgetHost
              moduleId={moduleId}
              boundId={bound?.id ?? null}
              adv={adv}
              onOpenPage={openNamedPage}
            />
          ) : null}

          {/* Module page opens as a contained inner window inside the center
              column -- the menu bar, left rail, and FaultyTerminal backdrop
              stay visible around it (the mock's embedded look). The page's own
              root is position:absolute;inset:0 with a transparent background, so
              the animated terminal shows through its panels. No top nav. */}
          {activePage ? renderPage(activePage) : null}
          {minimizedWindows.length > 0 ? (
            <div
              style={{
                position: "fixed",
                left: 0,
                right: 0,
                bottom: 0,
                zIndex: 31,
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "9px 14px",
                background: "var(--surface-chrome)",
                borderTop: "1px solid var(--border)",
                boxShadow: "0 -8px 30px rgba(0,0,0,0.5)",
                overflowX: "auto",
              }}
            >
              <span style={{ fontSize: 9, color: "var(--text-faint)", letterSpacing: "0.1em", textTransform: "uppercase", flex: "0 0 auto" }}>
                minimized
              </span>
              {minimizedWindows.map((w) => (
                <div
                  key={w.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 7,
                    padding: "3px 6px 3px 9px",
                    background: "var(--surface-card)",
                    border: "1px solid var(--border-soft)",
                    borderRadius: 2,
                    flex: "0 0 auto",
                  }}
                >
                  <span style={{ width: 7, height: 7, background: "var(--accent)", boxShadow: "0 0 7px var(--accent)", flex: "0 0 auto" }} />
                  <button
                    type="button"
                    onClick={() => setMinimized(w.id, false)}
                    title="restore"
                    style={{
                      background: "transparent",
                      border: 0,
                      color: "var(--text-primary)",
                      fontFamily: "var(--font-mono)",
                      fontSize: 10,
                      letterSpacing: "0.08em",
                      textTransform: "uppercase",
                      cursor: "pointer",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      maxWidth: 240,
                    }}
                  >
                    {w.title}
                  </button>
                  <button
                    type="button"
                    onClick={() => closeWindow(w.id)}
                    title="close"
                    style={{
                      background: "transparent",
                      border: 0,
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                      fontSize: 11,
                      cursor: "pointer",
                      padding: "0 3px",
                      flex: "0 0 auto",
                    }}
                  >
                    {"\u2715"}
                  </button>
                </div>
              ))}
            </div>
          ) : null}
        </section>

        <aside style={{ display: "none" }} />
      </main>

      {/* status bar */}
      <footer
        style={{
          flex: "0 0 var(--statusbar-h,24px)",
          height: "var(--statusbar-h,24px)",
          display: "flex",
          alignItems: "center",
          background: "var(--surface-chrome)",
          borderTop: "2px solid var(--border)",
          fontSize: 9.5,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--text-faint)",
          position: "relative",
          zIndex: 20,
        }}
      >
        <span
          style={{
            display: "flex",
            alignItems: "center",
            padding: "0 11px",
            height: "100%",
            background: adv ? "var(--accent)" : "var(--status-info)",
            color: "var(--text-on-accent)",
            fontWeight: 700,
            letterSpacing: "0.14em",
          }}
        >
          {adv ? "advanced" : "basic"}
        </span>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "0 11px", borderLeft: "1px solid var(--border-soft)", textTransform: "none", letterSpacing: "0.06em" }}>
          <span>aila.sh</span>
        </div>
      </footer>
    </div>
  );
}

