import { useEffect, useState } from "react";

import { useAuth } from "./api/auth";
import { useInvestigations } from "./api/hooks";
import type { BoundInvestigation, ModulePageProps } from "./console/contract";
import { shortCaseId } from "./console/ids";
import IntakeWizard from "./console/IntakeWizard";
import LeftRail from "./console/LeftRail";
import Login from "./console/Login";
import { MODULES } from "./console/nav";
import { resolvePage } from "./console/pages/registry";
import SettingsOverlay from "./console/SettingsOverlay";
import ChatConsole from "./console/ChatConsole";
import { FaultyTerminal } from "./desktop/FaultyTerminal";

// Faithful port of the `AILA Console` design page. Two modes: basic (console
// tab -- general assistant, rail collapsed) and advanced (workspace tab -- full
// left rail + bound investigation). The right rail is display:none in the mock;
// module pages / x-ray open as an overlay in the center column. All data is live.

const pad = (n: number): string => (n < 10 ? "0" : "") + n;

// A module page raised inside the console's center column as an overlay window.
interface OpenPage {
  /** Registry key: "xray", "vulnerability:findings", "vr:targets", "admin:users", ... */
  kind: string;
  title: string;
  investigationId: string | null;
  section: string;
}

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
  const [intakeOpen, setIntakeOpen] = useState(false);
  const [openPage, setOpenPage] = useState<OpenPage | null>(null);
  const [pageMin, setPageMin] = useState(false);
  const [pageFull, setPageFull] = useState(false);
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
    { label: "docs", on: false, onClick: () => {} },
  ];

  // Open any registered page (left-rail page / admin item) as a window. An
  // optional entity id binds the window to a selected row (e.g. a forensics
  // project detail), reusing the ModulePageProps.investigationId channel.
  //
  // A `section` may carry an in-page sub-intent past a colon (e.g.
  // "systems:new", "scan:<run_id>"). The registry key is derived from the
  // base slug (part before the colon) so the same registered renderer serves
  // both the base view and its sub-intents; the full section string is
  // handed through to the page so it can react to the intent.
  const openNamedPage = (moduleKey: string, section: string, label: string, investigationId: string | null = null) => {
    const colon = section.indexOf(":");
    const baseSection = colon >= 0 ? section.slice(0, colon) : section;
    const key = `${moduleKey}:${baseSection}`;
    if (!resolvePage(key)) return;
    setOpenPage({ kind: key, title: `${moduleKey} \u00b7 ${label}`, investigationId, section });
    setPageMin(false);
    setPageFull(false);
  };

  // LeftRail's "+" is module-aware: for vulnerability it opens the Systems
  // registry with an auto-open create form, matching the SystemForm invoked
  // from the Systems tab's "+ register system" button (there is no duplicate
  // IntakeWizard variant for that module). Every other module keeps the
  // existing generic IntakeWizard.
  const requestIntake = () => {
    if (moduleId === "vulnerability") {
      openNamedPage("vulnerability", "systems:new", "register system");
    } else {
      setIntakeOpen(true);
    }
  };

  // Opening a rail row binds it and raises the module's detail window. For
  // vr/malware that's the X-Ray; for forensics the row is a project, so we
  // route through the shared ForensicsProjectPage via the page registry.
  const openInvestigation = (inv: BoundInvestigation) => {
    setBound(inv);
    if (moduleId === "vr") {
      setOpenPage({
        kind: "xray",
        title: `vr \u00b7 ${shortCaseId("vr", inv.id)} \u00b7 x-ray`,
        investigationId: inv.id,
        section: "overview",
      });
      setPageMin(false);
      setPageFull(false);
    } else if (moduleId === "malware") {
      setOpenPage({
        kind: "malware:xray",
        title: `malware \u00b7 ${shortCaseId("malware", inv.id)} \u00b7 x-ray`,
        investigationId: inv.id,
        section: "overview",
      });
      setPageMin(false);
      setPageFull(false);
    } else if (moduleId === "forensics") {
      openNamedPage("forensics", "project", inv.title, inv.id);
    }
  };

  const closePage = () => {
    setOpenPage(null);
    setPageMin(false);
    setPageFull(false);
  };

  // The opened page renders inside the center-column overlay (or full viewport
  // when fullscreen). Resolved from the page registry by its kind key.
  const renderPage = (p: OpenPage) => {
    const entry = resolvePage(p.kind);
    const shared: ModulePageProps = {
      section: p.section,
      investigationId: p.investigationId,
      onBack: closePage,
      onMinimize: () => setPageMin(true),
      onNavigate: (section: string) => setOpenPage({ ...p, section }),
      isFullscreen: pageFull,
      onToggleFullscreen: () => setPageFull((v) => !v),
      onOpenPage: (m: string, s: string, l: string, invId?: string | null) => openNamedPage(m, s, l, invId ?? null),
    };
    if (!entry) {
      return (
        <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
          page not available: {p.kind}
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
          <span style={{ width: 9, height: 9, background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />
          <span style={{ fontWeight: 700, letterSpacing: "0.2em" }}>AILA</span>
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
        <div style={{ flex: 1 }} />
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
          {intakeOpen ? (
            <IntakeWizard
              moduleId={moduleId}
              onClose={() => setIntakeOpen(false)}
              onBind={(inv) => {
                setIntakeOpen(false);
                openInvestigation(inv);
              }}
              onRequestUpload={() => {
                setIntakeOpen(false);
                openNamedPage(moduleId, "new-target", "upload target");
              }}
            />
          ) : null}
          {!(openPage && !pageMin) ? (
            <ChatConsole
              mode={mode}
              moduleId={moduleId}
              investigationId={bound?.id ?? null}
              investigationTitle={bound?.title ?? null}
              onToggleMode={() => setMode(adv ? "basic" : "advanced")}
              onOpenIntake={requestIntake}
              onOpenXray={bound ? () => openInvestigation(bound) : undefined}
              dockOpen={openPage !== null && pageMin}
            />
          ) : null}

          {/* Module page opens as a contained inner window inside the center
              column -- the menu bar, left rail, and FaultyTerminal backdrop
              stay visible around it (the mock's embedded look). The page's own
              root is position:absolute;inset:0 with a transparent background, so
              the animated terminal shows through its panels. No top nav. */}
          {openPage && !pageMin ? (
            pageFull ? (
              <div style={{ position: "fixed", inset: 0, zIndex: 45, background: "var(--surface-page)" }}>{renderPage(openPage)}</div>
            ) : (
              renderPage(openPage)
            )
          ) : null}
          {openPage && pageMin ? (
            <div
              style={{
                position: "fixed",
                left: 0,
                right: 0,
                bottom: 0,
                zIndex: 31,
                display: "flex",
                alignItems: "center",
                gap: 9,
                padding: "9px 14px",
                background: "var(--surface-chrome)",
                borderTop: "1px solid var(--border)",
                boxShadow: "0 -8px 30px rgba(0,0,0,0.5)",
              }}
            >
              <span style={{ width: 7, height: 7, background: "var(--accent)", boxShadow: "0 0 7px var(--accent)", flex: "0 0 auto" }} />
              <span
                style={{
                  fontSize: 10,
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                  color: "var(--text-primary)",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {openPage.title}
              </span>
              <span style={{ fontSize: 9, color: "var(--text-faint)", letterSpacing: "0.06em", flex: "0 0 auto" }}>
                minimized
              </span>
              <span style={{ flex: 1 }} />
              <button
                type="button"
                onClick={() => setPageMin(false)}
                style={{
                  background: "transparent",
                  border: "1px solid var(--border-soft)",
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                  fontSize: 9,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  padding: "2px 8px",
                  borderRadius: 2,
                  cursor: "pointer",
                }}
              >
                restore
              </button>
              <button
                type="button"
                onClick={closePage}
                style={{
                  background: "transparent",
                  border: 0,
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                  cursor: "pointer",
                  padding: "0 4px",
                }}
              >
                {"\u2715"}
              </button>
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

