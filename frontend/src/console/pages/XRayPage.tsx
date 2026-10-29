import { useMemo, useState, type JSX } from "react";

import {
  useBranches,
  useDispatch,
  useGenerateNarrative,
  useHypotheses,
  useInvestigation,
  useInvestigationControl,
  useLedger,
  useMcpCalls,
  useMessages,
  usePostMessage,
  useToggleFavorite,
} from "../../api/hooks";
import type { Branch, DispatchState, Hypothesis, LedgerRow, McpCall, Message } from "../../api/types";
import type { EntityBindingProps, SectionRouteProps, WindowChromeProps } from "../contract";
import { css } from "../css";
import { shortCaseId } from "../ids";
import { ConsoleWindow } from "../window";
import { StatusStrip } from "./xray/chrome";
import { nodeStateOf } from "./xray/dispatch";
import { parseView } from "./xray/layout";
import { CommandPalette, KeymapHelp, shellCommands, type PalCmd } from "./xray/Overlays";
import { groupTurns, newestFirst } from "./xray/parsers";
import { VR_PERSONA_RULES, personaOf, type Persona } from "./xray/persona";
import { emptyNote } from "./xray/theme";
import { useXRayShell } from "./xray/useXRayShell";
import { VR_LAYOUT_PANES } from "./xray/vr/constants";
import { deriveToolCalls, findCrashMessage, findPocMessage } from "./xray/vr/derive";
import { FindingView } from "./xray/vr/FindingView";
import { GraphsView } from "./xray/vr/GraphsView";
import type { DetailItem } from "./xray/vr/OraclePanel";
import { OracleView } from "./xray/vr/OracleView";
import { OverviewView } from "./xray/vr/OverviewView";
import { RecordsView } from "./xray/vr/RecordsView";
import { SteeringBar } from "./xray/vr/SteeringBar";

/*
 * XRayPage -- faithful port of "VR Investigation - X-Ray.dc.html". A five-layout
 * multi-panel analysis workspace over one VR investigation, switched by the
 * status-bar buttons or number keys 1-5:
 *   1 OVERVIEW -> the multi-agent TURNS stream
 *   2 RECORDS  -> LEDGER + LEDGER ENTRY + HYPOTHESES + HYPOTHESIS
 *   3 GRAPHS   -> DISPATCH HUB node graph + branch lanes
 *   4 ORACLE   -> ORACLE requests + DISPATCH HUB gate + MCP CALLS + DETAIL
 *   5 FINDING  -> FINDING + REACHABILITY + PROOF OF CONCEPT + CRASH
 * Every data-backed panel reads the live /vr investigation, branches,
 * hypotheses and messages API; panels with no backing render honest empty
 * states -- no fabricated verdicts. Layout bodies live in ./xray/vr/.
 */
export default function XRayPage(props: WindowChromeProps & SectionRouteProps & EntityBindingProps): JSX.Element {
  const { section, investigationId, windowId, title, isFocused, onFocus, onBack, onMinimize, onNavigate, isFullscreen, onToggleFullscreen } = props;
  const view = parseView(section);
  const invId = investigationId ?? null;

  const inv = useInvestigation(invId);
  const branches = useBranches(invId);
  const hyps = useHypotheses(invId);
  const msgs = useMessages(invId);
  const post = usePostMessage(invId);
  const dispatch = useDispatch(invId);
  const ledgerRows = useLedger(invId);
  const mcpCallLog = useMcpCalls(invId);
  const control = useInvestigationControl(invId);
  const favorite = useToggleFavorite(invId);
  const narrative = useGenerateNarrative(invId);

  const [openDrawer, setOpenDrawer] = useState<string | null>(null);
  const [openTurn, setOpenTurn] = useState<string | null>(null);
  const [ledgerSel, setLedgerSel] = useState<LedgerRow | null>(null);
  const [showAudit, setShowAudit] = useState(false);
  const [hypSel, setHypSel] = useState<Hypothesis | null>(null);
  const [detail, setDetail] = useState<DetailItem | null>(null);

  const invStatus = (inv.data?.status ?? "").toLowerCase();
  const shell = useXRayShell({ view, panes: VR_LAYOUT_PANES, status: invStatus, control, onNavigate });

  const branchList: Branch[] = branches.data ?? [];
  const branchMap = useMemo(() => {
    const map = new Map<string, Branch>();
    for (const b of branchList) map.set(b.id, b);
    return map;
  }, [branchList]);
  const resolvePersona = (m: Message): Persona => personaOf(m, branchMap, VR_PERSONA_RULES);

  const allMsgs: Message[] = msgs.data ?? [];
  const turnGroups: Message[][] = useMemo(() => groupTurns(allMsgs), [allMsgs]);
  const recentMsgs: Message[] = useMemo(() => newestFirst(allMsgs), [allMsgs]);
  const mcpCalls = useMemo(
    () => deriveToolCalls(allMsgs, (m) => personaOf(m, branchMap, VR_PERSONA_RULES)),
    [allMsgs, branchMap],
  );
  const taintMsgs = useMemo(() => allMsgs.filter((m) => m.payload_kind === "taint_flow"), [allMsgs]);
  const pocMsg = useMemo(() => findPocMessage(allMsgs), [allMsgs]);
  const crashMsg = useMemo(() => findCrashMessage(allMsgs), [allMsgs]);

  const hypList: Hypothesis[] = hyps.data ?? [];
  const topHyp = hypList.find((h) => (h.state ?? "").toLowerCase() === "live") ?? hypList[0];
  const liveHyps = hypList.filter((h) => (h.state ?? "").toLowerCase() === "live").length;
  // The engine's draft outcome (answer + confidence + reasoning) drives the
  // finding view; the investigation row carries the ratified verdict head.
  const outcomeMsg = useMemo(() => allMsgs.find((m) => m.payload_kind === "outcome_pending"), [allMsgs]);

  const dispatchState: DispatchState | undefined = dispatch.data;
  const visitedSet = useMemo(() => new Set(dispatchState?.visited ?? []), [dispatchState]);
  const currentSet = useMemo(() => new Set(dispatchState?.current ?? []), [dispatchState]);
  const invRunning = !["completed", "failed", "cancelled"].includes(invStatus);
  const nodeState = (id: string) => nodeStateOf(id, { invRunning, visited: visitedSet, current: currentSet, branchCount: branchList.length });

  // Real append-only investigation ledger; oracle requests are its kind=request
  // rows. MCP call log (with latency) falls back to the tool-call-derived view
  // until the per-investigation endpoint is live.
  const ledgerData: LedgerRow[] = ledgerRows.data ?? [];
  const requestRows = useMemo(() => ledgerData.filter((r) => r.kind === "request"), [ledgerData]);
  const decisionRows = useMemo(() => ledgerData.filter((r) => r.kind === "decision"), [ledgerData]);
  // kind=recovery rows are the platform's operator/audit trail (every stale-
  // cursor GC, re-enqueue and crash-heal the resilience layer journals). They
  // are not investigation narrative -- a single reconcile sweep can append
  // hundreds -- so they are split out of the main ledger list and hidden
  // behind a toggle, leaving the discovery / decision / objective narrative
  // legible. See ResilienceLayer.emit_recovery_event.
  const narrativeLedger = useMemo(() => ledgerData.filter((r) => r.kind !== "recovery"), [ledgerData]);
  const auditLedger = useMemo(() => ledgerData.filter((r) => r.kind === "recovery"), [ledgerData]);
  const visibleLedger = showAudit ? ledgerData : narrativeLedger;
  const mcpData: McpCall[] = mcpCallLog.data ?? [];

  const caseId = invId ? shortCaseId("vr", invId) : "--";
  const target = inv.data?.title ?? "investigation";
  const promoted = branchList.filter((b) => b.promoted).length;
  const turnCount = inv.data?.message_count ?? allMsgs.length;
  const isPaused = invStatus === "paused";

  const doExport = (): void => {
    if (!invId) return;
    const blob = new Blob(
      [JSON.stringify({ investigation: inv.data, messages: allMsgs, ledger: ledgerData, dispatch: dispatchState }, null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const doReset = (): void => {
    if (!invId) return;
    if (window.confirm("Hard-reset this investigation? This permanently deletes all messages, outcomes, and non-root branches. No undo.")) {
      control.mutate("reset");
    }
  };
  const doReenqueue = (): void => {
    if (!invId) return;
    if (window.confirm("Re-enqueue this investigation? Clears all prior cursors, cancels queued/running tasks, and dispatches a fresh run from CREATED. No checkpoint is resumed. No undo.")) {
      control.mutate("re-enqueue");
    }
  };

  /* -------------------------------- layouts ------------------------------ */

  const { pv } = shell;
  const loading = inv.isLoading || msgs.isLoading;
  let body: JSX.Element;

  if (!invId) {
    body = <div style={css("flex:1;display:flex;align-items:center;justify-content:center;")}><span style={emptyNote}>no investigation bound — open one from the console.</span></div>;
  } else if (loading) {
    body = <div style={css("flex:1;display:flex;align-items:center;justify-content:center;")}><span style={emptyNote}>loading investigation&#8230;</span></div>;
  } else if (view === "overview") {
    body = (
      <OverviewView
        turns={{
          pane: pv("transcript"),
          inv: inv.data,
          invId,
          caseId,
          target,
          control,
          onNarrative: () => narrative.mutate(),
          narrativePending: narrative.isPending,
          onFavorite: () => favorite.mutate(),
          invRunning,
          isPaused,
          messageCount: allMsgs.length,
          onExport: doExport,
          onReset: doReset,
          onReenqueue: doReenqueue,
          turnGroups,
          openTurn,
          setOpenTurn,
          resolvePersona,
          branchCount: branchList.length,
          hypCount: hypList.length,
        }}
        shell={shell}
        openDrawer={openDrawer}
        setOpenDrawer={setOpenDrawer}
        inv={inv.data}
        caseId={caseId}
        target={target}
        hypList={hypList}
        liveHyps={liveHyps}
        branchList={branchList}
        turnCount={turnCount}
        promoted={promoted}
        recentMsgs={recentMsgs}
        resolvePersona={resolvePersona}
        onOpenHypothesis={(h) => { setHypSel(h); onNavigate("records"); }}
      />
    );
  } else if (view === "records") {
    body = (
      <RecordsView
        pv={pv}
        branchMap={branchMap}
        narrativeLedger={narrativeLedger}
        auditLedger={auditLedger}
        visibleLedger={visibleLedger}
        showAudit={showAudit}
        setShowAudit={setShowAudit}
        ledgerSel={ledgerSel}
        setLedgerSel={setLedgerSel}
        hypList={hypList}
        liveHyps={liveHyps}
        hypSel={hypSel}
        setHypSel={setHypSel}
      />
    );
  } else if (view === "graphs") {
    body = <GraphsView pv={pv} invId={invId} nodeState={nodeState} branchList={branchList} />;
  } else if (view === "oracle") {
    body = (
      <OracleView
        pv={pv}
        invId={invId}
        requestRows={requestRows}
        decisionRows={decisionRows}
        branchMap={branchMap}
        dispatchState={dispatchState}
        nodeState={nodeState}
        mcpData={mcpData}
        toolCalls={mcpCalls}
        detail={detail}
        setDetail={setDetail}
      />
    );
  } else {
    body = <FindingView pv={pv} invId={invId} inv={inv.data} branchList={branchList} caseId={caseId} outcomeMsg={outcomeMsg} topHyp={topHyp} taintMsgs={taintMsgs} pocMsg={pocMsg} crashMsg={crashMsg} />;
  }

  // Command palette (/ or Ctrl-K): layouts, pane focus, zoom/keymap, and the
  // same investigation controls as the turns toolbar.
  const palCommands: PalCmd[] = shellCommands(view, VR_LAYOUT_PANES, shell, onNavigate);
  const palHasOutcome = (inv.data?.outcome_count ?? 0) > 0;
  palCommands.push({ group: "run", label: isPaused ? "resume investigation" : "pause investigation", hint: "p", run: () => control.mutate(isPaused ? "resume" : "pause") });
  if (palHasOutcome) {
    palCommands.push({ group: "run", label: "generate narrative", run: () => narrative.mutate() });
    palCommands.push({ group: "run", label: "re-verify outcome", run: () => control.mutate("verify") });
  }
  palCommands.push({ group: "run", label: "export report (json)", run: doExport });
  palCommands.push({ group: "run", label: inv.data?.is_favorite ? "unfavorite" : "favorite", run: () => favorite.mutate() });
  palCommands.push({ group: "run", label: "reset investigation", run: doReset });
  palCommands.push({ group: "run", label: "re-enqueue investigation", run: doReenqueue });

  /* -------------------------------- render ------------------------------- */

  const statusStrip = (
    <StatusStrip status={inv.data?.status} view={view} onNavigate={onNavigate} shell={shell}>
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none", letterSpacing: "0.04em" }}>1-5 layout &#183; hjkl focus &#183; f zoom &#183; / find &#183; p pause &#183; ? keys</span>
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", borderLeft: "1px solid var(--border-soft)", textTransform: "none" }}>{branchList.length} live loops</span>
    </StatusStrip>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
        {body}
        <SteeringBar invId={invId} post={post} />
      </main>
      {shell.palette ? <CommandPalette commands={palCommands} shell={shell} /> : null}
      {shell.help ? <KeymapHelp onClose={() => shell.setHelp(false)} /> : null}
    </ConsoleWindow>
  );
}
