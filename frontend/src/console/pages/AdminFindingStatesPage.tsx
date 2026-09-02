/**
 * Admin read-only overview of the finding-workflow state machine.
 *
 * The backend platform owns the base states (new / investigating / mitigated /
 * verified / closed) and each production module contributes module-prefixed
 * extensions (vr.* / malware.* / forensics.*). This page fetches the merged
 * view -- GET /findings/workflow/states with no module filter -- so an admin
 * can inspect every registered state and its legal outbound edges in one
 * place. Editing is intentionally NOT surfaced here; state transitions happen
 * per-finding on the module's findings view, gated by role and the module-
 * scoped transition graph.
 */
import type { JSX } from "react";

import { useFindingWorkflowStates } from "../../api/findingWorkflow";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { WorkflowStateBadge } from "./badges";

function moduleOfState(state: string): string {
  const dot = state.indexOf(".");
  return dot > 0 ? state.slice(0, dot) : "base";
}

const MODULE_ORDER: readonly string[] = ["base", "vr", "malware", "forensics"];

function AdminFindingStatesPage(props: ModulePageProps): JSX.Element {
  const machineQ = useFindingWorkflowStates(null);
  const def = machineQ.data;

  const grouped: Record<string, string[]> = {};
  for (const s of def?.states ?? []) {
    const m = moduleOfState(s);
    (grouped[m] ??= []).push(s);
  }
  const moduleKeys = Object.keys(grouped).sort((a, b) => {
    const ai = MODULE_ORDER.indexOf(a);
    const bi = MODULE_ORDER.indexOf(b);
    if (ai !== bi) return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
    return a.localeCompare(b);
  });

  return (
    <ConsoleWindow
      id={props.windowId}
      kind="page"
      title={props.title}
      isFocused={props.isFocused ?? true}
      onFocus={props.onFocus}
      onClose={props.onBack}
      onMinimize={props.onMinimize}
      isFullscreen={props.isFullscreen}
      onToggleFullscreen={props.onToggleFullscreen}
    >
      <div style={css("position:absolute;inset:0;overflow:auto;padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>
        <div>
          <div style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>
            {"finding workflow \u00b7 read-only overview"}
          </div>
        </div>

        {machineQ.isLoading ? (
          <div style={css("padding:24px;text-align:center;font-size:11px;color:var(--text-faint);")}>loading state machine {"\u2026"}</div>
        ) : machineQ.isError || !def ? (
          <div style={css("padding:20px;text-align:center;font-size:11px;color:var(--status-warn);")}>
            failed to load finding workflow states.
          </div>
        ) : (
          <div style={css("display:flex;flex-direction:column;gap:14px;")}>
            {moduleKeys.map((mod) => (
              <section
                key={mod}
                style={css("border:1px solid var(--border);background:var(--surface-card);border-radius:4px;box-shadow:var(--bevel-raised);padding:12px 14px;")}
              >
                <header style={css("display:flex;align-items:center;gap:9px;margin-bottom:10px;")}>
                  <span style={css("width:8px;height:8px;background:var(--accent);flex:0 0 auto;")} />
                  <span style={css("font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>
                    {mod === "base" ? "platform base states" : mod + " module extensions"}
                  </span>
                  <span style={css("flex:1;")} />
                  <span style={css("font-size:10px;color:var(--text-faint);")}>{grouped[mod].length + " state(s)"}</span>
                </header>
                <div style={css("display:flex;flex-direction:column;gap:8px;")}>
                  {grouped[mod].map((state) => {
                    const outs = def.transitions[state] ?? [];
                    return (
                      <div
                        key={state}
                        style={css("display:grid;grid-template-columns:220px 1fr;gap:12px;padding:8px 10px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:3px;")}
                      >
                        <div style={css("display:flex;align-items:center;")}>
                          <WorkflowStateBadge value={state} />
                        </div>
                        <div style={css("display:flex;align-items:center;flex-wrap:wrap;gap:6px;font-size:10.5px;color:var(--text-muted);")}>
                          {outs.length === 0 ? (
                            <span style={css("color:var(--text-faint);font-style:italic;")}>terminal (no outbound transitions)</span>
                          ) : (
                            <>
                              <span style={css("color:var(--text-faint);letter-spacing:0.08em;text-transform:uppercase;font-size:9px;margin-right:2px;")}>
                                {"\u2192"}
                              </span>
                              {outs.map((t) => (
                                <WorkflowStateBadge key={t} value={t} />
                              ))}
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        )}
      </div>
    </ConsoleWindow>
  );
}

export default AdminFindingStatesPage;
