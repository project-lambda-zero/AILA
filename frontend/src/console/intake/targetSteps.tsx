/** The step bodies for the generic (vr / malware) intake wizard: kind grid,
 * registered-target picker with workspace filter, review form, and the
 * launch-stage animation list. */

import type { CSSProperties, JSX } from "react";

import type { TargetRow } from "../../api/intake";
import { css } from "../css";
import { FieldHelp } from "../wizards";
import type { GenericCfg } from "./config";

export interface TargetStepsProps {
  cfg: GenericCfg;
  step: number;
  kind: string | null;
  kd: GenericCfg["kinds"][number] | null;
  hasInv: boolean;
  invKind: string;
  setInvKind: (k: string) => void;
  auto: boolean;
  setAuto: (fn: (a: boolean) => boolean) => void;
  budget: number;
  setBudget: (n: number) => void;
  question: string;
  setQuestion: (q: string) => void;
  targetId: string | null;
  targetName: string;
  targetLine: string;
  workspaceFilter: string;
  setWorkspaceFilter: (id: string) => void;
  workspaceRows: Array<{ id: string; name: string }>;
  targetsState: {
    isLoading: boolean;
    isError: boolean;
    matches: TargetRow[];
  };
  onPickKind: (k: string) => void;
  onPickTarget: (t: TargetRow) => void;
  onRequestUpload?: () => void;
  autoStyle: CSSProperties;
  launchError: string | null;
  stage: number;
}

export function TargetSteps(props: TargetStepsProps): JSX.Element {
  const {
    cfg, step, kd, hasInv, invKind, setInvKind, auto, setAuto, budget, setBudget,
    question, setQuestion, targetId, targetName, targetLine,
    workspaceFilter, setWorkspaceFilter, workspaceRows, targetsState,
    onPickKind, onPickTarget, onRequestUpload, autoStyle, launchError, stage,
  } = props;

  if (step === 0) {
    return (
      <div style={css("display:flex;flex-direction:column;gap:12px;")}>
        {cfg.groups.map((g) => {
          const items = cfg.kinds.filter((k) => k.g === g[0]);
          return (
            <div key={g[0]}>
              <div style={css("font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);margin-bottom:6px;")}>
                {g[1]}
              </div>
              <div style={css("display:grid;grid-template-columns:repeat(3,1fr);gap:6px;")}>
                {items.map((k) => (
                  <button
                    key={k.k}
                    type="button"
                    onClick={(): void => onPickKind(k.k)}
                    style={css("padding:8px 9px;text-align:left;font-family:var(--font-mono);font-size:11px;letter-spacing:0.04em;color:var(--text-primary);background:var(--surface-card);border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;")}
                  >
                    <span>{k.l}</span>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  if (step === 1 && kd !== null) {
    return (
      <div style={css("display:flex;flex-direction:column;gap:11px;")}>
        <div style={css("display:flex;align-items:center;gap:10px;")}>
          <span style={css("font-size:11px;letter-spacing:0.06em;color:var(--text-muted);")}>
            <span style={css("color:var(--accent);")}>{"kind \u00b7"}</span> {kd.l}
          </span>
          <span style={css("flex:1;")} />
          {workspaceRows.length > 0 && (
            <select
              value={workspaceFilter}
              onChange={(e): void => setWorkspaceFilter(e.target.value)}
              style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:4px 7px;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;border-radius:2px;")}
              title="filter by workspace"
            >
              <option value="">all workspaces</option>
              {workspaceRows.map((w) => (
                <option key={w.id} value={w.id}>{w.name}</option>
              ))}
            </select>
          )}
          {onRequestUpload && (
            <button
              type="button"
              onClick={onRequestUpload}
              style={css("min-height:28px;padding:2px 8px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
              title="close and open the upload window"
            >
              + upload new target
            </button>
          )}
        </div>
        {targetsState.isLoading ? (
          <div style={css("padding:22px;text-align:center;font-size:11px;color:var(--text-faint);")}>
            {"loading targets\u2026"}
          </div>
        ) : targetsState.isError ? (
          <div style={css("padding:12px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;")}>
            failed to load targets
          </div>
        ) : targetsState.matches.length === 0 ? (
          <div style={css("padding:22px;text-align:center;font-size:11px;color:var(--text-faint);line-height:1.5;")}>
            no {kd.l} targets yet.
            {onRequestUpload ? " use \u201c+ upload new target\u201d above to create one." : ""}
          </div>
        ) : (
          <div style={css("display:flex;flex-direction:column;gap:5px;max-height:340px;overflow:auto;")}>
            {targetsState.matches.map((t) => {
              const on = t.id === targetId;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={(): void => onPickTarget(t)}
                  style={css(
                    `display:flex;align-items:center;gap:10px;padding:8px 11px;text-align:left;font-family:var(--font-mono);font-size:11px;color:${
                      on ? "var(--accent)" : "var(--text-primary)"
                    };background:${
                      on ? "color-mix(in srgb,var(--accent) 10%,transparent)" : "var(--surface-sunk)"
                    };border:1px solid ${on ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;cursor:pointer;`,
                  )}
                >
                  <span style={css(`width:6px;height:6px;flex:0 0 auto;border-radius:1px;background:${on ? "var(--accent)" : "var(--text-faint)"};`)} />
                  <span style={css("flex:1;min-width:0;display:flex;flex-direction:column;gap:2px;")}>
                    <span style={css("color:inherit;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{t.display_name}</span>
                    <span style={css("font-size:11px;color:var(--text-faint);letter-spacing:0.06em;")}>
                      {t.workspace_name ?? t.workspace_id ?? ""}
                      {t.analysis_state ? ` \u00b7 ${t.analysis_state}` : ""}
                    </span>
                  </span>
                  <span style={css("font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{t.kind}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  if (step === 2) {
    return (
      <div style={css("display:flex;flex-direction:column;gap:12px;")}>
        <div style={css("padding:9px 11px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:2px;")}>
          <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
            target
          </div>
          <div style={css("margin-top:4px;font-size:11px;color:var(--text-primary);")}>
            {kd?.l ?? "\u2014"} <span style={css("color:var(--text-faint);")}>{"\u00b7"}</span> {targetLine}
          </div>
        </div>
        <label style={css("display:flex;flex-direction:column;gap:4px;")}>
          <span style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
            initial question
          </span>
          <textarea
            value={question}
            onChange={(e): void => setQuestion(e.target.value)}
            placeholder="what should AILA find? e.g. memory-safety bugs reachable pre-auth"
            rows={2}
            style={css("resize:none;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:8px 9px;color:var(--text-primary);font-family:var(--font-sans,system-ui);font-size:12px;line-height:1.4;border-radius:2px;")}
          />
        </label>
        {hasInv && (
          <div>
            <span style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
              investigation kind
            </span>
            <div style={css("display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;")}>
              {cfg.invKinds.map((k) => {
                const on = k === invKind;
                return (
                  <button
                    key={k}
                    type="button"
                    onClick={(): void => setInvKind(k)}
                    style={css(
                      `padding:3px 8px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;border:1px solid ${
                        on ? "var(--accent)" : "var(--border-soft)"
                      };color:${on ? "var(--accent)" : "var(--text-muted)"};background:${
                        on ? "color-mix(in srgb,var(--accent) 12%,transparent)" : "transparent"
                      };border-radius:2px;`,
                    )}
                  >
                    {k}
                  </button>
                );
              })}
            </div>
          </div>
        )}
        <div style={css("display:flex;align-items:center;gap:14px;")}>
          <button type="button" onClick={(): void => setAuto((a) => !a)} style={autoStyle}>
            <span>auto-pilot</span>
            <span>{auto ? "on" : "off"}</span>
          </button>
          <FieldHelp text="auto-pilot lets AILA plan and run turns without asking for confirmation each step. turn off to step through every turn manually." />
          <label style={css("display:inline-flex;align-items:center;gap:7px;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>
            budget usd
            <input
              value={String(budget)}
              onChange={(e): void => {
                const n = Number(e.target.value);
                setBudget(Number.isFinite(n) ? n : 0);
              }}
              style={css("width:70px;background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:5px 8px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;border-radius:2px;")}
            />
          </label>
          <FieldHelp text="hard ceiling for LLM spend on this investigation in USD. defaults to 50; edit before launching to override." />
        </div>
      </div>
    );
  }

  return (
    <div style={css("display:flex;flex-direction:column;gap:9px;")}>
      <div style={css("font-size:11px;letter-spacing:0.06em;color:var(--text-muted);")}>
        {`creating investigation \u00b7 ${targetName || kd?.l || ""}`}
      </div>
      {launchError ? (
        <div style={css("padding:8px 10px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);white-space:pre-wrap;word-break:break-word;")}>
          {launchError}
        </div>
      ) : null}
      {cfg.stages.map((st, i) => {
        const done = stage > i;
        const run = stage === i;
        const dot = css(
          `width:9px;height:9px;flex:0 0 auto;border-radius:1px;background:${
            done ? "var(--status-ok)" : run ? "var(--accent)" : "var(--text-faint)"
          };${run ? "animation:acbreathe 1s ease-in-out infinite;" : ""}`,
        );
        const textStyle = css(
          `font-size:11px;letter-spacing:0.04em;color:${done || run ? "var(--text-primary)" : "var(--text-faint)"};`,
        );
        const stStyle = css(
          `font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:${
            done ? "var(--status-ok)" : run ? "var(--accent)" : "var(--text-faint)"
          };`,
        );
        const stTxt = done ? "done" : run ? "running" : "pending";
        return (
          <div
            key={st[0]}
            style={css("display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:2px;")}
          >
            <span style={dot} />
            <span style={css("display:flex;flex-direction:column;flex:1;min-width:0;")}>
              <span style={textStyle}>{st[0].replace(/_/g, " ")}</span>
              <span style={css("font-size:11px;color:var(--text-faint);letter-spacing:0.02em;")}>{st[1]}</span>
            </span>
            <span style={stStyle}>{stTxt}</span>
          </div>
        );
      })}
    </div>
  );
}
