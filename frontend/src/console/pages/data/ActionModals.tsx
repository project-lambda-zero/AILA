/** The DataPage action modals: the pre-flight collection form (PageAction
 * `fields`) and the one-shot reveal modal (PageAction `reveal`). */

import { useState } from "react";
import type { ChangeEvent, JSX } from "react";

import { css } from "../../css";
import { revealEntries } from "./rows";
import {
  ACTION_INPUT,
  actionErrBox,
  actionGhostBtn,
  actionLabel,
  actionPrimaryBtn,
  modalCard,
  modalScrim,
  modalTitle,
} from "./styles";
import type { ActionField, DataRow, PageAction } from "./types";

export interface ActionFormState {
  action: PageAction;
  row: DataRow | null;
}

export interface RevealState {
  action: PageAction;
  payload: unknown;
}

export interface ActionModalsProps {
  actionForm: ActionFormState | null;
  actionVals: Record<string, string>;
  setActionVals: (vals: Record<string, string>) => void;
  actionErr: string | null;
  visibleFields: (a: PageAction) => ActionField[];
  onSubmit: () => void;
  onCancel: () => void;
  actionPending: boolean;
  reveal: RevealState | null;
  onRevealClose: () => void;
}

export function ActionModals(props: ActionModalsProps): JSX.Element {
  const { actionForm, actionVals, setActionVals, actionErr, visibleFields, onSubmit, onCancel, actionPending, reveal, onRevealClose } = props;
  const [copied, setCopied] = useState(false);
  const copyReveal = (v: string): void => {
    void navigator.clipboard?.writeText(v);
    setCopied(true);
  };

  return (
    <>
      {actionForm ? (
        <div role="dialog" aria-modal="true" aria-label={`${actionForm.action.label} details`} onClick={onCancel} style={modalScrim(21)}>
          <form
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit();
            }}
            style={modalCard(460)}
          >
            <div style={modalTitle}>{actionForm.action.label}</div>
            {visibleFields(actionForm.action).map((f) => (
              <label key={f.name} style={actionLabel}>
                <span>
                  {f.label}
                  {f.required ? " *" : ""}
                </span>
                {f.type === "textarea" ? (
                  <textarea
                    value={actionVals[f.name] ?? ""}
                    placeholder={f.placeholder}
                    onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setActionVals({ ...actionVals, [f.name]: e.target.value })}
                    style={css(ACTION_INPUT + "min-height:64px;resize:vertical;")}
                  />
                ) : f.type === "select" ? (
                  <select
                    value={actionVals[f.name] ?? ""}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) => setActionVals({ ...actionVals, [f.name]: e.target.value })}
                    style={css(ACTION_INPUT + "cursor:pointer;")}
                  >
                    <option value="">{f.placeholder ?? "select\u2026"}</option>
                    {(f.options ?? []).map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={f.type === "number" ? "number" : "text"}
                    value={actionVals[f.name] ?? ""}
                    placeholder={f.type === "tags" ? (f.placeholder ?? "comma or space separated") : f.placeholder}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setActionVals({ ...actionVals, [f.name]: e.target.value })}
                    style={css(ACTION_INPUT)}
                  />
                )}
              </label>
            ))}
            {actionErr ? <div style={actionErrBox}>{actionErr}</div> : null}
            <div style={css("display:flex;justify-content:flex-end;gap:8px;")}>
              <button type="button" onClick={onCancel} style={actionGhostBtn}>
                cancel
              </button>
              <button type="submit" disabled={actionPending} style={actionPrimaryBtn}>
                {actionForm.action.label}
              </button>
            </div>
          </form>
        </div>
      ) : null}
      {reveal ? (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={reveal.action.reveal?.title ?? "result"}
          onClick={onRevealClose}
          style={modalScrim(22)}
        >
          <div onClick={(e) => e.stopPropagation()} style={modalCard(520)}>
            <div style={modalTitle}>{reveal.action.reveal?.title ?? reveal.action.label}</div>
            {reveal.action.reveal?.note ? (
              <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-ok);letter-spacing:0.03em;text-transform:none;")}>
                {reveal.action.reveal.note}
              </div>
            ) : null}
            {revealEntries(reveal.action, reveal.payload).map(([k, v]) => (
              <div key={k} style={css("display:flex;flex-direction:column;gap:4px;")}>
                <span style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>
                  {k}
                </span>
                <div style={css("display:flex;align-items:flex-start;gap:6px;")}>
                  <code style={css("flex:1;min-width:0;word-break:break-all;background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;padding:7px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>
                    {v}
                  </code>
                  <button type="button" onClick={() => copyReveal(v)} style={actionGhostBtn}>
                    {copied ? "copied" : "copy"}
                  </button>
                </div>
              </div>
            ))}
            <div style={css("display:flex;justify-content:flex-end;")}>
              <button type="button" onClick={onRevealClose} style={actionPrimaryBtn}>
                done
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
