/** The knowledge "+ operator note" ingest modal: module/scope pickers, the
 * live write-namespace preview, and the create/result states. */

import { useState } from "react";
import type { ChangeEvent, FormEvent, JSX } from "react";

import { useIngestKnowledge } from "../../../api/knowledge";
import { useWorkspaces } from "../../../api/intake";
import { css } from "../../css";
import {
  btnGhost,
  btnGhostDisabled,
  btnPrimary,
  chip,
  chipAccent,
  dot,
  inputStyle,
  labelStyle,
  modalBackdrop,
  modalCard,
  pad,
  panelTitle,
  stack,
  textareaStyle,
} from "./styles";

const SCOPES = [
  { value: "workspace", label: "workspace" },
  { value: "team", label: "team" },
  { value: "global", label: "global" },
  { value: "agent", label: "agent" },
] as const;

export type IngestScope = (typeof SCOPES)[number]["value"];

/** Live preview of the write namespace the backend will resolve, so the
 *  operator sees exactly where the note lands before submitting. Mirrors
 *  `_resolve_operator_namespace` in the router. */
function previewNamespace(module: string, scope: IngestScope, scopeId: string): string {
  const id = scopeId.trim();
  if (scope === "agent") return id ? `agent:${id}` : "agent:<name>";
  if (scope === "global") return `${module}.operator_note.global`;
  return `${module}.operator_note.${scope}.${id || "<id>"}`;
}

export function IngestModal({ onClose }: { onClose: () => void }): JSX.Element {
  const [module, setModule] = useState<"vr" | "malware">("vr");
  const [scope, setScope] = useState<IngestScope>("workspace");
  const [scopeId, setScopeId] = useState("");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");

  const ingest = useIngestKnowledge();
  const ws = useWorkspaces(module);

  const needsId = scope !== "global";
  const showWsSelect = scope === "workspace";
  const canSubmit =
    content.trim().length > 0 &&
    (!needsId || scopeId.trim().length > 0) &&
    !ingest.isPending;

  const submit = (e: FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    if (!canSubmit) return;
    ingest.mutate({
      module,
      scope,
      scope_id: needsId ? scopeId.trim() : undefined,
      title: title.trim() || undefined,
      content,
    });
  };

  const result = ingest.data;

  return (
    <div style={modalBackdrop} onClick={onClose}>
      <div style={modalCard} onClick={(e) => e.stopPropagation()}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>add operator note</span>
          <span style={css("flex:1;")} />
          <button type="button" style={btnGhost} onClick={onClose}>
            {"\u2715 close"}
          </button>
        </div>

        {result ? (
          <div style={{ ...pad, ...stack, overflow: "auto" }}>
            <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-ok);")}>
              note {result.operation} &mdash; entry #{result.entry_id ?? "?"}
            </div>
            <label style={labelStyle}>
              landed namespace
              <span style={chipAccent}>{result.namespace}</span>
            </label>
            <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);line-height:1.55;")}>
              agents in this scope recall it on their next turn.
            </div>
            <div style={css("display:flex;gap:8px;")}>
              <button type="button" style={btnPrimary} onClick={() => ingest.reset()}>
                add another
              </button>
              <button type="button" style={btnGhost} onClick={onClose}>
                done
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} style={{ ...pad, ...stack, overflow: "auto" }}>
            <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;")}>
              <label style={labelStyle}>
                module
                <select
                  style={inputStyle}
                  value={module}
                  disabled={scope === "agent"}
                  onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                    setModule(e.target.value === "malware" ? "malware" : "vr")
                  }
                >
                  <option value="vr">vr</option>
                  <option value="malware">malware</option>
                </select>
              </label>
              <label style={labelStyle}>
                scope
                <select
                  style={inputStyle}
                  value={scope}
                  onChange={(e: ChangeEvent<HTMLSelectElement>) => {
                    // SAFETY: the options are rendered from SCOPES, so the value is an IngestScope literal.
                    setScope(e.target.value as IngestScope);
                    setScopeId("");
                  }}
                >
                  {SCOPES.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {needsId ? (
              <label style={labelStyle}>
                {scope === "workspace" ? "workspace" : scope === "team" ? "team id" : "agent name"}
                {showWsSelect ? (
                  <select
                    style={inputStyle}
                    value={scopeId}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) => setScopeId(e.target.value)}
                  >
                    <option value="">
                      {ws.isLoading ? "loading\u2026" : ws.isError ? "workspaces unavailable" : "select workspace\u2026"}
                    </option>
                    {(ws.data ?? []).map((w) => (
                      <option key={w.id} value={w.id}>
                        {w.name} ({w.id.slice(0, 8)})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    style={inputStyle}
                    value={scopeId}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setScopeId(e.target.value)}
                    placeholder={scope === "team" ? "team id" : "agent name"}
                    autoComplete="off"
                  />
                )}
              </label>
            ) : null}

            <label style={labelStyle}>
              title (optional)
              <input
                type="text"
                style={inputStyle}
                value={title}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setTitle(e.target.value)}
                maxLength={200}
                autoComplete="off"
              />
            </label>

            <label style={labelStyle}>
              content
              <textarea
                style={textareaStyle}
                value={content}
                onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setContent(e.target.value)}
                placeholder="knowledge the agents should recall in this scope\u2026"
                rows={7}
              />
            </label>

            <label style={labelStyle}>
              target namespace
              <span style={chip}>{previewNamespace(module, scope, scopeId)}</span>
            </label>

            {ingest.isError ? (
              <div style={css("font-family:var(--font-mono);font-size:11px;color:#ffb85f;line-height:1.5;")}>
                {ingest.error instanceof Error ? ingest.error.message : "ingest failed"}
              </div>
            ) : null}

            <div style={css("display:flex;gap:8px;align-items:center;")}>
              <button type="submit" style={canSubmit ? btnPrimary : btnGhostDisabled} disabled={!canSubmit}>
                {ingest.isPending ? "storing\u2026" : "store note"}
              </button>
              <button type="button" style={btnGhost} onClick={onClose}>
                cancel
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
