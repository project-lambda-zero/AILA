/**
 * PersonaModelRoutingPage -- bespoke admin window for per-persona sibling
 * model routing (#151).
 *
 * The platform routes every sibling branch through one shared turn dispatch
 * (`platform/agents/turn_runner.py`). By default every persona runs the same
 * base model, so multi-persona debate is an expensive form of self-consistency
 * (the #151 finding). This window is the opt-in switch: map one or more of the
 * six sibling personas to a distinct model_role and their branches run a
 * different base model, turning the debate into real adversarial diversity.
 *
 * It edits a single ConfigRegistry key, `platform.persona_model_role_map`,
 * through the admin-gated config API:
 *   GET /config/platform/persona_model_role_map
 *   PUT /config/platform/persona_model_role_map  {value, value_type:"str"}
 * An empty map is persisted as the empty string -- the backend resolves that
 * as off, byte-identical to prior behavior.
 */

import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, CSSProperties, JSX } from "react";

import { ApiError } from "../../api/client";
import {
  PERSONA_ROLE_LABEL,
  PERSONA_VOICES,
  parsePersonaMap,
  usePersonaRoutingConfig,
  useUpdatePersonaRouting,
} from "../../api/personaRouting";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";

/* ------------------------------ constants -------------------------------- */

const H_WARN = "#ffb85f";

/* ------------------------------- styles ---------------------------------- */

const panelBox: CSSProperties = css(
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));",
);
const panelTitle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot: CSSProperties = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
const pad: CSSProperties = css("padding:12px 14px;");
const stack: CSSProperties = css("display:flex;flex-direction:column;gap:12px;");
const prose: CSSProperties = css(
  "font-family:var(--font-mono);font-size:11px;line-height:1.6;color:var(--text-muted);",
);
const inputStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:6px 9px;min-width:0;outline:none;width:100%;",
);
const inputDisabled: CSSProperties = css(
  "background:var(--surface-chrome);border:1px solid var(--border-faint);border-radius:2px;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;padding:6px 9px;min-width:0;outline:none;width:100%;cursor:not-allowed;",
);
const btnPrimary: CSSProperties = css(
  "padding:6px 14px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const btnPrimaryDisabled: CSSProperties = css(
  "padding:6px 14px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:not-allowed;",
);
const btnGhost: CSSProperties = css(
  "padding:5px 11px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const chipOk: CSSProperties = css(
  "display:inline-block;padding:1px 7px;border:1px solid color-mix(in srgb,var(--status-ok) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9px;line-height:1.6;letter-spacing:0.1em;text-transform:uppercase;color:var(--status-ok);background:color-mix(in srgb,var(--status-ok) 10%,transparent);",
);
const chipFaint: CSSProperties = css(
  "display:inline-block;padding:1px 7px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:9px;line-height:1.6;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);background:transparent;",
);
const chipWarn: CSSProperties = css(
  `display:inline-block;padding:1px 7px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9px;line-height:1.6;letter-spacing:0.1em;text-transform:uppercase;color:${H_WARN};background:color-mix(in srgb,${H_WARN} 12%,transparent);`,
);
const emptyNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const personaRow: CSSProperties = css(
  "display:grid;grid-template-columns:minmax(150px,180px) 1fr;gap:10px 14px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-faint);",
);
const personaName: CSSProperties = css(
  "font-family:var(--font-mono);font-size:12px;color:var(--text-primary);letter-spacing:0.04em;",
);
const roleTag: CSSProperties = css(
  "font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);",
);

/* ------------------------------ helpers ---------------------------------- */

function apiErrMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message || `HTTP ${err.status}`;
  if (err instanceof Error) return err.message;
  return String(err);
}

function RoutingEditor(): JSX.Element {
  const q = usePersonaRoutingConfig();
  const mut = useUpdatePersonaRouting();

  const serverMap = useMemo(
    () => parsePersonaMap(q.data?.effective_value),
    [q.data?.effective_value],
  );

  // Local editable state, seeded from the server map. `enabled` is derived
  // from the server map on load (non-empty = on) but is operator-controlled
  // thereafter, so the operator can flip the whole feature off in one click.
  const [enabled, setEnabled] = useState(false);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [seeded, setSeeded] = useState(false);

  useEffect(() => {
    if (q.data === undefined || seeded) return;
    setEnabled(Object.keys(serverMap).length > 0);
    setDrafts({ ...serverMap });
    setSeeded(true);
  }, [q.data, serverMap, seeded]);

  const draftMap = useMemo<Record<string, string>>(() => {
    if (!enabled) return {};
    const out: Record<string, string> = {};
    for (const persona of PERSONA_VOICES) {
      const value = (drafts[persona] ?? "").trim();
      if (value !== "") out[persona] = value;
    }
    return out;
  }, [enabled, drafts]);

  const dirty = useMemo(
    () => JSON.stringify(draftMap) !== JSON.stringify(serverMap),
    [draftMap, serverMap],
  );
  const mappedCount = Object.keys(draftMap).length;
  const envOverride = q.data?.overridden_by_env ?? false;

  const save = (): void => {
    mut.mutate(draftMap);
  };
  const reset = (): void => {
    setEnabled(Object.keys(serverMap).length > 0);
    setDrafts({ ...serverMap });
  };

  if (q.isLoading && q.data === undefined) {
    return (
      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>persona routing</span>
        </div>
        <div style={emptyNote}>loading /config/platform/persona_model_role_map&#8230;</div>
      </div>
    );
  }
  if (q.isError) {
    return (
      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>persona routing</span>
        </div>
        <div style={{ ...emptyNote, color: H_WARN }}>
          could not load the config key &mdash; {apiErrMessage(q.error)}
        </div>
      </div>
    );
  }

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>persona &rarr; model routing</span>
        <span style={css("flex:1;")} />
        {mappedCount > 0 ? (
          <span style={chipOk}>on &middot; {mappedCount} mapped</span>
        ) : (
          <span style={chipFaint}>off &middot; homogeneous</span>
        )}
        {q.data ? <span style={chipFaint}>src: {q.data.effective_source}</span> : null}
      </div>

      <div style={{ ...scroll }}>
        <div style={{ ...pad, ...stack }}>
          <p style={prose}>
            Route a distinct base model per sibling persona (#151). Homogeneous debate approximates
            self-consistency; distinct reasoners on distinct roles unlock cross-error rejection. This
            is <strong style={css("color:var(--text-primary);")}>opt-in</strong> &mdash; with no
            personas mapped, every branch keeps the default model and behavior is unchanged.
          </p>

          <label
            style={css(
              "display:inline-flex;align-items:center;gap:9px;font-family:var(--font-mono);font-size:12px;color:var(--text-primary);cursor:pointer;",
            )}
          >
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setEnabled(e.target.checked)}
              style={css("width:15px;height:15px;accent-color:var(--accent);cursor:pointer;")}
            />
            Route a distinct base model per sibling persona
          </label>

          {envOverride ? (
            <div style={css("display:flex;align-items:center;gap:8px;")}>
              <span style={chipWarn}>env override</span>
              <span style={css("font-family:var(--font-mono);font-size:10px;color:var(--text-faint);")}>
                {q.data?.env_key} is set; the live value comes from the environment and edits here will
                not take effect until it is unset.
              </span>
            </div>
          ) : null}

          <div style={css("display:flex;flex-direction:column;")}>
            {PERSONA_VOICES.map((persona) => (
              <div key={persona} style={personaRow}>
                <div style={css("display:flex;flex-direction:column;gap:2px;")}>
                  <span style={personaName}>{persona}</span>
                  <span style={roleTag}>{PERSONA_ROLE_LABEL[persona]}</span>
                </div>
                <input
                  type="text"
                  value={drafts[persona] ?? ""}
                  disabled={!enabled}
                  placeholder={enabled ? "model_role (e.g. researcher_opus) \u2014 blank = default model" : "\u2014"}
                  onChange={(e: ChangeEvent<HTMLInputElement>) =>
                    setDrafts((d) => ({ ...d, [persona]: e.target.value }))
                  }
                  style={enabled ? inputStyle : inputDisabled}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
            ))}
          </div>

          <p style={css("font-family:var(--font-mono);font-size:10px;line-height:1.6;color:var(--text-faint);")}>
            A model_role is a task_type the LLM client resolves through{" "}
            <code style={css("color:var(--text-muted);")}>llm_model_&#123;role&#125;</code>. Wire the
            underlying model for each role on the Config page (namespace{" "}
            <code style={css("color:var(--text-muted);")}>platform</code>). Leave a persona blank to
            keep it on the default model.
          </p>

          {mut.isError ? (
            <div style={css(`font-family:var(--font-mono);font-size:10.5px;color:${H_WARN};line-height:1.5;`)}>
              write failed &mdash; {apiErrMessage(mut.error)}
            </div>
          ) : null}
          {mut.isSuccess && !dirty ? (
            <div style={css("font-family:var(--font-mono);font-size:10.5px;color:var(--status-ok);")}>
              saved &middot; {mappedCount > 0 ? `${mappedCount} persona override(s) live` : "routing off"}
            </div>
          ) : null}

          <div style={css("display:flex;gap:9px;align-items:center;")}>
            <button
              type="button"
              onClick={save}
              disabled={!dirty || mut.isPending}
              style={!dirty || mut.isPending ? btnPrimaryDisabled : btnPrimary}
            >
              {mut.isPending ? "saving\u2026" : "save routing"}
            </button>
            <button type="button" onClick={reset} disabled={!dirty} style={btnGhost}>
              reset
            </button>
            <span style={css("flex:1;")} />
            <span style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>
              PUT /config/platform/persona_model_role_map
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* --------------------------------- page ---------------------------------- */

export default function PersonaModelRoutingPage(props: ModulePageProps): JSX.Element {
  const { windowId, title, isFocused, onFocus, onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--status-ok)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        admin &middot; agents
      </span>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          textTransform: "none",
          letterSpacing: "0.03em",
          color: "var(--text-muted)",
        }}
      >
        PersonaModelRouter &middot; platform.persona_model_role_map
      </span>
      <span style={{ flex: 1 }} />
    </>
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
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: 1,
            background: "var(--accent)",
            boxShadow: "0 0 7px var(--accent)",
          }}
        />
        <span style={{ color: "var(--text-primary)", fontWeight: 700, letterSpacing: "0.16em" }}>
          admin &middot; persona model routing
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          per-persona sibling model map &mdash; adversarial diversity (#151)
        </span>
      </header>

      <main
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          padding: 12,
        }}
      >
        <RoutingEditor />
      </main>

    </ConsoleWindow>
  );
}
