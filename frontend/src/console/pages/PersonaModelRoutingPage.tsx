/**
 * PersonaModelRoutingPage -- bespoke admin window for per-persona sibling
 * model routing (#151, req 31).
 *
 * The platform routes every sibling branch through one shared turn dispatch
 * (`platform/agents/turn_runner.py`). By default every persona runs the same
 * base model. This window is the opt-in switch: map one or more of a module's
 * personas to a distinct model_role and their branches run a different base
 * model, turning the debate into real adversarial diversity.
 *
 * The persona list, the role tag, and the finite list of model_role options
 * per persona are ALL driven by the registry endpoint
 * `GET /platform/agents/persona-registry` -- no hard-coded persona list, no
 * hard-coded model_role fallbacks. The config value schema is nested:
 * `{module_id: {persona_voice: model_role}}` with the sentinel `"__global__"`
 * as the fallback bucket. A legacy flat value read as the __global__ bucket
 * is displayed as a fallback per matching per-module select; the first save
 * from the new page rewrites the value in nested per-module form.
 */

import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, CSSProperties, JSX } from "react";

import { ApiError } from "../../api/client";
import {
  parsePersonaMap,
  usePersonaRegistry,
  usePersonaRoutingConfig,
  useUpdatePersonaRouting,
} from "../../api/personaRouting";
import type { PersonaRegistryModule } from "../../api/personaRouting";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";

/* ------------------------------ constants -------------------------------- */

const H_WARN = "#ffb85f";
const GLOBAL_BUCKET = "__global__";
type NestedMap = Record<string, Record<string, string>>;

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
const moduleHeader: CSSProperties = css(
  "display:flex;align-items:baseline;gap:10px;padding:14px 0 6px 0;border-bottom:1px solid var(--border-soft);",
);
const moduleTitle: CSSProperties = css(
  "font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-primary);",
);
const moduleId: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;color:var(--text-faint);",
);
const moduleEmpty: CSSProperties = css(
  "padding:8px 0;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.03em;",
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

function cloneNested(map: NestedMap): NestedMap {
  const out: NestedMap = {};
  for (const [k, inner] of Object.entries(map)) out[k] = { ...inner };
  return out;
}

/** Resolve the current display value for one per-module persona select.
 *  Prefer a module-specific entry; fall back to the __global__ bucket
 *  (legacy flat migration path); return "" (the leading `-- default --`
 *  option) if neither is set OR the stored value is not in this module's
 *  bounded option list. */
function currentValue(
  drafts: NestedMap,
  moduleIdKey: string,
  voice: string,
  options: string[],
): string {
  const local = drafts[moduleIdKey]?.[voice];
  if (local && options.includes(local)) return local;
  const global = drafts[GLOBAL_BUCKET]?.[voice];
  if (global && options.includes(global)) return global;
  return "";
}

/** Build the nested map that will be persisted. Iterates the registry so
 *  only real (module_id, voice) pairs land in the payload; the __global__
 *  bucket from a legacy read is intentionally dropped, so the first save
 *  from this page rewrites a legacy flat value into per-module nested form. */
function buildForSave(drafts: NestedMap, registry: PersonaRegistryModule[]): NestedMap {
  const out: NestedMap = {};
  for (const mod of registry) {
    const bucket: Record<string, string> = {};
    for (const persona of mod.personas) {
      const value = (drafts[mod.module_id]?.[persona.voice] ?? "").trim();
      if (value !== "" && persona.task_type_options.includes(value)) {
        bucket[persona.voice] = value;
      }
    }
    if (Object.keys(bucket).length > 0) out[mod.module_id] = bucket;
  }
  return out;
}

function RoutingEditor(): JSX.Element {
  const cfg = usePersonaRoutingConfig();
  const reg = usePersonaRegistry();
  const mut = useUpdatePersonaRouting();

  const serverMap = useMemo<NestedMap>(
    () => parsePersonaMap(cfg.data?.effective_value),
    [cfg.data?.effective_value],
  );
  const registry = reg.data ?? [];

  // Local editable state, seeded from the parsed server map. `enabled` is
  // derived from the server map on load (non-empty = on) but is
  // operator-controlled thereafter.
  const [enabled, setEnabled] = useState(false);
  const [drafts, setDrafts] = useState<NestedMap>({});
  const [seeded, setSeeded] = useState(false);

  useEffect(() => {
    if (cfg.data === undefined || seeded) return;
    setEnabled(Object.keys(serverMap).length > 0);
    setDrafts(cloneNested(serverMap));
    setSeeded(true);
  }, [cfg.data, serverMap, seeded]);

  const setPersona = (moduleIdKey: string, voice: string, value: string): void => {
    setDrafts((d) => {
      const copy = cloneNested(d);
      const bucket = copy[moduleIdKey] ?? {};
      if (value === "") {
        delete bucket[voice];
      } else {
        bucket[voice] = value;
      }
      if (Object.keys(bucket).length === 0) {
        delete copy[moduleIdKey];
      } else {
        copy[moduleIdKey] = bucket;
      }
      return copy;
    });
  };

  const draftMap = useMemo<NestedMap>(
    () => (enabled ? buildForSave(drafts, registry) : {}),
    [enabled, drafts, registry],
  );

  const dirty = useMemo(
    () => JSON.stringify(draftMap) !== JSON.stringify(serverMap),
    [draftMap, serverMap],
  );
  const mappedCount = Object.values(draftMap).reduce(
    (n, bucket) => n + Object.keys(bucket).length,
    0,
  );
  const envOverride = cfg.data?.overridden_by_env ?? false;

  const save = (): void => {
    mut.mutate(draftMap);
  };
  const reset = (): void => {
    setEnabled(Object.keys(serverMap).length > 0);
    setDrafts(cloneNested(serverMap));
  };

  if ((cfg.isLoading && cfg.data === undefined) || (reg.isLoading && reg.data === undefined)) {
    return (
      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>persona routing</span>
        </div>
        <div style={emptyNote}>loading persona registry &amp; config&#8230;</div>
      </div>
    );
  }
  if (cfg.isError) {
    return (
      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>persona routing</span>
        </div>
        <div style={{ ...emptyNote, color: H_WARN }}>
          could not load the config key &mdash; {apiErrMessage(cfg.error)}
        </div>
      </div>
    );
  }
  if (reg.isError) {
    return (
      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>persona routing</span>
        </div>
        <div style={{ ...emptyNote, color: H_WARN }}>
          could not load the persona registry &mdash; {apiErrMessage(reg.error)}
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
        {cfg.data ? <span style={chipFaint}>src: {cfg.data.effective_source}</span> : null}
      </div>

      <div style={{ ...scroll }}>
        <div style={{ ...pad, ...stack }}>
          <p style={prose}>
            Route a distinct base model per persona, per module (#151). Homogeneous debate
            approximates self-consistency; distinct reasoners on distinct roles unlock cross-error
            rejection. This is <strong style={css("color:var(--text-primary);")}>opt-in</strong>
            &mdash; with no personas mapped, every branch keeps the default model and behavior is
            unchanged. Options per persona are bounded to the task_types the module&apos;s router
            can legally emit.
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
            Route a distinct base model per persona
          </label>

          {envOverride ? (
            <div style={css("display:flex;align-items:center;gap:8px;")}>
              <span style={chipWarn}>env override</span>
              <span style={css("font-family:var(--font-mono);font-size:10px;color:var(--text-faint);")}>
                {cfg.data?.env_key} is set; the live value comes from the environment and edits
                here will not take effect until it is unset.
              </span>
            </div>
          ) : null}

          {registry.length === 0 ? (
            <div style={moduleEmpty}>no modules registered</div>
          ) : (
            registry.map((mod) => (
              <section key={mod.module_id} style={css("display:flex;flex-direction:column;")}>
                <div style={moduleHeader}>
                  <span style={moduleTitle}>{mod.module_label}</span>
                  <span style={moduleId}>{mod.module_id}</span>
                </div>
                {mod.personas.length === 0 ? (
                  <div style={moduleEmpty}>no operator-routable personas</div>
                ) : (
                  mod.personas.map((persona) => {
                    const options = persona.task_type_options;
                    const value = currentValue(drafts, mod.module_id, persona.voice, options);
                    return (
                      <div key={persona.voice} style={personaRow}>
                        <div style={css("display:flex;flex-direction:column;gap:2px;")}>
                          <span style={personaName}>{persona.voice}</span>
                          <span style={roleTag}>{persona.role ?? "\u2014"}</span>
                        </div>
                        <select
                          value={value}
                          disabled={!enabled}
                          onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                            setPersona(mod.module_id, persona.voice, e.target.value)
                          }
                          style={enabled ? inputStyle : inputDisabled}
                        >
                          <option value="">-- default --</option>
                          {options.map((opt) => (
                            <option key={opt} value={opt}>
                              {opt}
                            </option>
                          ))}
                        </select>
                      </div>
                    );
                  })
                )}
              </section>
            ))
          )}

          <p style={css("font-family:var(--font-mono);font-size:10px;line-height:1.6;color:var(--text-faint);")}>
            A model_role is a task_type the LLM client resolves through{" "}
            <code style={css("color:var(--text-muted);")}>llm_model_&#123;role&#125;</code>. Wire
            the underlying model for each role on the Config page (namespace{" "}
            <code style={css("color:var(--text-muted);")}>platform</code>). Leaving a persona at
            &#8220;-- default --&#8221; keeps it on the module&apos;s base task_type.
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
        <span style={{ fontFamily: "var(--font-display)", color: "var(--text-primary)", fontWeight: 400, letterSpacing: "0.16em" }}>
          admin &middot; persona model routing
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          per-module persona sibling model map &mdash; adversarial diversity (#151)
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
