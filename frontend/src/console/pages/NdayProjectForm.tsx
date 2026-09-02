/**
 * NdayProjectForm -- the n-day CVE reproduction surface. Opens as a bespoke
 * registry page (`vr:new-project`) from the CVE registry ("reproduce" on a row
 * or "+ new") and drives the existing VR_NDAY_V1 flow via POST /vr/projects:
 *
 *   setup -> research -> poc_development -> advisory -> response_emit
 *
 * The operator binds a workspace, the vulnerable target (an already-ingested
 * binary, a git repo, or a download url), an optional patched build for
 * differential PoC validation, a CVE (picked from the /vr/cves registry or
 * entered manually), the IDA analysis workstation, and -- optionally -- a PoC
 * executor host. When no executor host is bound the form states plainly that
 * PoC development is reported as `untested`; research + advisory still run.
 * Every field maps 1:1 to a declared field on VRProjectCreate; there is no
 * fabricated payload.
 */

import { Fragment, useEffect, useMemo, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import type { ApiError } from "../../api/client";
import type {
  CreatedVRProject,
  TargetIngestionSpecPayload,
} from "../../api/intake";
import { useCreateVrProject, useVrCves, useWorkspaces } from "../../api/intake";
import { useSystems } from "../../api/systems";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";

/* -------------------------------------------------------------------------- *
 * Ingestion sub-form
 * -------------------------------------------------------------------------- */

type TargetMode = "binary" | "git_repo" | "http_url";

const MODE_LABELS: Array<[TargetMode, string]> = [
  ["binary", "existing binary"],
  ["git_repo", "git repo"],
  ["http_url", "download url"],
];

const TARGET_CLASSES = [
  "native", "kernel", "hypervisor", "jvm", "python", "javascript",
  "php", "go", "rust", "android", "ios", "dotnet",
] as const;

interface IngestState {
  mode: TargetMode;
  binaryId: string;
  repoUrl: string;
  vulnerableRef: string;
  patchedRef: string;
  buildCommand: string;
  buildArtifact: string;
  downloadUrl: string;
}

const emptyIngest = (): IngestState => ({
  mode: "git_repo",
  binaryId: "",
  repoUrl: "",
  vulnerableRef: "",
  patchedRef: "",
  buildCommand: "",
  buildArtifact: "",
  downloadUrl: "",
});

function ingestReady(st: IngestState): boolean {
  if (st.mode === "binary") return st.binaryId.trim() !== "";
  if (st.mode === "git_repo") return st.repoUrl.trim() !== "";
  return st.downloadUrl.trim() !== "";
}

/** Materialize one IngestState into the TargetIngestionSpec the API expects.
 * `patched` routes the git ref field to `patched_ref` for the differential
 * build; the primary target carries `vulnerable_ref`. */
function buildSpec(
  st: IngestState,
  targetClass: string,
  sourceAvailable: boolean,
  patched: boolean,
): TargetIngestionSpecPayload {
  const base = { target_class: targetClass, source_available: sourceAvailable };
  if (st.mode === "binary") {
    return { ...base, input_source: "upload", binary_id: st.binaryId.trim() };
  }
  if (st.mode === "git_repo") {
    return {
      ...base,
      input_source: "git_repo",
      repo_url: st.repoUrl.trim(),
      vulnerable_ref: st.vulnerableRef.trim() || null,
      patched_ref: patched ? st.patchedRef.trim() || null : null,
      build_command: st.buildCommand.trim() || null,
      build_artifact: st.buildArtifact.trim() || null,
    };
  }
  return { ...base, input_source: "http_url", download_url: st.downloadUrl.trim() };
}

/* -------------------------------------------------------------------------- *
 * Style helpers -- mirror UploadForm / DataPage
 * -------------------------------------------------------------------------- */

const panelBox =
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));";
const panelTitle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const sectionLabel = css(
  "font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);",
);
const labelStyle = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);
const fieldCol = css("display:flex;flex-direction:column;gap:4px;");
const inputStyle = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;border-radius:2px;",
);
const selectStyle = inputStyle;
const chipRow = css("display:grid;grid-template-columns:repeat(3,1fr);gap:6px;");

function modeButton(active: boolean): string {
  return `padding:8px 9px;text-align:left;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.04em;color:${
    active ? "var(--accent)" : "var(--text-primary)"
  };background:${
    active ? "color-mix(in srgb,var(--accent) 10%,transparent)" : "var(--surface-card)"
  };border:1px solid ${active ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;cursor:pointer;`;
}

/* -------------------------------------------------------------------------- *
 * Ingestion block (target + optional patched build)
 * -------------------------------------------------------------------------- */

function IngestBlock({
  st,
  set,
  patched,
}: {
  st: IngestState;
  set: (patch: Partial<IngestState>) => void;
  patched?: boolean;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <div style={chipRow}>
        {MODE_LABELS.map(([m, lbl]) => (
          <button
            key={m}
            type="button"
            onClick={(): void => set({ mode: m })}
            style={css(modeButton(st.mode === m))}
          >
            {lbl}
          </button>
        ))}
      </div>
      {st.mode === "binary" ? (
        <label style={fieldCol}>
          <span style={labelStyle}>binary id</span>
          <input
            style={inputStyle}
            value={st.binaryId}
            placeholder="already-ingested mcp binary id"
            onChange={(e: ChangeEvent<HTMLInputElement>): void => set({ binaryId: e.target.value })}
          />
        </label>
      ) : st.mode === "git_repo" ? (
        <>
          <label style={fieldCol}>
            <span style={labelStyle}>repo url</span>
            <input
              style={inputStyle}
              value={st.repoUrl}
              placeholder="https://github.com/org/proj"
              onChange={(e: ChangeEvent<HTMLInputElement>): void => set({ repoUrl: e.target.value })}
            />
          </label>
          <label style={fieldCol}>
            <span style={labelStyle}>{patched ? "patched ref" : "vulnerable ref"}</span>
            <input
              style={inputStyle}
              value={patched ? st.patchedRef : st.vulnerableRef}
              placeholder="tag / branch / commit"
              onChange={(e: ChangeEvent<HTMLInputElement>): void =>
                set(patched ? { patchedRef: e.target.value } : { vulnerableRef: e.target.value })
              }
            />
          </label>
          <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:8px;")}>
            <label style={fieldCol}>
              <span style={labelStyle}>build command</span>
              <input
                style={inputStyle}
                value={st.buildCommand}
                placeholder="optional"
                onChange={(e: ChangeEvent<HTMLInputElement>): void => set({ buildCommand: e.target.value })}
              />
            </label>
            <label style={fieldCol}>
              <span style={labelStyle}>build artifact</span>
              <input
                style={inputStyle}
                value={st.buildArtifact}
                placeholder="optional path"
                onChange={(e: ChangeEvent<HTMLInputElement>): void => set({ buildArtifact: e.target.value })}
              />
            </label>
          </div>
        </>
      ) : (
        <label style={fieldCol}>
          <span style={labelStyle}>download url</span>
          <input
            style={inputStyle}
            value={st.downloadUrl}
            placeholder="https://.../target"
            onChange={(e: ChangeEvent<HTMLInputElement>): void => set({ downloadUrl: e.target.value })}
          />
        </label>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- *
 * Component
 * -------------------------------------------------------------------------- */

export default function NdayProjectForm(props: ModulePageProps): JSX.Element {
  const {
    investigationId,
    onBack,
    onMinimize,
    isFullscreen,
    onToggleFullscreen,
    windowId,
    title: windowTitle,
    isFocused,
    onFocus,
  } = props;

  const prefillCve = (investigationId ?? "").trim();

  const workspaces = useWorkspaces("vr");
  const systems = useSystems(1, 200);
  const cves = useVrCves();
  const createProject = useCreateVrProject();

  const [name, setName] = useState<string>(prefillCve);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [cveMode, setCveMode] = useState<"registry" | "manual">("registry");
  const [cveId, setCveId] = useState<string>(prefillCve);
  const [targetClass, setTargetClass] = useState<string>("native");
  const [sourceAvailable, setSourceAvailable] = useState<boolean>(false);
  const [target, setTarget] = useState<IngestState>(emptyIngest);
  const [patchedEnabled, setPatchedEnabled] = useState<boolean>(false);
  const [patched, setPatched] = useState<IngestState>(emptyIngest);
  const [analysisSystemId, setAnalysisSystemId] = useState<string>("");
  const [pocSystemId, setPocSystemId] = useState<string>("");
  const [notes, setNotes] = useState<string>("");
  const [created, setCreated] = useState<CreatedVRProject | null>(null);
  const [error, setError] = useState<string | null>(null);

  const systemRows = systems.data?.items ?? [];
  const wsRows = workspaces.data ?? [];
  const cveRows = cves.data ?? [];
  const busy = createProject.isPending;
  const noSystems = !systems.isLoading && systemRows.length === 0;
  const pocUntested = pocSystemId === "";

  // Idempotent defaults once the lists arrive.
  useEffect(() => {
    if (wsRows.length > 0 && workspaceId === "") setWorkspaceId(wsRows[0].id);
  }, [wsRows, workspaceId]);
  useEffect(() => {
    if (systemRows.length > 0 && analysisSystemId === "") {
      setAnalysisSystemId(String(systemRows[0].id));
    }
  }, [systemRows, analysisSystemId]);

  // Registry options include the prefilled CVE even before the list loads (or
  // when it isn't in the registry), so the prefill is always selectable.
  const cveOptions = useMemo(() => {
    const opts = cveRows.map((r) => ({
      value: r.cve_id,
      label: r.title ? `${r.cve_id} \u00b7 ${r.title}` : r.cve_id,
    }));
    if (prefillCve && !cveRows.some((r) => r.cve_id === prefillCve)) {
      opts.unshift({ value: prefillCve, label: prefillCve });
    }
    return opts;
  }, [cveRows, prefillCve]);

  const setTargetField = (patch: Partial<IngestState>): void => setTarget((s) => ({ ...s, ...patch }));
  const setPatchedField = (patch: Partial<IngestState>): void => setPatched((s) => ({ ...s, ...patch }));

  const canSubmit =
    !busy &&
    !created &&
    !noSystems &&
    workspaceId.trim() !== "" &&
    name.trim() !== "" &&
    analysisSystemId.trim() !== "" &&
    ingestReady(target) &&
    (!patchedEnabled || ingestReady(patched));

  async function onSubmit(): Promise<void> {
    if (!canSubmit) return;
    setError(null);
    try {
      const result = await createProject.mutateAsync({
        name: name.trim(),
        workspace_id: workspaceId,
        cve_id: cveId.trim() || null,
        target: buildSpec(target, targetClass, sourceAvailable, false),
        patched_target: patchedEnabled ? buildSpec(patched, targetClass, sourceAvailable, true) : null,
        context_notes: notes.trim(),
        analysis_system_id: Number(analysisSystemId),
        poc_system_id: pocSystemId === "" ? null : Number(pocSystemId),
      });
      setCreated(result);
    } catch (err) {
      const msg =
        err && typeof err === "object" && "message" in err
          ? String((err as ApiError).message || "").slice(0, 400)
          : "unknown error";
      setError(msg);
    }
  }

  /* ---- render blocks --------------------------------------------------- */

  const systemSelect = (
    value: string,
    onChange: (v: string) => void,
    allowNone: boolean,
  ): ReactNode => {
    if (systems.isLoading) {
      return <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading systems\u2026"}</span>;
    }
    if (noSystems) {
      return (
        <span style={css("font-size:11px;color:var(--status-warn);")}>
          {"no systems registered -- add one from platform \u00b7 systems first"}
        </span>
      );
    }
    return (
      <select
        value={value}
        onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange(e.target.value)}
        style={selectStyle}
      >
        {allowNone ? <option value="">{"\u2014 none (poc untested) \u2014"}</option> : null}
        {systemRows.map((s) => (
          <option key={s.id} value={String(s.id)}>
            {s.name} {"\u00b7"} {s.host}
          </option>
        ))}
      </select>
    );
  };

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--accent)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        {"vr \u00b7 n-day project"}
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
        POST /vr/projects {"\u2192"} VR_NDAY_V1
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={windowTitle}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <main style={{ flex: 1, minHeight: 0, display: "flex", padding: 12 }}>
        <div style={{ ...css(`flex:1;${panelBox}`) }}>
          <div style={panelTitle}>
            <span style={dot} />
            <span style={css("color:var(--text-primary);")}>{created ? "created" : "reproduce a known cve"}</span>
            <span style={css("flex:1;")} />
            <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
              n-day
            </span>
          </div>
          <div
            style={css(
              "flex:1;min-height:0;overflow:auto;padding:14px;display:flex;flex-direction:column;gap:16px;max-width:760px;",
            )}
          >
            {created ? (
              <div
                style={css(
                  "display:flex;flex-direction:column;gap:12px;padding:14px;border:1px solid var(--status-ok);border-radius:3px;background:color-mix(in srgb,var(--status-ok) 8%,transparent);",
                )}
              >
                <div style={css("font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--status-ok);")}>
                  {"n-day project created \u00b7 VR_NDAY_V1 started"}
                </div>
                <div style={css("display:grid;grid-template-columns:130px 1fr;gap:5px 12px;font-size:11.5px;")}>
                  <span style={css("color:var(--text-faint);")}>id</span>
                  <span style={css("color:var(--text-primary);word-break:break-all;")}>{created.id}</span>
                  <span style={css("color:var(--text-faint);")}>name</span>
                  <span style={css("color:var(--text-primary);")}>{created.name}</span>
                  <span style={css("color:var(--text-faint);")}>status</span>
                  <span style={css("color:var(--text-primary);")}>{created.status}</span>
                  {created.cve_id ? (
                    <>
                      <span style={css("color:var(--text-faint);")}>cve</span>
                      <span style={css("color:var(--text-primary);")}>{created.cve_id}</span>
                    </>
                  ) : null}
                </div>
                {pocUntested ? (
                  <div style={css("font-size:11px;color:var(--status-warn);word-break:break-word;")}>
                    {"no poc executor host was bound: poc development will be reported as `untested`. bind an executor host and re-run to develop a live poc."}
                  </div>
                ) : null}
              </div>
            ) : (
              <>
                {/* project */}
                <div style={css("display:flex;flex-direction:column;gap:10px;")}>
                  <span style={sectionLabel}>project</span>
                  <label style={fieldCol}>
                    <span style={labelStyle}>name</span>
                    <input
                      style={inputStyle}
                      value={name}
                      placeholder="reproduction name"
                      onChange={(e: ChangeEvent<HTMLInputElement>): void => setName(e.target.value)}
                    />
                  </label>
                  <label style={fieldCol}>
                    <span style={labelStyle}>workspace</span>
                    {workspaces.isLoading ? (
                      <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading workspaces\u2026"}</span>
                    ) : wsRows.length === 0 ? (
                      <span style={css("font-size:11px;color:var(--text-faint);")}>
                        {"no workspaces -- create one from vr \u00b7 workspaces first"}
                      </span>
                    ) : (
                      <select
                        value={workspaceId}
                        onChange={(e: ChangeEvent<HTMLSelectElement>): void => setWorkspaceId(e.target.value)}
                        style={selectStyle}
                      >
                        {wsRows.map((w) => (
                          <option key={w.id} value={w.id}>
                            {w.name}
                            {w.slug ? ` \u00b7 ${w.slug}` : ""}
                          </option>
                        ))}
                      </select>
                    )}
                  </label>
                </div>

                {/* cve */}
                <div style={css("display:flex;flex-direction:column;gap:10px;")}>
                  <span style={sectionLabel}>cve</span>
                  <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:6px;")}>
                    <button
                      type="button"
                      onClick={(): void => setCveMode("registry")}
                      style={css(modeButton(cveMode === "registry"))}
                    >
                      from registry
                    </button>
                    <button
                      type="button"
                      onClick={(): void => setCveMode("manual")}
                      style={css(modeButton(cveMode === "manual"))}
                    >
                      manual entry
                    </button>
                  </div>
                  {cveMode === "registry" ? (
                    cves.isLoading ? (
                      <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading cves\u2026"}</span>
                    ) : cveOptions.length === 0 ? (
                      <span style={css("font-size:11px;color:var(--text-faint);")}>
                        {"registry empty -- switch to manual entry or ingest a cve from vr \u00b7 cves"}
                      </span>
                    ) : (
                      <select
                        value={cveId}
                        onChange={(e: ChangeEvent<HTMLSelectElement>): void => setCveId(e.target.value)}
                        style={selectStyle}
                      >
                        <option value="">{"\u2014 select a cve \u2014"}</option>
                        {cveOptions.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    )
                  ) : (
                    <input
                      style={inputStyle}
                      value={cveId}
                      placeholder="CVE-2026-1234"
                      onChange={(e: ChangeEvent<HTMLInputElement>): void => setCveId(e.target.value)}
                    />
                  )}
                </div>

                {/* target ingestion */}
                <div style={css("display:flex;flex-direction:column;gap:10px;")}>
                  <span style={sectionLabel}>vulnerable target</span>
                  <IngestBlock st={target} set={setTargetField} />
                  <div style={css("display:grid;grid-template-columns:1fr auto;gap:10px;align-items:end;")}>
                    <label style={fieldCol}>
                      <span style={labelStyle}>target class</span>
                      <select
                        value={targetClass}
                        onChange={(e: ChangeEvent<HTMLSelectElement>): void => setTargetClass(e.target.value)}
                        style={selectStyle}
                      >
                        {TARGET_CLASSES.map((tc) => (
                          <option key={tc} value={tc}>
                            {tc}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;padding-bottom:8px;")}>
                      <input
                        type="checkbox"
                        checked={sourceAvailable}
                        onChange={(e: ChangeEvent<HTMLInputElement>): void => setSourceAvailable(e.target.checked)}
                      />
                      source available
                    </label>
                  </div>
                </div>

                {/* patched */}
                <div style={css("display:flex;flex-direction:column;gap:10px;")}>
                  <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
                    <input
                      type="checkbox"
                      checked={patchedEnabled}
                      onChange={(e: ChangeEvent<HTMLInputElement>): void => setPatchedEnabled(e.target.checked)}
                    />
                    <span style={sectionLabel}>bind patched build (differential poc)</span>
                  </label>
                  {patchedEnabled ? <IngestBlock st={patched} set={setPatchedField} patched /> : null}
                </div>

                {/* execution hosts */}
                <div style={css("display:flex;flex-direction:column;gap:10px;")}>
                  <span style={sectionLabel}>execution hosts</span>
                  <label style={fieldCol}>
                    <span style={labelStyle}>analysis workstation (required)</span>
                    {systemSelect(analysisSystemId, setAnalysisSystemId, false)}
                  </label>
                  <label style={fieldCol}>
                    <span style={labelStyle}>poc executor host (optional)</span>
                    {systemSelect(pocSystemId, setPocSystemId, true)}
                  </label>
                  {pocUntested && !noSystems ? (
                    <div style={css("font-size:11px;color:var(--status-warn);word-break:break-word;")}>
                      {"no poc executor host selected: research + advisory run, but poc development is reported as `untested` until an executor host is bound."}
                    </div>
                  ) : null}
                </div>

                {/* notes */}
                <label style={fieldCol}>
                  <span style={labelStyle}>context notes (optional)</span>
                  <textarea
                    style={css(`${inputStyle};min-height:64px;resize:vertical;`)}
                    value={notes}
                    placeholder="anything the agent should know about this target"
                    onChange={(e: ChangeEvent<HTMLTextAreaElement>): void => setNotes(e.target.value)}
                  />
                </label>
              </>
            )}

            {error ? (
              <div
                style={css(
                  "padding:8px 10px;border:1px solid var(--status-warn);color:var(--status-warn);font-size:11px;border-radius:2px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);white-space:pre-wrap;word-break:break-word;",
                )}
              >
                {error}
              </div>
            ) : null}

            <div
              style={css(
                "display:flex;align-items:center;gap:9px;padding-top:10px;border-top:1px solid var(--border-soft);",
              )}
            >
              <button
                type="button"
                onClick={onBack}
                style={css(
                  "padding:0 12px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);background:transparent;border:1px solid var(--border-soft);border-radius:3px;cursor:pointer;",
                )}
              >
                {created ? "close" : "cancel"}
              </button>
              <span style={css("flex:1;")} />
              {busy ? (
                <span style={css("font-size:11px;color:var(--accent);letter-spacing:0.06em;")}>{"submitting\u2026"}</span>
              ) : null}
              {!created ? (
                <button
                  type="button"
                  onClick={(): void => void onSubmit()}
                  disabled={!canSubmit}
                  style={css(
                    `padding:0 16px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:${
                      canSubmit ? "pointer" : "not-allowed"
                    };opacity:${canSubmit ? 1 : 0.5};`,
                  )}
                >
                  {"start reproduction \u25b8"}
                </button>
              ) : null}
            </div>
          </div>
        </div>
      </main>
    </ConsoleWindow>
  );
}

/* -------------------------------------------------------------------------- *
 * CVE detail body (the "reproduce" affordance in the /vr/cves detail panel)
 * -------------------------------------------------------------------------- */

/** Rendered as the DataPage detail body for a selected CVE row: the row's key
 * fields plus a prominent "reproduce" control that opens NdayProjectForm
 * prefilled with this CVE. */
export function CveReproduceDetail({
  row,
  onReproduce,
}: {
  row: Record<string, unknown>;
  onReproduce: () => void;
}): JSX.Element {
  const val = (k: string): string => {
    const v = row[k];
    return v === null || v === undefined ? "" : String(v);
  };
  const list = (k: string): string => {
    const v = row[k];
    return Array.isArray(v) ? v.map(String).join(", ") : "";
  };
  const fields: Array<[string, string]> = [
    ["cve", val("cve_id")],
    ["source", val("source")],
    ["cvss", val("cvss_score")],
    ["published", val("published_at")],
    ["cwe", list("cwe_ids")],
    ["components", list("affected_components")],
    ["title", val("title")],
  ];
  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <button
        type="button"
        onClick={onReproduce}
        style={css(
          "align-self:flex-start;padding:0 14px;height:32px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:3px;cursor:pointer;",
        )}
      >
        {"reproduce \u25b8 start n-day project"}
      </button>
      <div style={css("display:grid;grid-template-columns:110px 1fr;gap:5px 12px;font-size:11.5px;")}>
        {fields
          .filter(([, v]) => v !== "")
          .map(([k, v]) => (
            <Fragment key={k}>
              <span style={css("color:var(--text-faint);")}>{k}</span>
              <span style={css("color:var(--text-primary);word-break:break-word;")}>{v}</span>
            </Fragment>
          ))}
      </div>
      {val("description") ? (
        <div style={css("display:flex;flex-direction:column;gap:4px;")}>
          <span style={css("color:var(--text-faint);font-size:9px;letter-spacing:0.12em;text-transform:uppercase;")}>
            description
          </span>
          <p style={css("margin:0;font-size:11.5px;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;")}>
            {val("description")}
          </p>
        </div>
      ) : null}
    </div>
  );
}
