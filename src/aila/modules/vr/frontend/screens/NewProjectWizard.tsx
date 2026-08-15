import { useState } from "react";
import { useNavigate } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  SectionHeader,
  Segmented,
  MonoBadge,
} from "@/components/aila/mock";

import { useCreateVRProject } from "../mutations";
import { useRegisteredSystems, useWorkspaces } from "../queries";
import type {
  InputSource,
  RegisteredSystem,
  TargetClass,
  TargetIngestionSpec,
  VRWorkspaceSummary,
} from "../types";
import { UploadDropzone } from "../components/UploadDropzone";
import { WorkstationCompatibilityBadge } from "../components/WorkstationCompatibilityBadge";

/** 3-stage New Investigation wizard (08_FRONTEND_UX.md §1.2).
 *
 *  1. Target intake -- input source (upload / git_repo / http_url),
 *     target class, repo URL / refs / upload.
 *  2. Workstation selection -- pick a registered SSH host.
 *  3. Scope + authorisation -- name, CVE, notes, authorisation toggle. */

const INPUT_SOURCES: InputSource[] = ["upload", "git_repo", "http_url"];

const TARGET_CLASSES: TargetClass[] = [
  "native",
  "kernel",
  "hypervisor",
  "jvm",
  "python",
  "javascript",
  "php",
  "go",
  "rust",
  "android",
  "ios",
  "dotnet",
];

type StepId = "target" | "workstation" | "scope";

const STEP_OPTIONS: { value: StepId; label: string }[] = [
  { value: "target", label: "target" },
  { value: "workstation", label: "workstation" },
  { value: "scope", label: "scope" },
];

const STEP_ORDER: StepId[] = ["target", "workstation", "scope"];

// Shared inline styles for mock-language raw form controls.
const MOCK_INPUT_STYLE: React.CSSProperties = {
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  fontSize: 10.5,
  padding: "3px 6px",
  height: 26,
  borderRadius: 3,
  outline: "none",
  width: "100%",
};

const MOCK_TEXTAREA_STYLE: React.CSSProperties = {
  ...MOCK_INPUT_STYLE,
  height: "auto",
  padding: "6px 8px",
  lineHeight: 1.5,
};

const LABEL_STYLE: React.CSSProperties = {
  display: "block",
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
  textTransform: "uppercase",
  marginBottom: 5,
};

const FIELD_GAP = 12;

// ---------------------------------------------------------------------------
// Field wrapper -- lowercase mono uppercase label above the control.
// ---------------------------------------------------------------------------
function Field({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={htmlFor} style={LABEL_STYLE}>
        {label}
      </label>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// NewProjectWizard
// ---------------------------------------------------------------------------
export function NewProjectWizard() {
  const navigate = useNavigate();
  const { data: workspacesResult } = useWorkspaces();
  const { data: systems } = useRegisteredSystems();
  const createMut = useCreateVRProject();

  const [step, setStep] = useState<StepId>("target");

  // Step 1 -- target intake
  const [workspaceId, setWorkspaceId] = useState("");
  const [inputSource, setInputSource] = useState<InputSource>("git_repo");
  const [targetClass, setTargetClass] = useState<TargetClass>("native");
  const [sourceAvailable, setSourceAvailable] = useState(true);
  const [repoUrl, setRepoUrl] = useState("");
  const [vulnerableRef, setVulnerableRef] = useState("");
  const [patchedRef, setPatchedRef] = useState("");
  const [downloadUrl, setDownloadUrl] = useState("");
  const [uploadFilename, setUploadFilename] = useState("");

  // Step 2 -- workstation
  const [systemId, setSystemId] = useState<number | null>(null);

  // Step 3 -- scope
  const [name, setName] = useState("");
  const [cveId, setCveId] = useState("");
  const [contextNotes, setContextNotes] = useState("");
  const [authorised, setAuthorised] = useState(false);

  const workspaces: VRWorkspaceSummary[] = workspacesResult?.data ?? [];
  const systemList: RegisteredSystem[] = systems ?? [];

  const targetReady =
    !!workspaceId &&
    (inputSource === "upload"
      ? !!uploadFilename
      : inputSource === "git_repo"
        ? !!repoUrl
        : !!downloadUrl);
  const workstationReady = !!systemId;
  const scopeReady = !!name && authorised;

  // Only allow segment clicks to travel to an already-reachable step.
  const currentIdx = STEP_ORDER.indexOf(step);
  function onStepClick(next: StepId) {
    const nextIdx = STEP_ORDER.indexOf(next);
    if (nextIdx <= currentIdx) {
      setStep(next);
      return;
    }
    if (nextIdx === 1 && targetReady) setStep("workstation");
    else if (nextIdx === 2 && targetReady && workstationReady) setStep("scope");
  }

  function buildSpec(): TargetIngestionSpec {
    return {
      input_source: inputSource,
      target_class: targetClass,
      source_available: sourceAvailable,
      repo_url: inputSource === "git_repo" ? repoUrl : null,
      vulnerable_ref: inputSource === "git_repo" ? vulnerableRef || null : null,
      patched_ref: inputSource === "git_repo" ? patchedRef || null : null,
      download_url: inputSource === "http_url" ? downloadUrl : null,
      upload_filename: inputSource === "upload" ? uploadFilename : null,
    };
  }

  function submit() {
    if (!scopeReady || !systemId) return;
    createMut.mutate(
      {
        name,
        workspace_id: workspaceId,
        cve_id: cveId || null,
        target: buildSpec(),
        patched_target: null,
        context_notes: contextNotes,
        analysis_system_id: systemId,
      },
      {
        onSuccess: (result) => {
          navigate(`/vr/projects/${result.data.id}`);
        },
      },
    );
  }

  const headerActions = (
    <div className="flex items-center" style={{ gap: 10 }}>
      <Segmented<StepId>
        options={STEP_OPTIONS}
        value={step}
        onChange={onStepClick}
      />
      <button
        type="button"
        onClick={() => navigate("/vr")}
        className="font-mono uppercase"
        style={{
          height: 26,
          padding: "0 10px",
          fontSize: 9.5,
          letterSpacing: "0.09em",
          background: "transparent",
          color: "var(--text-muted)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
          cursor: "pointer",
        }}
      >
        cancel
      </button>
    </div>
  );

  return (
    <div className="flex flex-col" style={{ gap: 18 }}>
      <SectionHeader title="New Investigation" actions={headerActions} />

      {step === "target" && (
        <WindowPanel title="step 1 -- target intake" tone="accent">
          <div className="flex flex-col" style={{ gap: FIELD_GAP }}>
            <Field label="workspace" htmlFor="npw-workspace">
              <select
                id="npw-workspace"
                value={workspaceId}
                onChange={(e) => setWorkspaceId(e.target.value)}
                style={MOCK_INPUT_STYLE}
              >
                <option value="">-- pick a workspace --</option>
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name} ({w.theme})
                  </option>
                ))}
              </select>
            </Field>

            <Field label="input source">
              <div className="flex flex-wrap" style={{ gap: 6 }}>
                {INPUT_SOURCES.map((s) => {
                  const active = inputSource === s;
                  return (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setInputSource(s)}
                      className="font-mono uppercase"
                      style={{
                        height: 26,
                        padding: "0 10px",
                        fontSize: 9.5,
                        letterSpacing: "0.09em",
                        background: active ? "var(--accent)" : "var(--surface-sunk)",
                        color: active ? "var(--text-on-accent)" : "var(--text-muted)",
                        border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
                        borderRadius: 3,
                        cursor: "pointer",
                      }}
                    >
                      {s.replace("_", " ")}
                    </button>
                  );
                })}
              </div>
            </Field>

            <Field label="target class" htmlFor="npw-target-class">
              <select
                id="npw-target-class"
                value={targetClass}
                onChange={(e) => setTargetClass(e.target.value as TargetClass)}
                style={{ ...MOCK_INPUT_STYLE, width: 260 }}
              >
                {TARGET_CLASSES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </Field>

            <fieldset style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
              <legend className="sr-only">source availability</legend>
              <label
                className="flex items-center font-mono"
                style={{ gap: 6, fontSize: 10.5, color: "var(--text-primary)" }}
              >
                <input
                  type="checkbox"
                  checked={sourceAvailable}
                  onChange={(e) => setSourceAvailable(e.target.checked)}
                />
                <span>source code available (enables source-aware analysis)</span>
              </label>
            </fieldset>

            {inputSource === "git_repo" && (
              <>
                <Field label="repo url" htmlFor="npw-repo-url">
                  <input
                    id="npw-repo-url"
                    type="text"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    style={MOCK_INPUT_STYLE}
                  />
                </Field>
                <div
                  className="grid"
                  style={{ gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10 }}
                >
                  <Field label="vulnerable ref (optional)" htmlFor="npw-vulnerable-ref">
                    <input
                      id="npw-vulnerable-ref"
                      type="text"
                      value={vulnerableRef}
                      onChange={(e) => setVulnerableRef(e.target.value)}
                      placeholder="commit / tag / branch"
                      style={MOCK_INPUT_STYLE}
                    />
                  </Field>
                  <Field label="patched ref (optional)" htmlFor="npw-patched-ref">
                    <input
                      id="npw-patched-ref"
                      type="text"
                      value={patchedRef}
                      onChange={(e) => setPatchedRef(e.target.value)}
                      placeholder="commit / tag / branch"
                      style={MOCK_INPUT_STYLE}
                    />
                  </Field>
                </div>
              </>
            )}

            {inputSource === "http_url" && (
              <Field label="download url" htmlFor="npw-download-url">
                <input
                  id="npw-download-url"
                  type="text"
                  value={downloadUrl}
                  onChange={(e) => setDownloadUrl(e.target.value)}
                  placeholder="https://.../firmware.bin"
                  style={MOCK_INPUT_STYLE}
                />
              </Field>
            )}

            {inputSource === "upload" && (
              <Field label="upload artifact">
                <UploadDropzone
                  onFile={(file) => setUploadFilename(file.name)}
                  hint={
                    uploadFilename
                      ? `picked: ${uploadFilename}`
                      : "drop a .elf / .exe / .apk / .ipa / .so / .o"
                  }
                />
                <p
                  className="font-mono"
                  style={{ marginTop: 6, fontSize: 9.5, color: "var(--text-faint)" }}
                >
                  the file streams to the ida mcp after the project is created
                  (upload happens during scope submit). drop again to replace.
                </p>
              </Field>
            )}
          </div>
          <StepNav
            leftLabel={null}
            onLeft={null}
            rightLabel="next"
            rightAccent
            rightDisabled={!targetReady}
            onRight={() => setStep("workstation")}
          />
        </WindowPanel>
      )}

      {step === "workstation" && (
        <WindowPanel title="step 2 -- workstation" tone="info">
          <p
            className="font-mono"
            style={{ fontSize: 10.5, color: "var(--text-muted)", marginBottom: 12 }}
          >
            the research workstation runs the analysis pipeline (ida / fuzzers / poc execution).
            pick the host with the right tools + gpu + os.
          </p>
          {systemList.length === 0 ? (
            <div
              className="font-mono"
              style={{
                border: "1px dashed var(--accent)",
                background: "color-mix(in srgb, var(--accent) 4%, transparent)",
                borderRadius: 3,
                padding: 12,
                fontSize: 10.5,
                color: "var(--accent)",
              }}
            >
              no systems registered. register a workstation under <strong>systems</strong> first.
            </div>
          ) : (
            <div className="flex flex-col" style={{ gap: 6 }}>
              {systemList.map((s) => {
                const active = systemId === s.id;
                return (
                  <label
                    key={s.id}
                    className="flex items-center"
                    style={{
                      gap: 10,
                      border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
                      background: active
                        ? "color-mix(in srgb, var(--accent) 8%, transparent)"
                        : "var(--surface-card)",
                      borderRadius: 3,
                      padding: "10px 12px",
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="radio"
                      name="system"
                      checked={active}
                      onChange={() => setSystemId(s.id)}
                    />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        className="font-mono"
                        style={{
                          fontSize: 12,
                          color: "var(--text-primary)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {s.name}
                      </div>
                      <div
                        className="font-mono"
                        style={{ fontSize: 10, color: "var(--text-muted)" }}
                      >
                        {s.username}@{s.host}:{s.port}
                      </div>
                    </div>
                    <MonoBadge tone="info">system #{s.id}</MonoBadge>
                    <WorkstationCompatibilityBadge system={s} kind={targetClass} />
                  </label>
                );
              })}
            </div>
          )}
          <StepNav
            leftLabel="back"
            onLeft={() => setStep("target")}
            rightLabel="next"
            rightAccent
            rightDisabled={!workstationReady}
            onRight={() => setStep("scope")}
          />
        </WindowPanel>
      )}

      {step === "scope" && (
        <WindowPanel title="step 3 -- scope + authorisation" tone="warn">
          <div className="flex flex-col" style={{ gap: FIELD_GAP }}>
            <Field label="project name" htmlFor="npw-name">
              <input
                id="npw-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. cve-2024-12345 -- libpng analysis"
                style={MOCK_INPUT_STYLE}
              />
            </Field>
            <Field label="cve id (optional)" htmlFor="npw-cve">
              <input
                id="npw-cve"
                type="text"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                placeholder="CVE-YYYY-NNNNN"
                style={{ ...MOCK_INPUT_STYLE, width: 240 }}
              />
            </Field>
            <Field label="scope / context notes" htmlFor="npw-notes">
              <textarea
                id="npw-notes"
                value={contextNotes}
                onChange={(e) => setContextNotes(e.target.value)}
                rows={5}
                placeholder="what's in scope, what isn't. customer-supplied context. anything the agent should know up front."
                style={MOCK_TEXTAREA_STYLE}
              />
            </Field>
            <label
              className="flex items-start font-mono"
              style={{
                gap: 8,
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                borderRadius: 3,
                padding: 10,
                fontSize: 10.5,
                color: "var(--text-primary)",
              }}
            >
              <input
                type="checkbox"
                checked={authorised}
                onChange={(e) => setAuthorised(e.target.checked)}
                style={{ marginTop: 2 }}
              />
              <span>
                <strong>i confirm this engagement is in scope</strong> per signed
                authorisation. the project cannot be created without this
                (§1.2 / docs/vr/02_IDA_HEADLESS_MCP.md §6).
              </span>
            </label>
          </div>

          {createMut.isError && (
            <div
              className="font-mono"
              style={{
                marginTop: 12,
                border: "1px solid var(--accent)",
                background: "color-mix(in srgb, var(--accent) 5%, transparent)",
                borderRadius: 3,
                padding: 10,
                fontSize: 10.5,
                color: "var(--accent)",
              }}
            >
              {(createMut.error as Error)?.message ?? "create failed."}
            </div>
          )}

          <StepNav
            leftLabel="back"
            onLeft={() => setStep("workstation")}
            rightLabel={createMut.isPending ? "creating..." : "create project"}
            rightAccent
            rightDisabled={!scopeReady || createMut.isPending}
            onRight={submit}
          />
        </WindowPanel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// StepNav -- back / next / create-project button row at panel bottom.
// ---------------------------------------------------------------------------
function StepNav({
  leftLabel,
  onLeft,
  rightLabel,
  rightAccent,
  rightDisabled,
  onRight,
}: {
  leftLabel: string | null;
  onLeft: (() => void) | null;
  rightLabel: string;
  rightAccent: boolean;
  rightDisabled: boolean;
  onRight: () => void;
}) {
  return (
    <div
      className="flex items-center"
      style={{ justifyContent: "space-between", marginTop: 18 }}
    >
      {leftLabel && onLeft ? (
        <button
          type="button"
          onClick={onLeft}
          className="font-mono uppercase"
          style={{
            height: 28,
            padding: "0 14px",
            fontSize: 10,
            letterSpacing: "0.09em",
            background: "transparent",
            color: "var(--text-muted)",
            border: "1px solid var(--border-soft)",
            borderRadius: 3,
            cursor: "pointer",
          }}
        >
          {leftLabel}
        </button>
      ) : (
        <span />
      )}
      <button
        type="button"
        onClick={onRight}
        disabled={rightDisabled}
        className="font-mono uppercase"
        style={{
          height: 28,
          padding: "0 16px",
          fontSize: 10,
          letterSpacing: "0.09em",
          background: rightAccent ? "var(--accent)" : "var(--surface-sunk)",
          color: rightAccent ? "var(--text-on-accent)" : "var(--text-muted)",
          border: `1px solid ${rightAccent ? "var(--accent)" : "var(--border-soft)"}`,
          borderRadius: 3,
          cursor: rightDisabled ? "not-allowed" : "pointer",
          opacity: rightDisabled ? 0.4 : 1,
        }}
      >
        {rightLabel}
      </button>
    </div>
  );
}
