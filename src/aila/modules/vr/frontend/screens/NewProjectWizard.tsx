import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";

import { useCreateVRProject } from "../mutations";
import { useRegisteredSystems, useWorkspaces } from "../queries";
import type {
  InputSource,
  RegisteredSystem,
  TargetClass,
  TargetIngestionSpec,
  VRWorkspaceSummary,
} from "../types";

/** 3-stage New Project Wizard (08_FRONTEND_UX.md §1.2).
 *
 *  Steps:
 *    1. Target intake — input source (upload / git_repo / http_url),
 *       target class, repo URL / refs.
 *    2. Workstation selection — pick a registered SSH host.
 *    3. Scope + authorisation — name, CVE, notes, authorisation toggle.
 *
 *  The wizard never persists until the final step. Closing the tab
 *  discards everything per spec.
 *
 *  Backend gap: upload widget for firmware/binary upload at step 1 is
 *  pending (the workstation needs a binary already on its filesystem;
 *  v0.4.5 only supports IDA MCP upload via a separate target). Wizard
 *  shows the field but routes that flow through git_repo / http_url
 *  for now. */

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

type Step = 1 | 2 | 3;

export function NewProjectWizard() {
  const navigate = useNavigate();
  const { data: workspacesResult } = useWorkspaces();
  const { data: systems } = useRegisteredSystems();
  const createMut = useCreateVRProject();

  const [step, setStep] = useState<Step>(1);

  // Step 1 — target intake
  const [workspaceId, setWorkspaceId] = useState("");
  const [inputSource, setInputSource] = useState<InputSource>("git_repo");
  const [targetClass, setTargetClass] = useState<TargetClass>("native");
  const [sourceAvailable, setSourceAvailable] = useState(true);
  const [repoUrl, setRepoUrl] = useState("");
  const [vulnerableRef, setVulnerableRef] = useState("");
  const [patchedRef, setPatchedRef] = useState("");
  const [downloadUrl, setDownloadUrl] = useState("");
  const [uploadFilename, setUploadFilename] = useState("");

  // Step 2 — workstation
  const [systemId, setSystemId] = useState<number | null>(null);

  // Step 3 — scope
  const [name, setName] = useState("");
  const [cveId, setCveId] = useState("");
  const [contextNotes, setContextNotes] = useState("");
  const [authorised, setAuthorised] = useState(false);

  const workspaces: VRWorkspaceSummary[] = workspacesResult?.data ?? [];
  const systemList: RegisteredSystem[] = systems ?? [];

  const step1Ready =
    !!workspaceId &&
    (inputSource === "upload"
      ? !!uploadFilename
      : inputSource === "git_repo"
        ? !!repoUrl
        : !!downloadUrl);

  const step2Ready = !!systemId;
  const step3Ready = !!name && authorised;

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
    if (!step3Ready || !systemId) return;
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

  return (
    <div className="space-y-4 max-w-3xl mx-auto">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            New Project
          </h1>
          <p className="text-xs text-text-muted mt-1">
            3 steps. Nothing is persisted until you submit at step 3.
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate("/vr")}
          className="text-xs px-3 py-1.5 rounded bg-surface border border-border-default hover:bg-surface-hover"
        >
          Cancel
        </button>
      </div>

      {/* Stepper */}
      <WizardStepper step={step} />

      {/* Step 1 — Target intake */}
      {step === 1 && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Step 1 — Target intake
          </h2>
          <div className="space-y-3 text-sm">
            <Field label="Workspace">
              <select
                value={workspaceId}
                onChange={(e) => setWorkspaceId(e.target.value)}
                className="w-full px-2 py-1.5 text-sm rounded bg-surface border border-border-default"
              >
                <option value="">— Pick a workspace —</option>
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name} ({w.theme})
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Input source">
              <div className="flex gap-1 flex-wrap">
                {INPUT_SOURCES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setInputSource(s)}
                    className={
                      "px-2 py-1 text-xs font-mono rounded border " +
                      (inputSource === s
                        ? "bg-accent text-white border-accent"
                        : "bg-surface text-foreground border-border-default hover:bg-surface-hover")
                    }
                  >
                    {s}
                  </button>
                ))}
              </div>
            </Field>

            <Field label="Target class">
              <select
                value={targetClass}
                onChange={(e) => setTargetClass(e.target.value as TargetClass)}
                className="px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
              >
                {TARGET_CLASSES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </Field>

            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={sourceAvailable}
                onChange={(e) => setSourceAvailable(e.target.checked)}
              />
              <span>Source code available (enables source-aware analysis)</span>
            </label>

            {/* Source-specific fields */}
            {inputSource === "git_repo" && (
              <>
                <Field label="Repo URL">
                  <input
                    type="text"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
                  />
                </Field>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Vulnerable ref (optional)">
                    <input
                      type="text"
                      value={vulnerableRef}
                      onChange={(e) => setVulnerableRef(e.target.value)}
                      placeholder="commit / tag / branch"
                      className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
                    />
                  </Field>
                  <Field label="Patched ref (optional)">
                    <input
                      type="text"
                      value={patchedRef}
                      onChange={(e) => setPatchedRef(e.target.value)}
                      placeholder="commit / tag / branch"
                      className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
                    />
                  </Field>
                </div>
              </>
            )}

            {inputSource === "http_url" && (
              <Field label="Download URL">
                <input
                  type="text"
                  value={downloadUrl}
                  onChange={(e) => setDownloadUrl(e.target.value)}
                  placeholder="https://…/firmware.bin"
                  className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
                />
              </Field>
            )}

            {inputSource === "upload" && (
              <Field label="Upload filename">
                <input
                  type="text"
                  value={uploadFilename}
                  onChange={(e) => setUploadFilename(e.target.value)}
                  placeholder="binary.elf"
                  className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
                />
                <p className="text-[10px] text-text-muted mt-1">
                  <AilaBadge severity="info" size="sm">
                    upload pending
                  </AilaBadge>{" "}
                  Drag-drop upload widget ships once the workstation file
                  push endpoint lands. For now the filename is a reference
                  the project will surface to the operator.
                </p>
              </Field>
            )}
          </div>
          <div className="flex justify-between mt-4">
            <span />
            <button
              type="button"
              disabled={!step1Ready}
              onClick={() => setStep(2)}
              className="px-3 py-1.5 text-sm font-medium rounded bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
            >
              Continue →
            </button>
          </div>
        </AilaCard>
      )}

      {/* Step 2 — Workstation */}
      {step === 2 && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Step 2 — Workstation selection
          </h2>
          <p className="text-xs text-text-muted mb-3">
            The research workstation runs the analysis pipeline (IDA / fuzzers
            / PoC execution). Pick the host with the right tools + GPU + OS.
          </p>
          {systemList.length === 0 ? (
            <div className="border border-dashed border-border-danger rounded p-3 bg-surface/40">
              <p className="text-xs text-text-danger">
                No systems registered. Register a workstation under{" "}
                <strong>Systems</strong> first.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {systemList.map((s) => (
                <label
                  key={s.id}
                  className={
                    "block border rounded p-3 cursor-pointer transition-colors " +
                    (systemId === s.id
                      ? "border-accent bg-surface"
                      : "border-border-default hover:bg-surface-hover")
                  }
                >
                  <div className="flex items-center gap-3">
                    <input
                      type="radio"
                      name="system"
                      checked={systemId === s.id}
                      onChange={() => setSystemId(s.id)}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-mono text-foreground truncate">
                        {s.name}
                      </div>
                      <div className="text-xs text-text-muted font-mono">
                        {s.username}@{s.host}:{s.port}
                      </div>
                    </div>
                    <AilaBadge severity="info" size="sm">
                      system #{s.id}
                    </AilaBadge>
                  </div>
                </label>
              ))}
            </div>
          )}
          <div className="flex justify-between mt-4">
            <button
              type="button"
              onClick={() => setStep(1)}
              className="px-3 py-1.5 text-sm font-medium rounded bg-surface border border-border-default hover:bg-surface-hover"
            >
              ← Back
            </button>
            <button
              type="button"
              disabled={!step2Ready}
              onClick={() => setStep(3)}
              className="px-3 py-1.5 text-sm font-medium rounded bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
            >
              Continue →
            </button>
          </div>
        </AilaCard>
      )}

      {/* Step 3 — Scope + authorisation */}
      {step === 3 && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Step 3 — Scope + authorisation
          </h2>
          <div className="space-y-3 text-sm">
            <Field label="Project name">
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. 'CVE-2024-12345 — libpng analysis'"
                className="w-full px-2 py-1.5 text-sm rounded bg-surface border border-border-default"
              />
            </Field>

            <Field label="CVE ID (optional)">
              <input
                type="text"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                placeholder="CVE-YYYY-NNNNN"
                className="w-64 px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
              />
            </Field>

            <Field label="Scope / context notes">
              <textarea
                value={contextNotes}
                onChange={(e) => setContextNotes(e.target.value)}
                rows={4}
                placeholder="What's in scope, what isn't. Customer-supplied context. Anything the agent should know up front."
                className="w-full px-2 py-1.5 text-sm font-mono rounded bg-surface border border-border-default"
              />
            </Field>

            <label className="flex items-start gap-2 text-xs border border-border-default rounded p-3 bg-surface/40">
              <input
                type="checkbox"
                checked={authorised}
                onChange={(e) => setAuthorised(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                <strong className="text-foreground">
                  I confirm this engagement is in scope
                </strong>{" "}
                per signed authorisation. The project cannot be created
                without this (§1.2 / docs/vr/02_IDA_HEADLESS_MCP.md §6).
              </span>
            </label>
          </div>

          {createMut.isError && (
            <div className="mt-3 border border-border-danger rounded p-2 bg-surface/40 text-xs text-text-danger">
              {(createMut.error as Error)?.message ?? "Create failed."}
            </div>
          )}

          <div className="flex justify-between mt-4">
            <button
              type="button"
              onClick={() => setStep(2)}
              className="px-3 py-1.5 text-sm font-medium rounded bg-surface border border-border-default hover:bg-surface-hover"
            >
              ← Back
            </button>
            <button
              type="button"
              disabled={!step3Ready || createMut.isPending}
              onClick={submit}
              className="px-4 py-1.5 text-sm font-medium rounded bg-accent text-white hover:bg-accent/90 disabled:opacity-40"
            >
              {createMut.isPending ? "Starting…" : "Start research"}
            </button>
          </div>
        </AilaCard>
      )}
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs text-text-muted mb-1">{label}</label>
      {children}
    </div>
  );
}

function WizardStepper({ step }: { step: Step }) {
  const steps = ["Target intake", "Workstation", "Scope + auth"];
  return (
    <ol className="flex items-center gap-0 text-xs font-mono select-none">
      {steps.map((label, i) => {
        const num = (i + 1) as Step;
        const active = num === step;
        const done = num < step;
        return (
          <li key={label} className="flex items-center flex-1 last:flex-initial gap-2">
            <div
              className={
                "w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border-2 " +
                (active
                  ? "bg-accent border-accent text-white"
                  : done
                    ? "bg-surface border-border-default text-text-muted"
                    : "bg-surface border-border-default text-text-muted opacity-60")
              }
            >
              {done ? "✓" : num}
            </div>
            <span
              className={
                active
                  ? "text-foreground font-semibold"
                  : "text-text-muted " + (done ? "" : "opacity-60")
              }
            >
              {label}
            </span>
            {i < steps.length - 1 && (
              <div
                className={
                  "h-px flex-1 " +
                  (done ? "bg-accent/40" : "bg-border-default")
                }
              />
            )}
          </li>
        );
      })}
    </ol>
  );
}
