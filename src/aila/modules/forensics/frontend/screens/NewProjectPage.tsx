import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { ReadinessStreamPanel } from "../components/ReadinessStreamPanel";
import { useCreateProject } from "../mutations";
import { useRegisteredSystems } from "../queries";
import type { AnalyzerOS, ProjectKind, RegisteredSystem } from "../types";

type WizardStep = "select" | "readiness" | "confirm";

export function NewProjectPage() {
  const navigate = useNavigate();
  const { data: systems, isLoading: systemsLoading } = useRegisteredSystems();
  const createProject = useCreateProject();

  const [step, setStep] = useState<WizardStep>("select");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [systemId, setSystemId] = useState<number | null>(null);
  const [evidenceDir, setEvidenceDir] = useState("");
  const [analyzerOs, setAnalyzerOs] = useState<AnalyzerOS>("linux");
  const [projectKind, setProjectKind] = useState<ProjectKind>("disk_evidence");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [touched, setTouched] = useState<Record<string, boolean>>({});

  const errors = {
    name: !name.trim() ? "Project name is required" : null,
    systemId: !systemId ? "Select an analyzer machine" : null,
    evidenceDir: !evidenceDir.trim() ? "Evidence directory path is required" : null,
  };
  const hasErrors = Object.values(errors).some(Boolean);

  const selectedSystem = systems?.find((s: RegisteredSystem) => s.id === systemId);

  async function handleCreateAndCheck() {
    setTouched({ name: true, systemId: true, evidenceDir: true });
    if (hasErrors) return;
    try {
      const res = await createProject.mutateAsync({
        name,
        description,
        system_id: systemId!,
        evidence_directory: evidenceDir,
        analyzer_os: analyzerOs,
        project_kind: projectKind,
      });
      const id = res.data.id;
      setProjectId(id);
      setStep("readiness");
      // Readiness now streams live via ReadinessStreamPanel (autoStart). No
      // blocking mutation here — the panel handles its own lifecycle and the
      // user can watch installs progress in real time.
    } catch {
      // Error handled by mutation state
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Section header — dedup'd from the shell's route title. Vaporwave flavor
          via a neon gradient rule + retro mono/display pairing. */}
      <div className="space-y-1">
        <div
          aria-hidden="true"
          className="h-px w-24 rounded-full"
          style={{
            background:
              "linear-gradient(90deg, transparent 0%, #ff71ce 20%, #b967ff 55%, #05ffa1 100%)",
          }}
        />
        <p
          className="text-[11px] uppercase tracking-[0.32em] text-text-muted"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          // forensics / new case init
        </p>
        <h2
          className="text-2xl leading-tight"
          style={{
            fontFamily: "var(--font-display)",
            fontWeight: 700,
            letterSpacing: "-0.01em",
            background:
              "linear-gradient(90deg, var(--color-foreground, #f5f5ff) 0%, #ff71ce 70%, #b967ff 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          spin up a forensic scene
        </h2>
        <p className="text-sm text-text-muted">
          pick an analyzer, point at evidence, watch tools come online.
        </p>
      </div>

      <div className="flex gap-2 text-sm">
        {(["select", "readiness", "confirm"] as const).map((s, i) => (
          <div
            key={s}
            className={`px-3 py-1 rounded-full ${
              step === s
                ? "bg-accent text-white"
                : "bg-surface-secondary text-text-muted"
            }`}
          >
            {i + 1}. {s === "select" ? "Configure" : s === "readiness" ? "Readiness" : "Confirm"}
          </div>
        ))}
      </div>

      {step === "select" && (
        <AilaCard>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Project Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, name: true }))}
                placeholder="Project name"
                className={`w-full px-3 py-2 text-sm rounded-md border bg-surface text-foreground ${touched.name && errors.name ? "border-border-danger" : "border-border"}`}
              />
              {touched.name && errors.name && (
                <p className="mt-1 text-xs text-text-danger">{errors.name}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of the investigation..."
                rows={3}
                className="w-full px-3 py-2 text-sm rounded-md border border-border bg-surface text-foreground resize-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Analyzer Machine</label>
              {systemsLoading ? (
                <LoadingSkeleton size="sm" width="full" />
              ) : (
                <select
                  value={systemId ?? ""}
                  onChange={(e) => setSystemId(e.target.value ? Number(e.target.value) : null)}
                  onBlur={() => setTouched((t) => ({ ...t, systemId: true }))}
                  className={`w-full px-3 py-2 text-sm rounded-md border bg-surface text-foreground ${touched.systemId && errors.systemId ? "border-border-danger" : "border-border"}`}
                >
                  <option value="">Select a system...</option>
                  {(systems ?? []).map((sys: RegisteredSystem) => (
                    <option key={sys.id} value={sys.id}>
                      {sys.name} ({sys.host})
                    </option>
                  ))}
                </select>
              )}
              {touched.systemId && errors.systemId && (
                <p className="mt-1 text-xs text-text-danger">{errors.systemId}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Project Kind</label>
              <div className="flex gap-3">
                {([
                  { id: "disk_evidence", label: "Disk Evidence", hint: "E01 / raw / memory / pcap — full pipeline runs" },
                  { id: "raw_directory", label: "Raw Directory", hint: "rootfs / loose logs — intake only, ask directly" },
                ] as const).map((k) => (
                  <button
                    key={k.id}
                    type="button"
                    onClick={() => setProjectKind(k.id)}
                    className={`flex-1 px-4 py-3 text-sm font-medium rounded-md border transition-colors text-left ${
                      projectKind === k.id
                        ? "border-accent bg-accent/10 text-accent"
                        : "border-border bg-surface text-text-muted hover:bg-surface-secondary"
                    }`}
                  >
                    <span className="block text-sm font-semibold">{k.label}</span>
                    <span className="block text-[11px] text-text-muted mt-0.5">{k.hint}</span>
                  </button>
                ))}
              </div>
              <p className="mt-1 text-xs text-text-muted">
                {projectKind === "raw_directory"
                  ? "Raw Directory: the analyzer treats the evidence path as a real filesystem. No dissect, no pre/full-analysis — the investigator reads files directly when you ask questions."
                  : "Disk Evidence: the analyzer runs the standard intake → collection → deep_analysis pipeline over disk images / memory dumps / pcaps in the directory."}
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Analyzer OS</label>
              <div className="flex gap-3">
                {(["linux", "windows"] as const).map((os) => (
                  <button
                    key={os}
                    type="button"
                    onClick={() => {
                      setAnalyzerOs(os);
                      if (os === "windows" && evidenceDir.startsWith("/")) {
                        setEvidenceDir("");
                      } else if (os === "linux" && /^[A-Z]:\\/.test(evidenceDir)) {
                        setEvidenceDir("");
                      }
                    }}
                    className={`flex-1 px-4 py-3 text-sm font-medium rounded-md border transition-colors ${
                      analyzerOs === os
                        ? "border-accent bg-accent/10 text-accent"
                        : "border-border bg-surface text-text-muted hover:bg-surface-secondary"
                    }`}
                  >
                    <span className="block text-base mb-0.5">{os === "linux" ? "🐧" : "🪟"}</span>
                    {os === "linux" ? "Linux" : "Windows"}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-xs text-text-muted">
                {analyzerOs === "windows"
                  ? "Tool checks and commands will use PowerShell, cmd, and Windows paths."
                  : "Tool checks and commands will use bash, apt, and Unix paths."}
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Evidence Directory</label>
              <input
                type="text"
                value={evidenceDir}
                onChange={(e) => setEvidenceDir(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, evidenceDir: true }))}
                placeholder="Absolute path on the analyzer"
                className={`w-full px-3 py-2 text-sm rounded-md border bg-surface text-foreground ${touched.evidenceDir && errors.evidenceDir ? "border-border-danger" : "border-border"}`}
              />
              {touched.evidenceDir && errors.evidenceDir && (
                <p className="mt-1 text-xs text-text-danger">{errors.evidenceDir}</p>
              )}
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => navigate("/forensics")}
                className="px-4 py-2 text-sm rounded-md border border-border text-foreground hover:bg-surface-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleCreateAndCheck}
                disabled={createProject.isPending}
                className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {createProject.isPending ? "Creating..." : "Create & Check Readiness"}
              </button>
            </div>

            {createProject.isError && (
              <p className="text-sm text-text-danger">
                Failed to create project. Please check your inputs.
              </p>
            )}
          </div>
        </AilaCard>
      )}

      {step === "readiness" && projectId && (
        <>
          <ReadinessStreamPanel projectId={projectId} autoStart />
          <div className="flex justify-between items-center pt-2">
            <button
              type="button"
              onClick={() => navigate(`/forensics/projects/${projectId}`)}
              className="px-4 py-2 text-sm rounded-md border border-border text-foreground hover:bg-surface-secondary"
            >
              Skip — Go to Dashboard
            </button>
            <button
              type="button"
              onClick={() => setStep("confirm")}
              className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90"
            >
              Continue →
            </button>
          </div>
        </>
      )}

      {step === "confirm" && projectId && (
        <AilaCard>
          <div className="space-y-4">
            <h2 className="text-lg font-semibold font-mono text-foreground">Project Created</h2>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-text-muted">Name</dt>
              <dd className="text-foreground">{name}</dd>
              <dt className="text-text-muted">Machine</dt>
              <dd className="text-foreground">{selectedSystem?.name ?? "—"}</dd>
              <dt className="text-text-muted">OS</dt>
              <dd className="text-foreground capitalize">{analyzerOs === "windows" ? "🪟 Windows" : "🐧 Linux"}</dd>
              <dt className="text-text-muted">Kind</dt>
              <dd className="text-foreground">{projectKind === "raw_directory" ? "Raw Directory (intake only)" : "Disk Evidence"}</dd>
              <dt className="text-text-muted">Evidence Dir</dt>
              <dd className="text-foreground font-mono text-xs">{evidenceDir}</dd>
              <dt className="text-text-muted">Readiness</dt>
              <dd className="text-foreground text-xs text-text-muted">
                Checked — see dashboard Readiness tab for status
              </dd>
            </dl>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => navigate(`/forensics/projects/${projectId}/details`)}
                className="px-4 py-2 text-sm rounded-md border border-border text-foreground hover:bg-surface-secondary"
              >
                View Details
              </button>
              <button
                type="button"
                onClick={() => navigate(`/forensics/projects/${projectId}`)}
                className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90"
              >
                Go to Dashboard
              </button>
            </div>
          </div>
        </AilaCard>
      )}
    </div>
  );
}
