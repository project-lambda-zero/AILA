import { useState } from "react";
import { useNavigate } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";

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
      // blocking mutation here -- the panel handles its own lifecycle and the
      // user can watch installs progress in real time.
    } catch {
      // Error handled by mutation state
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Section header -- dedup'd from the shell's route title. Vaporwave flavor
          via a neon gradient rule + retro mono/display pairing. */}
      <div className="space-y-1">
        <div
          aria-hidden="true"
          className="h-px w-24"
          style={{ background: "linear-gradient(90deg, var(--color-accent) 0%, transparent 100%)" }}
        />
        <p
          className="font-mono text-2xs uppercase text-muted-foreground"
          style={{ letterSpacing: "0.18em" }}
        >
          forensics ; new case init
        </p>
        <h2
          className="text-2xl leading-tight text-foreground"
          style={{ fontFamily: "var(--font-display)", fontWeight: 300, letterSpacing: "-0.02em" }}
        >
          Spin up a forensic scene
        </h2>
        <p className="text-sm text-text-muted">
          Pick an analyzer, point at evidence, watch tools come online.
        </p>
      </div>

      <div className="flex gap-2">
        {(["select", "readiness", "confirm"] as const).map((s, i) => (
          <div
            key={s}
            className={`px-3 py-1 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] border ${
              step === s
                ? "bg-accent text-badge-text border-accent"
                : "bg-elevated text-text-muted border-border"
            }`}
          >
            {i + 1}. {s === "select" ? "Configure" : s === "readiness" ? "Readiness" : "Confirm"}
          </div>
        ))}
      </div>

      {step === "select" && (
        <WindowPanel title="configure case"><div className="space-y-4">
          <div>
            <label htmlFor="nproj-name" className="block text-sm font-medium text-foreground mb-1">Project Name</label>
            <input
              id="nproj-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, name: true }))}
              placeholder="Project name"
              className={`w-full px-3 py-2 text-sm rounded-md border bg-surface text-foreground ${touched.name && errors.name ? "border-critical" : "border-border"}`}
            />
            {touched.name && errors.name && (
              <p className="mt-1 text-xs text-critical">{errors.name}</p>
            )}
          </div>
        
          <div>
            <label htmlFor="nproj-description" className="block text-sm font-medium text-foreground mb-1">Description</label>
            <textarea
              id="nproj-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of the investigation..."
              rows={3}
              className="w-full px-3 py-2 text-sm rounded-md border border-border bg-surface text-foreground resize-none"
            />
          </div>
        
          <div>
            <label htmlFor="nproj-system" className="block text-sm font-medium text-foreground mb-1">Analyzer Machine</label>
            {systemsLoading ? (
              <LoadingSkeleton size="sm" width="full" />
            ) : (
              <select
                id="nproj-system"
                value={systemId ?? ""}
                onChange={(e) => setSystemId(e.target.value ? Number(e.target.value) : null)}
                onBlur={() => setTouched((t) => ({ ...t, systemId: true }))}
                className={`w-full px-3 py-2 text-sm rounded-md border bg-surface text-foreground ${touched.systemId && errors.systemId ? "border-critical" : "border-border"}`}
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
              <p className="mt-1 text-xs text-critical">{errors.systemId}</p>
            )}
          </div>
        
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Project Kind</label>
            <div className="flex gap-3">
              {([
                { id: "disk_evidence", label: "Disk Evidence", hint: "E01 / raw / memory / pcap -- full pipeline runs" },
                { id: "raw_directory", label: "Raw Directory", hint: "rootfs / loose logs -- intake only, ask directly" },
              ] as const).map((k) => (
                <button
                  key={k.id}
                  type="button"
                  onClick={() => setProjectKind(k.id)}
                  className={`flex-1 px-4 py-3 text-sm font-medium rounded-md border transition-colors text-left ${
                    projectKind === k.id
                      ? "border-accent bg-accent/10 text-accent"
                      : "border-border bg-surface text-text-muted hover:bg-elevated"
                  }`}
                >
                  <span className="block text-sm font-semibold">{k.label}</span>
                  <span className="block text-2xs text-text-muted mt-0.5">{k.hint}</span>
                </button>
              ))}
            </div>
            <p className="mt-1 text-xs text-text-muted">
              {projectKind === "raw_directory"
                ? "Raw Directory: the analyzer treats the evidence path as a real filesystem. No dissect, no pre/full-analysis -- the investigator reads files directly when you ask questions."
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
                      : "border-border bg-surface text-text-muted hover:bg-elevated"
                  }`}
                >
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
            <label htmlFor="nproj-evidence-dir" className="block text-sm font-medium text-foreground mb-1">Evidence Directory</label>
            <input
              id="nproj-evidence-dir"
              type="text"
              value={evidenceDir}
              onChange={(e) => setEvidenceDir(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, evidenceDir: true }))}
              placeholder="Absolute path on the analyzer"
              className={`w-full px-3 py-2 text-sm rounded-md border bg-surface text-foreground ${touched.evidenceDir && errors.evidenceDir ? "border-critical" : "border-border"}`}
            />
            {touched.evidenceDir && errors.evidenceDir && (
              <p className="mt-1 text-xs text-critical">{errors.evidenceDir}</p>
            )}
          </div>
        
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => navigate("/forensics")}
              className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] border border-border text-foreground hover:bg-elevated hover:border-border-hover transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleCreateAndCheck}
              disabled={createProject.isPending}
              className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] bg-accent text-badge-text hover:brightness-110 transition-[filter] disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ boxShadow: "var(--bevel-key)" }}
            >
              {createProject.isPending ? "Creating..." : "Create & Check Readiness"}
            </button>
          </div>
        
          {createProject.isError && (
            <p className="text-sm text-critical">
              Failed to create project. Please check your inputs.
            </p>
          )}
        </div></WindowPanel>
      )}

      {step === "readiness" && projectId && (
        <>
          <ReadinessStreamPanel projectId={projectId} autoStart />
          <div className="flex justify-between items-center pt-2">
            <button
              type="button"
              onClick={() => navigate(`/forensics/projects/${projectId}`)}
              className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] border border-border text-foreground hover:bg-elevated hover:border-border-hover transition-colors"
            >
              Skip -- Go to Dashboard
            </button>
            <button
              type="button"
              onClick={() => setStep("confirm")}
              className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] bg-accent text-badge-text hover:brightness-110 transition-[filter]"
              style={{ boxShadow: "var(--bevel-key)" }}
            >
              Continue →
            </button>
          </div>
        </>
      )}

      {step === "confirm" && projectId && (
        <WindowPanel title="project created" tone="ok" status="forensics ; case initialised"><div className="space-y-4">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground self-center">Name</dt>
            <dd className="text-foreground">{name}</dd>
            <dt className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground self-center">Machine</dt>
            <dd className="text-foreground">{selectedSystem?.name ?? "--"}</dd>
            <dt className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground self-center">OS</dt>
            <dd className="text-foreground capitalize">{analyzerOs === "windows" ? "Windows" : "Linux"}</dd>
            <dt className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground self-center">Kind</dt>
            <dd className="text-foreground">{projectKind === "raw_directory" ? "Raw Directory (intake only)" : "Disk Evidence"}</dd>
            <dt className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground self-center">Evidence Dir</dt>
            <dd className="text-foreground font-mono text-xs">{evidenceDir}</dd>
            <dt className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground self-center">Readiness</dt>
            <dd className="text-xs text-text-muted">
              Checked -- see dashboard Readiness tab for status
            </dd>
          </dl>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => navigate(`/forensics/projects/${projectId}/details`)}
              className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] border border-border text-foreground hover:bg-elevated hover:border-border-hover transition-colors"
            >
              View Details
            </button>
            <button
              type="button"
              onClick={() => navigate(`/forensics/projects/${projectId}`)}
              className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] bg-accent text-badge-text hover:brightness-110 transition-[filter]"
              style={{ boxShadow: "var(--bevel-key)" }}
            >
              Go to Dashboard
            </button>
          </div>
        </div></WindowPanel>
      )}
    </div>
  );
}
