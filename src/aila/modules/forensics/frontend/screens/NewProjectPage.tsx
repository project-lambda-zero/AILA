import { useState } from "react";
import { useNavigate } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { SectionHeader } from "@/components/aila/mock";

import { ReadinessStreamPanel } from "../components/ReadinessStreamPanel";
import { useCreateProject } from "../mutations";
import { useRegisteredSystems } from "../queries";
import type { AnalyzerOS, ProjectKind, RegisteredSystem } from "../types";

type WizardStep = "select" | "readiness" | "confirm";

const LABEL_STYLE: React.CSSProperties = {
  display: "block",
  marginBottom: 4,
  fontSize: 10,
  letterSpacing: "0.1em",
  color: "var(--text-faint)",
};

const INPUT_BASE: React.CSSProperties = {
  width: "100%",
  height: 32,
  padding: "0 12px",
  fontSize: 12,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const TEXTAREA_BASE: React.CSSProperties = {
  width: "100%",
  padding: "8px 12px",
  fontSize: 12,
  lineHeight: 1.55,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  resize: "vertical",
};

const SELECT_BASE: React.CSSProperties = {
  width: "100%",
  height: 32,
  padding: "0 12px",
  fontSize: 12,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const CHROME_BTN: React.CSSProperties = {
  height: 30,
  padding: "0 14px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const ACCENT_BTN: React.CSSProperties = {
  height: 30,
  padding: "0 14px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  boxShadow: "var(--bevel-key)",
};

const STEP_LABEL: Record<WizardStep, string> = {
  select: "Configure",
  readiness: "Readiness",
  confirm: "Confirm",
};

const STEPS: WizardStep[] = ["select", "readiness", "confirm"];

interface OptionCardProps {
  active: boolean;
  onClick: () => void;
  label: string;
  hint?: string;
}

function OptionCard({ active, onClick, label, hint }: OptionCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="font-mono flex-1 text-left"
      style={{
        padding: "12px 14px",
        borderRadius: 3,
        background: active
          ? "color-mix(in srgb, var(--accent) 12%, transparent)"
          : "var(--surface-sunk)",
        border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
        color: active ? "var(--accent)" : "var(--text-muted)",
        cursor: "pointer",
      }}
    >
      <span
        style={{
          display: "block",
          fontSize: 11.5,
          fontWeight: 500,
          color: active ? "var(--accent)" : "var(--text-primary)",
        }}
      >
        {label}
      </span>
      {hint && (
        <span
          style={{
            display: "block",
            marginTop: 3,
            fontSize: 9.5,
            color: "var(--text-faint)",
          }}
        >
          {hint}
        </span>
      )}
    </button>
  );
}

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

  const selectedSystem = systems?.find(
    (s: RegisteredSystem) => s.id === systemId,
  );

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

  const errStyle: React.CSSProperties = {
    marginTop: 4,
    fontSize: 10.5,
    color: "var(--accent)",
  };

  return (
    <div className="max-w-2xl mx-auto space-y-4">
      <SectionHeader
        icon={<PixelIcon name="spawn" />}
        title="spin up a forensic scene"
      />
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
      >
        forensics ; new case init {"\u00b7"} pick an analyzer, point at
        evidence, watch tools come online.
      </p>

      {/* Wizard step chips */}
      <div className="flex" style={{ gap: 6 }}>
        {STEPS.map((s, i) => {
          const active = step === s;
          return (
            <div
              key={s}
              className="font-mono uppercase"
              style={{
                padding: "6px 12px",
                fontSize: 9.5,
                letterSpacing: "0.1em",
                borderRadius: 3,
                color: active ? "var(--text-on-accent)" : "var(--text-muted)",
                background: active ? "var(--accent)" : "var(--surface-sunk)",
                border: `1px solid ${
                  active ? "var(--accent)" : "var(--border-soft)"
                }`,
              }}
            >
              {i + 1}. {STEP_LABEL[s]}
            </div>
          );
        })}
      </div>

      {step === "select" && (
        <WindowPanel title="configure case" status="wizard ; step 1 of 3">
          <div className="space-y-4">
            <div>
              <label htmlFor="nproj-name" className="font-mono uppercase" style={LABEL_STYLE}>
                Project Name
              </label>
              <input
                id="nproj-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, name: true }))}
                placeholder="Project name"
                className="font-mono"
                style={{
                  ...INPUT_BASE,
                  border: `1px solid ${
                    touched.name && errors.name
                      ? "var(--accent)"
                      : "var(--border-soft)"
                  }`,
                }}
              />
              {touched.name && errors.name && (
                <p className="font-mono" style={errStyle}>
                  {errors.name}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="nproj-description"
                className="font-mono uppercase"
                style={LABEL_STYLE}
              >
                Description
              </label>
              <textarea
                id="nproj-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of the investigation..."
                rows={3}
                className="font-mono"
                style={TEXTAREA_BASE}
              />
            </div>

            <div>
              <label
                htmlFor="nproj-system"
                className="font-mono uppercase"
                style={LABEL_STYLE}
              >
                Analyzer Machine
              </label>
              {systemsLoading ? (
                <LoadingSkeleton size="sm" width="full" />
              ) : (
                <select
                  id="nproj-system"
                  value={systemId ?? ""}
                  onChange={(e) =>
                    setSystemId(e.target.value ? Number(e.target.value) : null)
                  }
                  onBlur={() => setTouched((t) => ({ ...t, systemId: true }))}
                  className="font-mono"
                  style={{
                    ...SELECT_BASE,
                    border: `1px solid ${
                      touched.systemId && errors.systemId
                        ? "var(--accent)"
                        : "var(--border-soft)"
                    }`,
                  }}
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
                <p className="font-mono" style={errStyle}>
                  {errors.systemId}
                </p>
              )}
            </div>

            <div>
              <label className="font-mono uppercase" style={LABEL_STYLE}>
                Project Kind
              </label>
              <div className="flex" style={{ gap: 10 }}>
                <OptionCard
                  active={projectKind === "disk_evidence"}
                  onClick={() => setProjectKind("disk_evidence")}
                  label="Disk Evidence"
                  hint="E01 / raw / memory / pcap -- full pipeline runs"
                />
                <OptionCard
                  active={projectKind === "raw_directory"}
                  onClick={() => setProjectKind("raw_directory")}
                  label="Raw Directory"
                  hint="rootfs / loose logs -- intake only, ask directly"
                />
              </div>
              <p
                className="font-mono"
                style={{
                  marginTop: 6,
                  fontSize: 10.5,
                  color: "var(--text-faint)",
                  lineHeight: 1.55,
                }}
              >
                {projectKind === "raw_directory"
                  ? "Raw Directory: the analyzer treats the evidence path as a real filesystem. No dissect, no pre/full-analysis -- the investigator reads files directly when you ask questions."
                  : "Disk Evidence: the analyzer runs the standard intake -> collection -> deep_analysis pipeline over disk images / memory dumps / pcaps in the directory."}
              </p>
            </div>

            <div>
              <label className="font-mono uppercase" style={LABEL_STYLE}>
                Analyzer OS
              </label>
              <div className="flex" style={{ gap: 10 }}>
                {(["linux", "windows"] as const).map((os) => (
                  <OptionCard
                    key={os}
                    active={analyzerOs === os}
                    onClick={() => {
                      setAnalyzerOs(os);
                      if (os === "windows" && evidenceDir.startsWith("/")) {
                        setEvidenceDir("");
                      } else if (
                        os === "linux" &&
                        /^[A-Z]:\\/.test(evidenceDir)
                      ) {
                        setEvidenceDir("");
                      }
                    }}
                    label={os === "linux" ? "Linux" : "Windows"}
                  />
                ))}
              </div>
              <p
                className="font-mono"
                style={{
                  marginTop: 6,
                  fontSize: 10.5,
                  color: "var(--text-faint)",
                  lineHeight: 1.55,
                }}
              >
                {analyzerOs === "windows"
                  ? "Tool checks and commands will use PowerShell, cmd, and Windows paths."
                  : "Tool checks and commands will use bash, apt, and Unix paths."}
              </p>
            </div>

            <div>
              <label
                htmlFor="nproj-evidence-dir"
                className="font-mono uppercase"
                style={LABEL_STYLE}
              >
                Evidence Directory
              </label>
              <input
                id="nproj-evidence-dir"
                type="text"
                value={evidenceDir}
                onChange={(e) => setEvidenceDir(e.target.value)}
                onBlur={() =>
                  setTouched((t) => ({ ...t, evidenceDir: true }))
                }
                placeholder="Absolute path on the analyzer"
                className="font-mono"
                style={{
                  ...INPUT_BASE,
                  border: `1px solid ${
                    touched.evidenceDir && errors.evidenceDir
                      ? "var(--accent)"
                      : "var(--border-soft)"
                  }`,
                }}
              />
              {touched.evidenceDir && errors.evidenceDir && (
                <p className="font-mono" style={errStyle}>
                  {errors.evidenceDir}
                </p>
              )}
            </div>

            <div className="flex justify-end" style={{ gap: 8 }}>
              <button
                type="button"
                onClick={() => navigate("/forensics")}
                className="font-mono uppercase"
                style={CHROME_BTN}
              >
                cancel
              </button>
              <button
                type="button"
                onClick={handleCreateAndCheck}
                disabled={createProject.isPending}
                className="font-mono uppercase"
                style={{
                  ...ACCENT_BTN,
                  opacity: createProject.isPending ? 0.5 : 1,
                  cursor: createProject.isPending ? "not-allowed" : "pointer",
                }}
              >
                {createProject.isPending
                  ? "creating..."
                  : "create & check readiness"}
              </button>
            </div>

            {createProject.isError && (
              <p
                className="font-mono"
                style={{ fontSize: 11, color: "var(--accent)" }}
              >
                Failed to create project. Please check your inputs.
              </p>
            )}
          </div>
        </WindowPanel>
      )}

      {step === "readiness" && projectId && (
        <>
          <ReadinessStreamPanel projectId={projectId} autoStart />
          <div
            className="flex justify-between items-center"
            style={{ paddingTop: 8 }}
          >
            <button
              type="button"
              onClick={() => navigate(`/forensics/projects/${projectId}`)}
              className="font-mono uppercase"
              style={CHROME_BTN}
            >
              skip -- go to dashboard
            </button>
            <button
              type="button"
              onClick={() => setStep("confirm")}
              className="font-mono uppercase"
              style={ACCENT_BTN}
            >
              continue {"\u2192"}
            </button>
          </div>
        </>
      )}

      {step === "confirm" && projectId && (
        <WindowPanel
          title="project created"
          tone="ok"
          status="forensics ; case initialised"
        >
          <div className="space-y-4">
            <dl
              className="grid font-mono"
              style={{
                gridTemplateColumns: "minmax(0, 140px) 1fr",
                columnGap: 16,
                rowGap: 8,
                fontSize: 11,
              }}
            >
              <dt
                className="uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  alignSelf: "center",
                }}
              >
                Name
              </dt>
              <dd style={{ color: "var(--text-primary)" }}>{name}</dd>
              <dt
                className="uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  alignSelf: "center",
                }}
              >
                Machine
              </dt>
              <dd style={{ color: "var(--text-primary)" }}>
                {selectedSystem?.name ?? "--"}
              </dd>
              <dt
                className="uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  alignSelf: "center",
                }}
              >
                OS
              </dt>
              <dd style={{ color: "var(--text-primary)" }}>
                {analyzerOs === "windows" ? "Windows" : "Linux"}
              </dd>
              <dt
                className="uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  alignSelf: "center",
                }}
              >
                Kind
              </dt>
              <dd style={{ color: "var(--text-primary)" }}>
                {projectKind === "raw_directory"
                  ? "Raw Directory (intake only)"
                  : "Disk Evidence"}
              </dd>
              <dt
                className="uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  alignSelf: "center",
                }}
              >
                Evidence Dir
              </dt>
              <dd
                style={{
                  color: "var(--text-primary)",
                  fontSize: 10.5,
                  wordBreak: "break-all",
                }}
              >
                {evidenceDir}
              </dd>
              <dt
                className="uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  alignSelf: "center",
                }}
              >
                Readiness
              </dt>
              <dd style={{ color: "var(--text-muted)", fontSize: 10.5 }}>
                Checked -- see dashboard Readiness tab for status
              </dd>
            </dl>
            <div className="flex justify-end" style={{ gap: 8 }}>
              <button
                type="button"
                onClick={() =>
                  navigate(`/forensics/projects/${projectId}/details`)
                }
                className="font-mono uppercase"
                style={CHROME_BTN}
              >
                view details
              </button>
              <button
                type="button"
                onClick={() => navigate(`/forensics/projects/${projectId}`)}
                className="font-mono uppercase"
                style={ACCENT_BTN}
              >
                go to dashboard
              </button>
            </div>
          </div>
        </WindowPanel>
      )}
    </div>
  );
}
