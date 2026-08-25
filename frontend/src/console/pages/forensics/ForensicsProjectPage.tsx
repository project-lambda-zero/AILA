/**
 * Forensics project-detail window. Replaces the 15 flat forensics rail
 * sub-pages with one tabbed window scoped to a single project. Reuses the
 * WindowPanel chrome + status-bar patterns from XRayPage.tsx.
 *
 * Sub-routing: encoded through ModulePageProps.section so window identity
 * (minimize / fullscreen / dock) survives every navigation.
 *   - null / "" / "overview"  → default tab
 *   - <tab-id>                → that tab (e.g. "evidence", "artifacts")
 *   - "inv:<invId>"           → investigation drill-down sub-view
 *
 * The project id arrives via ModulePageProps.investigationId (reused as the
 * generic selected-entity id; NO change to contract.ts). When null, render
 * a placeholder that tells the analyst to open a project from the list.
 */
import type { JSX } from "react";
import { useMemo, useState } from "react";

import { useMutation, useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../../api/client";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";

import {
  CtlBtn,
  DictPanel,
  KV,
  Panel,
  StatusBadge,
  emptyNote,
  H,
} from "./panels";
import { InvestigateForm } from "./forms";
import {
  AnswersTab,
  ArtifactsTab,
  DirectivesTab,
  EvidenceTab,
  FindingsTab,
  InvestigationsTab,
  LeadsTab,
  NetworkAnalysisTab,
  OccurrencesTab,
  OverviewTab,
  RegistryAnalysisTab,
  SolidEvidenceTab,
  SuppressionsTab,
  TimelineTab,
  WriteupsTab,
} from "./tabs";
import type { ProjectSummary } from "./tabs";
import { InvestigationSubView } from "./InvestigationSubView";
import { ConsoleWindow } from "../../window";

const TAB_DEFS: { id: string; label: string }[] = [
  { id: "overview", label: "overview" },
  { id: "evidence", label: "evidence" },
  { id: "artifacts", label: "artifacts" },
  { id: "leads", label: "leads" },
  { id: "investigations", label: "investigations" },
  { id: "answers", label: "answers" },
  { id: "writeups", label: "write-ups" },
  { id: "timeline", label: "timeline" },
  { id: "occurrences", label: "occurrences" },
  { id: "directives", label: "directives" },
  { id: "solid-evidence", label: "solid evidence" },
  { id: "findings", label: "findings" },
  { id: "suppressions", label: "suppressions" },
  { id: "network-analysis", label: "network" },
  { id: "registry-analysis", label: "registry" },
];

const TAB_IDS: Record<string, true> = Object.fromEntries(TAB_DEFS.map((t) => [t.id, true as const]));

interface ReadinessResult {
  ready: boolean;
  system_id: number;
  system_name: string;
  analyzer_os: string;
  tools: { tool_name: string; required: boolean; status: string; version: string | null; message: string | null; install_method: string | null }[];
  message: string;
  already_queued: boolean;
  existing_task_id: string | null;
}

interface TaskDispatch {
  task_id: string;
  status: string;
}

export default function ForensicsProjectPage(props: ModulePageProps): JSX.Element {
  const { investigationId: projectId, section, onBack, onMinimize, onNavigate, isFullscreen, onToggleFullscreen, windowId, title: windowTitle, isFocused, onFocus } = props;

  const { tab, invSubId } = useMemo(() => parseSection(section), [section]);

  const project = useQuery<ProjectSummary>({
    queryKey: ["forensics", projectId ?? "", "project"],
    queryFn: () => apiFetch<ProjectSummary>(`/forensics/projects/${projectId}`),
    enabled: Boolean(projectId),
    retry: false,
  });

  const [investigateOpen, setInvestigateOpen] = useState(false);
  const [readinessOpen, setReadinessOpen] = useState(false);
  const [readinessResult, setReadinessResult] = useState<ReadinessResult | null>(null);
  const [fullAnalysisResult, setFullAnalysisResult] = useState<TaskDispatch | null>(null);
  const [notice, setNotice] = useState<{ tone: "ok" | "err" | "info"; msg: string } | null>(null);

  const readiness = useMutation({
    mutationFn: () =>
      apiFetch<ReadinessResult>(`/forensics/projects/${projectId}/readiness-check`, { method: "POST" }),
    onSuccess: (res) => {
      setReadinessResult(res);
      setReadinessOpen(true);
      setNotice({ tone: "ok", msg: "readiness check completed successfully." });
    },
    onError: (e: unknown) => {
      setReadinessResult(null);
      setReadinessOpen(true);
      setNotice({ tone: "err", msg: `readiness-check failed: ${e instanceof Error ? e.message : "request failed"}` });
    },
  });

  const fullAnalysis = useMutation({
    mutationFn: () =>
      apiFetch<TaskDispatch>(`/forensics/projects/${projectId}/full-analysis`, { method: "POST" }),
    onSuccess: (res) => {
      setFullAnalysisResult(res);
      setNotice({ tone: "ok", msg: `full-analysis queued: task ${res.task_id} (${res.status}).` });
    },
    onError: (e: unknown) => {
      setNotice({ tone: "err", msg: `full-analysis failed: ${e instanceof Error ? e.message : "request failed"}` });
    },
  });

  const openInvestigation = (invId: string): void => onNavigate(`inv:${invId}`);
  const backToTabs = (): void => onNavigate(tab === "overview" || !tab ? "overview" : tab);

  // BODY selector ----------------------------------------------------
  let body: JSX.Element;
  if (!projectId) {
    body = (
      <div style={emptyNote}>
        {"no project selected. open one from the forensics \u00b7 projects list."}
      </div>
    );
  } else if (invSubId) {
    body = (
      <InvestigationSubView
        projectId={projectId}
        investigationId={invSubId}
        onBackToTabs={backToTabs}
      />
    );
  } else {
    body = renderTab(tab, projectId, project.data ?? null, openInvestigation);
  }

  const activeTab = invSubId ? "investigations" : tab;
  const title = project.data?.name ?? (projectId ? `project ${projectId.slice(0, 8)}` : "no project selected");
  const kind = project.data?.project_kind ?? "";
  const isDiskEvidence = kind === "disk_evidence";
  const projectMissing = !projectId;
  const busy = readiness.isPending || fullAnalysis.isPending;

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
        {"forensics \u00b7 project"}
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
        {invSubId ? `investigation ${invSubId.slice(0, 12)}` : `tab \u00b7 ${activeTab}`}
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
      {/* HEADER BAND ------------------------------------------------- */}
      <div
        style={css(
          "flex:0 0 auto;display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);",
        )}
      >
        {invSubId ? (
          <button
            type="button"
            onClick={backToTabs}
            style={css(
              "background:transparent;border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;padding:2px 8px;border-radius:2px;cursor:pointer;",
            )}
          >
            {"\u2039 project"}
          </button>
        ) : null}
        <div style={css("display:flex;align-items:center;gap:9px;min-width:0;")}>
          <span style={css("width:9px;height:9px;background:var(--accent);border-radius:1px;box-shadow:0 0 8px var(--accent);flex:0 0 auto;")} />
          <span style={css("font-family:var(--font-mono);font-size:12.5px;letter-spacing:0.06em;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px;")}>
            {title}
          </span>
          {project.data ? <StatusBadge value={project.data.status} /> : null}
          {kind ? (
            <span style={css("font-family:var(--font-mono);font-size:9px;color:var(--text-faint);letter-spacing:0.08em;text-transform:uppercase;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;")}>{kind}</span>
          ) : null}
        </div>
        <span style={css("flex:1;")} />
        {project.data ? (
          <div style={css("display:flex;gap:14px;font-family:var(--font-mono);font-size:9.5px;color:var(--text-muted);letter-spacing:0.05em;")}>
            <Counter label="evidence" n={project.data.evidence_count} />
            <Counter label="artifacts" n={project.data.artifact_count} />
            <Counter label="leads" n={project.data.lead_count} />
            <Counter label="investigations" n={project.data.investigation_count} />
          </div>
        ) : null}
      </div>

      {/* PROJECT ACTION TOOLBAR ------------------------------------ */}
      <div
        style={css(
          "flex:0 0 auto;display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:8px 14px;background:color-mix(in srgb,var(--surface-card) 60%,transparent);border-bottom:1px solid var(--border);",
        )}
      >
        <CtlBtn
          label="readiness check"
          tone="accent"
          onClick={() => readiness.mutate()}
          disabled={projectMissing || busy}
        />
        <CtlBtn
          label={isDiskEvidence ? "full analysis" : "full analysis (disk_evidence only)"}
          tone={isDiskEvidence ? "accent" : "muted"}
          onClick={() => fullAnalysis.mutate()}
          disabled={projectMissing || busy || !isDiskEvidence}
        />
        <CtlBtn
          label="+ new investigation"
          tone="accent"
          onClick={() => setInvestigateOpen(true)}
          disabled={projectMissing}
        />
        <CtlBtn
          label="download writeups.md"
          tone="muted"
          onClick={() => bearerDownload(`/forensics/projects/${projectId}/writeups.md`, `writeups-${(projectId ?? "").slice(0, 8)}.md`, (msg) => setNotice({ tone: "err", msg }))}
          disabled={projectMissing}
        />
        <CtlBtn
          label="download directives.md"
          tone="muted"
          onClick={() => bearerDownload(`/forensics/projects/${projectId}/directives.md`, `directives-${(projectId ?? "").slice(0, 8)}.md`, (msg) => setNotice({ tone: "err", msg }))}
          disabled={projectMissing}
        />
        <span style={css("flex:1;")} />
        {fullAnalysisResult ? (
          <span style={css("font-size:9px;color:var(--text-faint);letter-spacing:0.05em;")}>
            last full-analysis task: {fullAnalysisResult.task_id} ({fullAnalysisResult.status})
          </span>
        ) : null}
        {notice ? (
          <div style={css(`width:100%;display:flex;align-items:center;gap:8px;padding:4px 10px;margin-top:4px;border-radius:2px;font-size:10px;background:color-mix(in srgb,${notice.tone === "ok" ? "var(--status-ok)" : notice.tone === "err" ? "var(--status-warn)" : "var(--accent)"} 12%,transparent);border:1px solid ${notice.tone === "ok" ? "var(--status-ok)" : notice.tone === "err" ? "var(--status-warn)" : "var(--accent)"}55;color:${notice.tone === "ok" ? "var(--status-ok)" : notice.tone === "err" ? "var(--status-warn)" : "var(--accent)"};`)}>
            <span>{notice.msg}</span>
            <span style={css("flex:1;")} />
            <button type="button" onClick={() => setNotice(null)} style={css("background:transparent;border:0;color:inherit;cursor:pointer;font-size:11px;")}>{"\u2715"}</button>
          </div>
        ) : null}
      </div>

      {/* HORIZONTAL TAB STRIP -------------------------------------- */}
      <div
        style={css(
          "flex:0 0 auto;display:flex;gap:4px;overflow-x:auto;padding:6px 14px;background:color-mix(in srgb,var(--surface-card) 40%,transparent);border-bottom:1px solid var(--border);",
        )}
      >
        {TAB_DEFS.map((t) => {
          const on = activeTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => onNavigate(t.id)}
              disabled={projectMissing}
              style={css(
                `background:${on ? "var(--accent)" : "transparent"};color:${on ? "var(--text-on-accent)" : projectMissing ? "var(--text-faint)" : "var(--text-muted)"};border:1px solid ${on ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;padding:3px 10px;cursor:${projectMissing ? "default" : "pointer"};white-space:nowrap;${projectMissing ? "opacity:0.5;" : ""}`,
              )}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {/* BODY ------------------------------------------------------- */}
      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: 12, gap: 10 }}>{body}</main>

      {/* Investigation form modal (opened from toolbar) ------------ */}
      {investigateOpen && projectId ? (
        <InvestigateForm
          projectId={projectId}
          onClose={() => setInvestigateOpen(false)}
          onCreated={openInvestigation}
        />
      ) : null}

      {/* Readiness-check result modal ------------------------------ */}
      {readinessOpen && readinessResult ? (
        <ReadinessModal result={readinessResult} onClose={() => setReadinessOpen(false)} />
      ) : null}
    </ConsoleWindow>
  );
}

function Counter({ label, n }: { label: string; n: number }): JSX.Element {
  return (
    <span style={css("display:inline-flex;gap:5px;")}>
      <span style={css("color:var(--text-faint);text-transform:uppercase;")}>{label}</span>
      <span style={css("color:var(--text-primary);font-weight:700;")}>{n}</span>
    </span>
  );
}

function parseSection(section: string | null | undefined): { tab: string; invSubId: string | null } {
  if (!section) return { tab: "overview", invSubId: null };
  if (section.startsWith("inv:")) return { tab: "investigations", invSubId: section.slice(4) };
  if (TAB_IDS[section]) return { tab: section, invSubId: null };
  return { tab: "overview", invSubId: null };
}

function renderTab(
  tab: string,
  projectId: string,
  project: ProjectSummary | null,
  onOpenInvestigation: (id: string) => void,
): JSX.Element {
  const p = { projectId, onOpenInvestigation };
  switch (tab) {
    case "overview":
      return <OverviewTab projectId={projectId} project={project} />;
    case "evidence":
      return <EvidenceTab {...p} />;
    case "artifacts":
      return <ArtifactsTab {...p} />;
    case "leads":
      return <LeadsTab {...p} />;
    case "investigations":
      return <InvestigationsTab {...p} />;
    case "answers":
      return <AnswersTab {...p} />;
    case "writeups":
      return <WriteupsTab {...p} />;
    case "timeline":
      return <TimelineTab {...p} />;
    case "occurrences":
      return <OccurrencesTab {...p} />;
    case "directives":
      return <DirectivesTab {...p} />;
    case "solid-evidence":
      return <SolidEvidenceTab {...p} />;
    case "findings":
      return <FindingsTab {...p} />;
    case "suppressions":
      return <SuppressionsTab {...p} />;
    case "network-analysis":
      return <NetworkAnalysisTab {...p} />;
    case "registry-analysis":
      return <RegistryAnalysisTab {...p} />;
    default:
      return <OverviewTab projectId={projectId} project={project} />;
  }
}

/* --- Bearer-authenticated file download (mirrors tabs.tsx) -------- */

async function bearerDownload(path: string, filename: string, onError?: (msg: string) => void): Promise<void> {
  try {
    const text = await apiFetch<string>(path);
    const blob = new Blob([text], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    const msg = `download failed: ${e instanceof Error ? e.message : "request failed"}`;
    if (onError) onError(msg);
    else console.warn(msg);
  }
}

/* --- Readiness-check result modal --------------------------------- */

function ReadinessModal({ result, onClose }: { result: ReadinessResult; onClose: () => void }): JSX.Element {
  return (
    <div
      style={css(
        "position:absolute;inset:0;background:color-mix(in srgb,var(--surface-page) 78%,transparent);display:flex;align-items:center;justify-content:center;z-index:10;padding:32px;",
      )}
    >
      <div
        style={css(
          "width:min(720px,100%);max-height:100%;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:var(--surface-card);box-shadow:0 12px 36px rgba(0,0,0,0.55);display:flex;flex-direction:column;",
        )}
      >
        <div
          style={css(
            "display:flex;align-items:center;gap:10px;padding:9px 13px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:10px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);",
          )}
        >
          <span style={css(`width:9px;height:9px;border-radius:1px;background:${result.ready ? H.mint : H.warn};box-shadow:0 0 8px ${result.ready ? H.mint : H.warn};`)} />
          <span>machine readiness</span>
          <span style={css("flex:1;")} />
          <button
            type="button"
            onClick={onClose}
            style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:14px;")}
          >
            {"\u2715"}
          </button>
        </div>
        <div style={css("padding:12px 14px;")}>
          <KV
            entries={[
              ["ready", result.ready ? "yes" : "no"],
              ["system", `${result.system_name} (#${result.system_id})`],
              ["os", result.analyzer_os],
              ["message", result.message || "\u2014"],
              ["already queued", result.already_queued ? `yes (task ${result.existing_task_id ?? "?"})` : "no"],
            ]}
          />
        </div>
        <div style={css("padding:0 14px 12px;")}>
          <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>tool checks ({result.tools.length})</div>
          <ToolsTable tools={result.tools} />
        </div>
      </div>
    </div>
  );
}

function ToolsTable({ tools }: { tools: ReadinessResult["tools"] }): JSX.Element {
  if (tools.length === 0) return <div style={emptyNote}>no tool checks recorded.</div>;
  return (
    <div style={css("border:1px solid var(--border-soft);border-radius:2px;overflow:hidden;")}>
      <table style={css("width:100%;border-collapse:collapse;font-size:11px;")}>
        <thead>
          <tr>
            {["tool", "required", "status", "version", "install method", "message"].map((c) => (
              <th
                key={c}
                style={css(
                  "text-align:left;padding:6px 9px;background:var(--surface-chrome);border-bottom:1px solid var(--border-soft);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;",
                )}
              >
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {tools.map((t) => {
            const tone =
              t.status === "installed" || t.status === "installed_online" || t.status === "installed_offline"
                ? H.mint
                : t.status === "missing" || t.status === "install_failed"
                ? H.danger
                : t.status === "skipped"
                ? "var(--text-faint)"
                : H.warn;
            return (
              <tr key={t.tool_name} style={css("border-bottom:1px solid var(--border-faint);")}>
                <td style={css("padding:5px 9px;color:var(--text-primary);")}>{t.tool_name}</td>
                <td style={css("padding:5px 9px;color:var(--text-muted);")}>{t.required ? "yes" : "no"}</td>
                <td style={css(`padding:5px 9px;color:${tone};`)}>{t.status}</td>
                <td style={css("padding:5px 9px;color:var(--text-muted);")}>{t.version ?? "\u2014"}</td>
                <td style={css("padding:5px 9px;color:var(--text-muted);")}>{t.install_method ?? "\u2014"}</td>
                <td style={css("padding:5px 9px;color:var(--text-muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{t.message ?? "\u2014"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
