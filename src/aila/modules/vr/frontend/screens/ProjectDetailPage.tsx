import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  Segmented,
  DataGrid,
  MonoBadge,
  type GridColumn,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
import { WorkflowStepper } from "../components/WorkflowStepper";
import { useDeleteProject } from "../mutations";
import {
  useFuzzCampaigns,
  useInvestigationMessages,
  useInvestigations,
  useSystemHeartbeat,
  useSystemMap,
  useTargetName,
  useVRFindings,
  useVRProject,
} from "../queries";
import type {
  DisclosureStatus,
  VRFinding,
  VRProjectStatus,
  VRProjectSummary,
} from "../types";

type TabId = "overview" | "findings" | "agent" | "advisory";

const TAB_OPTIONS: { value: TabId; label: string }[] = [
  { value: "overview", label: "overview" },
  { value: "findings", label: "findings" },
  { value: "agent", label: "agent log" },
  { value: "advisory", label: "advisory" },
];

const projectStatusTone: Record<VRProjectStatus, "info" | "warn" | "ok" | "critical" | "muted"> = {
  created: "info",
  analyzing: "warn",
  completed: "ok",
  failed: "critical",
  stalled: "muted",
};

const disclosureTone: Record<DisclosureStatus, "warn" | "info" | "ok" | "muted"> = {
  undisclosed: "warn",
  reported: "info",
  acknowledged: "info",
  patch_pending: "info",
  patched: "ok",
  public: "ok",
};

function formatDateTime(value?: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function formatTime(value?: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ---------------------------------------------------------------------------
// Brief row -- uppercase mono label above the mono value, border-bottom rule.
// Used on Overview + Advisory (matches the mock's project-brief pattern).
// ---------------------------------------------------------------------------
function BriefRow({
  label,
  children,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview tab -- two side-by-side WindowPanels (project brief + progress).
// ---------------------------------------------------------------------------
function OverviewTab({
  project,
}: {
  project: VRProjectSummary;
}) {
  const targetName = useTargetName(project.target_id);
  const systemMap = useSystemMap();
  const { data: invsResult } = useInvestigations();
  const { data: fuzzResult } = useFuzzCampaigns({
    targetId: project.target_id ?? undefined,
  });
  const { data: heartbeat } = useSystemHeartbeat(project.analysis_system_id ?? null);

  const allInvs = invsResult?.data ?? [];
  const projInvs = allInvs.filter((i) => i.target_id === project.target_id);
  const campaigns = fuzzResult?.data ?? [];

  const system = project.analysis_system_id
    ? systemMap.get(project.analysis_system_id)
    : undefined;
  const heartbeatLive = heartbeat?.reachable === true;
  const heartbeatLabel = !project.analysis_system_id
    ? "unassigned"
    : heartbeat
      ? heartbeatLive
        ? `reachable (${heartbeat.latency_ms ?? "?"}ms)`
        : `unreachable (${heartbeat.error ?? "no response"})`
      : "probing";

  const currentState =
    project.status === "completed"
      ? "response_emit"
      : project.status === "failed" || project.status === "analyzing"
        ? "research"
        : "setup";

  return (
    <div
      className="grid"
      style={{
        gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
        gap: 14,
      }}
    >
      <WindowPanel title="project brief" tone="accent">
        <BriefRow label="workspace">{project.workspace_id ?? "--"}</BriefRow>
        <BriefRow label="target">
          {project.target_id ? (
            <Link
              to={`/vr/targets/${project.target_id}`}
              style={{ color: "var(--accent)", textDecoration: "none" }}
            >
              {targetName}
            </Link>
          ) : (
            "--"
          )}
        </BriefRow>
        <BriefRow label="operator">{project.operator_id ?? "--"}</BriefRow>
        <BriefRow label="created">{formatDateTime(project.created_at)}</BriefRow>
        <BriefRow label="cve">{project.cve_id ?? "--"}</BriefRow>
        <BriefRow label="status">
          <MonoBadge tone={projectStatusTone[project.status] ?? "muted"}>
            {project.status}
          </MonoBadge>
        </BriefRow>
        <BriefRow label="host">
          {system ? `${system.username}@${system.host}:${system.port}` : "--"}
        </BriefRow>
        <BriefRow label="heartbeat">
          <span className="flex items-center" style={{ gap: 6 }}>
            <span
              aria-hidden="true"
              style={{
                display: "inline-block",
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: heartbeatLive
                  ? "var(--status-ok)"
                  : heartbeat
                    ? "var(--accent)"
                    : "var(--text-faint)",
              }}
            />
            {heartbeatLabel}
          </span>
        </BriefRow>
      </WindowPanel>

      <WindowPanel title="progress" tone="info">
        <WorkflowStepper
          flow="nday"
          currentState={currentState}
          failedAt={project.status === "failed" ? "research" : null}
        />
        <div
          className="grid"
          style={{
            marginTop: 14,
            gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
            gap: 1,
            background: "var(--border-faint)",
            border: "1px solid var(--border-faint)",
            borderRadius: 3,
          }}
        >
          <StatusCell label="findings" value={project.finding_count} />
          <StatusCell label="investigations" value={projInvs.length} />
          <StatusCell label="fuzz campaigns" value={campaigns.length} />
        </div>
      </WindowPanel>
    </div>
  );
}

function StatusCell({
  label,
  value,
}: {
  label: string;
  value: number | string;
}) {
  return (
    <div
      className="font-mono"
      style={{
        background: "var(--surface-sunk)",
        padding: "10px 12px",
        display: "flex",
        flexDirection: "column",
        gap: 4,
      }}
    >
      <span
        className="uppercase"
        style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
      >
        {label}
      </span>
      <span style={{ fontSize: 20, color: "var(--text-primary)", letterSpacing: "-0.02em" }}>
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Findings tab -- DataGrid of findings with row navigation to detail.
// ---------------------------------------------------------------------------
const FINDING_COLUMNS: GridColumn[] = [
  { label: "status", width: "110px" },
  { label: "cve", width: "140px" },
  { label: "severity", width: "100px" },
  { label: "title", width: "minmax(0, 1.6fr)" },
  { label: "host", width: "minmax(0, 1fr)" },
  { label: "created", width: "110px" },
  { label: "\u00d7", width: "34px", align: "center" },
];

function FindingsTab({
  projectId,
  projectTargetName,
}: {
  projectId: string;
  projectTargetName: string;
}) {
  const navigate = useNavigate();
  const { data: result, isLoading, isError } = useVRFindings(projectId);
  const findings = result?.data ?? [];

  if (isLoading) {
    return (
      <WindowPanel title="findings" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }
  if (isError) {
    return (
      <WindowPanel title="findings" tone="accent">
        <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
          failed to load findings.
        </p>
      </WindowPanel>
    );
  }
  return (
    <WindowPanel title="findings" tone="accent" flush>
      <DataGrid<VRFinding>
        columns={FINDING_COLUMNS}
        rows={findings}
        getKey={(f) => f.id ?? Math.random().toString(36)}
        onRowClick={(f) => {
          if (f.id) navigate(`/vr/projects/${projectId}/findings/${f.id}`);
        }}
        empty={
          <div
            className="font-mono"
            style={{ padding: 34, textAlign: "center", fontSize: 12, color: "var(--text-muted)" }}
          >
            no findings yet -- they appear here once the engine completes a poc.
          </div>
        }
        renderCells={(f) => [
          <MonoBadge tone={disclosureTone[f.disclosure_status] ?? "muted"}>
            {f.disclosure_status}
          </MonoBadge>,
          <span
            style={{
              color: f.assigned_cve_id ? "var(--accent)" : "var(--text-faint)",
              fontSize: 11,
              letterSpacing: "0.08em",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              display: "block",
            }}
          >
            {f.assigned_cve_id ?? "--"}
          </span>,
          f.crash_type ? (
            <MonoBadge tone="high">{f.crash_type}</MonoBadge>
          ) : (
            <span style={{ fontSize: 10, color: "var(--text-faint)" }}>--</span>
          ),
          <span
            style={{
              color: "var(--text-primary)",
              fontSize: 12,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              display: "block",
            }}
          >
            {f.vulnerable_function || "(unknown function)"}
          </span>,
          <span
            style={{
              color: "var(--text-muted)",
              fontSize: 11,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              display: "block",
            }}
          >
            {projectTargetName}
          </span>,
          <span style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
            {formatDateTime(f.reported_at ?? null)}
          </span>,
          <span
            onClick={(e) => e.stopPropagation()}
            style={{ display: "inline-flex", justifyContent: "center" }}
          >
            {f.id ? (
              <Link
                to={`/vr/projects/${projectId}/findings/${f.id}`}
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.08em",
                  color: "var(--text-muted)",
                  textDecoration: "none",
                }}
              >
                open
              </Link>
            ) : null}
          </span>,
        ]}
      />
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Agent log tab -- mono log stream of turns from the project's primary
// investigation, with per-investigation link header.
// ---------------------------------------------------------------------------
function AgentLogTab({
  project,
}: {
  project: VRProjectSummary;
}) {
  const { data: invsResult, isLoading: invsLoading } = useInvestigations();
  const projInvs = (invsResult?.data ?? []).filter(
    (i) => i.target_id === project.target_id,
  );
  const primary = projInvs[0];
  const { data: messagesResult, isLoading: msgsLoading } = useInvestigationMessages(
    primary?.id ?? "",
  );
  const messages = messagesResult?.data ?? [];

  if (invsLoading) {
    return (
      <WindowPanel title="agent log" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }
  if (projInvs.length === 0) {
    return (
      <WindowPanel title="agent log" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", padding: 20 }}
        >
          no investigations have been started for this project&#39;s target yet.
        </p>
      </WindowPanel>
    );
  }

  const headerActions = (
    <div className="flex items-center" style={{ gap: 8 }}>
      {projInvs.slice(0, 3).map((inv) => (
        <Link
          key={inv.id}
          to={`/vr/investigations/${inv.id}`}
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.09em",
            color: inv.id === primary?.id ? "var(--accent)" : "var(--text-muted)",
            textDecoration: "none",
          }}
        >
          {inv.title.length > 24 ? inv.title.slice(0, 24) + "..." : inv.title}
        </Link>
      ))}
    </div>
  );

  return (
    <WindowPanel title="agent log" tone="info" actions={headerActions} flush>
      {msgsLoading ? (
        <div style={{ padding: 14 }}>
          <LoadingSkeleton size="lg" width="full" />
        </div>
      ) : messages.length === 0 ? (
        <div
          className="font-mono"
          style={{ padding: 24, textAlign: "center", fontSize: 11, color: "var(--text-muted)" }}
        >
          no turns yet -- engine has not reasoned about this target.
        </div>
      ) : (
        <div style={{ maxHeight: 520, overflowY: "auto" }}>
          {messages.map((m) => {
            const senderTone = m.sender_kind === "operator" ? "accent" : "info";
            const senderLabel = m.sender_kind === "operator" ? "operator" : "engine";
            const prose = extractProse(m.payload);
            return (
              <div
                key={m.id}
                className="font-mono"
                style={{
                  display: "grid",
                  gridTemplateColumns: "84px 96px 1fr 40px",
                  gap: 10,
                  padding: "6px 12px",
                  borderBottom: "1px solid var(--border-faint)",
                  background: "var(--surface-card)",
                  fontSize: 10.5,
                  alignItems: "center",
                }}
              >
                <span style={{ color: "var(--text-faint)" }}>
                  {formatTime(m.created_at)}
                </span>
                <MonoBadge tone={senderTone}>{senderLabel}</MonoBadge>
                <span
                  style={{
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {prose || m.payload_kind}
                </span>
                <span
                  style={{
                    color: "var(--text-faint)",
                    fontSize: 9.5,
                    textAlign: "right",
                  }}
                >
                  {m.at_turn != null ? `t${m.at_turn}` : ""}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </WindowPanel>
  );
}

function extractProse(payload: Record<string, unknown>): string {
  const candidate = payload["text"] ?? payload["message"] ?? payload["prose"] ?? payload["content"];
  if (typeof candidate === "string") return candidate.replace(/\s+/g, " ").trim();
  return "";
}

// ---------------------------------------------------------------------------
// Advisory tab -- disclosure brief per finding.
// ---------------------------------------------------------------------------
function AdvisoryTab({
  project,
}: {
  project: VRProjectSummary;
}) {
  const { data: findingsResult, isLoading } = useVRFindings(project.id);
  if (isLoading) {
    return (
      <WindowPanel title="disclosure" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }
  const findings = findingsResult?.data ?? [];
  if (findings.length === 0) {
    return (
      <WindowPanel title="disclosure" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", padding: 20 }}
        >
          no findings to advise on yet.
        </p>
      </WindowPanel>
    );
  }
  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      {findings.map((f) => (
        <WindowPanel
          key={f.id ?? Math.random().toString(36)}
          title="disclosure"
          tone={f.disclosure_status === "patched" || f.disclosure_status === "public" ? "ok" : "warn"}
          actions={
            <MonoBadge tone={disclosureTone[f.disclosure_status] ?? "muted"}>
              {f.disclosure_status}
            </MonoBadge>
          }
        >
          <BriefRow label="finding">
            {f.vulnerable_function || "(unknown function)"}
          </BriefRow>
          <BriefRow label="tracking">
            {f.assigned_cve_id ? (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.assigned_cve_id)}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--accent)", textDecoration: "none" }}
              >
                {f.assigned_cve_id}
              </a>
            ) : (
              "--"
            )}
          </BriefRow>
          <BriefRow label="status">
            <MonoBadge tone={disclosureTone[f.disclosure_status] ?? "muted"}>
              {f.disclosure_status}
            </MonoBadge>
          </BriefRow>
          <BriefRow label="target vendor">{f.vendor_contact ?? "--"}</BriefRow>
          <BriefRow label="advisory url">
            {f.advisory_id ? (
              <Link
                to="/vr/disclosures"
                style={{ color: "var(--accent)", textDecoration: "none" }}
              >
                {f.advisory_id}
              </Link>
            ) : (
              "--"
            )}
          </BriefRow>
        </WindowPanel>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ProjectDetailPage
// ---------------------------------------------------------------------------
export function ProjectDetailPage() {
  const { projectId = "" } = useParams<{ projectId: string }>();
  const { data: project, isLoading, isError } = useVRProject(projectId);
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const headerTargetName = useTargetName(project?.target_id);
  const deleteMut = useDeleteProject();
  const navigate = useNavigate();

  if (isLoading) {
    return (
      <WindowPanel title="project" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }
  if (isError || !project) {
    return (
      <WindowPanel title="project" tone="accent">
        <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
          failed to load vr project.
        </p>
      </WindowPanel>
    );
  }

  const deleteAction = (
    <DeleteButton
      id={project.id}
      label={`project "${project.name}"`}
      mutation={deleteMut}
      onDeleted={() => navigate("/vr")}
    />
  );

  return (
    <div className="flex flex-col" style={{ gap: 18 }}>
      <h2 className="sr-only">Project sections</h2>
      <SectionHeader
        title={
          <span className="flex items-baseline" style={{ gap: 12 }}>
            <span>{project.name}</span>
            {project.cve_id ? (
              <span
                className="font-mono"
                style={{
                  fontSize: 11,
                  color: "var(--accent)",
                  letterSpacing: "0.08em",
                }}
              >
                {project.cve_id}
              </span>
            ) : null}
          </span>
        }
        actions={deleteAction}
      />

      <Segmented<TabId>
        options={TAB_OPTIONS}
        value={activeTab}
        onChange={setActiveTab}
      />

      {activeTab === "overview" && <OverviewTab project={project} />}
      {activeTab === "findings" && (
        <FindingsTab
          projectId={projectId}
          projectTargetName={headerTargetName}
        />
      )}
      {activeTab === "agent" && <AgentLogTab project={project} />}
      {activeTab === "advisory" && <AdvisoryTab project={project} />}
    </div>
  );
}
