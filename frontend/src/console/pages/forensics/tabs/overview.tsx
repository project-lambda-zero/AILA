import type { JSX } from "react";

import {
  parseArtifactPage,
  parseInvestigationSummary,
  parseLead,
  parseRows,
  useForensicsQuery,
} from "../../../../api/forensics";
import type { Artifact, InvestigationSummary, Lead, ProjectSummary } from "../../../../api/forensics";
import { css } from "../../../css";
import { DataTable, KV, Panel, StatusBadge, emptyNote } from "../panels";
import type { TableColumn } from "../panels";

const LEAD_COLS: TableColumn<Lead>[] = [
  { field: "score", label: "score", width: 64, render: (r) => r.score.toFixed(1) },
  { field: "artifact_family", label: "family", width: 90 },
  { field: "artifact_type", label: "type", width: 130 },
  { field: "reason", label: "reason" },
];

const INV_COLS: TableColumn<InvestigationSummary>[] = [
  { field: "question", label: "question" },
  { field: "status", label: "status", width: 120, render: (r) => <StatusBadge value={r.status} /> },
  { field: "attempts_used", label: "turns", width: 70, render: (r) => `${r.attempts_used}${r.max_attempts != null ? "/" + r.max_attempts : ""}` },
  { field: "confidence", label: "confidence", width: 100 },
];

const ART_COLS: TableColumn<Artifact>[] = [
  { field: "artifact_family", label: "family", width: 90 },
  { field: "artifact_type", label: "type" },
  { field: "source_tool", label: "tool", width: 130 },
  { field: "lead_score", label: "score", width: 70, render: (r) => (r.lead_score == null ? "\u2014" : r.lead_score.toFixed(2)) },
];

export function OverviewTab({
  projectId,
  project,
  onOpenInvestigation,
}: {
  projectId: string;
  project: ProjectSummary | null;
  onOpenInvestigation: (id: string) => void;
}): JSX.Element {
  const leadsQ = useForensicsQuery(projectId, ["leads-overview"], `/forensics/projects/${projectId}/leads?limit=10`, (raw) => parseRows(raw, parseLead));
  const invQ = useForensicsQuery(
    projectId,
    ["inv-overview"],
    `/forensics/projects/${projectId}/investigations`,
    (raw) => parseRows(raw, parseInvestigationSummary),
    8000,
  );
  const artQ = useForensicsQuery(projectId, ["art-overview"], `/forensics/projects/${projectId}/artifacts?page=1&page_size=10`, parseArtifactPage);

  const leads = leadsQ.data ?? [];
  const invs = invQ.data ?? [];
  const arts = artQ.data?.items ?? [];

  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;padding:10px;min-height:0;overflow:auto;")}>
      {/* metadata row */}
      <Panel title="project" tag={project ? `#${projectId.slice(0, 8)}` : ""}>
        {project ? (
          <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:0;")}>
            <KV
              entries={[
                ["name", project.name],
                ["status", <StatusBadge value={project.status} key="s" />],
                ["kind", project.project_kind],
                ["analyzer os", project.analyzer_os],
                ["system", project.system_name ?? `#${project.system_id}`],
                ["evidence dir", project.evidence_directory],
              ]}
            />
            <KV
              entries={[
                ["evidence", project.evidence_count],
                ["artifacts", project.artifact_count],
                ["leads", project.lead_count],
                ["investigations", project.investigation_count],
                ["created", project.created_at ?? "\u2014"],
                ["description", project.description || "\u2014"],
              ]}
            />
          </div>
        ) : (
          <div style={emptyNote}>project not loaded.</div>
        )}
      </Panel>

      {/* leads + investigations row */}
      <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;min-height:180px;")}>
        <Panel title="top leads" tag={`${leads.length}`}>
          {leadsQ.isLoading ? (
            <div style={emptyNote}>{"loading\u2026"}</div>
          ) : leads.length === 0 ? (
            <div style={emptyNote}>no leads yet.</div>
          ) : (
            <DataTable rows={leads} columns={LEAD_COLS} />
          )}
        </Panel>

        <Panel title="investigations" tag={`${invs.length}`}>
          {invQ.isLoading ? (
            <div style={emptyNote}>{"loading\u2026"}</div>
          ) : invs.length === 0 ? (
            <div style={emptyNote}>no investigations yet.</div>
          ) : (
            <DataTable rows={invs} columns={INV_COLS} onSelect={(r) => onOpenInvestigation(r.id)} />
          )}
        </Panel>
      </div>

      {/* artifacts row */}
      <Panel title="recent artifacts" tag={`${arts.length}`} style={{ minHeight: 140 }}>
        {artQ.isLoading ? (
          <div style={emptyNote}>{"loading\u2026"}</div>
        ) : arts.length === 0 ? (
          <div style={emptyNote}>no artifacts yet.</div>
        ) : (
          <DataTable rows={arts} columns={ART_COLS} />
        )}
      </Panel>
    </div>
  );
}
