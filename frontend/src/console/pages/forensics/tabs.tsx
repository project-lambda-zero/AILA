/**
 * The 15 project-scoped tab panels for ForensicsProjectPage. Each panel
 * owns its own react-query fetch against its exact /forensics/projects/
 * {project_id}/... endpoint, renders a real table (mirroring DataPage's
 * table styling via css()), and drops in-row/toolbar actions that hit
 * the correct mutations. Dict-valued fields render through DictPanel;
 * never as raw JSON. Honest loading/empty/error states throughout.
 */
import type { JSX, ReactNode } from "react";
import { useMemo, useState } from "react";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, ApiError } from "../../../api/client";
import { asRecord, readArray, readNum, readStr } from "../../../api/parse";
import { css } from "../../css";

import {
  CtlBtn,
  DataTable,
  DictPanel,
  KV,
  Panel,
  renderValue,
  Select,
  StatusBadge,
  TextInput,
  VerdictBadge,
  emptyNote,
  inlineNote,
  H,
} from "./panels";
import type { TableColumn } from "./panels";
import { DirectiveCreateForm, InvestigateForm, SuppressFindingForm } from "./forms";
import type { FindingRow } from "./forms";

/* --- Shared fetch scaffolding ---------------------------------------- */

interface TabProps {
  projectId: string;
  /** Sub-route callback shared with the page-level router (opens the
   *  Investigations drill-down via `section="inv:<id>"`). */
  onOpenInvestigation: (investigationId: string) => void;
}

function useForensicsQuery<T>(projectId: string, key: string[], path: string, enabled = true, extra: Record<string, unknown> = {}) {
  return useQuery<T>({
    queryKey: ["forensics", projectId, ...key],
    queryFn: () => apiFetch<T>(path),
    enabled: enabled && Boolean(projectId),
    retry: false,
    ...extra,
  });
}

function LoadingErrorEmpty({
  q,
  emptyLabel,
  endpoint,
  minRows,
}: {
  q: { isLoading: boolean; isError: boolean; error: unknown };
  emptyLabel: string;
  endpoint: string;
  minRows: boolean;
}): JSX.Element | null {
  if (q.isLoading) return <div style={emptyNote}>{"loading\u2026"}</div>;
  if (q.isError) {
    const msg = q.error instanceof Error ? q.error.message : "request failed";
    return (
      <div style={emptyNote}>
        could not load {endpoint} &mdash; {msg}
      </div>
    );
  }
  if (minRows) return <div style={emptyNote}>{emptyLabel}</div>;
  return null;
}

/* --- 0. OVERVIEW ----------------------------------------------------- */

export interface ProjectSummary {
  id: string;
  name: string;
  description: string;
  system_id: number;
  system_name: string | null;
  evidence_directory: string;
  analyzer_os: string;
  project_kind: string;
  status: string;
  evidence_count: number;
  artifact_count: number;
  lead_count: number;
  investigation_count: number;
  created_at?: string | null;
  updated_at?: string | null;
}

export function OverviewTab({ projectId, project }: { projectId: string; project: ProjectSummary | null }): JSX.Element {
  return (
    <Panel title="project overview" tag={project ? `#${projectId.slice(0, 8)}` : ""}>
      {project ? (
        <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:14px;")}>
          <div>
            <KV
              entries={[
                ["name", project.name],
                ["status", <StatusBadge value={project.status} key="s" />],
                ["kind", project.project_kind],
                ["analyzer os", project.analyzer_os],
                ["analyzer system", project.system_name ?? `#${project.system_id}`],
                ["evidence directory", project.evidence_directory],
                ["created", project.created_at ?? "\u2014"],
                ["updated", project.updated_at ?? "\u2014"],
              ]}
            />
          </div>
          <div>
            <KV
              entries={[
                ["evidence count", project.evidence_count],
                ["artifact count", project.artifact_count],
                ["lead count", project.lead_count],
                ["investigation count", project.investigation_count],
                ["description", project.description || "\u2014"],
              ]}
            />
          </div>
        </div>
      ) : (
        <div style={emptyNote}>project not loaded.</div>
      )}
    </Panel>
  );
}

/* --- 1. EVIDENCE ----------------------------------------------------- */

interface EvidenceItem extends Record<string, unknown> {
  id: string;
  file_path: string;
  evidence_type: string;
  file_hash_sha256: string | null;
  size_bytes: number | null;
}

const EVIDENCE_COLS: TableColumn<EvidenceItem>[] = [
  { field: "file_path", label: "path" },
  { field: "evidence_type", label: "type", width: 130 },
  { field: "file_hash_sha256", label: "sha256", width: 220 },
  {
    field: "size_bytes",
    label: "size",
    width: 110,
    render: (r) => (r.size_bytes == null ? "\u2014" : humanBytes(r.size_bytes)),
  },
];

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

export function EvidenceTab({ projectId }: TabProps): JSX.Element {
  const q = useForensicsQuery<EvidenceItem[]>(projectId, ["evidence"], `/forensics/projects/${projectId}/evidence`);
  const rows = q.data ?? [];
  const [sel, setSel] = useState<EvidenceItem | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no evidence files." endpoint="/evidence" minRows={rows.length === 0} />;
  return (
    <TableWithDetail
      title="evidence"
      tag={`${rows.length} rows`}
      table={
        state ?? (
          <DataTable rows={rows} columns={EVIDENCE_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
    />
  );
}

/* --- 2. ARTIFACTS ---------------------------------------------------- */

interface Artifact extends Record<string, unknown> {
  id: string;
  project_id: string;
  artifact_family: string;
  artifact_type: string;
  source_tool: string;
  source_evidence_id: string | null;
  source_investigation_id: string | null;
  data: Record<string, unknown>;
  lead_score: number | null;
}

const ARTIFACT_FAMILIES = [
  "host",
  "user",
  "execution",
  "browser",
  "network",
  "memory",
  "malware",
  "log",
  "filesystem",
  "container",
  "cloud",
  "mobile",
  "firmware",
];

const ARTIFACT_COLS: TableColumn<Artifact>[] = [
  { field: "artifact_family", label: "family", width: 100 },
  { field: "artifact_type", label: "type" },
  { field: "source_tool", label: "tool", width: 140 },
  {
    field: "lead_score",
    label: "score",
    width: 80,
    render: (r) => (r.lead_score == null ? "\u2014" : r.lead_score.toFixed(2)),
  },
  { field: "source_investigation_id", label: "from inv", width: 120 },
];

export function ArtifactsTab({ projectId }: TabProps): JSX.Element {
  const [family, setFamily] = useState<string>("");
  const [type, setType] = useState<string>("");
  const [source, setSource] = useState<string>("");
  const [invId, setInvId] = useState<string>("");
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const qs = new URLSearchParams();
  if (family) qs.set("artifact_family", family);
  if (type) qs.set("artifact_type", type);
  if (source) qs.set("source", source);
  if (invId) qs.set("investigation_id", invId);
  qs.set("page", String(page));
  qs.set("page_size", String(pageSize));
  const path = `/forensics/projects/${projectId}/artifacts?${qs.toString()}`;
  const q = useForensicsQuery<{ items: Artifact[]; total?: number }>(
    projectId,
    ["artifacts", qs.toString()],
    path,
  );
  const rows = q.data?.items ?? [];
  const [sel, setSel] = useState<Artifact | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no artifacts match." endpoint="/artifacts" minRows={rows.length === 0} />;
  return (
    <TableWithDetail
      title="artifacts"
      tag={`page ${page} \u00b7 ${rows.length} rows${q.data?.total != null ? ` \u00b7 total ${q.data.total}` : ""}`}
      right={
        <>
          <CtlBtn label={"\u25c0"} title="prev page" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} />
          <CtlBtn label={"\u25b6"} title="next page" onClick={() => setPage((p) => p + 1)} disabled={q.data?.total != null ? page * pageSize >= q.data.total : rows.length < pageSize} />
        </>
      }
      filters={
        <>
          <FilterField label="family">
            <Select
              value={family}
              onChange={(v) => {
                setFamily(v);
                setPage(1);
              }}
              options={[{ value: "", label: "any" }, ...ARTIFACT_FAMILIES.map((f) => ({ value: f, label: f }))]}
            />
          </FilterField>
          <FilterField label="type">
            <TextInput value={type} onChange={setType} placeholder="e.g. autorun_entry" />
          </FilterField>
          <FilterField label="source">
            <Select
              value={source}
              onChange={(v) => setSource(v)}
              options={[
                { value: "", label: "any" },
                { value: "collectors", label: "collectors" },
                { value: "investigations", label: "investigations" },
              ]}
            />
          </FilterField>
          <FilterField label="investigation id">
            <TextInput value={invId} onChange={setInvId} placeholder="\u2014" />
          </FilterField>
        </>
      }
      table={
        state ?? (
          <DataTable rows={rows} columns={ARTIFACT_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["id", row.id],
              ["family", row.artifact_family],
              ["type", row.artifact_type],
              ["tool", row.source_tool],
              ["lead score", row.lead_score],
              ["evidence id", row.source_evidence_id],
              ["from investigation", row.source_investigation_id],
            ]}
          />
          <div style={css("padding:0 3px;")}>
            <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>data</div>
            <DictPanel data={row.data ?? {}} initialOpen />
          </div>
        </div>
      )}
    />
  );
}

/* --- 3. LEADS -------------------------------------------------------- */

interface Lead extends Record<string, unknown> {
  id: string;
  score: number;
  reason: string;
  artifact_family: string;
  artifact_type: string;
  source_tool: string | null;
  evidence: { keyword: string; path: string; excerpt: string }[];
  related_artifact_ids: string[];
  question_families: string[];
}

const LEAD_COLS: TableColumn<Lead>[] = [
  {
    field: "score",
    label: "score",
    width: 70,
    render: (r) => r.score.toFixed(1),
  },
  { field: "artifact_family", label: "family", width: 100 },
  { field: "artifact_type", label: "type", width: 140 },
  { field: "source_tool", label: "tool", width: 130 },
  { field: "reason", label: "reason" },
];

export function LeadsTab({ projectId }: TabProps): JSX.Element {
  const [limit, setLimit] = useState(200);
  const q = useForensicsQuery<Lead[]>(projectId, ["leads", String(limit)], `/forensics/projects/${projectId}/leads?limit=${limit}`);
  const rows = q.data ?? [];
  const [sel, setSel] = useState<Lead | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no leads yet." endpoint="/leads" minRows={rows.length === 0} />;
  return (
    <TableWithDetail
      title="leads"
      tag={`${rows.length} of ${limit}`}
      right={
        <>
          <FilterField label="limit">
            <Select
              value={String(limit)}
              onChange={(v) => setLimit(Number(v))}
              options={[
                { value: "50", label: "50" },
                { value: "200", label: "200" },
                { value: "500", label: "500" },
                { value: "1000", label: "1000" },
              ]}
            />
          </FilterField>
        </>
      }
      table={state ?? <DataTable rows={rows} columns={LEAD_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["score", row.score.toFixed(2)],
              ["reason", row.reason],
              ["family", row.artifact_family],
              ["type", row.artifact_type],
              ["tool", row.source_tool],
              ["question families", row.question_families],
              ["related artifact ids", row.related_artifact_ids],
            ]}
          />
          <div>
            <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:8px 0 5px;")}>evidence</div>
            {row.evidence.length === 0 ? (
              <div style={emptyNote}>none.</div>
            ) : (
              <div style={css("display:flex;flex-direction:column;gap:6px;")}>
                {row.evidence.map((e, i) => (
                  <div
                    key={i}
                    style={css(
                      "border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);padding:7px 9px;font-size:10.5px;color:var(--text-primary);",
                    )}
                  >
                    <div style={css("display:flex;gap:9px;font-size:9.5px;color:var(--text-muted);margin-bottom:4px;")}>
                      <span style={css("color:var(--accent);")}>{e.keyword}</span>
                      <span>{e.path}</span>
                    </div>
                    <div style={css("white-space:pre-wrap;word-break:break-word;font-family:var(--font-mono);font-size:10px;color:var(--text-primary);")}>{e.excerpt}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    />
  );
}

/* --- 4. INVESTIGATIONS ---------------------------------------------- */

interface InvestigationSummary extends Record<string, unknown> {
  id: string;
  project_id: string;
  question: string;
  status: string;
  attempts_used: number;
  max_attempts: number | null;
  final_answer: string | null;
  confidence: string | null;
  task_id: string | null;
  parent_investigation_id: string | null;
  needs_reap: boolean;
  needs_reap_reason: string | null;
}

export function InvestigationsTab({ projectId, onOpenInvestigation }: TabProps): JSX.Element {
  const q = useForensicsQuery<InvestigationSummary[]>(
    projectId,
    ["investigations"],
    `/forensics/projects/${projectId}/investigations`,
    true,
    { refetchInterval: 6000 },
  );
  const rows = q.data ?? [];
  const [openForm, setOpenForm] = useState(false);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no investigations yet." endpoint="/investigations" minRows={rows.length === 0} />;
  const cols: TableColumn<InvestigationSummary>[] = [
    { field: "question", label: "question" },
    { field: "status", label: "status", width: 130, render: (r) => <StatusBadge value={r.status} /> },
    {
      field: "attempts_used",
      label: "attempts",
      width: 90,
      render: (r) => `${r.attempts_used}${r.max_attempts != null ? "/" + r.max_attempts : ""}`,
    },
    { field: "confidence", label: "confidence", width: 110 },
    { field: "final_answer", label: "final answer" },
    {
      field: "needs_reap",
      label: "reap",
      width: 70,
      render: (r) =>
        r.needs_reap ? (
          <span style={css(`color:${H.warn};font-size:9px;letter-spacing:0.08em;text-transform:uppercase;`)}>needs reap</span>
        ) : (
          "\u2014"
        ),
    },
  ];
  return (
    <>
      <Panel
        title="investigations"
        tag={`${rows.length}`}
        right={
          <CtlBtn label="+ ask a question" tone="accent" onClick={() => setOpenForm(true)} />
        }
      >
        {state ?? (
          <DataTable
            rows={rows}
            columns={cols}
            onSelect={(r) => onOpenInvestigation(r.id)}
            empty="no investigations yet."
          />
        )}
      </Panel>
      {openForm ? (
        <InvestigateForm projectId={projectId} onClose={() => setOpenForm(false)} onCreated={onOpenInvestigation} />
      ) : null}
    </>
  );
}

/* --- 5. ANSWERS ------------------------------------------------------ */

interface AnswerCandidate extends Record<string, unknown> {
  id: string;
  investigation_id: string | null;
  question_text: string;
  answer_text: string;
  confidence: string;
  primary_artifact_id: string | null;
  corroboration: string[];
  format_hint: string;
  created_at: string | null;
}

const ANSWER_COLS: TableColumn<AnswerCandidate>[] = [
  { field: "question_text", label: "question" },
  { field: "answer_text", label: "answer" },
  { field: "confidence", label: "confidence", width: 110 },
  { field: "primary_artifact_id", label: "primary artifact" },
  { field: "created_at", label: "created", width: 170 },
];

export function AnswersTab({ projectId }: TabProps): JSX.Element {
  const q = useForensicsQuery<AnswerCandidate[]>(projectId, ["answers"], `/forensics/projects/${projectId}/answers`);
  const rows = q.data ?? [];
  const [sel, setSel] = useState<AnswerCandidate | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no answered questions yet." endpoint="/answers" minRows={rows.length === 0} />;
  return (
    <TableWithDetail
      title="answers"
      tag={`${rows.length}`}
      table={state ?? <DataTable rows={rows} columns={ANSWER_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["question", row.question_text],
              ["answer", row.answer_text],
              ["confidence", row.confidence],
              ["primary artifact", row.primary_artifact_id],
              ["investigation", row.investigation_id],
              ["format hint", row.format_hint],
              ["created", row.created_at],
              ["corroboration", row.corroboration],
            ]}
          />
        </div>
      )}
    />
  );
}

/* --- 6. WRITEUPS ----------------------------------------------------- */

interface WriteUp extends Record<string, unknown> {
  id: string;
  investigation_id: string | null;
  title: string;
  content_markdown: string;
  methodology: string;
  artifacts_referenced: string[];
  created_at: string | null;
}

export function WriteupsTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const q = useForensicsQuery<WriteUp[]>(projectId, ["writeups"], `/forensics/projects/${projectId}/writeups`);
  const rows = q.data ?? [];
  const [sel, setSel] = useState<WriteUp | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no write-ups yet." endpoint="/writeups" minRows={rows.length === 0} />;
  const del = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/forensics/projects/${projectId}/writeups/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "writeups"] });
      setSel(null);
    },
  });
  const cols: TableColumn<WriteUp>[] = [
    { field: "title", label: "title" },
    { field: "methodology", label: "methodology" },
    {
      field: "artifacts_referenced",
      label: "artifacts",
      width: 90,
      render: (r) => String(r.artifacts_referenced.length),
    },
    { field: "created_at", label: "created", width: 170 },
  ];
  return (
    <TableWithDetail
      title="write-ups"
      tag={`${rows.length}`}
      right={
        <CtlBtn label="download all .md" tone="muted" onClick={() => downloadFile(`/forensics/projects/${projectId}/writeups.md`, `writeups-${projectId.slice(0, 8)}.md`)} />
      }
      table={
        state ?? (
          <DataTable
            rows={rows}
            columns={cols}
            selected={sel}
            onSelect={(r) => setSel((c) => (c === r ? null : r))}
            rowActions={(r) => (
              <div style={css("display:inline-flex;gap:5px;")}>
                <CtlBtn label="download" tone="muted" onClick={() => downloadFile(`/forensics/projects/${projectId}/writeups/${r.id}.md`, `${r.title || r.id}.md`)} />
                <CtlBtn label="delete" tone="danger" onClick={() => window.confirm("Delete write-up?") && del.mutate(r.id)} />
              </div>
            )}
          />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV entries={[["title", row.title], ["methodology", row.methodology], ["investigation", row.investigation_id], ["created", row.created_at], ["artifacts referenced", row.artifacts_referenced]]} />
          <div>
            <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:6px 0 4px;")}>content</div>
            <pre style={css("margin:0;padding:10px;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:60vh;overflow:auto;")}>
              {row.content_markdown}
            </pre>
          </div>
        </div>
      )}
    />
  );
}

/* --- 7. TIMELINE ---------------------------------------------------- */

interface TimelineEntry extends Record<string, unknown> {
  timestamp: string;
  source: string;
  event_type: string;
  description: string;
  artifact_id: string | null;
  source_investigation_id: string | null;
  timestamp_origin: string;
  data: Record<string, unknown>;
}

const CONF_OPTIONS = [
  { value: "low", label: "low (any event-time)" },
  { value: "medium", label: "medium (default)" },
  { value: "high", label: "high (confirmed only)" },
];

export function TimelineTab({ projectId }: TabProps): JSX.Element {
  const [minConf, setMinConf] = useState("medium");
  const q = useForensicsQuery<TimelineEntry[]>(
    projectId,
    ["timeline", minConf],
    `/forensics/projects/${projectId}/timeline?min_confidence=${minConf}&limit=2000`,
  );
  const rows = q.data ?? [];
  const [sel, setSel] = useState<TimelineEntry | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no time-anchored events at this confidence." endpoint="/timeline" minRows={rows.length === 0} />;
  const cols: TableColumn<TimelineEntry>[] = [
    { field: "timestamp", label: "timestamp", width: 200 },
    { field: "source", label: "source", width: 130 },
    { field: "event_type", label: "event", width: 130 },
    { field: "description", label: "description" },
  ];
  return (
    <TableWithDetail
      title="timeline"
      tag={`${rows.length} events`}
      right={
        <FilterField label="min confidence">
          <Select value={minConf} onChange={setMinConf} options={CONF_OPTIONS} />
        </FilterField>
      }
      table={state ?? <DataTable rows={rows} columns={cols} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["timestamp", row.timestamp],
              ["origin", row.timestamp_origin],
              ["source", row.source],
              ["event type", row.event_type],
              ["description", row.description],
              ["artifact id", row.artifact_id],
              ["from investigation", row.source_investigation_id],
            ]}
          />
          <div>
            <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:6px 0 4px;")}>data</div>
            <DictPanel data={row.data ?? {}} initialOpen />
          </div>
        </div>
      )}
    />
  );
}

/* --- 8. OCCURRENCES ------------------------------------------------- */

interface Occurrence extends Record<string, unknown> {
  source: string;
  event_type: string;
  description: string;
  artifact_id: string | null;
  source_investigation_id: string | null;
  recorded_at: string;
  data: Record<string, unknown>;
}

export function OccurrencesTab({ projectId }: TabProps): JSX.Element {
  const [minConf, setMinConf] = useState("medium");
  const q = useForensicsQuery<Occurrence[]>(
    projectId,
    ["occurrences", minConf],
    `/forensics/projects/${projectId}/occurrences?min_confidence=${minConf}&limit=2000`,
  );
  const rows = q.data ?? [];
  const [sel, setSel] = useState<Occurrence | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no confident findings without event-time." endpoint="/occurrences" minRows={rows.length === 0} />;
  const cols: TableColumn<Occurrence>[] = [
    { field: "source", label: "source", width: 130 },
    { field: "event_type", label: "event", width: 130 },
    { field: "description", label: "description" },
    { field: "recorded_at", label: "recorded", width: 200 },
  ];
  return (
    <TableWithDetail
      title="occurrences"
      tag={`${rows.length}`}
      right={
        <FilterField label="min confidence">
          <Select value={minConf} onChange={setMinConf} options={CONF_OPTIONS} />
        </FilterField>
      }
      table={state ?? <DataTable rows={rows} columns={cols} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["source", row.source],
              ["event type", row.event_type],
              ["description", row.description],
              ["artifact id", row.artifact_id],
              ["from investigation", row.source_investigation_id],
              ["recorded at", row.recorded_at],
            ]}
          />
          <div>
            <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:6px 0 4px;")}>data</div>
            <DictPanel data={row.data ?? {}} initialOpen />
          </div>
        </div>
      )}
    />
  );
}

/* --- 9. DIRECTIVES -------------------------------------------------- */

interface Directive extends Record<string, unknown> {
  id: string;
  investigation_id: string | null;
  text: string;
  created_by: string | null;
  created_at: string;
  resolved_at: string | null;
  active: boolean;
  verdict: string | null;
  strategy_family: string | null;
  required_artifact: string | null;
}

export function DirectivesTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const [includeInactive, setIncludeInactive] = useState(false);
  const q = useForensicsQuery<Directive[]>(
    projectId,
    ["directives", String(includeInactive)],
    `/forensics/projects/${projectId}/directives?include_inactive=${includeInactive}`,
  );
  const rows = q.data ?? [];
  const [openForm, setOpenForm] = useState(false);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no directives." endpoint="/directives" minRows={rows.length === 0} />;
  const del = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/forensics/projects/${projectId}/directives/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["forensics", projectId, "directives"] }),
  });
  const cols: TableColumn<Directive>[] = [
    { field: "text", label: "directive" },
    {
      field: "investigation_id",
      label: "scope",
      width: 130,
      render: (r) => (r.investigation_id ? `inv ${r.investigation_id.slice(0, 8)}` : "project-wide"),
    },
    { field: "active", label: "active", width: 70, render: (r) => (r.active ? "yes" : "no") },
    { field: "verdict", label: "verdict", width: 110, render: (r) => <VerdictBadge verdict={r.verdict} /> },
    { field: "strategy_family", label: "strategy", width: 140 },
    { field: "created_by", label: "by", width: 130 },
    { field: "created_at", label: "created", width: 170 },
  ];
  return (
    <>
      <Panel
        title="directives"
        tag={`${rows.length}`}
        right={
          <>
            <label style={css("display:inline-flex;gap:6px;align-items:center;font-family:var(--font-mono);font-size:9px;color:var(--text-muted);")}>
              <input type="checkbox" checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} />
              include inactive
            </label>
            <CtlBtn label="download .md" tone="muted" onClick={() => downloadFile(`/forensics/projects/${projectId}/directives.md`, `directives-${projectId.slice(0, 8)}.md`)} />
            <CtlBtn label="+ new" tone="accent" onClick={() => setOpenForm(true)} />
          </>
        }
      >
        {state ?? (
          <DataTable
            rows={rows}
            columns={cols}
            rowActions={(r) =>
              r.active ? (
                <CtlBtn
                  label="deactivate"
                  tone="danger"
                  onClick={() => window.confirm("Soft-delete this directive?") && del.mutate(r.id)}
                />
              ) : null
            }
          />
        )}
      </Panel>
      {openForm ? <DirectiveCreateForm projectId={projectId} onClose={() => setOpenForm(false)} /> : null}
    </>
  );
}

/* --- 10. SOLID EVIDENCE --------------------------------------------- */

interface SolidEvidence extends Record<string, unknown> {
  id: string;
  question: string;
  answer: string;
  verdict: "true" | "false";
  confidence: string;
  source_investigation_id: string | null;
  primary_artifact: string | null;
  corroboration: string[];
  tagged_by: string | null;
  tagged_at: string;
  notes: string;
}

export function SolidEvidenceTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const q = useForensicsQuery<SolidEvidence[]>(projectId, ["solid-evidence"], `/forensics/projects/${projectId}/solid-evidence`);
  const rows = q.data ?? [];
  const [sel, setSel] = useState<SolidEvidence | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no analyst-tagged evidence." endpoint="/solid-evidence" minRows={rows.length === 0} />;
  const del = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/forensics/projects/${projectId}/solid-evidence/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "solid-evidence"] });
      setSel(null);
    },
  });
  const cols: TableColumn<SolidEvidence>[] = [
    { field: "question", label: "question" },
    { field: "answer", label: "answer" },
    { field: "verdict", label: "verdict", width: 100, render: (r) => <VerdictBadge verdict={r.verdict} /> },
    { field: "confidence", label: "confidence", width: 110 },
    { field: "primary_artifact", label: "artifact" },
    { field: "tagged_by", label: "by", width: 130 },
    { field: "tagged_at", label: "tagged", width: 170 },
  ];
  return (
    <TableWithDetail
      title="solid evidence"
      tag={`${rows.length}`}
      table={
        state ?? (
          <DataTable
            rows={rows}
            columns={cols}
            selected={sel}
            onSelect={(r) => setSel((c) => (c === r ? null : r))}
            rowActions={(r) => (
              <CtlBtn
                label="delete"
                tone="danger"
                onClick={() => window.confirm("Remove this solid-evidence row?") && del.mutate(r.id)}
              />
            )}
          />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;")}>
          <KV
            entries={[
              ["question", row.question],
              ["answer", row.answer],
              ["verdict", <VerdictBadge verdict={row.verdict} key="v" />],
              ["confidence", row.confidence],
              ["primary artifact", row.primary_artifact],
              ["from investigation", row.source_investigation_id],
              ["tagged by", row.tagged_by],
              ["tagged at", row.tagged_at],
              ["notes", row.notes || "\u2014"],
              ["corroboration", row.corroboration],
            ]}
          />
        </div>
      )}
    />
  );
}

/* --- 11. FINDINGS ---------------------------------------------------- */

export function FindingsTab({ projectId }: TabProps): JSX.Element {
  const q = useForensicsQuery<FindingRow[]>(projectId, ["findings"], `/forensics/projects/${projectId}/findings`);
  const rows = q.data ?? [];
  const [sel, setSel] = useState<FindingRow | null>(null);
  const [suppress, setSuppress] = useState<FindingRow | null>(null);
  const state = <LoadingErrorEmpty q={q} emptyLabel="no suspicious findings." endpoint="/findings" minRows={rows.length === 0} />;
  const cols: TableColumn<FindingRow>[] = [
    { field: "artifact_type", label: "type", width: 150 },
    { field: "executable", label: "executable" },
    { field: "path", label: "path" },
    { field: "name", label: "name" },
    { field: "user", label: "user", width: 120 },
    {
      field: "suspicious_reasons",
      label: "reasons",
      render: (r) => {
        const rs = readArray(r, "suspicious_reasons");
        return rs ? rs.join(", ") : "\u2014";
      },
    },
    {
      field: "occurrences",
      label: "count",
      width: 70,
      render: (r) => String(readNum(r, "occurrences") ?? 1),
    },
  ];
  return (
    <>
      <TableWithDetail
        title="findings"
        tag={`${rows.length} rows`}
        table={
          state ?? (
            <DataTable
              rows={rows}
              columns={cols}
              selected={sel}
              onSelect={(r) => setSel((c) => (c === r ? null : r))}
              rowActions={(r) => (
                <CtlBtn label="suppress" tone="warn" onClick={() => setSuppress(r)} />
              )}
            />
          )
        }
        detail={sel}
        onClose={() => setSel(null)}
        detailRenderer={(row) => (
          <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
            <KV
              entries={[
                ["fingerprint", readStr(row, "fingerprint") ?? "\u2014"],
                ["artifact type", readStr(row, "artifact_type") ?? "\u2014"],
                ["artifact family", row["artifact_family"]],
                ["source tool", row["source_tool"]],
                ["executable", readStr(row, "executable") ?? "\u2014"],
                ["path", readStr(row, "path") ?? "\u2014"],
                ["name", readStr(row, "name") ?? "\u2014"],
                ["user", readStr(row, "user") ?? "\u2014"],
                ["reasons", row["suspicious_reasons"]],
                ["last run", row["last_run"]],
                ["run count", row["run_count"]],
                ["occurrences", row["occurrences"]],
              ]}
            />
            <div>
              <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:6px 0 4px;")}>raw record</div>
              <DictPanel data={asRecord(row["raw_record"]) ?? {}} />
            </div>
          </div>
        )}
      />
      {suppress ? (
        <SuppressFindingForm projectId={projectId} row={suppress} onClose={() => setSuppress(null)} />
      ) : null}
    </>
  );
}

/* --- 12. SUPPRESSIONS ----------------------------------------------- */

interface Suppression extends Record<string, unknown> {
  id: string;
  fingerprint: string;
  artifact_type: string | null;
  executable: string | null;
  path: string | null;
  name: string | null;
  finding_user: string | null;
  reasons: string[];
  notes: string;
  suppressed_by: string | null;
  suppressed_at: string;
}

export function SuppressionsTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const q = useForensicsQuery<Suppression[]>(projectId, ["suppressions"], `/forensics/projects/${projectId}/findings/suppressions`);
  const rows = q.data ?? [];
  const state = <LoadingErrorEmpty q={q} emptyLabel="no suppressions." endpoint="/findings/suppressions" minRows={rows.length === 0} />;
  const del = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/forensics/projects/${projectId}/findings/suppressions/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "suppressions"] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "findings"] });
    },
  });
  const cols: TableColumn<Suppression>[] = [
    { field: "fingerprint", label: "fingerprint" },
    { field: "artifact_type", label: "type", width: 140 },
    { field: "path", label: "path" },
    { field: "name", label: "name" },
    { field: "reasons", label: "reasons", render: (r) => r.reasons.join(", ") },
    { field: "suppressed_by", label: "by", width: 130 },
    { field: "suppressed_at", label: "suppressed", width: 180 },
  ];
  return (
    <Panel title="suppressions" tag={`${rows.length}`}>
      {state ?? (
        <DataTable
          rows={rows}
          columns={cols}
          rowActions={(r) => (
            <CtlBtn
              label="delete"
              tone="danger"
              onClick={() => window.confirm("Remove suppression? The row re-appears.") && del.mutate(r.id)}
            />
          )}
        />
      )}
    </Panel>
  );
}

/* --- 13. NETWORK ANALYSIS ------------------------------------------- */

interface NetworkAnalysisPayload {
  stats: Record<string, unknown>;
  protocol_hierarchy: Record<string, unknown>[];
  hosts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
  dns: Record<string, unknown>[];
  suspicious_dns: Record<string, unknown>[];
  http_requests: Record<string, unknown>[];
  http_responses: Record<string, unknown>[];
  tls_client_hellos: Record<string, unknown>[];
  unusual_ports: Record<string, unknown>[];
  user_agents: Record<string, unknown>[];
  credentials: Record<string, unknown>[];
  beacons: Record<string, unknown>[];
  anomalies: Record<string, unknown>[];
  commentary: Record<string, unknown>[];
  // Index signature so the payload satisfies the `T extends Record<string, unknown>`
  // constraint on StructuredAnalysisTab; the specific keys above narrow further.
  [k: string]: unknown;
}

const NETWORK_SECTIONS: [keyof NetworkAnalysisPayload, string][] = [
  ["protocol_hierarchy", "protocol hierarchy"],
  ["hosts", "hosts"],
  ["sessions", "sessions"],
  ["dns", "dns"],
  ["suspicious_dns", "suspicious dns"],
  ["http_requests", "http requests"],
  ["http_responses", "http responses"],
  ["tls_client_hellos", "tls client hellos"],
  ["unusual_ports", "unusual ports"],
  ["user_agents", "user agents"],
  ["credentials", "credentials"],
  ["beacons", "beacons"],
  ["anomalies", "anomalies"],
  ["commentary", "commentary"],
];

export function NetworkAnalysisTab({ projectId }: TabProps): JSX.Element {
  return (
    <StructuredAnalysisTab<NetworkAnalysisPayload>
      projectId={projectId}
      path={`/forensics/projects/${projectId}/network-analysis`}
      queryKey="network-analysis"
      title="network analysis"
      sections={NETWORK_SECTIONS as [string, string][]}
      statsKey="stats"
    />
  );
}

/* --- 14. REGISTRY ANALYSIS ------------------------------------------ */

interface RegistryAnalysisPayload {
  autoruns: Record<string, unknown>[];
  services: Record<string, unknown>[];
  installed_software: Record<string, unknown>[];
  user_accounts: Record<string, unknown>[];
  usb_history: Record<string, unknown>[];
  recent_docs: Record<string, unknown>[];
  network_interfaces: Record<string, unknown>[];
  shellbags: Record<string, unknown>[];
  amcache: Record<string, unknown>[];
  shimcache: Record<string, unknown>[];
  bam: Record<string, unknown>[];
  security_packages: Record<string, unknown>[];
  [k: string]: unknown;
}

const REGISTRY_SECTIONS: [keyof RegistryAnalysisPayload, string][] = [
  ["autoruns", "autoruns"],
  ["services", "services"],
  ["installed_software", "installed software"],
  ["user_accounts", "user accounts"],
  ["usb_history", "usb history"],
  ["recent_docs", "recent docs"],
  ["network_interfaces", "network interfaces"],
  ["shellbags", "shellbags"],
  ["amcache", "amcache"],
  ["shimcache", "shimcache"],
  ["bam", "bam"],
  ["security_packages", "security packages"],
];

export function RegistryAnalysisTab({ projectId }: TabProps): JSX.Element {
  return (
    <StructuredAnalysisTab<RegistryAnalysisPayload>
      projectId={projectId}
      path={`/forensics/projects/${projectId}/registry-analysis`}
      queryKey="registry-analysis"
      title="registry analysis"
      sections={REGISTRY_SECTIONS as [string, string][]}
    />
  );
}

/* --- helpers: multi-section structured analysis ---------------------- */

function StructuredAnalysisTab<T extends Record<string, unknown>>({
  projectId,
  path,
  queryKey,
  title,
  sections,
  statsKey,
}: {
  projectId: string;
  path: string;
  queryKey: string;
  title: string;
  sections: [string, string][];
  statsKey?: string;
}): JSX.Element {
  const q = useForensicsQuery<T>(projectId, [queryKey], path);
  const [active, setActive] = useState<string>(sections[0][0]);
  if (q.isLoading) return <div style={emptyNote}>{"loading\u2026"}</div>;
  if (q.isError) {
    const msg = q.error instanceof Error ? q.error.message : "request failed";
    return <div style={emptyNote}>could not load {title} &mdash; {msg}</div>;
  }
  const data = q.data;
  if (!data) return <div style={emptyNote}>no data.</div>;
  const rows = (readArray(data, active) ?? []).filter(
    (r): r is Record<string, unknown> => asRecord(r) !== null,
  );
  const stats = statsKey ? asRecord(data[statsKey]) : null;

  return (
    <Panel
      title={title}
      tag={`${sections.length} sections`}
      right={
        <div style={css("display:flex;gap:4px;flex-wrap:wrap;")}>
          {sections.map(([k, label]) => {
            const src = readArray(data, k as string);
            const n = src ? src.length : 0;
            return (
              <button
                key={k}
                type="button"
                onClick={() => setActive(k)}
                style={css(
                  `background:${active === k ? "var(--accent)" : "transparent"};color:${active === k ? "var(--text-on-accent)" : "var(--text-muted)"};border:1px solid ${active === k ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;padding:2px 7px;cursor:pointer;`,
                )}
              >
                {label} {n ? `\u00b7 ${n}` : ""}
              </button>
            );
          })}
        </div>
      }
    >
      <div style={css("padding:12px;display:flex;flex-direction:column;gap:12px;")}>
        {stats && Object.keys(stats).length ? (
          <div>
            <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>stats</div>
            <DictPanel data={stats} initialOpen />
          </div>
        ) : null}
        <div>
          <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>{sections.find(([k]) => k === active)?.[1] ?? active}</div>
          {rows.length === 0 ? (
            <div style={inlineNote}>no rows in this section.</div>
          ) : (
            <SectionAutoTable rows={rows} />
          )}
        </div>
      </div>
    </Panel>
  );
}

function SectionAutoTable({ rows }: { rows: Record<string, unknown>[] }): JSX.Element {
  const cols = useMemo<TableColumn<Record<string, unknown>>[]>(() => {
    const keys: string[] = [];
    const seen: Record<string, true> = {};
    for (const r of rows.slice(0, 60)) {
      for (const k of Object.keys(r)) {
        if (!seen[k]) {
          seen[k] = true;
          keys.push(k);
        }
      }
    }
    return keys.slice(0, 10).map((k) => ({
      field: k,
      label: k.replace(/_/g, " "),
      render: (row) => {
        const v = row[k];
        if (v === null || v === undefined) return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
        if (typeof v === "object") return renderValue(v);
        return String(v);
      },
    }));
  }, [rows]);
  return <DataTable rows={rows} columns={cols} />;
}

/* --- Shared TableWithDetail layout ---------------------------------- */

function TableWithDetail<R>({
  title,
  tag,
  right,
  filters,
  table,
  detail,
  onClose,
  detailRenderer,
}: {
  title: string;
  tag?: string;
  right?: ReactNode;
  filters?: ReactNode;
  table: ReactNode;
  detail: R | null;
  onClose: () => void;
  detailRenderer?: (row: R) => ReactNode;
}): JSX.Element {
  const showDetail = detail !== null && detail !== undefined;
  return (
    <div style={css("flex:1;min-height:0;display:flex;gap:10px;flex-direction:column;")}>
      {filters ? (
        <div
          style={css(
            "display:flex;flex-wrap:wrap;gap:9px;align-items:end;padding:8px 10px;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);",
          )}
        >
          {filters}
        </div>
      ) : null}
      <div style={css("flex:1;min-height:0;display:flex;gap:10px;")}>
        <div style={{ flex: showDetail ? "1 1 62%" : "1 1 100%", minWidth: 0, display: "flex" }}>
          <Panel title={title} tag={tag} right={right}>
            {table}
          </Panel>
        </div>
        {showDetail ? (
          <div style={{ flex: "1 1 38%", minWidth: 0, display: "flex" }}>
            <Panel
              title="detail"
              right={
                <button
                  type="button"
                  onClick={onClose}
                  style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:12px;")}
                >
                  {"\u2715"}
                </button>
              }
            >
              {detailRenderer && detail
                ? detailRenderer(detail)
                : detail
                ? (
                  <div style={css("padding:11px 13px;")}>
                    <KV entries={Object.entries(asRecord(detail) ?? {})} />
                  </div>
                )
                : null}
            </Panel>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function FilterField({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <label style={css("display:flex;flex-direction:column;gap:3px;min-width:130px;")}>
      <span style={css("font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>{label}</span>
      {children}
    </label>
  );
}

/* --- Bearer-authenticated file download ----------------------------- */

async function downloadFile(path: string, filename: string): Promise<void> {
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
    const msg = e instanceof ApiError ? e.message : e instanceof Error ? e.message : "download failed";
    console.warn(`download failed: ${msg}`);
  }
}
