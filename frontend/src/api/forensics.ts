/**
 * Forensics project API surface: typed rows for every /forensics/projects/
 * {project_id}/... read the project window renders, parsed ONCE at the fetch
 * boundary with the narrowers in ./parse, plus the Bearer-authenticated file
 * download. Reasoning-graph replay lives in ./forensicsReasoning.
 *
 * Field shapes mirror the backend Pydantic response models in
 * src/aila/modules/forensics/contracts.
 */
import { useQuery } from "@tanstack/react-query";

import { useAuth } from "./auth";
import { API_BASE, ApiError, apiFetch } from "./client";
import {
  asRecord,
  readBool,
  readNum,
  readRecordArray,
  readStr,
  readStrArray,
} from "./parse";

type Obj = Record<string, unknown>;

const str = (o: Obj, k: string): string => readStr(o, k) ?? "";
const rec = (o: Obj, k: string): Obj => asRecord(o[k]) ?? {};
/** Numeric fields some collectors emit where others emit text (epoch vs ISO). */
const numText = (o: Obj, k: string): string | null => {
  const n = readNum(o, k);
  return n === null ? null : String(n);
};

/** Parse a JSON array response, keeping only object elements. */
export function parseRows<T>(raw: unknown, parse: (o: Obj) => T): T[] {
  if (!Array.isArray(raw)) return [];
  const out: T[] = [];
  for (const el of raw) {
    const o = asRecord(el);
    if (o) out.push(parse(o));
  }
  return out;
}

/** Parse a single-object response; a non-object body is a contract break. */
export function parseOne<T>(raw: unknown, parse: (o: Obj) => T): T {
  const o = asRecord(raw);
  if (!o) throw new Error("malformed response: expected an object");
  return parse(o);
}

/** Project-scoped forensics query: one react-query key namespace
 * (`["forensics", projectId, ...key]`) and the parser applied in queryFn. */
export function useForensicsQuery<T>(
  projectId: string,
  key: readonly string[],
  path: string,
  parse: (raw: unknown) => T,
  refetchInterval: number | false = false,
) {
  return useQuery({
    queryKey: ["forensics", projectId, ...key],
    queryFn: async () => parse(await apiFetch<unknown>(path)),
    enabled: Boolean(projectId),
    retry: false,
    refetchInterval,
  });
}

/* --- project ---------------------------------------------------------- */

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
  created_at: string | null;
  updated_at: string | null;
}

export function parseProjectSummary(o: Obj): ProjectSummary {
  return {
    id: str(o, "id"),
    name: str(o, "name"),
    description: str(o, "description"),
    system_id: readNum(o, "system_id") ?? 0,
    system_name: readStr(o, "system_name"),
    evidence_directory: str(o, "evidence_directory"),
    analyzer_os: str(o, "analyzer_os"),
    project_kind: str(o, "project_kind"),
    status: str(o, "status"),
    evidence_count: readNum(o, "evidence_count") ?? 0,
    artifact_count: readNum(o, "artifact_count") ?? 0,
    lead_count: readNum(o, "lead_count") ?? 0,
    investigation_count: readNum(o, "investigation_count") ?? 0,
    created_at: readStr(o, "created_at"),
    updated_at: readStr(o, "updated_at"),
  };
}

/* --- evidence --------------------------------------------------------- */

export interface EvidenceItem {
  id: string;
  file_path: string;
  evidence_type: string;
  file_hash_sha256: string | null;
  size_bytes: number | null;
}

export function parseEvidenceItem(o: Obj): EvidenceItem {
  return {
    id: str(o, "id"),
    file_path: str(o, "file_path"),
    evidence_type: str(o, "evidence_type"),
    file_hash_sha256: readStr(o, "file_hash_sha256"),
    size_bytes: readNum(o, "size_bytes"),
  };
}

/* --- artifacts -------------------------------------------------------- */

/** A Zeek-carved file reference: `carved_file` artifacts carry the sha256
 * the download route keys on and the filename Zeek recorded, if any. */
export interface CarvedFile {
  sha256: string;
  filename: string;
}

export interface Artifact {
  id: string;
  project_id: string;
  artifact_family: string;
  artifact_type: string;
  source_tool: string;
  source_evidence_id: string | null;
  source_investigation_id: string | null;
  data: Obj;
  lead_score: number | null;
  carved: CarvedFile | null;
}

function carvedFileOf(artifactType: string, data: Obj): CarvedFile | null {
  if (artifactType !== "carved_file") return null;
  const sha256 = readStr(data, "sha256");
  if (!sha256) return null;
  return { sha256, filename: readStr(data, "filename_guess") ?? `carved_${sha256.slice(0, 12)}.bin` };
}

export function parseArtifact(o: Obj): Artifact {
  const artifactType = str(o, "artifact_type");
  const data = rec(o, "data");
  return {
    id: str(o, "id"),
    project_id: str(o, "project_id"),
    artifact_family: str(o, "artifact_family"),
    artifact_type: artifactType,
    source_tool: str(o, "source_tool"),
    source_evidence_id: readStr(o, "source_evidence_id"),
    source_investigation_id: readStr(o, "source_investigation_id"),
    data,
    lead_score: readNum(o, "lead_score"),
    carved: carvedFileOf(artifactType, data),
  };
}

export interface ArtifactPage {
  items: Artifact[];
  total: number | null;
}

export function parseArtifactPage(raw: unknown): ArtifactPage {
  const o = asRecord(raw) ?? {};
  return { items: parseRows(o.items, parseArtifact), total: readNum(o, "total") };
}

/** Download path for a carved file (GET /pcap/carved/{sha256}). */
export function carvedFilePath(projectId: string, sha256: string): string {
  return `/forensics/projects/${projectId}/pcap/carved/${encodeURIComponent(sha256)}`;
}

/* --- leads ------------------------------------------------------------ */

export interface LeadEvidence {
  keyword: string;
  path: string;
  excerpt: string;
}

export interface Lead {
  id: string;
  score: number;
  reason: string;
  artifact_family: string;
  artifact_type: string;
  source_tool: string | null;
  evidence: LeadEvidence[];
  related_artifact_ids: string[];
  question_families: string[];
}

export function parseLead(o: Obj): Lead {
  return {
    id: str(o, "id"),
    score: readNum(o, "score") ?? 0,
    reason: str(o, "reason"),
    artifact_family: str(o, "artifact_family"),
    artifact_type: str(o, "artifact_type"),
    source_tool: readStr(o, "source_tool"),
    evidence: readRecordArray(o, "evidence").map((e) => ({
      keyword: str(e, "keyword"),
      path: str(e, "path"),
      excerpt: str(e, "excerpt"),
    })),
    related_artifact_ids: readStrArray(o, "related_artifact_ids"),
    question_families: readStrArray(o, "question_families"),
  };
}

/* --- investigations --------------------------------------------------- */

export interface InvestigationSummary {
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

export function parseInvestigationSummary(o: Obj): InvestigationSummary {
  return {
    id: str(o, "id"),
    project_id: str(o, "project_id"),
    question: str(o, "question"),
    status: str(o, "status"),
    attempts_used: readNum(o, "attempts_used") ?? 0,
    max_attempts: readNum(o, "max_attempts"),
    final_answer: readStr(o, "final_answer"),
    confidence: readStr(o, "confidence"),
    task_id: readStr(o, "task_id"),
    parent_investigation_id: readStr(o, "parent_investigation_id"),
    needs_reap: readBool(o, "needs_reap") ?? false,
    needs_reap_reason: readStr(o, "needs_reap_reason"),
  };
}

/* --- answers ---------------------------------------------------------- */

export interface AnswerCandidate {
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

export function parseAnswerCandidate(o: Obj): AnswerCandidate {
  return {
    id: str(o, "id"),
    investigation_id: readStr(o, "investigation_id"),
    question_text: str(o, "question_text"),
    answer_text: str(o, "answer_text"),
    confidence: str(o, "confidence"),
    primary_artifact_id: readStr(o, "primary_artifact_id"),
    corroboration: readStrArray(o, "corroboration"),
    format_hint: str(o, "format_hint"),
    created_at: readStr(o, "created_at"),
  };
}

/* --- write-ups -------------------------------------------------------- */

export interface WriteUp {
  id: string;
  investigation_id: string | null;
  title: string;
  content_markdown: string;
  methodology: string;
  artifacts_referenced: string[];
  created_at: string | null;
}

export function parseWriteUp(o: Obj): WriteUp {
  return {
    id: str(o, "id"),
    investigation_id: readStr(o, "investigation_id"),
    title: str(o, "title"),
    content_markdown: str(o, "content_markdown"),
    methodology: str(o, "methodology"),
    artifacts_referenced: readStrArray(o, "artifacts_referenced"),
    created_at: readStr(o, "created_at"),
  };
}

/* --- timeline + occurrences ------------------------------------------- */

export interface TimelineEntry {
  timestamp: string;
  source: string;
  event_type: string;
  description: string;
  artifact_id: string | null;
  source_investigation_id: string | null;
  timestamp_origin: string;
  data: Obj;
}

export function parseTimelineEntry(o: Obj): TimelineEntry {
  return {
    timestamp: str(o, "timestamp"),
    source: str(o, "source"),
    event_type: str(o, "event_type"),
    description: str(o, "description"),
    artifact_id: readStr(o, "artifact_id"),
    source_investigation_id: readStr(o, "source_investigation_id"),
    timestamp_origin: str(o, "timestamp_origin"),
    data: rec(o, "data"),
  };
}

export interface Occurrence {
  source: string;
  event_type: string;
  description: string;
  artifact_id: string | null;
  source_investigation_id: string | null;
  recorded_at: string;
  data: Obj;
}

export function parseOccurrence(o: Obj): Occurrence {
  return {
    source: str(o, "source"),
    event_type: str(o, "event_type"),
    description: str(o, "description"),
    artifact_id: readStr(o, "artifact_id"),
    source_investigation_id: readStr(o, "source_investigation_id"),
    recorded_at: str(o, "recorded_at"),
    data: rec(o, "data"),
  };
}

/* --- directives ------------------------------------------------------- */

export interface Directive {
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

export function parseDirective(o: Obj): Directive {
  return {
    id: str(o, "id"),
    investigation_id: readStr(o, "investigation_id"),
    text: str(o, "text"),
    created_by: readStr(o, "created_by"),
    created_at: str(o, "created_at"),
    resolved_at: readStr(o, "resolved_at"),
    active: readBool(o, "active") ?? true,
    verdict: readStr(o, "verdict"),
    strategy_family: readStr(o, "strategy_family"),
    required_artifact: readStr(o, "required_artifact"),
  };
}

/* --- solid evidence --------------------------------------------------- */

export interface SolidEvidence {
  id: string;
  question: string;
  answer: string;
  verdict: string;
  confidence: string;
  source_investigation_id: string | null;
  primary_artifact: string | null;
  corroboration: string[];
  tagged_by: string | null;
  tagged_at: string;
  notes: string;
}

export function parseSolidEvidence(o: Obj): SolidEvidence {
  return {
    id: str(o, "id"),
    question: str(o, "question"),
    answer: str(o, "answer"),
    verdict: str(o, "verdict"),
    confidence: str(o, "confidence"),
    source_investigation_id: readStr(o, "source_investigation_id"),
    primary_artifact: readStr(o, "primary_artifact"),
    corroboration: readStrArray(o, "corroboration"),
    tagged_by: readStr(o, "tagged_by"),
    tagged_at: str(o, "tagged_at"),
    notes: str(o, "notes"),
  };
}

/* --- findings + suppressions ------------------------------------------ */

/** One derived suspicious finding (GET /findings). Findings have no row id:
 * the fingerprint is the `finding_id` key of the workflow state machine. */
export interface ForensicsFinding {
  fingerprint: string;
  artifact_type: string;
  artifact_family: string;
  source_tool: string;
  suspicious_reasons: string[];
  executable: string | null;
  path: string | null;
  name: string | null;
  user: string | null;
  last_run: string | null;
  run_count: number | null;
  occurrences: number;
  workflow_state: string;
  raw_record: Obj;
}

export function parseFinding(o: Obj): ForensicsFinding {
  return {
    fingerprint: str(o, "fingerprint"),
    artifact_type: str(o, "artifact_type"),
    artifact_family: str(o, "artifact_family"),
    source_tool: str(o, "source_tool"),
    suspicious_reasons: readStrArray(o, "suspicious_reasons"),
    executable: readStr(o, "executable"),
    path: readStr(o, "path"),
    name: readStr(o, "name"),
    user: readStr(o, "user"),
    last_run: readStr(o, "last_run") ?? numText(o, "last_run"),
    run_count: readNum(o, "run_count"),
    occurrences: readNum(o, "occurrences") ?? 1,
    workflow_state: readStr(o, "workflow_state") ?? "new",
    raw_record: rec(o, "raw_record"),
  };
}

export interface Suppression {
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

export function parseSuppression(o: Obj): Suppression {
  return {
    id: str(o, "id"),
    fingerprint: str(o, "fingerprint"),
    artifact_type: readStr(o, "artifact_type"),
    executable: readStr(o, "executable"),
    path: readStr(o, "path"),
    name: readStr(o, "name"),
    finding_user: readStr(o, "finding_user"),
    reasons: readStrArray(o, "reasons"),
    notes: str(o, "notes"),
    suppressed_by: readStr(o, "suppressed_by"),
    suppressed_at: str(o, "suppressed_at"),
  };
}

/* --- network / registry structured analysis --------------------------- */

/** Multi-section analysis payload. Section rows are tool-emitted records
 * with open-ended keys, rendered by an auto-column table. */
export interface StructuredAnalysis {
  stats: Obj | null;
  sections: Record<string, Obj[]>;
}

export function parseStructuredAnalysis(raw: unknown, sectionKeys: readonly string[], statsKey: string | null): StructuredAnalysis {
  const o = asRecord(raw) ?? {};
  const sections: Record<string, Obj[]> = {};
  for (const k of sectionKeys) sections[k] = readRecordArray(o, k);
  return { stats: statsKey ? asRecord(o[statsKey]) : null, sections };
}

/* --- authenticated download ------------------------------------------- */

/** Fetch `path` with the Bearer token and save the body under `filename`.
 * Reads the response as a Blob so binary payloads (carved files) survive;
 * apiFetch would decode them as UTF-8 text. Throws on any non-2xx. */
export async function downloadForensicsFile(path: string, filename: string): Promise<void> {
  const token = useAuth.getState().token;
  const res = await fetch(API_BASE + path, {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  if (res.status === 401) {
    useAuth.getState().logout();
    throw new Error("Session expired -- sign in again.");
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(res.status, detail || res.statusText);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
