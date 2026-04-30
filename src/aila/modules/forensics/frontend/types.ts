export type AnalyzerOS = "linux" | "windows";

export type ProjectKind = "disk_evidence" | "raw_directory";

export interface ProjectSummary {
  id: string;
  name: string;
  description: string;
  system_id: number;
  system_name: string | null;
  evidence_directory: string;
  analyzer_os: AnalyzerOS;
  project_kind: ProjectKind;
  status: string;
  evidence_count: number;
  artifact_count: number;
  lead_count: number;
  investigation_count: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface ProjectCreate {
  name: string;
  description: string;
  system_id: number;
  evidence_directory: string;
  analyzer_os: AnalyzerOS;
  project_kind: ProjectKind;
}

export interface FetchRawRequest {
  evidence_id: string;
}

export interface EvidenceItem {
  id: string;
  file_path: string;
  evidence_type: string;
  file_hash_sha256: string | null;
  size_bytes: number | null;
}

export interface ToolCheckResult {
  tool_name: string;
  required: boolean;
  status: string;
  version: string | null;
  message: string | null;
}

export interface MachineReadinessResult {
  ready: boolean;
  system_id: number;
  system_name: string;
  analyzer_os: AnalyzerOS;
  tools: ToolCheckResult[];
  message: string;
}

export interface NormalizedArtifact {
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

export interface LeadEvidence {
  keyword: string;
  path: string;
  excerpt: string;
}

export interface PromotedLead {
  id: string;
  project_id: string;
  artifact_id: string;
  score: number;
  reason: string;
  artifact_family: string;
  artifact_type?: string;
  source_tool?: string | null;
  evidence?: LeadEvidence[];
  related_artifact_ids: string[];
  question_families: string[];
}

export interface AgentHypothesis {
  id?: string;
  claim?: string;
  why_plausible?: string;
  kill_criterion?: string;
  reason?: string;
}

export interface AgentContract {
  answer_type?: string;
  answer_format?: string;
  evidence_domain?: string;
  depends_on?: string[];
}

export interface AgentProvenance {
  primary_artifact?: string;
  corroboration?: string[];
  rejected_alternatives?: string[];
}

export interface AgentStep {
  id: string;
  step_number: number;
  action: string;
  script_content: string | null;
  command: string | null;
  stdout: string | null;
  stderr: string | null;
  exit_code: number | null;
  reasoning: string;
  created_at: string | null;
  contract?: AgentContract | null;
  hypotheses?: AgentHypothesis[];
  rejected?: AgentHypothesis[];
  observables?: Record<string, unknown> | null;
  provenance?: AgentProvenance | null;
  expected_observation?: string | null;
  submitted?: boolean;
}

export interface InvestigationSummary {
  id: string;
  project_id: string;
  question: string;
  status: string;
  attempts_used: number;
  max_attempts: number | null;
  final_answer: string | null;
  confidence: string | null;
  task_id?: string | null;
  parent_investigation_id?: string | null;
}

export interface InvestigationDetail extends InvestigationSummary {
  max_attempts: number;
  steps: AgentStep[];
}

export interface InvestigationRequest {
  question: string;
  max_attempts: number;
}

export interface RerunInvestigationRequest {
  max_attempts?: number;
  question_override?: string | null;
}

export interface AnswerCandidate {
  id: string;
  project_id: string;
  investigation_id: string | null;
  question_text: string;
  answer_text: string;
  confidence: string;
  primary_artifact_id: string | null;
  corroboration: string[];
  format_hint: string;
  created_at: string | null;
}

export interface WriteUpItem {
  id: string;
  project_id: string;
  investigation_id: string | null;
  title: string;
  content_markdown: string;
  methodology: string;
  artifacts_referenced: string[];
  created_at: string | null;
}

export interface NetworkStats {
  packet_count?: number;
  byte_count?: number;
  duration_s?: number;
  start_time?: string;
  end_time?: string;
}

export interface NetworkCommentary {
  subject: string;
  narrative: string;
  severity: "info" | "low" | "medium" | "high" | string;
}

export interface NetworkAnalysis {
  stats: NetworkStats;
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
  commentary: NetworkCommentary[];
}

export interface RegistryAnalysis {
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
}

export interface TimelineEntry {
  timestamp: string;
  source: string;
  event_type: string;
  description: string;
  artifact_id: string | null;
  source_investigation_id?: string | null;
  timestamp_origin?: string;
  data: Record<string, unknown>;
}

export interface Occurrence {
  source: string;
  event_type: string;
  description: string;
  artifact_id: string | null;
  source_investigation_id?: string | null;
  recorded_at: string;
  data: Record<string, unknown>;
}

export interface PaginatedResponse<T> {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: T[];
}

export interface RegisteredSystem {
  id: number;
  name: string;
  host: string;
  username: string;
  port: number;
}

export interface AnalystDirective {
  id: string;
  project_id: string;
  investigation_id: string | null;
  text: string;
  created_by: string | null;
  created_at: string;
  resolved_at: string | null;
  active: boolean;
  verdict: TagVerdict | null;
  source_investigation_id: string | null;
  source_answer_id: string | null;
}

export interface AnalystDirectiveCreate {
  text: string;
  investigation_id?: string | null;
}

export type TagVerdict = "true" | "false";

export interface TagInvestigationRequest {
  verdict: TagVerdict;
  answer_id?: string | null;
  notes?: string;
}

export interface SolidEvidence {
  id: string;
  project_id: string;
  question: string;
  answer: string;
  verdict: TagVerdict;
  confidence: string;
  source_investigation_id: string | null;
  source_answer_id: string | null;
  source_directive_id: string | null;
  primary_artifact: string | null;
  corroboration: string[];
  tagged_by: string | null;
  tagged_at: string;
  notes: string;
}

export interface CancelInvestigationResult {
  investigation_id: string;
  status: string;
  task_cancelled?: boolean;
  already_terminal?: boolean;
}

export interface FindingSuppressionRequest {
  fingerprint: string;
  artifact_type?: string | null;
  executable?: string | null;
  path?: string | null;
  name?: string | null;
  finding_user?: string | null;
  reasons?: string[];
  notes?: string;
}

export interface FindingSuppression {
  id: string;
  project_id: string;
  fingerprint: string;
  artifact_type: string | null;
  executable: string | null;
  path: string | null;
  name: string | null;
  finding_user: string | null;
  reasons: string[];
  notes: string;
  source_directive_id: string | null;
  suppressed_by: string | null;
  suppressed_at: string;
}

export interface RetrieveFileRequest {
  virtual_path: string;
  evidence_id?: string | null;
}

export interface RetrieveFileResult {
  filename: string;
  size_bytes: number;
  sha256: string;
}
