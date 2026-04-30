export interface QuestionOption {
  value: string;
  label: string;
}

export interface BaseQuestion {
  id: string;
  row: number;
  prompt: string;
  instruction: string;
  comments: string;
  guideline: string;
  group: string;
  required: boolean;
  depends_on?: string | null;
  expected_when?: string | null;
  options: QuestionOption[];
}

export interface SectionItem {
  row: number;
  id: string;
  type: string;
  title_or_requirement: string;
  questionnaire_prompt: string;
  answer_options: string;
  question_options: string[];
  requirement_text: string;
  security_comment: string;
  policy_reference: string;
}

export interface SectionDefinition {
  sheet: string;
  mode: string;
  title: string;
  intro: string;
  item_count: number;
  items: SectionItem[];
}

export interface RecommendationCatalogItem {
  key: string;
  label: string;
  category: string;
}

export interface DocumentModelResponse {
  source_workbook: string;
  question_groups: Record<string, string[]>;
  base_questions: BaseQuestion[];
  sections: SectionDefinition[];
  recommendation_catalog: RecommendationCatalogItem[];
}

export interface DocumentProfile {
  project_name: string;
  requester_name: string;
  team_name: string;
  jira_reference: string;
  service_summary: string;
  architecture_notes: string;
  interface_notes: string;
  deployment_notes: string;
}

export interface RequirementAnswer {
  compliance: string | null;
  project_response: string;
}

export interface ScopeDecision {
  sheet: string;
  mode: string;
  status: string;
  reasons: string[];
  active_item_ids: string[];
  answered_requirements: number;
  total_requirements: number;
}

export interface ValidationSummary {
  missing_profile_fields: string[];
  missing_base_questions: string[];
  missing_requirement_answers: Array<{
    sheet: string;
    requirement_id: string;
    prompt: string;
  }>;
  missing_project_responses: Array<{
    sheet: string;
    requirement_id: string;
  }>;
  warnings: string[];
  ready_for_architect_review: boolean;
}

export interface CompletionSummary {
  answered_base_questions: number;
  total_base_questions: number;
  answered_requirements: number;
  total_requirements: number;
  ready_for_architect_review: boolean;
}

export interface DocumentSession {
  id: string;
  status: string;
  source_workbook: string;
  profile: DocumentProfile;
  base_answers: Record<string, string>;
  requirement_answers: Record<string, Record<string, RequirementAnswer>>;
  scope_summary: ScopeDecision[];
  validation: ValidationSummary;
  completion: CompletionSummary;
  updated_at: string;
}

export interface DocumentAnswersUpdateRequest {
  profile: DocumentProfile;
  base_answers: Record<string, string>;
  requirement_answers: Record<string, Record<string, RequirementAnswer>>;
}

export interface GuidanceRecommendation {
  key: string;
  label: string;
  status: string;
  rationale: string;
  source: string;
  provisional_component: boolean;
}

export interface NextStepsResponse {
  guidance_summary: string;
  guidance_mode: string;
  recommendations: GuidanceRecommendation[];
  requester_expectations: string[];
  architect_review: string[];
  validation_warnings: string[];
}

export interface JiraDraftResponse {
  summary: string;
  description_markdown: string;
  suggested_components: string[];
  suggested_sub_tasks: string[];
  workbook_filename: string;
  component_mapping_status: string;
  labels: string[];
}

export interface WorkbookSectionSummary {
  sheet: string;
  status: string;
  answered_requirements: number;
  total_requirements: number;
}

export interface GeneratedWorkbookResponse {
  filename: string;
  media_type: string;
  content_base64: string;
  generated_at: string;
  pending_fields: number;
  ready_for_architect_review: boolean;
  section_summaries: WorkbookSectionSummary[];
}

// --- v2.2 Wizard Types ---

export interface QuestionOptionResponse {
  value: string;
  label: string;
  description: string | null;
  display_order: number;
}

export interface SubtaskMappingResponse {
  subtask_key: string;
}

export interface QuestionResponse {
  id: string;
  question_type: string;
  depth_level: string;
  answer_type: string;
  label: string;
  instruction: string | null;
  guideline: string | null;
  help_text: string | null;
  is_required: boolean;
  depends_on_question_id: string | null;
  expected_when: string | null;
  condition_expr_json: string | null;
  display_order: number;
  max_length: number | null;
  options: QuestionOptionResponse[];
  subtask_mappings: SubtaskMappingResponse[];
}

export interface SubgroupResponse {
  id: string;
  subgroup_key: string;
  label: string;
  description: string | null;
  display_order: number;
  questions: QuestionResponse[];
}

export interface SectionResponse {
  id: string;
  section_key: string;
  label: string;
  description: string | null;
  icon_hint: string | null;
  display_order: number;
  depends_on_question_id: string | null;
  expected_when: string | null;
  condition_expr_json: string | null;
  subgroups: SubgroupResponse[];
}

export interface SubtaskComponentResponse {
  key: string;
  label: string;
  category: string;
  description: string;
  icon_hint: string;
  display_order: number;
  is_active: boolean;
}

export interface SchemaTreeResponse {
  schema_version: number;
  sections: SectionResponse[];
  subtask_components: SubtaskComponentResponse[];
}

export interface SectionProgressResponse {
  section_key: string;
  visible_count: number;
  answered_count: number;
  total_count: number;
}

export interface AnswerResponse {
  question_id: string;
  answer_value: string;
  note_text: string | null;
  answered_by_name: string;
  answered_by_email: string;
  updated_at: string;
}

export interface SessionSummaryResponse {
  id: string;
  status: string;
  project_name: string;
  description: string | null;
  business_unit: string | null;
  requestor_name: string;
  requestor_email: string;
  target_date: string | null;
  is_template: boolean;
  template_name: string | null;
  tags: string[];
  assigned_architect_id: string | null;
  architect_notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface ActivityResponse {
  id: string;
  event_type: string;
  actor_name: string | null;
  actor_email: string | null;
  detail_json: Record<string, unknown>;
  created_at: string;
}

export interface SubmitForReviewRequest {
  notes?: string | null;
}

export interface ApproveSessionRequest {
  notes?: string | null;
}

export interface ArchitectNotesRequest {
  notes: string;
}

export interface SaveAsTemplateRequest {
  template_name: string;
}

export interface SessionDetailResponse {
  session: SessionSummaryResponse;
  schema_version: number;
  share_token: string;
  answers: AnswerResponse[];
  section_progress: SectionProgressResponse[];
  next_unanswered_question_id: string | null;
}

export interface SessionCreateRequest {
  project_name: string;
  description: string | null;
  business_unit: string | null;
  requestor_name: string;
  requestor_email: string;
  target_date: string | null;
  tags: string[];
}

export interface AnswerInput {
  question_id: string;
  answer_value: string;
  note_text: string | null;
}

export interface BulkAnswerRequest {
  answers: AnswerInput[];
}

export interface ComponentClassificationResponse {
  subtask_key: string;
  subtask_label: string;
  classification: string;
  confidence: number;
  reasoning: string;
  cited_question_ids: string[];
}

export interface ResolutionResultResponse {
  session_id: string;
  status: string;
  resolved_at: string | null;
  components: ComponentClassificationResponse[];
  executive_summary: string | null;
}

export interface AssistRequest {
  message: string;
  history: Array<Record<string, string>>;
  current_answer: string | null;
}

export interface AssistResponse {
  reply: string;
}

/** Flat SSE event dict from Redis Streams (resolution_service.py). */
export interface SessionSseEvent {
  event: string;
  timestamp: string;
  answer_count?: string;
  component_count?: string;
  error?: string;
  message?: string;
}

/** SHA-256 integrity hash for a SbD report PDF (EXEC-04). */
export interface ReportHashData {
  session_id: string;
  sha256: string | null;
  computed_at: string | null;
  status: "available" | "not_generated";
}

export interface ReportHashResponse {
  data: ReportHashData;
  error: string | null;
  meta: Record<string, unknown>;
}
