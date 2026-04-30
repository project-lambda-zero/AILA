/**
 * editor/types.ts — Flat TypeScript contracts for the schema editor UI.
 *
 * These are derived from Phase 155 API shapes (SectionListResponse,
 * QuestionListResponse) and used across all editor components.
 *
 * Created by Plan 156-02 (parallel wave 1) to unblock SubtaskMappingEditor
 * and ConditionalLogicVisualizer. Plan 156-01 owns the canonical copy and
 * may extend or refine these types.
 */

// ---------------------------------------------------------------------------
// Flat section model from GET /sbd_nfr/schema/sections
// ---------------------------------------------------------------------------

export interface SectionFlat {
  id: string;
  section_key: string;
  label: string;
  description: string | null;
  icon_hint: string | null;
  display_order: number;
  is_active: boolean;
  depends_on_question_id: string | null;
  expected_when: string | null;
  condition_expr_json: string | null;
}

// ---------------------------------------------------------------------------
// Flat subgroup model from GET /sbd_nfr/schema/sections (nested in section)
// ---------------------------------------------------------------------------

export interface SubgroupFlat {
  id: string;
  subgroup_key: string;
  label: string;
  description: string | null;
  display_order: number;
  section_id: string;
  section_key: string;
  section_label: string;
}

export interface QuestionListItem {
  id: string;
  subgroup_id: string;
  question_type: string;
  depth_level: string;
  answer_type: string;
  label: string;
  instruction: string | null;
  guideline: string | null;
  help_text: string | null;
  is_required: boolean;
  is_active: boolean;
  depends_on_question_id: string | null;
  expected_when: string | null;
  condition_expr_json: string | null;
  display_order: number;
  max_length: number | null;
}


// ---------------------------------------------------------------------------
// Flat question model from GET /sbd_nfr/schema/questions
// ---------------------------------------------------------------------------

export interface QuestionFlat {
  id: string;
  question_type: string;
  depth_level: string;
  answer_type: string;
  label: string;
  instruction: string | null;
  guideline: string | null;
  help_text: string | null;
  is_required: boolean;
  is_active: boolean;
  depends_on_question_id: string | null;
  expected_when: string | null;
  condition_expr_json: string | null;
  display_order: number
  max_length: number | null
  subgroup_id: string
  subgroup_key: string
  subgroup_label: string
  section_id: string
  section_key: string
  section_label: string
  options: Array<{ value: string; label: string; description: string | null; display_order: number }>
  subtask_mappings: Array<{ subtask_key: string }>
}

// ---------------------------------------------------------------------------
// Option model from GET /sbd_nfr/schema/options?question_id=...
// ---------------------------------------------------------------------------

export interface OptionRow {
  id: string;
  question_id: string;
  value: string;
  label: string;
  description: string | null;
  display_order: number;
}

// ---------------------------------------------------------------------------
// Subtask mapping model from GET /sbd_nfr/schema/mappings
// ---------------------------------------------------------------------------

export interface MappingRecord {
  id: string;
  question_id: string;
  subtask_key: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Schema version from GET /sbd_nfr/schema/version
// ---------------------------------------------------------------------------

export interface SchemaVersionRecord {
  version: number;
  published_at: string | null;
  published_by: string | null;
  note: string | null;
}

// ---------------------------------------------------------------------------
// Form model for creating/updating a question (QuestionEditorDrawer)
// ---------------------------------------------------------------------------

export interface QuestionUpsertForm {
  subgroup_id: string;
  label: string;
  question_type: string;
  depth_level: string;
  answer_type: string;
  instruction: string | null;
  guideline: string | null;
  help_text: string | null;
  is_required: boolean;
  depends_on_question_id: string | null;
  expected_when: string | null;
  condition_expr_json: string | null;
  max_length: number | null;
}
