import type {
  QuestionResponse,
  SchemaTreeResponse,
  SectionResponse,
  SubgroupResponse,
} from '../types';
import type { QuestionFlat, SectionFlat, SubgroupFlat } from './types';

export interface EditorSubgroupTree extends SubgroupFlat {
  questions: QuestionFlat[];
}

export interface EditorSectionTree extends SectionFlat {
  subgroups: EditorSubgroupTree[];
}

function questionToFlat(
  question: QuestionResponse,
  subgroup: SubgroupResponse,
  section: SectionResponse,
): QuestionFlat {
  return {
    id: question.id,
    question_type: question.question_type,
    depth_level: question.depth_level,
    answer_type: question.answer_type,
    label: question.label,
    instruction: question.instruction,
    guideline: question.guideline,
    help_text: question.help_text,
    is_required: question.is_required,
    is_active: true,
    depends_on_question_id: question.depends_on_question_id,
    expected_when: question.expected_when,
    condition_expr_json: question.condition_expr_json,
    display_order: question.display_order,
    max_length: question.max_length,
    subgroup_id: subgroup.id,
    subgroup_key: subgroup.subgroup_key,
    subgroup_label: subgroup.label,
    section_id: section.id,
    section_key: section.section_key,
    section_label: section.label,
    options: question.options,
    subtask_mappings: question.subtask_mappings,
  };
}

export function toEditorSections(schema?: SchemaTreeResponse | null): EditorSectionTree[] {
  if (!schema) {
    return [];
  }
  return schema.sections.map((section) => ({
    id: section.id,
    section_key: section.section_key,
    label: section.label,
    description: section.description,
    icon_hint: section.icon_hint,
    display_order: section.display_order,
    is_active: true,
    depends_on_question_id: section.depends_on_question_id,
    expected_when: section.expected_when,
    condition_expr_json: section.condition_expr_json,
    subgroups: section.subgroups
      .map((subgroup) => ({
        id: subgroup.id,
        subgroup_key: subgroup.subgroup_key,
        label: subgroup.label,
        description: subgroup.description,
        display_order: subgroup.display_order,
        section_id: section.id,
        section_key: section.section_key,
        section_label: section.label,
        questions: subgroup.questions.map((question) => questionToFlat(question, subgroup, section)),
      }))
      .sort((left, right) => left.display_order - right.display_order),
  }));
}

export function collectEditorQuestions(schema?: SchemaTreeResponse | null): QuestionFlat[] {
  return toEditorSections(schema).flatMap((section) =>
    section.subgroups.flatMap((subgroup) => subgroup.questions),
  );
}

export function buildQuestionId(subgroupKey: string, label: string): string {
  const normalizedPrefix = subgroupKey
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
  const normalizedLabel = label
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
  if (!normalizedPrefix && !normalizedLabel) {
    return 'QUESTION';
  }
  if (!normalizedPrefix) {
    return normalizedLabel.slice(0, 50);
  }
  if (!normalizedLabel) {
    return normalizedPrefix.slice(0, 50);
  }
  return `${normalizedPrefix}-${normalizedLabel}`.slice(0, 50);
}
