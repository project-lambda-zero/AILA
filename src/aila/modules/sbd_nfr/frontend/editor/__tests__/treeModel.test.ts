import { describe, expect, it } from 'vitest';

import type { SchemaTreeResponse } from '../../types';
import { buildQuestionId, collectEditorQuestions, toEditorSections } from '../treeModel';

const schema: SchemaTreeResponse = {
  schema_version: 7,
  subtask_components: [],
  sections: [
    {
      id: 'sec-1',
      section_key: 'scope',
      label: 'Scope',
      description: null,
      icon_hint: null,
      display_order: 1,
      depends_on_question_id: null,
      expected_when: null,
      condition_expr_json: null,
      subgroups: [
        {
          id: 'sg-1',
          subgroup_key: 'scope_core',
          label: 'Scope Core',
          description: null,
          display_order: 1,
          questions: [
            {
              id: 'SCOPE-01',
              question_type: 'scope',
              depth_level: 'primary',
              answer_type: 'single_choice',
              label: 'What is the system type?',
              instruction: null,
              guideline: null,
              help_text: null,
              is_required: true,
              depends_on_question_id: null,
              expected_when: null,
              condition_expr_json: null,
              display_order: 1,
              max_length: null,
              options: [],
              subtask_mappings: [],
            },
          ],
        },
      ],
    },
  ],
};

describe('treeModel', () => {
  it('preserves nested sections for the editor tree', () => {
    const sections = toEditorSections(schema);
    expect(sections).toHaveLength(1);
    expect(sections[0].subgroups).toHaveLength(1);
    expect(sections[0].subgroups[0].questions[0].id).toBe('SCOPE-01');
  });

  it('flattens nested questions with subgroup and section metadata', () => {
    const questions = collectEditorQuestions(schema);
    expect(questions).toEqual([
      expect.objectContaining({
        id: 'SCOPE-01',
        subgroup_id: 'sg-1',
        subgroup_key: 'scope_core',
        section_id: 'sec-1',
        section_key: 'scope',
        section_label: 'Scope',
      }),
    ]);
  });

  it('builds a usable question id from subgroup key and label', () => {
    expect(buildQuestionId('scope_core', 'What is the system type?')).toBe('SCOPE_CORE-WHAT_IS_THE_SYSTEM_TYPE');
  });
});
