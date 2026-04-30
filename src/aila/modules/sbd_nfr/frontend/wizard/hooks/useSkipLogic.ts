import type { QuestionResponse, SectionResponse } from "../../types";

/**
 * Client-side skip logic evaluation functions (D-05, Pattern 5).
 *
 * These are pure functions — not hooks — so they can be used in both React
 * components and non-React contexts (e.g., useSectionNavigation, tests).
 *
 * Skip logic rule: a section or question is visible when either:
 *   - condition_expr_json is set → evaluated with AND/OR multi-condition logic, or
 *   - depends_on_question_id is null (no dependency — always visible), or
 *   - answers[depends_on_question_id] === expected_when
 *
 * condition_expr_json takes precedence over depends_on_question_id + expected_when
 * when both are present.  Format:
 *   {"op": "and"|"or", "conditions": [{"question_id": string, "expected": string}, ...]}
 */

interface ConditionEntry {
  question_id: string;
  expected: string;
}

interface ConditionExpr {
  op: "and" | "or";
  conditions: ConditionEntry[];
}

/**
 * Evaluate a condition_expr_json string against the current answers map.
 *
 * Returns:
 *   true  — all/any conditions satisfied (AND/OR semantics)
 *   false — conditions not satisfied or JSON is malformed (fail-safe: hide)
 *   null  — exprJson is null; caller falls back to legacy single-condition logic
 */
function evaluateConditionExpr(
  exprJson: string | null,
  answers: Record<string, string>,
): boolean | null {
  if (exprJson === null) return null;
  let expr: ConditionExpr;
  try {
    expr = JSON.parse(exprJson) as ConditionExpr;
  } catch {
    return false; // fail-safe: malformed JSON hides the item
  }
  const { op = "and", conditions = [] } = expr;
  if (conditions.length === 0) return true; // no constraints → visible
  const results = conditions.map((c) => answers[c.question_id] === c.expected);
  return op === "or" ? results.some(Boolean) : results.every(Boolean);
}

/**
 * Returns true when the section should be shown given the current answers map.
 *
 * answers: Record<question_id, answer_value>
 */
export function isSectionVisible(
  section: SectionResponse,
  answers: Record<string, string>,
): boolean {
  // condition_expr_json takes precedence over legacy single-condition
  const exprResult = evaluateConditionExpr(section.condition_expr_json, answers);
  if (exprResult !== null) return exprResult;
  // Legacy fallback
  if (section.depends_on_question_id === null) {
    return true;
  }
  return answers[section.depends_on_question_id] === section.expected_when;
}

/**
 * Returns true when the question should be shown given the current answers map.
 */
export function isQuestionVisible(
  question: QuestionResponse,
  answers: Record<string, string>,
): boolean {
  // condition_expr_json takes precedence over legacy single-condition
  const exprResult = evaluateConditionExpr(
    question.condition_expr_json,
    answers,
  );
  if (exprResult !== null) return exprResult;
  // Legacy fallback
  if (question.depends_on_question_id === null) {
    return true;
  }
  return answers[question.depends_on_question_id] === question.expected_when;
}

/**
 * Filters sections to only those visible given the current answers.
 */
export function getVisibleSections(
  sections: SectionResponse[],
  answers: Record<string, string>,
): SectionResponse[] {
  return sections.filter((s) => isSectionVisible(s, answers));
}

/**
 * Filters questions to only those visible given the current answers.
 */
export function getVisibleQuestions(
  questions: QuestionResponse[],
  answers: Record<string, string>,
): QuestionResponse[] {
  return questions.filter((q) => isQuestionVisible(q, answers));
}
