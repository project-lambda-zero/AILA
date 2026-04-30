import { useState } from "react";

import { motion } from "motion/react";

import type {
  AnswerInput,
  QuestionResponse,
  SchemaTreeResponse,
  SessionDetailResponse,
  SubtaskComponentResponse,
} from "../types";
import { Button } from "@/components/ui/button";
import { isQuestionVisible } from "./hooks/useSkipLogic";
import { BinaryToggleInput } from "./inputs/BinaryToggleInput";
import { HelpModal } from "./inputs/HelpModal";
import { MaturityTierInput } from "./inputs/MaturityTierInput";
import { NoteField } from "./inputs/NoteField";
import { RadioCardInput } from "./inputs/RadioCardInput";
import { SelectInput } from "./inputs/SelectInput";
import { TextInput } from "./inputs/TextInput";

export interface WizardSectionProps {
  schema: SchemaTreeResponse;
  session: SessionDetailResponse;
  sectionKey: string;
  answersMap: Record<string, string>;
  onAnswer: (answer: AnswerInput) => void;
  onNext?: () => void;
  onPrev?: () => void;
  onAssist?: (question: QuestionResponse) => void;
}

// ──────────────────────────────────────────────────────────────────────────────
// Build a lookup from subtask_key → SubtaskComponentResponse for inline display
// ──────────────────────────────────────────────────────────────────────────────

function buildSubtaskLookup(
  schema: SchemaTreeResponse,
): Map<string, SubtaskComponentResponse> {
  const map = new Map<string, SubtaskComponentResponse>();
  for (const comp of schema.subtask_components ?? []) {
    map.set(comp.key, comp);
  }
  return map;
}

// ──────────────────────────────────────────────────────────────────────────────
// Compliance option detection
// A compliance question has options whose values are a subset of these tokens.
// ──────────────────────────────────────────────────────────────────────────────

const COMPLIANCE_VALUES = new Set(["yes", "no", "partial", "na", "n/a", "not_applicable"]);

function isComplianceQuestion(question: QuestionResponse): boolean {
  if (question.answer_type === "compliance") return true;
  if (question.options.length === 0) return false;
  return question.options.every((o) => COMPLIANCE_VALUES.has(o.value.toLowerCase()));
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-question input renderer
// ──────────────────────────────────────────────────────────────────────────────

interface QuestionInputProps {
  question: QuestionResponse;
  answersMap: Record<string, string>;
  subtaskLookup: Map<string, SubtaskComponentResponse>;
  onAnswer: (answer: AnswerInput) => void;
  onAssist?: (question: QuestionResponse) => void;
}

function QuestionInput({ question, answersMap, subtaskLookup, onAnswer, onAssist }: QuestionInputProps) {
  const currentValue = answersMap[question.id] ?? null;
  const currentNote = null; // notes come from session answers; derive if needed
  const [detailsOpen, setDetailsOpen] = useState(false);

  // Auto-expand details when question is answered
  const isAnswered = currentValue !== null && currentValue !== "";

  function handleValueChange(newValue: string) {
    onAnswer({
      question_id: question.id,
      answer_value: newValue,
      note_text: currentNote,
    });
    // Auto-expand details on first answer
    if (!detailsOpen && newValue) {
      setDetailsOpen(true);
    }
  }

  function handleNoteChange(newNote: string) {
    onAnswer({
      question_id: question.id,
      answer_value: currentValue ?? "",
      note_text: newNote || null,
    });
  }

  let inputElement: React.ReactNode;

  if (question.answer_type === "binary") {
    // Binary yes/no pill toggle
    inputElement = (
      <BinaryToggleInput
        value={currentValue}
        onChange={handleValueChange}
      />
    );
  } else if (question.answer_type === "maturity_tier") {
    // 4-option horizontal maturity selector with prose descriptor
    inputElement = (
      <MaturityTierInput
        options={question.options}
        value={currentValue}
        onChange={handleValueChange}
        name={question.id}
      />
    );
  } else if (isComplianceQuestion(question)) {
    // Compliance radio cards
    inputElement = (
      <RadioCardInput
        name={question.id}
        options={question.options}
        value={currentValue}
        onChange={handleValueChange}
      />
    );
  } else if (question.options.length > 0) {
    // Non-compliance options → select
    inputElement = (
      <SelectInput
        options={question.options}
        value={currentValue}
        onChange={handleValueChange}
      />
    );
  } else {
    // Free text / textarea
    inputElement = (
      <TextInput
        value={currentValue ?? ""}
        onChange={handleValueChange}
        maxLength={question.max_length ?? undefined}
        multiline={question.answer_type === "textarea"}
      />
    );
  }

  const hasHelp = question.instruction || question.guideline || question.help_text;

  // Resolve subtask components triggered by this question's answer
  const triggeredSubtasks: SubtaskComponentResponse[] = [];
  if (isAnswered && question.subtask_mappings.length > 0) {
    const lowerVal = currentValue!.toLowerCase();
    // A "yes" / "partial" answer triggers mapped subtasks; "no" / "na" does not
    const isTriggering = lowerVal === "yes" || lowerVal === "partial";
    if (isTriggering) {
      for (const mapping of question.subtask_mappings) {
        const comp = subtaskLookup.get(mapping.subtask_key);
        if (comp) triggeredSubtasks.push(comp);
      }
    }
  }

  // Determine if there's any detail content to show
  const hasDetailContent = hasHelp || triggeredSubtasks.length > 0;
  const showDetails = detailsOpen && hasDetailContent;

  return (
    <div className="rounded-[var(--radius-md)] border border-border bg-surface p-5 mb-5" data-question-id={question.id}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <label className="font-sans text-sm font-semibold text-text block" htmlFor={question.id}>
          {question.label}
          {question.is_required && (
            <span className="text-critical" aria-label="required"> *</span>
          )}
        </label>
        <div className="flex items-center gap-2 shrink-0">
          {hasHelp && (
            <HelpModal
              instruction={question.instruction}
              guideline={question.guideline}
              helpText={question.help_text}
            />
          )}
          {onAssist && (
            <button
              className="text-xs font-mono px-2 py-1 rounded-[var(--radius-sm)] border border-accent/30 text-accent cursor-pointer transition-colors hover:bg-accent-muted"
              type="button"
              onClick={() => onAssist(question)}
              aria-label={`Ask AI about: ${question.label}`}
              title="Ask AI"
            >
              Ask AI
            </button>
          )}
        </div>
      </div>
      {inputElement}

      {/* Inline details: guidance + triggered subtask components */}
      {hasDetailContent && (
        <button
          className="text-xs text-text-muted cursor-pointer mt-2 flex items-center gap-1 hover:text-accent transition-colors"
          type="button"
          onClick={() => setDetailsOpen((prev) => !prev)}
          aria-expanded={showDetails ? true : false}
        >
          {showDetails ? "Hide details" : "Details"}
          {triggeredSubtasks.length > 0 && !showDetails && (
            <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-accent text-badge-text text-[9px] font-bold">{triggeredSubtasks.length}</span>
          )}
        </button>
      )}
      {showDetails && (
        <div className="mt-3 p-3 rounded-[var(--radius-md)] bg-elevated border border-border flex flex-col gap-3" role="region" aria-label="Question details">
          {question.help_text && (
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-accent mb-1 block">Help</span>
              <p className="text-sm text-text-muted leading-relaxed">{question.help_text}</p>
            </div>
          )}
          {question.guideline && (
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-accent mb-1 block">Guideline</span>
              <p className="text-sm text-text-muted leading-relaxed">{question.guideline}</p>
            </div>
          )}
          {question.instruction && (
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-accent mb-1 block">Instruction</span>
              <p className="text-sm text-text-muted leading-relaxed">{question.instruction}</p>
            </div>
          )}
          {triggeredSubtasks.length > 0 && (
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-accent mb-1 block">
                Triggered components ({triggeredSubtasks.length})
              </span>
              <ul className="list-none p-0 m-0 flex flex-col gap-1">
                {triggeredSubtasks.map((comp) => (
                  <li key={comp.key} className="flex items-center justify-between gap-2 text-sm">
                    <span className="text-text">{comp.label}</span>
                    <span className="text-[10px] font-mono text-text-muted uppercase">{comp.category}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <NoteField
        value={null}
        onChange={handleNoteChange}
      />
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Section renderer
// ──────────────────────────────────────────────────────────────────────────────

export function WizardSection({
  schema,
  session: _session,
  sectionKey,
  answersMap,
  onAnswer,
  onNext,
  onPrev,
  onAssist,
}: WizardSectionProps) {
  const section = schema.sections.find((s) => s.section_key === sectionKey);

  if (!section) {
    return (
      <div className="flex flex-col gap-6">
        <p className="text-sm text-text-muted">Section not found: {sectionKey}</p>
      </div>
    );
  }

  const subtaskLookup = buildSubtaskLookup(schema);

  const sortedSubgroups = [...section.subgroups].sort(
    (a, b) => a.display_order - b.display_order,
  );

  // Determine severity high-risk: any binary "yes" answer in a scope section
  // or on a question whose label mentions internet or PII
  const isSeverityHighRisk = sortedSubgroups.some((sg) =>
    sg.questions.some((q) => {
      if (q.answer_type !== "binary") return false;
      if (answersMap[q.id] !== "yes") return false;
      const labelLower = q.label.toLowerCase();
      const isScopeSection = section.section_key.toLowerCase().includes("scope");
      const isInternetOrPii =
        labelLower.includes("internet") || labelLower.includes("pii");
      return isScopeSection || isInternetOrPii;
    }),
  );

  return (
    <motion.div
      key={sectionKey}
      className={`flex flex-col gap-6${isSeverityHighRisk ? " animate-severity-pulse" : ""}`}
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.22, ease: [0.25, 0.1, 0.25, 1] }}
    >
      <header>
        <h2 className="font-display text-2xl font-bold text-text mb-2">{section.label}</h2>
        {section.description && (
          <p className="text-sm leading-relaxed text-text-muted mb-6 max-w-prose">
            {section.description}
          </p>
        )}
      </header>

      <div className="flex flex-col gap-8">
        {sortedSubgroups.map((subgroup) => {
          const sortedQuestions = [...subgroup.questions].sort(
            (a, b) => a.display_order - b.display_order,
          );
          const visibleQuestions = sortedQuestions.filter((q) =>
            isQuestionVisible(q, answersMap),
          );

          if (visibleQuestions.length === 0) return null;

          // Only show subgroup heading when label differs from section label
          const showSubgroupLabel = subgroup.label !== section.label;

          return (
            <div key={subgroup.id} className="flex flex-col gap-4">
              {showSubgroupLabel && (
                <h3 className="font-mono text-xs uppercase tracking-wider text-accent mb-3">
                  {subgroup.label}
                </h3>
              )}
              {subgroup.description && (
                <p className="text-sm text-text-muted -mt-2">{subgroup.description}</p>
              )}
              {visibleQuestions.map((question) => (
                <QuestionInput
                  key={question.id}
                  question={question}
                  answersMap={answersMap}
                  subtaskLookup={subtaskLookup}
                  onAnswer={onAnswer}
                  onAssist={onAssist}
                />
              ))}
            </div>
          );
        })}
      </div>

      <div className="flex justify-between items-center mt-8 pt-6 border-t border-border">
        <Button
          variant="outline"
          type="button"
          onClick={onPrev}
          disabled={!onPrev}
        >
          ← Previous
        </Button>
        <Button
          type="button"
          onClick={onNext}
          disabled={!onNext}
        >
          Next →
        </Button>
      </div>
    </motion.div>
  );
}
