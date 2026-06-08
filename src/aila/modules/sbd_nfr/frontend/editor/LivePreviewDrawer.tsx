import { useState } from "react";

import { ArrowCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowCounterClockwise";
import { Eye } from "@phosphor-icons/react/dist/csr/Eye";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Input } from "@/components/ui/input";

import { useSchemaTree } from "./api";
import type { QuestionFlat } from "./types";
import { collectEditorQuestions, toEditorSections } from "./treeModel";

function isSectionVisible(
  section: { depends_on_question_id: string | null; expected_when: string | null },
  answers: Record<string, string>,
): boolean {
  if (!section.depends_on_question_id) return true;
  const answer = answers[section.depends_on_question_id];
  if (!answer) return false;
  if (section.expected_when) return answer === section.expected_when;
  return true;
}

interface AnswerInputProps {
  question: QuestionFlat;
  value: string | undefined;
  onChange: (value: string) => void;
}

function AnswerInput({ question, value, onChange }: AnswerInputProps) {
  const { answer_type } = question;

  if (answer_type === "binary") {
    return (
      <div className="flex gap-2">
        {(["yes", "no"] as const).map((opt) => (
          <Button
            key={opt}
            type="button"
            size="sm"
            variant={value === opt ? "default" : "outline"}
            onClick={() => onChange(opt)}
            className={
              value === opt
                ? "bg-amber-500 hover:bg-amber-400 text-sbd-base font-semibold font-mono text-xs"
                : "border-amber-500/30 text-amber-400 hover:bg-amber-500/10 font-mono text-xs"
            }
          >
            {opt === "yes" ? "Yes" : "No"}
          </Button>
        ))}
      </div>
    );
  }

  if (answer_type === "maturity_tier") {
    return (
      <div className="flex gap-1.5">
        {(["0", "1", "2", "3"] as const).map((tier) => (
          <Button
            key={tier}
            type="button"
            size="sm"
            variant={value === tier ? "default" : "outline"}
            onClick={() => onChange(tier)}
            className={
              value === tier
                ? "bg-amber-500 hover:bg-amber-400 text-sbd-base font-semibold font-mono text-xs min-w-9"
                : "border-amber-500/30 text-amber-400 hover:bg-amber-500/10 font-mono text-xs min-w-9"
            }
          >
            {tier}
          </Button>
        ))}
      </div>
    );
  }

  if (answer_type === "single_choice" && question.options.length > 0) {
    return (
      <div className="flex flex-col gap-1.5">
        {question.options.map((opt) => (
          <Button
            key={opt.value}
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onChange(opt.value)}
            className={
              value === opt.value
                ? "border-amber-400 bg-amber-500/10 text-amber-300 font-mono text-xs justify-start"
                : "border-amber-500/20 text-amber-500/70 hover:bg-amber-500/10 hover:text-amber-300 font-mono text-xs justify-start"
            }
          >
            {opt.label}
          </Button>
        ))}
      </div>
    );
  }

  return (
    <Input
      type="text"
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
      placeholder="Type an answer…"
      className="bg-sbd-base border-amber-500/20 text-amber-100 placeholder:text-amber-500/40 focus-visible:ring-amber-500/40 font-mono text-sm h-8"
    />
  );
}

function QuestionPreviewCard({
  question,
  value,
  onChange,
}: {
  question: QuestionFlat;
  value: string | undefined;
  onChange: (value: string) => void;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-sharp border border-amber-500/10 bg-sbd-input p-3">
      <div className="flex items-start gap-2">
        <span className="mt-0.5 shrink-0 rounded-sharp border border-amber-500/30 bg-amber-500/10 px-1 py-0.5 font-mono text-3xs text-amber-500 uppercase">
          {question.answer_type}
        </span>
        {question.question_type === "scope" && (
          <span className="mt-0.5 shrink-0 rounded-sharp border border-cyan-500/30 bg-cyan-500/10 px-1 py-0.5 font-mono text-3xs text-cyan-400 uppercase">
            scope
          </span>
        )}
      </div>
      <p className="text-sm text-amber-100 leading-relaxed">{question.label}</p>
      {question.instruction && <p className="text-xs text-amber-500/60 italic">{question.instruction}</p>}
      <AnswerInput question={question} value={value} onChange={onChange} />
    </div>
  );
}

interface LivePreviewDrawerProps {
  open: boolean;
  onClose: () => void;
}

export function LivePreviewDrawer({ open, onClose }: LivePreviewDrawerProps) {
  const [simulatedAnswers, setSimulatedAnswers] = useState<Record<string, string>>({});
  const [activeSection, setActiveSection] = useState<string | null>(null);

  const schemaTreeQuery = useSchemaTree();
  const sections = toEditorSections(schemaTreeQuery.data);
  const allQuestions = collectEditorQuestions(schemaTreeQuery.data);

  const visibleSections = sections.filter((section) => isSectionVisible(section, simulatedAnswers));
  const hiddenSections = sections.filter((section) => !isSectionVisible(section, simulatedAnswers));
  const resolvedActiveSection =
    activeSection && sections.some((section) => section.id === activeSection)
      ? activeSection
      : (visibleSections[0]?.id ?? null);
  const activeSectionData = sections.find((section) => section.id === resolvedActiveSection) ?? null;
  const activeQuestions = resolvedActiveSection
    ? allQuestions.filter((question) => question.section_id === resolvedActiveSection)
    : [];

  function handleAnswer(questionId: string, value: string) {
    setSimulatedAnswers((prev) => ({ ...prev, [questionId]: value }));
  }

  function handleReset() {
    setSimulatedAnswers({});
    setActiveSection(null);
  }

  const isLoading = schemaTreeQuery.isPending;

  return (
    <Sheet open={open} onOpenChange={(visible) => !visible && onClose()}>
      <SheetContent
        side="right"
        className="w-full max-w-5xl bg-sbd-base border-l border-amber-500/20 p-0 flex flex-col"
      >
        <SheetHeader className="flex-none border-b border-amber-500/20 px-6 py-4">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Eye className="h-5 w-5 text-amber-400" weight="bold" />
              <SheetTitle className="font-mono text-amber-300 text-base">
                Live Preview — Draft Schema
              </SheetTitle>
              <span className="rounded-sharp border border-amber-500/50 bg-amber-500/15 px-2 py-0.5 font-mono text-3xs font-semibold text-amber-400 uppercase tracking-wide">
                PREVIEW ONLY — no session created
              </span>
            </div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={handleReset}
              className="shrink-0 border-amber-500/30 text-amber-500/70 hover:bg-amber-500/10 hover:text-amber-400 font-mono text-xs"
            >
              <ArrowCounterClockwise className="mr-1.5 h-3.5 w-3.5" />
              Reset
            </Button>
          </div>
          <SheetDescription className="font-mono text-xs text-amber-500/50 mt-1">
            Answering scope questions will show or hide conditional sections instantly. No data is saved.
          </SheetDescription>
        </SheetHeader>

        {isLoading && (
          <div className="flex flex-1 items-center justify-center">
            <p className="font-mono text-sm text-amber-500/50">Loading schema…</p>
          </div>
        )}

        {!isLoading && sections.length === 0 && (
          <div className="flex flex-1 items-center justify-center">
            <p className="font-mono text-sm text-amber-500/50">No sections found in schema.</p>
          </div>
        )}

        {!isLoading && sections.length > 0 && (
          <div className="flex flex-1 min-h-0 overflow-hidden">
            <nav className="w-64 shrink-0 overflow-y-auto border-r border-amber-500/20 bg-sbd-input py-3">
              <p className="px-4 pb-2 font-mono text-3xs uppercase tracking-wide text-amber-500/50">
                Sections
              </p>
              {visibleSections.map((section) => {
                const questions = allQuestions.filter((question) => question.section_id === section.id);
                const answered = questions.filter((question) => simulatedAnswers[question.id] !== undefined).length;
                const isActive = resolvedActiveSection === section.id;
                return (
                  <button
                    key={section.id}
                    type="button"
                    onClick={() => setActiveSection(section.id)}
                    className={[
                      "w-full px-4 py-2.5 text-left transition-colors",
                      isActive
                        ? "bg-amber-500/10 border-l-2 border-amber-400"
                        : "border-l-2 border-transparent hover:bg-amber-500/5",
                    ].join(" ")}
                  >
                    <p className={[
                      "font-mono text-xs leading-snug truncate",
                      isActive ? "text-amber-300" : "text-amber-400/80",
                    ].join(" ")}>
                      {section.label}
                    </p>
                    <p className="font-mono text-3xs text-amber-500/40 mt-0.5">
                      {answered}/{questions.length} answered
                    </p>
                  </button>
                );
              })}

              {hiddenSections.length > 0 && (
                <>
                  <p className="px-4 pt-3 pb-1 font-mono text-3xs uppercase tracking-wide text-amber-500/30">
                    Conditional (hidden)
                  </p>
                  {hiddenSections.map((section) => (
                    <div key={section.id} className="w-full px-4 py-2 border-l-2 border-transparent">
                      <p className="font-mono text-xs text-amber-500/30 truncate">{section.label}</p>
                      <p className="font-mono text-3xs text-amber-500/20 mt-0.5 italic">(hidden — answer triggers)</p>
                    </div>
                  ))}
                </>
              )}
            </nav>

            <div className="flex-1 overflow-y-auto px-6 py-4">
              {activeSectionData ? (
                <>
                  <h2 className="font-mono text-sm font-semibold text-amber-400 mb-1">
                    {activeSectionData.label}
                  </h2>
                  {activeSectionData.description && (
                    <p className="font-mono text-xs text-amber-500/60 mb-4 leading-relaxed">
                      {activeSectionData.description}
                    </p>
                  )}

                  {activeQuestions.length === 0 ? (
                    <p className="font-mono text-sm text-amber-500/40 italic">No questions in this section.</p>
                  ) : (
                    <div className="flex flex-col gap-3">
                      {activeQuestions.map((question) => (
                        <QuestionPreviewCard
                          key={question.id}
                          question={question}
                          value={simulatedAnswers[question.id]}
                          onChange={(value) => handleAnswer(question.id, value)}
                        />
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="font-mono text-sm text-amber-500/40 italic">Select a section from the left panel.</p>
              )}
            </div>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
