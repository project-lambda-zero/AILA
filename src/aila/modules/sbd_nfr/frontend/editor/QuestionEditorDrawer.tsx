/**
 * QuestionEditorDrawer — shadcn Sheet with full question form.
 *
 * EDIT-02: Admins can select response type (binary/maturity_tier/single_choice),
 * define answer options inline, and set a depends_on + expected_when conditional
 * from a single form.
 */
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Plus, Trash } from "@phosphor-icons/react";

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetFooter,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import {
  useCreateOption,
  useCreateQuestion,
  useDeleteOption,
  usePatchOption,
  usePatchQuestion,
  useSchemaOptions,
  useSchemaTree,
} from "./api";
import { buildQuestionId, collectEditorQuestions, toEditorSections } from "./treeModel";
import type { QuestionFlat, QuestionUpsertForm } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QuestionEditorDrawerProps {
  /** When provided, pre-loads the existing question for edit mode. */
  question?: QuestionFlat | null;
  /** Required — the subgroup this question belongs to. */
  subgroupId: string;
  open: boolean;
  onClose: () => void;
}

interface LocalOptionDraft {
  tempId: string;
  value: string;
  label: string;
  description: string;
}

interface SuggestedQuestionTemplate {
  label: string;
  question_type: string;
  answer_type: string;
  instruction: string;
}

const SUGGESTED_QUESTION_TEMPLATES: Record<string, SuggestedQuestionTemplate[]> = {
  scope: [
    {
      label: "What trust boundary does this workflow cross?",
      question_type: "scope",
      answer_type: "single_choice",
      instruction: "Capture the highest-risk boundary crossed by this system.",
    },
    {
      label: "What identity source authorizes the primary user action?",
      question_type: "scope",
      answer_type: "single_choice",
      instruction: "Identify the real identity system behind the action.",
    },
  ],
  auth: [
    {
      label: "Is step-up authentication required for privileged actions?",
      question_type: "core",
      answer_type: "binary",
      instruction: "Use this when admin or sensitive actions need stronger auth.",
    },
  ],
  data: [
    {
      label: "Are sensitive fields encrypted before leaving the trust boundary?",
      question_type: "core",
      answer_type: "binary",
      instruction: "Capture control coverage for export, sync, and third-party forwarding.",
    },
  ],
  network: [
    {
      label: "Which outbound integrations are restricted to an allowlist?",
      question_type: "core",
      answer_type: "text",
      instruction: "List the concrete destinations or service classes that are allowed.",
    },
  ],
};

function suggestedTemplatesForSubgroup(subgroupKey: string): SuggestedQuestionTemplate[] {
  const lowered = subgroupKey.toLowerCase();
  for (const [prefix, templates] of Object.entries(SUGGESTED_QUESTION_TEMPLATES)) {
    if (lowered.includes(prefix)) return templates;
  }
  return [
    {
      label: "What failure mode matters most in this subgroup?",
      question_type: "core",
      answer_type: "text",
      instruction: "Turn the subgroup intent into one concrete design-risk question.",
    },
    {
      label: "Is there an explicit control owner for this subgroup?",
      question_type: "core",
      answer_type: "binary",
      instruction: "Use this when ownership and accountability are unclear.",
    },
  ];
}

// ---------------------------------------------------------------------------
// Blank form factory
// ---------------------------------------------------------------------------

function blankForm(subgroupId: string): QuestionUpsertForm {
  return {
    subgroup_id: subgroupId,
    label: "",
    question_type: "core",
    depth_level: "primary",
    answer_type: "binary",
    instruction: "",
    guideline: "",
    help_text: "",
    is_required: true,
    depends_on_question_id: null,
    expected_when: null,
    condition_expr_json: null,
    max_length: null,
  };
}

function formFromQuestion(q: QuestionFlat): QuestionUpsertForm {
  return {
    subgroup_id: q.subgroup_id,
    label: q.label,
    question_type: q.question_type,
    depth_level: q.depth_level,
    answer_type: q.answer_type,
    instruction: q.instruction ?? "",
    guideline: q.guideline ?? "",
    help_text: q.help_text ?? "",
    is_required: q.is_required,
    depends_on_question_id: q.depends_on_question_id,
    expected_when: q.expected_when,
    condition_expr_json: q.condition_expr_json,
    max_length: q.max_length,
  };
}

// ---------------------------------------------------------------------------
// Field row helper
// ---------------------------------------------------------------------------

function FieldRow({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label
        htmlFor={htmlFor}
        className="font-mono text-xs text-amber-500/70 uppercase tracking-wider"
      >
        {label}
      </label>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Native select with cyberpunk style
// ---------------------------------------------------------------------------

function CyberSelect({
  id,
  value,
  onChange,
  children,
  disabled,
}: {
  id?: string;
  value: string;
  onChange: (v: string) => void;
  children: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <select
      id={id}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded-[2px] border border-amber-500/20 bg-[#1a1a1a] px-2.5 py-1.5 font-mono text-sm text-amber-100 outline-none focus:border-amber-500/60 transition-colors disabled:opacity-50"
    >
      {children}
    </select>
  );
}

// ---------------------------------------------------------------------------
// Options editor — shown only for single_choice answer type
// ---------------------------------------------------------------------------

interface OptionsEditorProps {
  questionId?: string;
  localOptions: LocalOptionDraft[];
  onChange: (opts: LocalOptionDraft[]) => void;
}

function OptionsEditor({ questionId, localOptions, onChange }: OptionsEditorProps) {
  const existingOptions = useSchemaOptions(questionId ?? "");

  // Merge server options into local view on load
  useEffect(() => {
    if (questionId && existingOptions.data && localOptions.length === 0) {
      const mapped: LocalOptionDraft[] = existingOptions.data.map((o) => ({
        tempId: o.id,
        value: o.value,
        label: o.label,
        description: o.description ?? "",
      }));
      onChange(mapped);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [questionId, existingOptions.data]);

  function addOption() {
    onChange([
      ...localOptions,
      {
        tempId: `new-${Date.now()}`,
        value: "",
        label: "",
        description: "",
      },
    ]);
  }

  function removeOption(tempId: string) {
    onChange(localOptions.filter((o) => o.tempId !== tempId));
  }

  function updateOption(tempId: string, field: keyof LocalOptionDraft, value: string) {
    onChange(
      localOptions.map((o) => (o.tempId === tempId ? { ...o, [field]: value } : o)),
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs text-amber-500/70 uppercase tracking-wider">
          Answer Options
        </span>
        <button
          type="button"
          onClick={addOption}
          className="flex items-center gap-1 font-mono text-xs text-amber-500/60 hover:text-amber-400 border border-amber-500/20 hover:border-amber-500/40 rounded-[2px] px-2 py-0.5 transition-colors"
        >
          <Plus size={11} weight="bold" />
          Add option
        </button>
      </div>

      {localOptions.map((opt, idx) => (
        <div key={opt.tempId} className="flex items-center gap-2">
          <span className="font-mono text-xs text-amber-500/40 w-4 flex-shrink-0">
            {idx + 1}.
          </span>
          <input
            value={opt.value}
            onChange={(e) => updateOption(opt.tempId, "value", e.target.value)}
            placeholder="value"
            className="w-24 flex-shrink-0 rounded-[2px] border border-amber-500/20 bg-[#1a1a1a] px-1.5 py-1 font-mono text-xs text-amber-100 outline-none focus:border-amber-500/60"
          />
          <input
            value={opt.label}
            onChange={(e) => updateOption(opt.tempId, "label", e.target.value)}
            placeholder="label"
            className="flex-1 rounded-[2px] border border-amber-500/20 bg-[#1a1a1a] px-1.5 py-1 font-mono text-xs text-amber-100 outline-none focus:border-amber-500/60"
          />
          <button
            type="button"
            aria-label="Remove option"
            onClick={() => removeOption(opt.tempId)}
            className="text-amber-500/40 hover:text-red-400 transition-colors flex-shrink-0"
          >
            <Trash size={13} weight="bold" />
          </button>
        </div>
      ))}

      {localOptions.length === 0 && (
        <p className="font-mono text-xs text-amber-500/30 pl-6">
          No options yet. Add at least one option for single_choice questions.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dependency picker — flattens all sections/subgroups/questions into a select
// ---------------------------------------------------------------------------

interface DependencyPickerProps {
  value: string | null;
  onChange: (questionId: string | null) => void;
}

function DependencyPicker({ value, onChange }: DependencyPickerProps) {
  const schemaTreeQuery = useSchemaTree();
  const allQuestions = collectEditorQuestions(schemaTreeQuery.data).map((question) => ({
    id: question.id,
    label: question.label,
    sectionLabel: question.section_label,
  }));

  return (
    <CyberSelect
      id="dep-question"
      value={value ?? ""}
      onChange={(v) => onChange(v === "" ? null : v)}
    >
      <option value="">None</option>
      {allQuestions.map((question) => (
        <option key={question.id} value={question.id}>
          [{question.sectionLabel}] {question.label}
        </option>
      ))}
    </CyberSelect>
  );
}

// ---------------------------------------------------------------------------
// QuestionEditorDrawer — main export
// ---------------------------------------------------------------------------

export function QuestionEditorDrawer({
  question,
  subgroupId,
  open,
  onClose,
}: QuestionEditorDrawerProps) {
  const isEdit = Boolean(question);
  const createQuestion = useCreateQuestion();
  const patchQuestion = usePatchQuestion();
  const createOption = useCreateOption();
  const patchOption = usePatchOption();
  const deleteOption = useDeleteOption();
  const schemaTreeQuery = useSchemaTree();
  const existingOptionsQuery = useSchemaOptions(question?.id ?? "");

  const [form, setForm] = useState<QuestionUpsertForm>(() =>
    question ? formFromQuestion(question) : blankForm(subgroupId),
  );
  const [localOptions, setLocalOptions] = useState<LocalOptionDraft[]>([]);
  const [showConditional, setShowConditional] = useState(false);

  // Reset form when question or subgroupId changes
  useEffect(() => {
    setForm(question ? formFromQuestion(question) : blankForm(subgroupId));
    setLocalOptions([]);
  }, [question, subgroupId]);

  const subgroup = toEditorSections(schemaTreeQuery.data)
    .flatMap((section) => section.subgroups)
    .find((candidate) => candidate.id === subgroupId);
  const subgroupKey = subgroup?.subgroup_key ?? subgroupId;
  const subgroupLabel = subgroup?.label ?? subgroupId;
  const suggestedTemplates = suggestedTemplatesForSubgroup(subgroupKey);

  function applySuggestedTemplate(template: SuggestedQuestionTemplate) {
    setForm((prev) => ({
      ...prev,
      label: prev.label.trim() ? prev.label : template.label,
      question_type: template.question_type,
      answer_type: template.answer_type,
      instruction: prev.instruction?.trim() ? prev.instruction : template.instruction,
    }));
  }
  function update<K extends keyof QuestionUpsertForm>(
    field: K,
    value: QuestionUpsertForm[K],
  ) {
    setForm((prev: QuestionUpsertForm) => ({ ...prev, [field]: value }));
  }

  const isPending = createQuestion.isPending || patchQuestion.isPending;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    if (!form.label.trim()) {
      toast.error("Question label is required");
      return;
    }

    try {
      let savedId: string | undefined = question?.id;

      if (isEdit && question) {
        await patchQuestion.mutateAsync({ id: question.id, patch: form });
      } else {
        const created = await createQuestion.mutateAsync({
          ...form,
          question_id: buildQuestionId(subgroupKey, form.label),
        });
        savedId = created.id;
      }

      if (form.answer_type === "single_choice" && savedId) {
        const serverOptions = existingOptionsQuery.data ?? [];
        const localExistingIds = new Set(
          localOptions.filter((option) => !option.tempId.startsWith("new-")).map((option) => option.tempId),
        );

        if (localOptions.some((option) => !option.value.trim())) {
          toast.error("Every answer option needs a value before you can save the question.");
          return;
        }

        for (let i = 0; i < localOptions.length; i++) {
          const opt = localOptions[i];
          if (opt.tempId.startsWith("new-")) {
            await createOption.mutateAsync({
              question_id: savedId,
              value: opt.value,
              label: opt.label || opt.value,
              description: opt.description || null,
              display_order: i + 1,
            });
            continue;
          }

          const original = serverOptions.find((option) => option.id === opt.tempId);
          if (
            original && (
              original.value !== opt.value ||
              original.label !== (opt.label || opt.value) ||
              (original.description ?? "") !== opt.description ||
              original.display_order !== i + 1
            )
          ) {
            await patchOption.mutateAsync({
              id: opt.tempId,
              patch: {
                value: opt.value,
                label: opt.label || opt.value,
                description: opt.description || null,
                display_order: i + 1,
              },
            });
          }
        }

        for (const serverOption of serverOptions) {
          if (!localExistingIds.has(serverOption.id)) {
            await deleteOption.mutateAsync(serverOption.id);
          }
        }
      }

      toast.success("Question saved");
      onClose();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to save question");
    }
  }

  const title = isEdit ? "Edit Question" : "Add Question";

  return (
    <Sheet open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-lg bg-[#131313] border-l border-amber-500/20 overflow-y-auto"
        showCloseButton
      >
        <SheetHeader className="px-0 pb-4 border-b border-amber-500/10">
          <SheetTitle className="font-mono text-amber-100">{title}</SheetTitle>
          <p className="font-mono text-xs text-amber-500/50">
            Subgroup: <span className="text-amber-400/70">{subgroupLabel} ({subgroupKey})</span>
          </p>
        </SheetHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-5 py-4">
          {!isEdit && (
            <div className="rounded-[8px] border border-amber-500/15 bg-amber-500/5 p-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-amber-400/80">Suggested questions</span>
                <span className="font-mono text-[10px] text-amber-500/40">Click to prefill</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {suggestedTemplates.map((template) => (
                  <button
                    key={template.label}
                    type="button"
                    onClick={() => applySuggestedTemplate(template)}
                    className="rounded-full border border-amber-500/20 bg-[#161616] px-3 py-1.5 text-left text-xs text-amber-100/75 transition hover:border-amber-400/40 hover:text-amber-100"
                  >
                    {template.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          <FieldRow label="Label *" htmlFor="q-label">
            <Input
              id="q-label"
              value={form.label}
              onChange={(e) => update("label", e.target.value)}
              placeholder="Enter question label"
              required
              className="font-mono text-sm bg-[#1a1a1a] border-amber-500/20 text-amber-100 focus-visible:border-amber-500/60"
            />
          </FieldRow>

          {/* 2. Question type */}
          <FieldRow label="Question Type" htmlFor="q-type">
            <CyberSelect
              id="q-type"
              value={form.question_type}
              onChange={(v) => update("question_type", v)}
            >
              <option value="scope">scope</option>
              <option value="core">core</option>
              <option value="conditional">conditional</option>
            </CyberSelect>
          </FieldRow>

          {/* 3. Depth level */}
          <FieldRow label="Depth Level" htmlFor="q-depth">
            <CyberSelect
              id="q-depth"
              value={form.depth_level}
              onChange={(v) => update("depth_level", v)}
            >
              <option value="primary">primary</option>
              <option value="secondary">secondary</option>
            </CyberSelect>
          </FieldRow>

          {/* 4. Answer type */}
          <FieldRow label="Answer Type" htmlFor="q-answer-type">
            <CyberSelect
              id="q-answer-type"
              value={form.answer_type}
              onChange={(v) => update("answer_type", v)}
            >
              <option value="binary">binary</option>
              <option value="maturity_tier">maturity_tier</option>
              <option value="single_choice">single_choice</option>
              <option value="text">text</option>
            </CyberSelect>
          </FieldRow>

          {/* 5. Instruction */}
          <FieldRow label="Instruction" htmlFor="q-instruction">
            <textarea
              id="q-instruction"
              value={form.instruction ?? ""}
              onChange={(e) => update("instruction", e.target.value)}
              rows={2}
              placeholder="Optional instruction text"
              className="w-full rounded-[2px] border border-amber-500/20 bg-[#1a1a1a] px-2.5 py-1.5 font-mono text-sm text-amber-100 outline-none focus:border-amber-500/60 resize-y transition-colors"
            />
          </FieldRow>

          {/* 6. Guideline */}
          <FieldRow label="Guideline" htmlFor="q-guideline">
            <textarea
              id="q-guideline"
              value={form.guideline ?? ""}
              onChange={(e) => update("guideline", e.target.value)}
              rows={2}
              placeholder="Optional guideline text"
              className="w-full rounded-[2px] border border-amber-500/20 bg-[#1a1a1a] px-2.5 py-1.5 font-mono text-sm text-amber-100 outline-none focus:border-amber-500/60 resize-y transition-colors"
            />
          </FieldRow>

          {/* 7. Required toggle */}
          <div className="flex items-center gap-2">
            <input
              id="q-required"
              type="checkbox"
              checked={form.is_required}
              onChange={(e) => update("is_required", e.target.checked)}
              className="accent-amber-500"
            />
            <label
              htmlFor="q-required"
              className="font-mono text-xs text-amber-500/70 cursor-pointer select-none"
            >
              Required
            </label>
          </div>

          {/* 8. Conditional dependency section */}
          <div className="flex flex-col gap-3 rounded-[2px] border border-amber-500/10 p-3">
            <button
              type="button"
              onClick={() => setShowConditional((v) => !v)}
              className="flex items-center justify-between font-mono text-xs text-amber-500/60 hover:text-amber-400 transition-colors w-full text-left"
            >
              <span className="uppercase tracking-wider">Conditional Dependency</span>
              <span className="text-amber-500/30">{showConditional ? "▲" : "▼"}</span>
            </button>

            {showConditional && (
              <div className="flex flex-col gap-3">
                <FieldRow label="Depends On Question" htmlFor="dep-question">
                  <DependencyPicker
                    value={form.depends_on_question_id}
                    onChange={(v) => update("depends_on_question_id", v)}
                  />
                </FieldRow>

                <FieldRow label="Expected When (answer value)" htmlFor="q-expected-when">
                  <Input
                    id="q-expected-when"
                    value={form.expected_when ?? ""}
                    onChange={(e) =>
                      update("expected_when", e.target.value || null)
                    }
                    placeholder="e.g. yes or true"
                    className="font-mono text-sm bg-[#1a1a1a] border-amber-500/20 text-amber-100 focus-visible:border-amber-500/60"
                  />
                </FieldRow>

                {/* 9. Advanced condition JSON */}
                <FieldRow label='Advanced Condition (JSON)' htmlFor="q-condition-json">
                  <textarea
                    id="q-condition-json"
                    value={form.condition_expr_json ?? ""}
                    onChange={(e) =>
                      update("condition_expr_json", e.target.value || null)
                    }
                    rows={3}
                    placeholder={`{"op":"AND","conditions":[...]}`}
                    className="w-full rounded-[2px] border border-amber-500/20 bg-[#1a1a1a] px-2.5 py-1.5 font-mono text-xs text-amber-100/80 outline-none focus:border-amber-500/60 resize-y transition-colors"
                  />
                </FieldRow>
              </div>
            )}
          </div>

          {/* 10. Options list — shown only for single_choice */}
          {form.answer_type === "single_choice" && (
            <div className="rounded-[2px] border border-amber-500/10 p-3">
              <OptionsEditor
                questionId={question?.id}
                localOptions={localOptions}
                onChange={setLocalOptions}
              />
            </div>
          )}

          <SheetFooter className="px-0 pt-2 border-t border-amber-500/10">
            <div className="flex gap-2 w-full">
              <Button
                type="submit"
                disabled={isPending}
                className="flex-1 bg-amber-500 hover:bg-amber-400 text-[#131313] font-mono font-semibold"
              >
                {isPending ? "Saving…" : isEdit ? "Save Changes" : "Create Question"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                className="font-mono border-amber-500/20 text-amber-500/70 hover:text-amber-400"
              >
                Cancel
              </Button>
            </div>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
