import { useCallback, useEffect, useState } from "react";
import {
  DndContext,
  PointerSensor,
  KeyboardSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
  arrayMove,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import {
  DotsSixVertical,
  PencilSimple,
  Check,
  X,
  Plus,
} from "@phosphor-icons/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";

import type { QuestionFlat } from "./types";
import { usePatchSection, usePatchSubgroup } from "./api";
import type { EditorSectionTree, EditorSubgroupTree } from "./treeModel";

type AnswerTypeBadgeVariant = "info" | "medium" | "low" | "neutral";

function answerTypeSeverity(answerType: string): AnswerTypeBadgeVariant {
  switch (answerType) {
    case "binary":
      return "info";
    case "maturity_tier":
      return "medium";
    case "single_choice":
      return "low";
    default:
      return "neutral";
  }
}

interface InlineLabelProps {
  value: string;
  onSave: (value: string) => void;
  className?: string;
}

function InlineLabel({ value, onSave, className }: InlineLabelProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);

  function startEdit() {
    setDraft(value);
    setEditing(true);
  }

  function commit() {
    const trimmed = draft.trim();
    if (trimmed && trimmed !== value) {
      onSave(trimmed);
    }
    setEditing(false);
  }

  function handleKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") commit();
    if (e.key === "Escape") setEditing(false);
  }

  if (editing) {
    return (
      <span className="flex items-center gap-1">
        <input
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={handleKey}
          className="rounded-[2px] border border-amber-500/40 bg-[#1a1a1a] px-1.5 py-0.5 font-mono text-sm text-amber-100 outline-none focus:border-amber-500"
        />
        <button
          type="button"
          aria-label="Save label"
          onClick={commit}
          className="text-amber-500 hover:text-amber-400 transition-colors"
        >
          <Check size={14} weight="bold" />
        </button>
        <button
          type="button"
          aria-label="Cancel edit"
          onClick={() => setEditing(false)}
          className="text-amber-500/50 hover:text-amber-400 transition-colors"
        >
          <X size={14} weight="bold" />
        </button>
      </span>
    );
  }

  return (
    <span className={`flex items-center gap-1.5 group/label ${className ?? ""}`}>
      <span>{value}</span>
      <button
        type="button"
        aria-label="Edit label"
        onClick={startEdit}
        className="opacity-0 group-hover/label:opacity-100 transition-opacity text-amber-500/50 hover:text-amber-400"
      >
        <PencilSimple size={13} weight="bold" />
      </button>
    </span>
  );
}

function QuestionChip({ question, onEdit }: { question: QuestionFlat; onEdit: (q: QuestionFlat) => void }) {
  const hasLogic = Boolean(question.depends_on_question_id || question.condition_expr_json);
  const mappingCount = question.subtask_mappings.length;
  return (
    <button
      type="button"
      onClick={() => onEdit(question)}
      aria-label={`Edit question: ${question.label}`}
      className="group flex w-full items-start gap-3 rounded-xl border border-amber-500/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.03),rgba(255,255,255,0.01))] px-3 py-3 text-left transition hover:border-amber-400/30 hover:bg-[#171717]"
    >
      <div className="mt-0.5 h-2.5 w-2.5 rounded-full bg-amber-400/70 shadow-[0_0_10px_rgba(245,158,11,0.35)]" />
      <div className="min-w-0 flex-1 space-y-2">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate font-medium text-amber-50" title={question.label}>{question.label}</p>
            <p className="mt-1 line-clamp-2 text-xs leading-5 text-amber-100/55">{question.instruction || question.guideline || "Open the drawer to edit wording, answer type, and logic."}</p>
          </div>
          <PencilSimple size={15} weight="bold" className="shrink-0 text-amber-500/45 transition group-hover:text-amber-300" />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <AilaBadge severity={answerTypeSeverity(question.answer_type)} size="sm">{question.answer_type}</AilaBadge>
          {hasLogic && <AilaBadge severity="medium" size="sm">logic</AilaBadge>}
          {mappingCount > 0 && <AilaBadge severity="info" size="sm">{mappingCount} links</AilaBadge>}
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-amber-500/35">{question.question_type}</span>
        </div>
      </div>
    </button>
  );
}

interface SubgroupRowProps {
  subgroup: EditorSubgroupTree;
  onEditQuestion: (q: QuestionFlat, subgroupId: string) => void;
  onAddQuestion: (subgroupId: string) => void;
  onLabelSave: (subgroupId: string, label: string) => void;
}

function SubgroupRow({ subgroup, onEditQuestion, onAddQuestion, onLabelSave }: SubgroupRowProps) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: subgroup.id });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };

  return (
    <div ref={setNodeRef} style={style} className="flex flex-col gap-2 rounded-[14px] border border-amber-500/10 bg-[#111111] p-3">
      <div className="flex items-center gap-2">
        <button
          type="button"
          aria-label="Drag to reorder subgroup"
          className="flex-shrink-0 cursor-grab active:cursor-grabbing text-amber-500/30 hover:text-amber-500 transition-colors touch-none"
          {...attributes}
          {...listeners}
        >
          <DotsSixVertical size={14} />
        </button>
        <InlineLabel
          value={subgroup.label}
          onSave={(label) => onLabelSave(subgroup.id, label)}
          className="flex-1 font-mono text-xs font-medium text-amber-300/80"
        />
        <span className="font-mono text-[10px] text-amber-500/40 border border-amber-500/20 px-1 rounded-[2px]">
          {subgroup.subgroup_key}
        </span>
      </div>

      <div className="pl-5">
        <div className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-[0.18em] text-amber-500/35">
          <span>{subgroup.questions.length} questions</span>
        </div>
        {subgroup.questions.length > 0 && (
          <div className="flex flex-col gap-2">
            {subgroup.questions
              .slice()
              .sort((a, b) => a.display_order - b.display_order)
              .map((q) => (
                <QuestionChip
                  key={q.id}
                  question={q}
                  onEdit={(question) => onEditQuestion(question, subgroup.id)}
                />
              ))}
          </div>
        )}
      </div>

      <div className="pl-5 pt-0.5">
        <button
          type="button"
          aria-label={`Add question to ${subgroup.label}`}
          onClick={() => onAddQuestion(subgroup.id)}
          className="flex items-center gap-1 rounded-full border border-amber-500/20 bg-[#161616] px-3 py-1.5 font-mono text-xs text-amber-200/75 transition hover:border-amber-400/35 hover:text-amber-100"
        >
          <Plus size={12} weight="bold" />
          Add question
        </button>
      </div>
    </div>
  );
}

interface SectionRowProps {
  section: EditorSectionTree;
  onEditQuestion: (q: QuestionFlat, subgroupId: string) => void;
  onAddQuestion: (subgroupId: string) => void;
  onSectionLabelSave: (sectionId: string, label: string) => void;
  onSubgroupLabelSave: (subgroupId: string, label: string) => void;
  onSubgroupDragEnd: (sectionId: string, event: DragEndEvent) => void;
}

function SectionRow({
  section,
  onEditQuestion,
  onAddQuestion,
  onSectionLabelSave,
  onSubgroupLabelSave,
  onSubgroupDragEnd,
}: SectionRowProps) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: section.id });
  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };
  const subgroupSensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );
  const subgroupIds = section.subgroups.map((sg) => sg.id);

  const questionCount = section.subgroups.reduce((total, subgroup) => total + subgroup.questions.length, 0);
  const logicCount = section.subgroups.reduce(
    (total, subgroup) => total + subgroup.questions.filter((question) => question.depends_on_question_id || question.condition_expr_json).length,
    0,
  ) + (section.depends_on_question_id || section.condition_expr_json ? 1 : 0);

  return (
    <div ref={setNodeRef} style={style} className="flex flex-col gap-3 rounded-[18px] border border-amber-500/20 bg-[linear-gradient(180deg,rgba(255,255,255,0.025),rgba(255,255,255,0.01))] p-4 shadow-[0_12px_28px_rgba(0,0,0,0.22)]">
      <div className="flex items-start gap-3">
        <button
          type="button"
          aria-label="Drag to reorder section"
          className="mt-0.5 flex-shrink-0 cursor-grab active:cursor-grabbing text-amber-500/50 hover:text-amber-500 transition-colors touch-none"
          {...attributes}
          {...listeners}
        >
          <DotsSixVertical size={18} />
        </button>
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <InlineLabel
                value={section.label}
                onSave={(label) => onSectionLabelSave(section.id, label)}
                className="font-mono text-base font-semibold text-amber-100"
              />
              {section.description ? (
                <p className="mt-2 max-w-3xl text-sm leading-6 text-amber-100/60">{section.description}</p>
              ) : (
                <p className="mt-2 text-sm leading-6 text-amber-100/45">Use this section as a blueprint lane. Drag subgroups to re-order the conversation and open chips to edit logic or suggested prompts.</p>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              <AilaBadge severity="info" size="sm">{section.subgroups.length} lanes</AilaBadge>
              <AilaBadge severity="info" size="sm">{questionCount} questions</AilaBadge>
              {logicCount > 0 && <AilaBadge severity="medium" size="sm">{logicCount} logic links</AilaBadge>}
              <span className="rounded-full border border-amber-500/20 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.2em] text-amber-500/45">{section.section_key}</span>
            </div>
          </div>

          {section.subgroups.length > 0 && (
            <DndContext sensors={subgroupSensors} collisionDetection={closestCenter} onDragEnd={(event) => onSubgroupDragEnd(section.id, event)}>
              <SortableContext items={subgroupIds} strategy={verticalListSortingStrategy}>
                <div className="flex flex-col gap-3 pl-2">
                  {section.subgroups.map((sg) => (
                    <SubgroupRow
                      key={sg.id}
                      subgroup={sg}
                      onEditQuestion={onEditQuestion}
                      onAddQuestion={onAddQuestion}
                      onLabelSave={(id, label) => onSubgroupLabelSave(id, label)}
                    />
                  ))}
                </div>
              </SortableContext>
            </DndContext>
          )}
        </div>
      </div>
    </div>
  );
}

export interface SectionTreeProps {
  sections: EditorSectionTree[];
  onEditQuestion: (questionId: string, subgroupId: string) => void;
  onAddQuestion: (subgroupId: string) => void;
}

export function SectionTree({ sections: treeSections, onEditQuestion, onAddQuestion }: SectionTreeProps) {
  const patchSection = usePatchSection();
  const patchSubgroup = usePatchSubgroup();
  const [localSections, setLocalSections] = useState<EditorSectionTree[]>(treeSections);

  useEffect(() => {
    setLocalSections(treeSections);
  }, [treeSections]);

  const sectionSensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const handleSectionDragEnd = useCallback(
    (event: DragEndEvent) => {
      const { active, over } = event;
      if (!over || active.id === over.id) return;

      setLocalSections((prev) => {
        const oldIdx = prev.findIndex((s) => s.id === active.id);
        const newIdx = prev.findIndex((s) => s.id === over.id);
        if (oldIdx === -1 || newIdx === -1) return prev;
        const reordered = arrayMove(prev, oldIdx, newIdx);
        reordered.forEach((section, index) => {
          patchSection.mutate({ id: section.id, patch: { display_order: index + 1 } });
        });
        return reordered;
      });
    },
    [patchSection],
  );

  const handleSubgroupDragEnd = useCallback(
    (sectionId: string, event: DragEndEvent) => {
      const { active, over } = event;
      if (!over || active.id === over.id) return;

      setLocalSections((prev) =>
        prev.map((section) => {
          if (section.id !== sectionId) return section;
          const oldIdx = section.subgroups.findIndex((sg) => sg.id === active.id);
          const newIdx = section.subgroups.findIndex((sg) => sg.id === over.id);
          if (oldIdx === -1 || newIdx === -1) return section;
          const reordered = arrayMove(section.subgroups, oldIdx, newIdx);
          reordered.forEach((subgroup, index) => {
            patchSubgroup.mutate({ id: subgroup.id, patch: { display_order: index + 1 } });
          });
          return { ...section, subgroups: reordered };
        }),
      );
    },
    [patchSubgroup],
  );

  const handleSectionLabelSave = useCallback(
    (sectionId: string, label: string) => {
      patchSection.mutate({ id: sectionId, patch: { label } });
      setLocalSections((prev) => prev.map((section) => (section.id === sectionId ? { ...section, label } : section)));
    },
    [patchSection],
  );

  const handleSubgroupLabelSave = useCallback(
    (subgroupId: string, label: string) => {
      patchSubgroup.mutate({ id: subgroupId, patch: { label } });
      setLocalSections((prev) =>
        prev.map((section) => ({
          ...section,
          subgroups: section.subgroups.map((subgroup) =>
            subgroup.id === subgroupId ? { ...subgroup, label } : subgroup,
          ),
        })),
      );
    },
    [patchSubgroup],
  );

  if (localSections.length === 0) {
    return (
      <EmptyState
        title="No sections found"
        description="The schema has no sections yet. Seed the schema or publish a version before editing."
      />
    );
  }

  const sectionIds = localSections.map((section) => section.id);

  return (
    <DndContext sensors={sectionSensors} collisionDetection={closestCenter} onDragEnd={handleSectionDragEnd}>
      <SortableContext items={sectionIds} strategy={verticalListSortingStrategy}>
        <div className="flex flex-col gap-3">
          {localSections.map((section) => (
            <SectionRow
              key={section.id}
              section={section}
              onEditQuestion={(question, subgroupId) => onEditQuestion(question.id, subgroupId)}
              onAddQuestion={onAddQuestion}
              onSectionLabelSave={handleSectionLabelSave}
              onSubgroupLabelSave={handleSubgroupLabelSave}
              onSubgroupDragEnd={handleSubgroupDragEnd}
            />
          ))}
        </div>
      </SortableContext>
    </DndContext>
  );
}
