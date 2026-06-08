/**
 * SubtaskMappingEditor.tsx — EDIT-03
 *
 * Multi-select question assignment panel for subtask components.
 * - Left column: list of all subtask components with coverage count chip
 * - Right column: current mappings (with remove) + question picker (with add)
 *
 * Coverage indicator: amber if >= 2 questions mapped, red if < 2.
 *
 * Inline hooks (not in editor/api.ts to avoid circular imports):
 *   useSubtaskMappingsLocal — GET /sbd_nfr/schema/mappings
 *   useCreateSubtaskMapping — POST /sbd_nfr/schema/mappings
 *   useDeleteSubtaskMapping — DELETE /sbd_nfr/schema/mappings/{id}
 *
 * Schema tree (subtask_components list):
 *   useSchemaTreeLocal — GET /sbd_nfr/schema/tree
 */
import * as React from "react";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield } from "@phosphor-icons/react/dist/csr/Shield";
import { X } from "@phosphor-icons/react/dist/csr/X";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { authorizedRequestJson } from "@platform/api/http";
import { EmptyState } from "@/components/aila/EmptyState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";

import { useSchemaQuestions } from "./api";
import type { MappingRecord, QuestionListItem as QuestionFlat } from "./types";
import type { SubtaskComponentResponse, SchemaTreeResponse } from "../types";

// ---------------------------------------------------------------------------
// Local inline hooks
// ---------------------------------------------------------------------------

function useSchemaTreeLocal() {
  return useQuery({
    queryKey: ["schema-editor", "subtasks"],
    queryFn: () =>
      authorizedRequestJson<SubtaskComponentResponse[]>("/sbd_nfr/schema/subtasks"),
    staleTime: 60_000,
  });
}

function useSubtaskMappingsLocal() {
  return useQuery({
    queryKey: ["schema-editor", "mappings"],
    queryFn: () =>
      authorizedRequestJson<MappingRecord[]>("/sbd_nfr/schema/mappings"),
    staleTime: 30_000,
  });
}

interface CreateMappingPayload {
  question_id: string;
  subtask_key: string;
}

function useCreateSubtaskMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateMappingPayload) =>
      authorizedRequestJson<MappingRecord>("/sbd_nfr/schema/mappings", {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "mappings"] });
    },
  });
}

function useDeleteSubtaskMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (mappingId: string) =>
      authorizedRequestJson<void>(
        `/sbd_nfr/schema/mappings/${encodeURIComponent(mappingId)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "mappings"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface CoverageChipProps {
  count: number;
}

function CoverageChip({ count }: CoverageChipProps) {
  if (count >= 2) {
    return (
      <span className="text-xs font-mono text-amber-400">
        {count} {count === 1 ? "question" : "questions"} mapped
      </span>
    );
  }
  return (
    <span className="text-xs font-mono text-red-400 font-bold">
      {count} {count === 1 ? "question" : "questions"} mapped
    </span>
  );
}

interface SubtaskRowProps {
  component: SubtaskComponentResponse;
  mappingCount: number;
  isSelected: boolean;
  onSelect: () => void;
}

function SubtaskRow({ component, mappingCount, isSelected, onSelect }: SubtaskRowProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={[
        "w-full text-left px-3 py-2.5 flex flex-col gap-1 transition-colors cursor-pointer",
        isSelected
          ? "bg-amber-500/10 border-l-2 border-amber-400"
          : "border-l-2 border-transparent hover:bg-sbd-hover",
      ].join(" ")}
    >
      <div className="flex items-center gap-2">
        <span className="text-base" aria-hidden="true">
          {component.icon_hint || <Shield className="h-4 w-4 text-amber-400" />}
        </span>
        <span className="font-mono text-sm text-white truncate">{component.label}</span>
      </div>
      <div className="flex items-center gap-2 pl-6">
        <Badge variant="outline" className="text-3xs text-amber-400/80 border-amber-400/30">
          {component.category}
        </Badge>
        <CoverageChip count={mappingCount} />
      </div>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Mapped question row
// ---------------------------------------------------------------------------

interface MappedQuestionRowProps {
  mapping: MappingRecord;
  question: QuestionFlat | undefined;
  onRemove: () => void;
  isRemoving: boolean;
}

function MappedQuestionRow({ mapping, question, onRemove, isRemoving }: MappedQuestionRowProps) {
  const label = question?.label ?? mapping.question_id;
  return (
    <div className="flex items-start justify-between gap-2 px-3 py-2 border-b border-amber-500/10 last:border-0">
      <div className="flex flex-col gap-0.5 min-w-0">
        <span className="font-mono text-sm text-white truncate">{label}</span>
        {question && (
          <span className="font-mono text-2xs text-amber-400/60">{question.answer_type}</span>
        )}
      </div>
      <Button
        size="icon-xs"
        variant="ghost"
        onClick={onRemove}
        disabled={isRemoving}
        aria-label={`Remove ${label}`}
        className="shrink-0 text-red-400 hover:text-red-300 hover:bg-red-400/10"
      >
        <X className="h-3 w-3" />
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Picker question row
// ---------------------------------------------------------------------------

interface PickerQuestionRowProps {
  question: QuestionFlat;
  breadcrumb: string;
  onAdd: () => void;
  isAdding: boolean;
}

function PickerQuestionRow({ question, breadcrumb, onAdd, isAdding }: PickerQuestionRowProps) {
  return (
    <div className="flex items-start justify-between gap-2 px-3 py-2 border-b border-amber-500/10 last:border-0 hover:bg-sbd-hover transition-colors">
      <div className="flex flex-col gap-0.5 min-w-0">
        <span className="font-mono text-sm text-white/90 truncate">{question.label}</span>
        <div className="flex items-center gap-1.5">
          <Badge
            variant="outline"
            className="text-3xs text-amber-400/70 border-amber-400/20 shrink-0"
          >
            {question.answer_type}
          </Badge>
          <span className="font-mono text-3xs text-white/40 truncate">{breadcrumb}</span>
        </div>
      </div>
      <Button
        size="icon-xs"
        variant="ghost"
        onClick={onAdd}
        disabled={isAdding}
        aria-label={`Add ${question.label}`}
        className="shrink-0 text-amber-400 hover:text-amber-300 hover:bg-amber-400/10"
      >
        <Plus className="h-3 w-3" />
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Coverage indicator footer
// ---------------------------------------------------------------------------

interface CoverageFooterProps {
  count: number;
}

function CoverageFooter({ count }: CoverageFooterProps) {
  if (count >= 2) {
    return (
      <div className="px-4 py-2 border-t border-amber-500/20 bg-sbd-base">
        <p className="font-mono text-xs text-amber-400">
          Coverage: {count} questions mapped (sufficient)
        </p>
      </div>
    );
  }
  return (
    <div className="px-4 py-2 border-t border-red-500/30 bg-sbd-base">
      <p className="font-mono text-xs text-red-400 font-bold">
        Coverage: {count} questions mapped{" "}
        <span className="text-red-300">(minimum 2 required)</span>
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Right panel
// ---------------------------------------------------------------------------

interface RightPanelProps {
  subtaskKey: string;
  allMappings: MappingRecord[];
  allQuestions: QuestionFlat[];
  createMapping: ReturnType<typeof useCreateSubtaskMapping>;
  deleteMapping: ReturnType<typeof useDeleteSubtaskMapping>;
}

function RightPanel({
  subtaskKey,
  allMappings,
  allQuestions,
  createMapping,
  deleteMapping,
}: RightPanelProps) {
  const [search, setSearch] = React.useState("");

  const currentMappings = React.useMemo(
    () => allMappings.filter((m) => m.subtask_key === subtaskKey),
    [allMappings, subtaskKey],
  );

  const mappedQuestionIds = React.useMemo(
    () => new Set(currentMappings.map((m) => m.question_id)),
    [currentMappings],
  );

  const questionMap = React.useMemo(() => {
    const map = new Map<string, QuestionFlat>();
    for (const q of allQuestions) {
      map.set(q.id, q);
    }
    return map;
  }, [allQuestions]);

  const availableQuestions = React.useMemo(
    () =>
      allQuestions.filter(
        (q) =>
          !mappedQuestionIds.has(q.id) &&
          (search.trim() === "" ||
            q.label.toLowerCase().includes(search.trim().toLowerCase()) ||
            q.question_type.toLowerCase().includes(search.trim().toLowerCase())),
      ),
    [allQuestions, mappedQuestionIds, search],
  );

  function getBreadcrumb(q: QuestionFlat): string {
    return q.question_type;
  }

  const [addingId, setAddingId] = React.useState<string | null>(null);
  const [removingId, setRemovingId] = React.useState<string | null>(null);

  async function handleAdd(questionId: string) {
    setAddingId(questionId);
    try {
      await createMapping.mutateAsync({ question_id: questionId, subtask_key: subtaskKey });
    } finally {
      setAddingId(null);
    }
  }

  async function handleRemove(mappingId: string) {
    setRemovingId(mappingId);
    try {
      await deleteMapping.mutateAsync(mappingId);
    } finally {
      setRemovingId(null);
    }
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Current mappings */}
      <div className="flex flex-col flex-shrink-0" style={{ maxHeight: "40%" }}>
        <div className="px-4 py-2 border-b border-amber-500/20 bg-sbd-input">
          <p className="font-mono text-xs text-amber-400/70 uppercase tracking-wider">
            Mapped questions
          </p>
        </div>
        {currentMappings.length === 0 ? (
          <div className="px-4 py-3">
            <p className="font-mono text-xs text-white/40">No questions mapped yet</p>
          </div>
        ) : (
          <ScrollArea className="flex-1" style={{ maxHeight: 150 }}>
            {currentMappings.map((m) => (
              <MappedQuestionRow
                key={m.id}
                mapping={m}
                question={questionMap.get(m.question_id)}
                onRemove={() => void handleRemove(m.id)}
                isRemoving={removingId === m.id}
              />
            ))}
          </ScrollArea>
        )}
      </div>

      {/* Question picker */}
      <div className="flex flex-col flex-1 min-h-0">
        <div className="px-4 py-2 border-t border-b border-amber-500/20 bg-sbd-input flex items-center gap-2">
          <MagnifyingGlass className="h-3.5 w-3.5 text-amber-400/60 shrink-0" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search questions to add..."
            className="flex-1 bg-transparent font-mono text-xs text-white placeholder:text-white/30 outline-none"
          />
        </div>
        {availableQuestions.length === 0 ? (
          <div className="px-4 py-3">
            <p className="font-mono text-xs text-white/40">
              {search.trim() !== "" ? "No questions match your search" : "All questions mapped"}
            </p>
          </div>
        ) : (
          <ScrollArea className="flex-1">
            {availableQuestions.map((q) => (
              <PickerQuestionRow
                key={q.id}
                question={q}
                breadcrumb={getBreadcrumb(q)}
                onAdd={() => void handleAdd(q.id)}
                isAdding={addingId === q.id}
              />
            ))}
          </ScrollArea>
        )}
      </div>

      {/* Coverage indicator */}
      <CoverageFooter count={currentMappings.length} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * SubtaskMappingEditor — EDIT-03
 *
 * Two-column panel for managing question→subtask component mappings.
 * Reads real data from /sbd_nfr/schema/tree and /sbd_nfr/schema/mappings.
 * No mock data.
 */
export function SubtaskMappingEditor() {
  const [selectedKey, setSelectedKey] = React.useState<string | null>(null);

  const {
    data: subtaskComponents,
    isLoading: loadingComponents,
    isError: errorComponents,
  } = useSchemaTreeLocal();

  const {
    data: allMappings,
    isLoading: loadingMappings,
  } = useSubtaskMappingsLocal();

  const {
    data: allQuestions,
    isLoading: loadingQuestions,
  } = useSchemaQuestions();

  const createMapping = useCreateSubtaskMapping();
  const deleteMapping = useDeleteSubtaskMapping();

  const isLoading = loadingComponents || loadingMappings || loadingQuestions;

  // Select first active component on load
  React.useEffect(() => {
    if (!selectedKey && subtaskComponents && subtaskComponents.length > 0) {
      const first = subtaskComponents.find((c) => c.is_active) ?? subtaskComponents[0];
      setSelectedKey(first.key);
    }
  }, [subtaskComponents, selectedKey]);

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center bg-sbd-base">
        <p className="font-mono text-sm text-amber-400/60 animate-pulse">
          Loading schema data...
        </p>
      </div>
    );
  }

  if (errorComponents) {
    return (
      <div className="flex h-64 items-center justify-center bg-sbd-base">
        <p className="font-mono text-sm text-red-400">Failed to load subtask components</p>
      </div>
    );
  }

  const activeComponents = (subtaskComponents ?? []).filter((c) => c.is_active);

  if (activeComponents.length === 0) {
    return (
      <EmptyState
        title="No subtask components found"
        description="The schema tree returned no active subtask components."
      />
    );
  }

  if ((allQuestions ?? []).length === 0) {
    return (
      <EmptyState
        title="No questions found"
        description="No questions are currently defined in the schema."
      />
    );
  }

  const mappings = allMappings ?? [];
  const questions = allQuestions ?? [];

  function getCoverageCount(subtaskKey: string): number {
    return mappings.filter((m) => m.subtask_key === subtaskKey).length;
  }

  return (
    <div className="flex h-full bg-sbd-base rounded-lg border border-amber-500/20 overflow-hidden" style={{ minHeight: 500 }}>
      {/* Left column — subtask list */}
      <div className="w-64 flex-shrink-0 border-r border-amber-500/20 bg-sbd-input overflow-y-auto">
        <div className="px-3 py-2 border-b border-amber-500/20">
          <p className="font-mono text-xs text-amber-400/70 uppercase tracking-wider">
            Subtask components
          </p>
        </div>
        {activeComponents.map((component) => (
          <SubtaskRow
            key={component.key}
            component={component}
            mappingCount={getCoverageCount(component.key)}
            isSelected={selectedKey === component.key}
            onSelect={() => setSelectedKey(component.key)}
          />
        ))}
      </div>

      {/* Right column — mapping detail */}
      <div className="flex-1 flex flex-col min-w-0">
        {selectedKey == null ? (
          <div className="flex h-full items-center justify-center">
            <p className="font-mono text-sm text-white/30">
              Select a subtask component to manage its mappings
            </p>
          </div>
        ) : (
          <RightPanel
            key={selectedKey}
            subtaskKey={selectedKey}
            allMappings={mappings}
            allQuestions={questions}
            createMapping={createMapping}
            deleteMapping={deleteMapping}
          />
        )}
      </div>
    </div>
  );
}
