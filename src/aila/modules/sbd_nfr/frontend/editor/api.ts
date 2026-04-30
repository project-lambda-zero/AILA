/**
 * editor/api.ts — TanStack Query hooks for all schema editor API calls.
 *
 * Wraps Phase 155 endpoints under /sbd_nfr/schema/*.
 * Uses authorizedRequestJson from @platform/api/http for JWT-authenticated calls.
 *
 * Query key namespace: ["schema-editor", ...]
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import type { SchemaTreeResponse } from "../types";
import type {
  MappingRecord,
  OptionRow,
  QuestionFlat,
  QuestionListItem,
  SchemaVersionRecord,
  SectionFlat,
  SubgroupFlat,
} from "./types";

// ---------------------------------------------------------------------------
// Read hooks — usable by any authenticated caller
// ---------------------------------------------------------------------------

export function useSchemaTree() {
  return useQuery({
    queryKey: ["schema-editor", "tree"],
    queryFn: () => authorizedRequestJson<SchemaTreeResponse>("/sbd_nfr/schema"),
    staleTime: 30_000,
  });
}


export function useSchemaSections() {
  return useQuery({
    queryKey: ["schema-editor", "sections"],
    queryFn: () =>
      authorizedRequestJson<SectionFlat[]>("/sbd_nfr/schema/sections"),
    staleTime: 30_000,
  });
}

export function useSchemaQuestions(params?: { subgroup_id?: string; include_inactive?: boolean }) {
  const qs = new URLSearchParams();
  if (params?.subgroup_id) qs.set("subgroup_id", params.subgroup_id);
  if (params?.include_inactive) qs.set("include_inactive", "true");
  const search = qs.toString();
  return useQuery({
    queryKey: ["schema-editor", "questions", params],
    queryFn: () =>
      authorizedRequestJson<QuestionListItem[]>(
        `/sbd_nfr/schema/questions${search ? `?${search}` : ""}`,
      ),
    staleTime: 30_000,
  });
}

export function useSchemaVersion() {
  return useQuery({
    queryKey: ["schema-editor", "version"],
    queryFn: () =>
      authorizedRequestJson<SchemaVersionRecord>("/sbd_nfr/schema/version"),
    staleTime: 60_000,
  });
}

export function useSchemaOptions(questionId: string) {
  return useQuery({
    queryKey: ["schema-editor", "options", questionId],
    queryFn: () =>
      authorizedRequestJson<OptionRow[]>(
        `/sbd_nfr/schema/options?question_id=${encodeURIComponent(questionId)}`,
      ),
    enabled: Boolean(questionId),
    staleTime: 30_000,
  });
}

// ---------------------------------------------------------------------------
// Section mutations (admin only)
// ---------------------------------------------------------------------------

export function usePatchSection() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: { display_order?: number; label?: string; description?: string };
    }) =>
      authorizedRequestJson<SectionFlat>(`/sbd_nfr/schema/sections/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: patch,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "sections"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Subgroup mutations (admin only)
// ---------------------------------------------------------------------------

export function usePatchSubgroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: { display_order?: number; label?: string; description?: string };
    }) =>
      authorizedRequestJson<SubgroupFlat>(
        `/sbd_nfr/schema/subgroups/${encodeURIComponent(id)}`,
        {
          method: "PATCH",
          body: patch,
        },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "sections"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Question mutations (admin only)
// ---------------------------------------------------------------------------

interface QuestionCreateRequest {
  subgroup_id: string;
  question_id?: string | null;
  question_type: string;
  depth_level: string;
  answer_type: string;
  label: string;
  instruction?: string | null;
  guideline?: string | null;
  help_text?: string | null;
  is_required?: boolean;
  depends_on_question_id?: string | null;
  expected_when?: string | null;
  condition_expr_json?: string | null;
  display_order?: number;
  max_length?: number | null;
}

interface QuestionUpdateRequest {
  label?: string;
  instruction?: string | null;
  guideline?: string | null;
  help_text?: string | null;
  is_required?: boolean;
  depends_on_question_id?: string | null;
  expected_when?: string | null;
  condition_expr_json?: string | null;
  display_order?: number;
  answer_type?: string;
  max_length?: number | null;
}

export function useCreateQuestion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: QuestionCreateRequest) =>
      authorizedRequestJson<QuestionFlat>("/sbd_nfr/schema/questions", {
        method: "POST",
        body,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "questions"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

export function usePatchQuestion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: QuestionUpdateRequest }) =>
      authorizedRequestJson<QuestionFlat>(
        `/sbd_nfr/schema/questions/${encodeURIComponent(id)}`,
        {
          method: "PATCH",
          body: patch,
        },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "questions"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Answer option mutations (admin only — used by QuestionEditorDrawer)
// ---------------------------------------------------------------------------

interface OptionCreateRequest {
  question_id: string;
  value: string;
  label: string;
  description: string | null;
  display_order: number;
}

export function useCreateOption() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: OptionCreateRequest) =>
      authorizedRequestJson<OptionRow>("/sbd_nfr/schema/options", {
        method: "POST",
        body,
      }),
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({
        queryKey: ["schema-editor", "options", variables.question_id],
      });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

export function useDeleteOption() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(`/sbd_nfr/schema/options/${encodeURIComponent(id)}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "options"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

export function usePatchOption() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: { value?: string; label?: string; description?: string | null; display_order?: number };
    }) =>
      authorizedRequestJson<OptionRow>(`/sbd_nfr/schema/options/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: patch,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "options"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "questions"] });
    },
  });
}


// ---------------------------------------------------------------------------
// Schema version publish (admin only)
// ---------------------------------------------------------------------------

export function usePublishSchemaVersion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (note?: string) =>
      authorizedRequestJson<SchemaVersionRecord>("/sbd_nfr/schema/version/publish", {
        method: "POST",
        body: { note: note ?? null },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "version"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "sections"] });
      void queryClient.invalidateQueries({ queryKey: ["schema-editor", "tree"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Subtask mapping read (for completeness — SubtaskMappingEditor uses its own
// inline hooks to avoid circular imports)
// ---------------------------------------------------------------------------

export function useSubtaskMappings(params?: { question_id?: string; subtask_key?: string }) {
  const qs = new URLSearchParams();
  if (params?.question_id) qs.set("question_id", params.question_id);
  if (params?.subtask_key) qs.set("subtask_key", params.subtask_key);
  const search = qs.toString();
  return useQuery({
    queryKey: ["schema-editor", "mappings", params],
    queryFn: () =>
      authorizedRequestJson<MappingRecord[]>(
        `/sbd_nfr/schema/mappings${search ? `?${search}` : ""}`,
      ),
    staleTime: 30_000,
  });
}
