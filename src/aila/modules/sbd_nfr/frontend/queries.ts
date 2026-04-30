import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson, requestBlob } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { saveBlobResponse } from "@platform/api/download";

import type {
  ActivityResponse,
  ApproveSessionRequest,
  ArchitectNotesRequest,
  DocumentAnswersUpdateRequest,
  DocumentModelResponse,
  DocumentSession,
  GeneratedWorkbookResponse,
  JiraDraftResponse,
  NextStepsResponse,
  SaveAsTemplateRequest,
  SubmitForReviewRequest,
  // v2.2 Wizard types
  AssistRequest,
  AssistResponse,
  BulkAnswerRequest,
  ResolutionResultResponse,
  SchemaTreeResponse,
  SessionCreateRequest,
  SessionDetailResponse,
  SessionSummaryResponse,
} from "./types";

export function useSbdNfrDocumentModel() {
  return useQuery({
    queryKey: ["sbd-nfr", "model"],
    queryFn: () => authorizedRequestJson<DocumentModelResponse>("/sbd_nfr/document-model"),
  });
}

export function useSbdNfrDocument(documentId: string | null) {
  return useQuery({
    queryKey: ["sbd-nfr", "document", documentId],
    queryFn: () => authorizedRequestJson<DocumentSession>(`/sbd_nfr/documents/${documentId}`),
    enabled: Boolean(documentId),
  });
}

export function useSbdNfrNextSteps(documentId: string | null) {
  return useQuery({
    queryKey: ["sbd-nfr", "next-steps", documentId],
    queryFn: () => authorizedRequestJson<NextStepsResponse>(`/sbd_nfr/documents/${documentId}/next-steps`),
    enabled: Boolean(documentId),
  });
}

export function useSbdNfrJiraDraft(documentId: string | null) {
  return useQuery({
    queryKey: ["sbd-nfr", "jira-draft", documentId],
    queryFn: () => authorizedRequestJson<JiraDraftResponse>(`/sbd_nfr/documents/${documentId}/jira-draft`),
    enabled: Boolean(documentId),
  });
}

export async function createSbdNfrDocument(): Promise<DocumentSession> {
  return authorizedRequestJson<DocumentSession>("/sbd_nfr/documents", {
    method: "POST",
    body: {},
  });
}

export async function updateSbdNfrDocumentAnswers(
  documentId: string,
  payload: DocumentAnswersUpdateRequest,
): Promise<DocumentSession> {
  return authorizedRequestJson<DocumentSession>(`/sbd_nfr/documents/${documentId}/answers`, {
    method: "PUT",
    body: payload,
  });
}

export async function generateSbdNfrWorkbook(
  documentId: string,
): Promise<GeneratedWorkbookResponse> {
  return authorizedRequestJson<GeneratedWorkbookResponse>(
    `/sbd_nfr/documents/${documentId}/generated-workbook`,
  );
}

// --- v2.2 Wizard Query Hooks ---

export function useWizardSchema() {
  return useQuery({
    queryKey: ["sbd-nfr", "schema"],
    queryFn: () => authorizedRequestJson<SchemaTreeResponse>("/sbd_nfr/schema"),
    staleTime: 5 * 60 * 1000,
  });
}

interface SessionListPage {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: SessionSummaryResponse[];
}

export function useWizardSessionList() {
  return useQuery({
    queryKey: ["sbd-nfr", "sessions"],
    // SBD-01 fix: backend returns PaginatedResponse, not a bare array.
    // Map the paginated envelope to the items list so callers receive SessionSummaryResponse[].
    queryFn: () =>
      authorizedRequestJson<SessionListPage>("/sbd_nfr/sessions").then((page) => page.items),
  });
}

export function useWizardSessionDetail(sessionId: string) {
  return useQuery({
    queryKey: ["sbd-nfr", "session", sessionId],
    queryFn: () =>
      authorizedRequestJson<SessionDetailResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}`,
      ),
    enabled: Boolean(sessionId),
  });
}

export function useWizardResolution(sessionId: string) {
  return useQuery({
    queryKey: ["sbd-nfr", "resolution", sessionId],
    queryFn: () =>
      authorizedRequestJson<ResolutionResultResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/resolution`,
      ),
    enabled: Boolean(sessionId),
  });
}

export function useCreateSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: SessionCreateRequest) =>
      authorizedRequestJson<SessionSummaryResponse>("/sbd_nfr/sessions", {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "sessions"] });
    },
  });
}

export function useCloneSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (sessionId: string) =>
      authorizedRequestJson<SessionSummaryResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/clone`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "sessions"] });
    },
  });
}

export function useCompleteSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (sessionId: string) =>
      authorizedRequestJson<SessionSummaryResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/complete`,
        { method: "POST" },
      ),
    onSuccess: (_data, sessionId) => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "session", sessionId] });
    },
  });
}

export function useAssistChat(questionId: string) {
  return useMutation({
    mutationFn: (payload: AssistRequest) =>
      authorizedRequestJson<AssistResponse>(
        `/sbd_nfr/questions/${encodeURIComponent(questionId)}/assist`,
        {
          method: "POST",
          body: payload,
        },
      ),
  });
}

type ArtifactKind = "report/pdf" | "workbook" | "jira-draft";

export async function downloadArtifact(
  sessionId: string,
  artifact: ArtifactKind,
): Promise<void> {
  const token = await getAuthTokenStandalone();
  const path = `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/artifacts/${artifact}`;
  const payload = await requestBlob(path, { token });
  const fallbackNames: Record<ArtifactKind, string> = {
    "report/pdf": `nfr-report-${sessionId}.pdf`,
    workbook: `nfr-workbook-${sessionId}.xlsx`,
    "jira-draft": `nfr-jira-${sessionId}.txt`,
  };
  saveBlobResponse(payload, fallbackNames[artifact]);
}

// Re-export BulkAnswerRequest so hook consumers can use it without importing from types directly
export type { BulkAnswerRequest };

// ---------------------------------------------------------------------------
// Phase 145: Architect workflow hooks
// ---------------------------------------------------------------------------

export function useSubmitForReview() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ sessionId, body }: { sessionId: string; body?: SubmitForReviewRequest }) =>
      authorizedRequestJson<SessionSummaryResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/submit-for-review`,
        { method: "POST", body: body ?? {} },
      ),
    onSuccess: (_data, { sessionId }) => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "sessions"] });
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "session", sessionId] });
    },
  });
}

export function useApproveSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ sessionId, body }: { sessionId: string; body?: ApproveSessionRequest }) =>
      authorizedRequestJson<SessionSummaryResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/approve`,
        { method: "POST", body: body ?? {} },
      ),
    onSuccess: (_data, { sessionId }) => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "sessions"] });
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "session", sessionId] });
    },
  });
}

export function useSaveArchitectNotes() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ sessionId, notes }: { sessionId: string; notes: string }) =>
      authorizedRequestJson<SessionSummaryResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/architect-notes`,
        { method: "PATCH", body: { notes } satisfies ArchitectNotesRequest },
      ),
    onSuccess: (_data, { sessionId }) => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "session", sessionId] });
    },
  });
}

export function useTemplateList() {
  return useQuery({
    queryKey: ["sbd-nfr", "templates"],
    queryFn: () =>
      authorizedRequestJson<{ total: number; page: number; page_size: number; pages: number; items: SessionSummaryResponse[] }>(
        "/sbd_nfr/sessions?is_template=true&page_size=250",
      ).then((page) => page.items),
  });
}

export function useSaveAsTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ sessionId, templateName }: { sessionId: string; templateName: string }) =>
      authorizedRequestJson<SessionSummaryResponse>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/save-as-template`,
        { method: "POST", body: { template_name: templateName } satisfies SaveAsTemplateRequest },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "sessions"] });
      void queryClient.invalidateQueries({ queryKey: ["sbd-nfr", "templates"] });
    },
  });
}

export function useSessionActivity(sessionId: string) {
  return useQuery({
    queryKey: ["sbd-nfr", "activity", sessionId],
    queryFn: () =>
      authorizedRequestJson<ActivityResponse[]>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/activity`,
      ),
    enabled: Boolean(sessionId),
  });
}

// ---------------------------------------------------------------------------
// Phase 147: Report hash (EXEC-04)
// ---------------------------------------------------------------------------

export function useReportHash(sessionId: string) {
  return useQuery({
    queryKey: ["sbd-nfr", "report-hash", sessionId],
    queryFn: () =>
      authorizedRequestJson<{ data: { session_id: string; sha256: string | null; computed_at: string | null; status: string } }>(
        `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/artifacts/report/hash`,
      ).then((r) => r.data),
    enabled: Boolean(sessionId),
    staleTime: 30_000,
  });
}
