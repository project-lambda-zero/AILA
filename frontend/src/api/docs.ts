/**
 * Docs page API hooks -- read-only fetch of the platform docs corpus.
 *
 * Backend contract (aila.api.routers.docs):
 *   GET /docs/topics             -> DataEnvelope[list[DocTopic]]
 *   GET /docs/topics/{slug}      -> DataEnvelope[DocTopicBody]
 *
 * apiFetch<T> unwraps the DataEnvelope envelope, so the resolved types are
 * the payload directly. useDocTopic is disabled until a slug is supplied so
 * the initial mount does not fire a bare /docs/topics/null request.
 */

import { useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

export interface DocTopic {
  slug: string;
  title: string;
}

export interface DocTopicBody {
  slug: string;
  title: string;
  body: string;
}

export function useDocTopics(): UseQueryResult<DocTopic[]> {
  return useQuery({
    queryKey: ["docs", "topics"],
    queryFn: () => apiFetch<DocTopic[]>("/docs/topics"),
  });
}

export function useDocTopic(slug: string | null): UseQueryResult<DocTopicBody> {
  return useQuery({
    queryKey: ["docs", "topic", slug],
    queryFn: () => apiFetch<DocTopicBody>(`/docs/topics/${slug ?? ""}`),
    enabled: !!slug,
  });
}
