import { useRef } from "react";

import { useWizardSchema, useWizardSessionDetail } from "../../queries";
import type { SchemaTreeResponse, SessionDetailResponse } from "../../types";

export interface WizardSessionResult {
  schema: SchemaTreeResponse | undefined;
  session: SessionDetailResponse | undefined;
  isLoading: boolean;
  isError: boolean;
  /** Schema version pinned at the moment this session's schema first loaded. */
  pinnedSchemaVersion: number | null;
  /** True when the current schema version differs from what this session was created with. */
  schemaDrifted: boolean;
}

/**
 * Combined data-loading hook for the NFR wizard (Pattern 2, RESEARCH.md).
 *
 * Fires both queries in parallel — TanStack Query v5 naturally runs separate
 * useQuery calls concurrently.  Schema is stale-timed at 5 min (rarely changes);
 * session query is enabled only when sessionId is non-empty.
 *
 * Schema version pinning (WIZ-05): pinnedVersion is captured on first successful
 * schema load via useRef. If the schema is republished while a user is mid-assessment,
 * subsequent refetches may return a new schema_version. schemaDrifted detects this
 * condition so the caller can warn the user without interrupting the session.
 */
export function useWizardSession(sessionId: string): WizardSessionResult {
  const schemaQuery = useWizardSchema();
  const sessionQuery = useWizardSessionDetail(sessionId);

  // Pin the schema version on first successful load.
  // useRef persists across renders without triggering re-render.
  const pinnedVersion = useRef<number | null>(null);
  if (schemaQuery.data && pinnedVersion.current === null) {
    pinnedVersion.current = schemaQuery.data.schema_version;
  }

  const sessionSchemaVersion = sessionQuery.data?.schema_version ?? null;
  const currentSchemaVersion = schemaQuery.data?.schema_version ?? null;

  // Drifted = session was created with a different version than what the API now returns.
  // This can happen if schema is republished while user is mid-assessment.
  const schemaDrifted =
    sessionSchemaVersion !== null &&
    currentSchemaVersion !== null &&
    sessionSchemaVersion !== currentSchemaVersion;

  return {
    schema: schemaQuery.data,
    session: sessionQuery.data,
    isLoading: schemaQuery.isLoading || sessionQuery.isLoading,
    isError: schemaQuery.isError || sessionQuery.isError,
    pinnedSchemaVersion: pinnedVersion.current,
    schemaDrifted,
  };
}
