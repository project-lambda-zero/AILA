import { authorizedRequestJson } from "@platform/api/http";

export interface SessionRecord {
  id: string;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string | null;
  expires_at: string | null;
}

interface DataEnvelope<T> {
  data: T;
  meta?: unknown;
}

export async function fetchSessions(): Promise<SessionRecord[]> {
  const response = await authorizedRequestJson<DataEnvelope<SessionRecord[]>>(
    "/auth/sessions",
  );
  return response.data;
}

export async function revokeSession(sessionId: string): Promise<void> {
  await authorizedRequestJson<DataEnvelope<{ revoked: string }>>(
    `/auth/sessions/${sessionId}`,
    { method: "DELETE" },
  );
}
