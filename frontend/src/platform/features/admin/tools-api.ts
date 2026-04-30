/**
 * API layer for the Admin Tools Console (/admin/tools).
 *
 * Uses authorizedRequestJson<T> exclusively — no raw fetch, no hardcoded /api/ paths.
 * Every call has an explicit type parameter (honesty rule 11).
 */

import { authorizedRequestJson } from "@platform/api/http";
import type { ToolDetail, ToolInvokeResponse, ToolSummary } from "./tools-types";

export async function fetchToolsList(): Promise<ToolSummary[]> {
  return authorizedRequestJson<ToolSummary[]>("/tools", { method: "GET" });
}

export async function fetchToolDetail(toolKey: string): Promise<ToolDetail> {
  return authorizedRequestJson<ToolDetail>(
    `/tools/${encodeURIComponent(toolKey)}`,
    { method: "GET" },
  );
}

export async function invokeTool(
  toolKey: string,
  kwargs: Record<string, unknown>,
): Promise<ToolInvokeResponse> {
  return authorizedRequestJson<ToolInvokeResponse>(
    `/tools/${encodeURIComponent(toolKey)}`,
    {
      method: "POST",
      body: JSON.stringify({ kwargs }),
    },
  );
}
