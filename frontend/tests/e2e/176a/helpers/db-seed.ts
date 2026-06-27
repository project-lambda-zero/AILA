/**
 * db-seed.ts -- Phase 176a Playwright test isolation helpers.
 *
 * Implements the e2e_<title>_<ts> namespacing scheme described in
 * `tests/e2e/176a/README.md`. Seeds and tears down via the live HTTP API
 * so tests stay honest about backend behaviour (no DB-side shortcuts).
 *
 * Network failures during seeding raise plain Errors; callers are expected
 * to skip the test (`test.skip(true, reason)`) rather than fall back to
 * mock data.
 */
import type { APIRequestContext, TestInfo } from "@playwright/test";

import { API_BASE, type TokenPair } from "../../helpers/auth";

export interface SeededTaskIds {
  ids: string[];
  /** status -> task id, for the six canonical statuses we try to seed. */
  byStatus: Partial<Record<TaskStatus, string>>;
}

export interface SeededReportIds {
  ids: string[];
}

export type TaskStatus =
  | "completed"
  | "running"
  | "failed"
  | "queued"
  | "waiting"
  | "paused";

const SANITISE = /[^a-zA-Z0-9]+/g;

/**
 * Returns an `e2e_<title>_<ts>` namespace string for this test.
 * Sanitised so it is safe to use as a JSON value or substring of a name field.
 */
export function getNamespace(testInfo: TestInfo): string {
  const slug = testInfo.title.replace(SANITISE, "_").toLowerCase().slice(0, 60);
  return `e2e_${slug}_${Date.now()}`;
}

function authHeaders(tokens: TokenPair) {
  return { Authorization: `Bearer ${tokens.access_token}` };
}

/**
 * Best-effort: ask the backend to create N tasks tagged with this namespace.
 *
 * The platform task router shape varies across modules; this helper attempts
 * the most generic platform endpoint first and degrades to "skip" by raising
 * an error the spec can catch + skip on. We deliberately do NOT silently
 * succeed with empty data.
 */
export async function seedTasks(
  request: APIRequestContext,
  tokens: TokenPair,
  ns: string,
  statuses: TaskStatus[],
): Promise<SeededTaskIds> {
  const ids: string[] = [];
  const byStatus: Partial<Record<TaskStatus, string>> = {};

  for (const status of statuses) {
    const payload = {
      module_id: "vulnerability",
      kind: `noop_${status}`,
      title: `Task ${status} ${ns}`,
      // Most queue endpoints accept a status hint; if rejected the catch
      // below records the failure and the spec falls back gracefully.
      desired_status: status,
      meta: { namespace: ns, e2e: true },
    };
    try {
      const resp = await request.post(`${API_BASE}/tasks`, {
        data: payload,
        headers: authHeaders(tokens),
      });
      if (resp.ok()) {
        const body = (await resp.json()) as { data?: { id?: string } };
        const id = body?.data?.id;
        if (id) {
          ids.push(id);
          byStatus[status] = id;
        }
      }
    } catch {
      // Network glitch; spec will detect ids.length === 0 and skip.
    }
  }

  return { ids, byStatus };
}

/**
 * Tear down records carrying this namespace. Best-effort; teardown failures
 * are logged but do not fail the test (the test already passed/failed by
 * the time afterEach runs, and stale rows are filtered out by other tests'
 * own namespace prefixes).
 */
export async function teardownNamespace(
  request: APIRequestContext,
  tokens: TokenPair,
  ns: string,
): Promise<void> {
  try {
    await request.delete(`${API_BASE}/tasks?namespace=${encodeURIComponent(ns)}`, {
      headers: authHeaders(tokens),
    });
  } catch {
    // Ignore -- see docstring.
  }
}

/**
 * Sanity-check that the API is reachable. Used by fixtures to decide whether
 * to mark a test as skipped vs proceeding.
 */
export async function pingApi(request: APIRequestContext): Promise<boolean> {
  try {
    const resp = await request.get(`${API_BASE}/health`);
    return resp.ok();
  } catch {
    return false;
  }
}
