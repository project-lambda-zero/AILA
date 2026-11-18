import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LiveEventsProvider, useLiveEvents } from "./liveEvents";
import type { SseMessage, SseOpenInfo, UseSseStreamOptions } from "./sse";

const transport = vi.hoisted(() => ({
  options: null as UseSseStreamOptions | null,
}));

vi.mock("./sse", () => ({
  useSseStream: (options: UseSseStreamOptions) => {
    transport.options = options;
    return { state: "open", error: null };
  },
}));

const clients: QueryClient[] = [];

function renderLive() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <LiveEventsProvider>{children}</LiveEventsProvider>
      </QueryClientProvider>
    );
  }
  const rendered = renderHook(() => useLiveEvents(), { wrapper: Wrapper });
  return { client, ...rendered };
}

function frame(event: string, data: Record<string, unknown>): SseMessage {
  return {
    event,
    data: JSON.stringify({ timestamp: "2026-11-13T00:00:00Z", data }),
    lastEventId: "1",
  };
}

function seed(client: QueryClient, keys: readonly (readonly unknown[])[]): void {
  for (const key of keys) client.setQueryData(key, { seeded: true });
}

function isInvalidated(client: QueryClient, key: readonly unknown[]): boolean {
  return client.getQueryState(key)?.isInvalidated ?? false;
}

/** Advance past the invalidation batch window so the queued pass runs. */
function flushInvalidationWindow(ms = 300): void {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
}

const PROJECT_A = "project-aaaa1111";
const PROJECT_B = "project-bbbb2222";
const INVESTIGATION_1 = "investigation-1111";
const INVESTIGATION_2 = "investigation-2222";

const FORENSICS_KEYS = [
  ["forensics", PROJECT_A, "investigation", INVESTIGATION_1],
  ["forensics", PROJECT_A, "investigation", INVESTIGATION_2],
  ["forensics", PROJECT_A, "investigations"],
  ["forensics", PROJECT_B, "investigations"],
  ["forensics", PROJECT_A, "project"],
  ["forensics", PROJECT_B, "project"],
  ["forensics", "projects", "rail"],
] as const;

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  for (const client of clients.splice(0)) client.clear();
  transport.options = null;
  cleanup();
  vi.useRealTimers();
});

describe("LiveEventsProvider forensics invalidation", () => {
  it("invalidates the matching investigation keys across projects on an investigation event", () => {
    const { client, result } = renderLive();
    seed(client, FORENSICS_KEYS);

    act(() => {
      transport.options?.onMessage(
        frame("investigation.status_changed", {
          module: "forensics",
          investigation_id: INVESTIGATION_1,
          status: "completed",
          previous_status: "running",
        }),
      );
    });
    flushInvalidationWindow();

    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigation", INVESTIGATION_1])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigations"])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_B, "investigations"])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigation", INVESTIGATION_2])).toBe(false);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "project"])).toBe(false);
    expect(isInvalidated(client, ["forensics", "projects", "rail"])).toBe(false);
    expect(result.current.events[0]?.investigation).toEqual({
      module: "forensics",
      investigationId: INVESTIGATION_1,
      status: "completed",
      previousStatus: "running",
    });
  });

  it("invalidates one project's keys and the rail on a project status event", () => {
    const { client, result } = renderLive();
    seed(client, FORENSICS_KEYS);

    act(() => {
      transport.options?.onMessage(
        frame("project.status_changed", {
          module: "forensics",
          project_id: PROJECT_A,
          status: "analysing",
          previous_status: "draft",
        }),
      );
    });
    flushInvalidationWindow();

    expect(isInvalidated(client, ["forensics", PROJECT_A, "project"])).toBe(true);
    expect(isInvalidated(client, ["forensics", "projects", "rail"])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigations"])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_B, "project"])).toBe(false);
    expect(isInvalidated(client, ["forensics", PROJECT_B, "investigations"])).toBe(false);
    expect(result.current.events[0]?.project).toEqual({
      module: "forensics",
      projectId: PROJECT_A,
      status: "analysing",
      previousStatus: "draft",
    });
    expect(result.current.events[0]?.summary).toBe("forensics project-: draft \u2192 analysing");
  });

  it("invalidates every forensics key on reconnect", () => {
    const { client } = renderLive();
    seed(client, FORENSICS_KEYS);
    const info: SseOpenInfo = { reconnected: true };

    act(() => {
      transport.options?.onOpen?.(info);
    });

    for (const key of FORENSICS_KEYS) {
      expect(isInvalidated(client, key)).toBe(true);
    }
  });

  it("batches a burst of investigation events into one invalidation pass", () => {
    const { client } = renderLive();
    seed(client, FORENSICS_KEYS);
    const invalidate = vi.spyOn(client, "invalidateQueries");

    const ids = [INVESTIGATION_1, INVESTIGATION_2, "investigation-3333", "investigation-4444", "investigation-5555"];
    for (const id of ids) {
      act(() => {
        transport.options?.onMessage(
          frame("investigation.status_changed", {
            module: "forensics",
            investigation_id: id,
            status: "running",
            previous_status: "queued",
          }),
        );
      });
      act(() => {
        vi.advanceTimersByTime(20);
      });
    }

    expect(invalidate).not.toHaveBeenCalled();
    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigations"])).toBe(false);

    flushInvalidationWindow(200);

    expect(invalidate).toHaveBeenCalledTimes(1);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigation", INVESTIGATION_1])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigations"])).toBe(true);
    expect(isInvalidated(client, ["forensics", PROJECT_A, "project"])).toBe(false);
  });

  it("drops a queued batch when the provider unmounts before the window elapses", () => {
    const { client, unmount } = renderLive();
    seed(client, FORENSICS_KEYS);

    act(() => {
      transport.options?.onMessage(
        frame("investigation.status_changed", {
          module: "forensics",
          investigation_id: INVESTIGATION_1,
          status: "completed",
          previous_status: "running",
        }),
      );
    });
    unmount();
    flushInvalidationWindow();

    expect(isInvalidated(client, ["forensics", PROJECT_A, "investigation", INVESTIGATION_1])).toBe(false);
  });

  it("keeps the provider value identity stable across rerenders with no state change", () => {
    const { result, rerender } = renderLive();
    const first = result.current;

    rerender();

    expect(result.current).toBe(first);
  });
});

describe("LiveEventsProvider generic investigation invalidation", () => {
  it("flushes vr and malware bursts once per module and keeps their keys separate", () => {
    const { client } = renderLive();
    seed(client, [
      ["vr", "investigations"],
      ["vr", "investigation", "vr-1"],
      ["malware", "investigations"],
      ["malware", "investigation", "mal-1"],
    ]);

    act(() => {
      transport.options?.onMessage(
        frame("investigation.status_changed", {
          module: "vr",
          investigation_id: "vr-1",
          status: "completed",
          previous_status: "running",
        }),
      );
      transport.options?.onMessage(
        frame("investigation.status_changed", {
          module: "malware",
          investigation_id: "mal-2",
          status: "running",
          previous_status: "queued",
        }),
      );
    });
    expect(isInvalidated(client, ["vr", "investigations"])).toBe(false);
    flushInvalidationWindow();

    expect(isInvalidated(client, ["vr", "investigations"])).toBe(true);
    expect(isInvalidated(client, ["vr", "investigation", "vr-1"])).toBe(true);
    expect(isInvalidated(client, ["malware", "investigations"])).toBe(true);
    expect(isInvalidated(client, ["malware", "investigation", "mal-1"])).toBe(false);
  });

  it("invalidates filtered DataPage keys for the changed module", () => {
    const { client } = renderLive();
    seed(client, [
      ["datapage", "/vr/investigations", 1],
      ["datapage", "/vr/investigations?status=running", 1],
      ["datapage", "/malware/investigations", 1],
    ]);

    act(() => {
      transport.options?.onMessage(
        frame("investigation.status_changed", {
          module: "vr",
          investigation_id: "vr-1",
          status: "completed",
          previous_status: "running",
        }),
      );
    });
    flushInvalidationWindow();

    expect(isInvalidated(client, ["datapage", "/vr/investigations", 1])).toBe(true);
    expect(isInvalidated(client, ["datapage", "/vr/investigations?status=running", 1])).toBe(true);
    expect(isInvalidated(client, ["datapage", "/malware/investigations", 1])).toBe(false);
  });
});
