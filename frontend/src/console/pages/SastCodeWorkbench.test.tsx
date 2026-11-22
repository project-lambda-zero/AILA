import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import SastCodeWorkbench from "./SastCodeWorkbench";
import type { SastDiagnostic } from "./SastAuditResults";

const probe = vi.hoisted(() => ({
  markers: [] as Array<Record<string, unknown>>,
  reveals: [] as Array<Record<string, unknown>>,
  selections: [] as Array<Record<string, unknown>>,
  model: null as null | {
    uri: { toString: () => string };
    getLineCount: () => number;
    getLineMaxColumn: (line: number) => number;
    dispose: () => void;
  },
}));

vi.mock("monaco-editor", () => ({
  MarkerSeverity: { Hint: 1, Info: 2, Warning: 4, Error: 8 },
  editor: {
    setModelMarkers: (_model: unknown, _owner: string, markers: Array<Record<string, unknown>>) => { probe.markers = markers; },
    getModels: () => probe.model ? [probe.model] : [],
  },
}));

vi.mock("@monaco-editor/react", async () => {
  const { createElement, useEffect, useRef } = await import("react");
  const monaco = await import("monaco-editor");
  return {
    loader: { config: () => undefined },
    default: ({ path, value, onMount }: { path: string; value: string; onMount: (editor: unknown, api: unknown) => void }) => {
      const mountRef = useRef(onMount);
      mountRef.current = onMount;
      useEffect(() => {
        const model = {
          uri: { toString: () => path },
          getLineCount: () => 2,
          getLineMaxColumn: () => 80,
          dispose: vi.fn(),
        };
        probe.model = model;
        const editor = {
          getModel: () => model,
          revealRangeInCenter: (range: Record<string, unknown>) => { probe.reveals.push(range); },
          setSelection: (range: Record<string, unknown>) => { probe.selections.push(range); },
          focus: vi.fn(),
        };
        mountRef.current(editor, monaco);
      }, [path, value]);
      return createElement("div", { "data-testid": "monaco-source" }, value);
    },
  };
});

const diagnostics: SastDiagnostic[] = [{
  id: "outcome-1:0",
  skillId: "sast-sqli",
  investigationId: "inv-sqli",
  outcomeId: "outcome-1",
  message: "User input reaches SQL query",
  description: "Concatenated query text is executable SQL.",
  severity: "high",
  confidence: "high",
  path: "src/app.py",
  lineStart: 2,
  lineEnd: 2,
  columnStart: 10,
  columnEnd: 20,
  relatedLocations: [{ path: "src/app.py", lineStart: 1, lineEnd: 1, columnStart: null, columnEnd: null }],
}, {
  id: "outcome-2:0",
  skillId: "sast-missingauth",
  investigationId: "inv-auth",
  outcomeId: "outcome-2",
  message: "Authorization review needs manual confirmation",
  description: "No verified coordinate was persisted.",
  severity: "medium",
  confidence: "low",
  path: null,
  lineStart: null,
  lineEnd: null,
  columnStart: null,
  columnEnd: null,
  relatedLocations: [],
}];

function json(data: unknown): Response {
  return new Response(JSON.stringify({ data, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
}

beforeEach(() => {
  probe.markers = [];
  probe.reveals = [];
  probe.selections = [];
  probe.model = null;
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/sast-audit-files")) return json({
      complete: true,
      files: [{ path: "src/app.py", language: "python", diagnostic_count: 1 }],
    });
    if (url.pathname.endsWith("/sast-audit-source")) {
      expect(url.searchParams.get("path")).toBe("src/app.py");
      return json({ path: "src/app.py", content: "def handle(request):\n    return query(request)\n", language: "python", total_lines: 2, truncated: false });
    }
    throw new Error(`Unexpected ${url.pathname}`);
  }));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("SastCodeWorkbench", () => {
  it("loads clicked files and navigates exact markers without inventing unlocated ones", async () => {
    const onClose = vi.fn();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><SastCodeWorkbench targetId="target-1" auditId="audit-1" diagnostics={diagnostics} onClose={onClose} /></QueryClientProvider>);

    expect(await screen.findByText(/def handle/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /User input reaches SQL query/ }));
    await waitFor(() => expect(probe.reveals.at(-1)).toMatchObject({ startLineNumber: 2, startColumn: 10, endColumn: 20 }));
    expect(probe.selections.at(-1)).toMatchObject({ startLineNumber: 2, endLineNumber: 2 });
    await waitFor(() => expect(probe.markers).toHaveLength(1));
    expect(probe.markers[0]).toMatchObject({ startLineNumber: 2, startColumn: 10, source: "AILA SAST" });

    fireEvent.click(screen.getByRole("button", { name: "src/app.py:1" }));
    await waitFor(() => expect(probe.reveals.at(-1)).toMatchObject({ startLineNumber: 1 }));

    const revealCount = probe.reveals.length;
    fireEvent.click(screen.getByRole("button", { name: /Authorization review needs manual confirmation/ }));
    expect(await screen.findByText(/no verified source coordinate/i)).toBeTruthy();
    expect(probe.reveals).toHaveLength(revealCount);
    expect(probe.markers).toHaveLength(1);

    fireEvent.change(screen.getByLabelText("Filter repository files"), { target: { value: "no-match" } });
    expect(screen.getByText("No source files match.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledOnce();
  });
});
