import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { Suspense } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Synthetic code fixture; no real artifact content.
const CODE = "def score(x):\n    return x * 2\n";

const probe = vi.hoisted(() => ({ monacoEvaluations: 0, editorFails: false }));

// Monaco cannot run under jsdom. These doubles stand in at the package boundary:
// evaluation of the monaco-editor module is counted, and the editor stub can be
// told to fail on initialisation the way a broken Monaco install would.
vi.mock("monaco-editor", () => {
  probe.monacoEvaluations += 1;

  return {};
});

vi.mock("@monaco-editor/react", async () => {
  // vi.mock factories are hoisted above the file's imports, so React is loaded inside the factory.
  const { createElement } = await import("react");

  return {
    loader: { config: () => undefined },
    default: ({ value }: { value: string }) => {
      if (probe.editorFails) throw new Error("monaco initialisation failed");

      return createElement("div", { "data-testid": "monaco-editor" }, value);
    },
  };
});

beforeEach(() => {
  vi.resetModules();
  probe.monacoEvaluations = 0;
  probe.editorFails = false;
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("LazyCodeBlock", () => {
  it("loads Monaco only when a code surface renders and shows the code in it", async () => {
    // Dynamic import after vi.resetModules(): this test exercises the module-loading boundary,
    // and a static import would share one module graph across tests, so the count would not start at zero.
    const { LazyCodeBlock } = await import("./xray/LazyCode");
    expect(probe.monacoEvaluations).toBe(0);

    render(
      <Suspense fallback={null}>
        <LazyCodeBlock code={CODE} language="python" />
      </Suspense>,
    );

    const editor = await screen.findByTestId("monaco-editor");
    expect(editor.textContent).toBe(CODE);
    expect(probe.monacoEvaluations).toBe(1);
  });

  it("keeps the code readable when the editor fails to initialise", async () => {
    probe.editorFails = true;
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    // Dynamic import for the same reason as the previous test: each test loads a fresh module graph.
    const { LazyCodeBlock } = await import("./xray/LazyCode");

    const { container } = render(
      <Suspense fallback={null}>
        <LazyCodeBlock code={CODE} language="python" />
      </Suspense>,
    );

    await waitFor(() => expect(container.querySelector("pre")?.textContent).toBe(CODE));
  });
});
