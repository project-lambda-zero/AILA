import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import type { ReactElement } from "react";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { useState } from "react";

import { AppErrorBoundary } from "@app/ErrorBoundary";

function Thrower({
  message = "boom",
  attachTraceId,
}: {
  message?: string;
  attachTraceId?: string;
}): ReactElement {
  const err = new Error(message);
  if (attachTraceId) {
    (err as unknown as { trace_id: string }).trace_id = attachTraceId;
  }
  throw err;
}

describe("AppErrorBoundary", () => {
  // Silence React's error-boundary noisy console.error inside the test block.
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("catches render errors and shows fallback (shell does not propagate)", () => {
    render(
      <MemoryRouter>
        <AppErrorBoundary>
          <Thrower message="boom-message" />
        </AppErrorBoundary>
      </MemoryRouter>,
    );

    expect(screen.getByTestId("app-error-boundary-fallback")).toBeInTheDocument();
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(screen.getByText(/boom-message/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reload/i })).toBeInTheDocument();
  });

  it("shows trace_id when the caught error has one", () => {
    render(
      <MemoryRouter>
        <AppErrorBoundary>
          <Thrower attachTraceId="abc-123-trace" />
        </AppErrorBoundary>
      </MemoryRouter>,
    );

    expect(screen.getByText(/trace_id:/i)).toBeInTheDocument();
    expect(screen.getByText("abc-123-trace")).toBeInTheDocument();
  });

  it("shows a current timestamp when no trace_id is attached (D-26)", () => {
    render(
      <MemoryRouter>
        <AppErrorBoundary>
          <Thrower message="no-trace" />
        </AppErrorBoundary>
      </MemoryRouter>,
    );

    const ts = screen.queryByText(/Timestamp:/i);
    expect(ts).not.toBeNull();
    // Surfaced timestamp is an ISO string from this run.
    const isoRegex = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
    const container = ts!.parentElement!;
    expect(container.textContent ?? "").toMatch(isoRegex);
  });

  it("never exposes error.stack in the rendered UI", () => {
    render(
      <MemoryRouter>
        <AppErrorBoundary>
          <Thrower message="renderable" />
        </AppErrorBoundary>
      </MemoryRouter>,
    );

    // Stack traces include function-call frames ("at ") — they must not be in the DOM.
    const fallback = screen.getByTestId("app-error-boundary-fallback");
    expect(fallback.textContent ?? "").not.toMatch(/\n\s+at\s/);
  });

  it("timestamp is stable across re-renders (C1)", () => {
    // A parent with its own state can force the boundary to re-render after
    // the error has been caught. The displayed timestamp must not drift.
    let forceRerender: (n: number) => void = () => {};

    function Parent() {
      const [n, setN] = useState(0);
      forceRerender = setN;
      return (
        <AppErrorBoundary>
          <Thrower message={`boom-${n}`} />
        </AppErrorBoundary>
      );
    }

    const { rerender } = render(
      <MemoryRouter>
        <Parent />
      </MemoryRouter>,
    );

    const first = screen.getByTestId("app-error-boundary-fallback").textContent ?? "";
    const firstMatch = first.match(
      /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z/,
    );
    expect(firstMatch).not.toBeNull();

    // Force several re-renders — any new Date().toISOString() call in render()
    // would surface a new timestamp.
    forceRerender(1);
    rerender(
      <MemoryRouter>
        <Parent />
      </MemoryRouter>,
    );

    const second = screen.getByTestId("app-error-boundary-fallback").textContent ?? "";
    const secondMatch = second.match(
      /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z/,
    );
    expect(secondMatch).not.toBeNull();
    expect(secondMatch![0]).toBe(firstMatch![0]);
  });
});
