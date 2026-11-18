// @vitest-environment jsdom
/** ConsoleWindow body error boundary: a throwing body is contained to its own
 * window, the footer controls stay reachable, Retry re-renders the body, and a
 * suspended body is left to the surrounding Suspense boundary. */

import { Suspense } from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConsoleWindow from "./ConsoleWindow";

const FALLBACK = "this view failed to render";

function Boom(): never {
  throw new Error("boom");
}

function Healthy({ label }: { label: string }) {
  return <div>{label}</div>;
}

function windowProps(id: string) {
  return {
    id,
    title: id,
    kind: "page" as const,
    onClose: vi.fn(),
    onMinimize: vi.fn(),
  };
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("ConsoleWindow body error boundary", () => {
  it("shows the fallback and keeps the footer close control reachable when the body throws", () => {
    const props = windowProps("throwing");
    render(
      <ConsoleWindow {...props}>
        <Boom />
      </ConsoleWindow>,
    );

    expect(screen.getByText(FALLBACK)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();

    fireEvent.click(screen.getByTitle("close"));
    expect(props.onClose).toHaveBeenCalledTimes(1);
  });

  it("leaves a sibling window mounted when the other window's body throws", () => {
    render(
      <>
        <ConsoleWindow {...windowProps("broken")}>
          <Boom />
        </ConsoleWindow>
        <ConsoleWindow {...windowProps("healthy")}>
          <Healthy label="still rendering" />
        </ConsoleWindow>
      </>,
    );

    expect(screen.getByText(FALLBACK)).toBeTruthy();
    expect(screen.getByText("still rendering")).toBeTruthy();
  });

  it("re-renders the body when Retry is pressed after the throw condition clears", () => {
    let shouldThrow = true;
    function Flaky() {
      if (shouldThrow) throw new Error("boom");
      return <Healthy label="recovered" />;
    }
    render(
      <ConsoleWindow {...windowProps("flaky")}>
        <Flaky />
      </ConsoleWindow>,
    );
    expect(screen.getByText(FALLBACK)).toBeTruthy();

    shouldThrow = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(screen.queryByText(FALLBACK)).toBeNull();
    expect(screen.getByText("recovered")).toBeTruthy();
  });

  it("leaves a suspended body to the outer Suspense boundary instead of the error fallback", async () => {
    let resolveGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      resolveGate = resolve;
    });
    let resolved = false;
    function Lazy() {
      if (!resolved) throw gate;
      return <Healthy label="resolved" />;
    }
    render(
      <Suspense fallback={<div>loading body</div>}>
        <ConsoleWindow {...windowProps("suspending")}>
          <Lazy />
        </ConsoleWindow>
      </Suspense>,
    );

    expect(screen.getByText("loading body")).toBeTruthy();
    expect(screen.queryByText(FALLBACK)).toBeNull();

    resolved = true;
    await act(async () => {
      resolveGate();
    });

    expect(screen.getByText("resolved")).toBeTruthy();
    expect(screen.queryByText(FALLBACK)).toBeNull();
  });
});
