/**
 * useChartExport.test.ts -- unit tests for the useChartExport hook.
 *
 * Tests state machine transitions: initial state, null element error,
 * isExporting lifecycle, and SVG-not-found error.
 *
 * html2canvas is mocked to avoid DOM canvas operations in jsdom.
 */
import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock html2canvas before importing the hook
vi.mock("html2canvas", () => ({
  default: vi.fn().mockResolvedValue({
    toDataURL: vi.fn().mockReturnValue("data:image/png;base64,abc123"),
  }),
}));

import { useChartExport } from "./useChartExport";

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

function makeDiv(): HTMLDivElement {
  const div = document.createElement("div");
  document.body.appendChild(div);
  return div;
}

function makeContainerWithSvg(): HTMLDivElement {
  const div = document.createElement("div");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  div.appendChild(svg);
  document.body.appendChild(div);
  return div;
}

describe("useChartExport", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clean up any appended elements
    document.body.innerHTML = "";
  });

  it("initial state: isExporting=false, error=null", () => {
    const { result } = renderHook(() => useChartExport());
    expect(result.current.isExporting).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("sets error when element is null", async () => {
    const { result } = renderHook(() => useChartExport());

    await act(async () => {
      await result.current.exportChart(null, "test-chart", "png");
    });

    expect(result.current.error).toBe("No chart element to export.");
    expect(result.current.isExporting).toBe(false);
  });

  it("sets error when no SVG found in container for svg format", async () => {
    const { result } = renderHook(() => useChartExport());
    const divWithoutSvg = makeDiv();

    await act(async () => {
      await result.current.exportChart(divWithoutSvg, "test-chart", "svg");
    });

    expect(result.current.error).toBe("No SVG found in chart. Use PNG export instead.");
    expect(result.current.isExporting).toBe(false);
  });

  it("clears error from previous failure on next successful call", async () => {
    const { result } = renderHook(() => useChartExport());

    // First call: null element → sets error
    await act(async () => {
      await result.current.exportChart(null, "test", "png");
    });
    expect(result.current.error).not.toBeNull();

    // Second call: null again → error replaced (not stacked)
    await act(async () => {
      await result.current.exportChart(null, "test", "png");
    });
    expect(result.current.error).toBe("No chart element to export.");
  });

  it("isExporting returns to false after completion (null element path)", async () => {
    const { result } = renderHook(() => useChartExport());

    await act(async () => {
      await result.current.exportChart(null, "test", "png");
    });

    // After rejection, isExporting must reset to false
    expect(result.current.isExporting).toBe(false);
  });

  it("calls html2canvas for png export when element is provided", async () => {
    const html2canvas = (await import("html2canvas")).default;
    const { result } = renderHook(() => useChartExport());

    // Mock link click to avoid jsdom navigation errors
    const linkClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    const container = makeDiv();
    await act(async () => {
      await result.current.exportChart(container, "my-chart", "png");
    });

    expect(html2canvas).toHaveBeenCalledWith(container, expect.objectContaining({ scale: 2 }));
    expect(result.current.error).toBeNull();
    expect(result.current.isExporting).toBe(false);

    linkClickSpy.mockRestore();
  });

  it("svg export succeeds when container has an SVG child", async () => {
    const { result } = renderHook(() => useChartExport());
    const container = makeContainerWithSvg();

    const linkClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    // URL.createObjectURL is not in jsdom -- stub it
    const createObjectURL = vi.fn().mockReturnValue("blob:mock-url");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL });

    await act(async () => {
      await result.current.exportChart(container, "svg-chart", "svg");
    });

    expect(result.current.error).toBeNull();
    expect(result.current.isExporting).toBe(false);
    expect(createObjectURL).toHaveBeenCalled();

    linkClickSpy.mockRestore();
    vi.unstubAllGlobals();
  });
});
