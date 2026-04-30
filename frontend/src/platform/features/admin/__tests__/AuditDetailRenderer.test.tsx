/**
 * AuditDetailRenderer tests (Plan 176e P1).
 *
 * Verifies the rendering rules described in the component header:
 *   - top-level primitives render as label: value rows
 *   - nested objects render in <details>/<summary>
 *   - arrays render as bullet lists
 *   - long strings get a Copy button
 *   - UUIDs render monospace with a Copy button
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { AuditDetailRenderer } from "../AuditDetailRenderer";

beforeAll(() => {
  // jsdom does not implement clipboard.writeText by default.
  Object.assign(navigator, {
    clipboard: {
      writeText: vi.fn().mockResolvedValue(undefined),
    },
  });
});

describe("AuditDetailRenderer", () => {
  it("renders flat primitives as label/value rows", () => {
    render(
      <AuditDetailRenderer
        details={{
          host: "web01",
          attempts: 3,
          succeeded: true,
        }}
      />,
    );
    expect(screen.getByText("host")).toBeTruthy();
    expect(screen.getByText("web01")).toBeTruthy();
    expect(screen.getByText("attempts")).toBeTruthy();
    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getByText("succeeded")).toBeTruthy();
    // boolean true renders as the string "true"
    expect(screen.getByText("true")).toBeTruthy();
  });

  it("renders nested objects inside <details>/<summary>", () => {
    render(
      <AuditDetailRenderer
        details={{
          request: {
            method: "POST",
            path: "/scan",
          },
        }}
      />,
    );
    const summary = screen.getByText(/request/i, { selector: "summary" });
    expect(summary).toBeTruthy();
    // Nested primitives are present when the details element is open (depth=0).
    expect(screen.getByText("method")).toBeTruthy();
    expect(screen.getByText("POST")).toBeTruthy();
  });

  it("renders arrays as bullet lists", () => {
    const { container } = render(
      <AuditDetailRenderer details={{ items: ["a", "b", "c"] }} />,
    );
    // Nested object summary for `items` container + ul inside.
    const ul = container.querySelector("ul");
    expect(ul).toBeTruthy();
    expect(ul!.querySelectorAll("li").length).toBe(3);
  });

  it("shows Copy button for long strings", () => {
    const long = "x".repeat(120);
    render(<AuditDetailRenderer details={{ note: long }} />);
    const copyBtn = screen.getByLabelText("Copy note");
    expect(copyBtn).toBeTruthy();
    fireEvent.click(copyBtn);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(long);
  });

  it("shows Copy button for UUID-shaped values", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    render(<AuditDetailRenderer details={{ run_id: uuid }} />);
    const copyBtn = screen.getByLabelText("Copy run_id");
    expect(copyBtn).toBeTruthy();
  });

  it("formats ISO timestamp strings to local time", () => {
    const iso = "2025-01-15T12:34:56Z";
    render(<AuditDetailRenderer details={{ when: iso }} />);
    const expected = new Date(iso).toLocaleString();
    expect(screen.getByText(expected)).toBeTruthy();
  });

  it("renders empty placeholder for null details", () => {
    render(<AuditDetailRenderer details={null} />);
    expect(screen.getByText(/no details captured/i)).toBeTruthy();
  });

  it("renders empty placeholder for empty object", () => {
    render(<AuditDetailRenderer details={{}} />);
    expect(screen.getByText(/empty object/i)).toBeTruthy();
  });
});
