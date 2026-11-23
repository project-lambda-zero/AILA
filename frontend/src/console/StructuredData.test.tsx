import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { structuredSummary, StructuredData } from "./StructuredData";

afterEach(cleanup);

describe("StructuredData", () => {
  it("renders nested objects and arrays as labeled fields instead of JSON", () => {
    render(<StructuredData label="Execution details" value={{
      max_requests: 10,
      verified: true,
      evidence: [{ id: "evidence-1", quote: "response contained the marker" }],
    }} />);

    expect(screen.getByLabelText("Execution details")).toBeTruthy();
    expect(screen.getByText("max requests")).toBeTruthy();
    expect(screen.getByText("10")).toBeTruthy();
    expect(screen.getByText("Yes")).toBeTruthy();
    expect(screen.getByText("evidence-1")).toBeTruthy();
    expect(screen.getByText("response contained the marker")).toBeTruthy();
  });

  it("derives concise trace summaries from actual fields", () => {
    expect(structuredSummary({ title: "Authentication bypass" })).toBe("Authentication bypass");
    expect(structuredSummary({ content: { nested: true } })).toBe("1 fields");
    expect(structuredSummary(["one", "two"])).toBe("2 items");
  });
});
