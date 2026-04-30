import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { DocsPage } from "@app/screens/DocsPage";

describe("DocsPage", () => {
  it("renders the five canonical H2 section headings", () => {
    render(<DocsPage />);

    const required = [
      "What this tool does",
      "How to register a system",
      "How to run a scan",
      "How to read results",
      "Where to set the API key",
    ];

    for (const heading of required) {
      expect(
        screen.getByRole("heading", { level: 2, name: heading }),
      ).toBeInTheDocument();
    }
  });

  it("is not a README dump or old onboarding verbatim", () => {
    const { container } = render(<DocsPage />);
    const text = container.textContent ?? "";

    // Markers that would indicate a README dump.
    expect(text).not.toMatch(/^# AILA/m);
    expect(text).not.toMatch(/README/i);
  });
});
