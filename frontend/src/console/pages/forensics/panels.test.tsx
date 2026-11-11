import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { KV, StatusBadge, renderValue } from "./panels";

afterEach(() => {
  cleanup();
});

describe("forensics value rendering", () => {
  it("renders React elements directly while preserving structured object rendering", () => {
    const badge = <StatusBadge value="completed" />;

    expect(renderValue(badge)).toBe(badge);

    const { container } = render(
      <KV
        entries={[
          ["status", badge],
          ["metadata", { family: "synthetic-family" }],
        ]}
      />,
    );

    expect(screen.getByText("completed")).toBeTruthy();
    expect(screen.getByText("family")).toBeTruthy();
    expect(screen.getByText("synthetic-family")).toBeTruthy();
    expect(container.textContent).not.toContain("$$typeof");
    expect(container.textContent).not.toContain("_owner");
  });
});
