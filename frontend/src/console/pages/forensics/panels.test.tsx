import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { KV, StatusBadge, renderValue } from "./panels";

const REACT_INTERNALS = ["$$typeof", "_owner", "_store"];

afterEach(cleanup);

describe("renderValue", () => {
  it("returns a React element as-is instead of rendering its internals", () => {
    const badge = <StatusBadge value="failed" />;

    expect(renderValue(badge)).toBe(badge);
  });

  it("renders a React element's visible output, not its internal fields", () => {
    const { container } = render(<>{renderValue(<StatusBadge value="failed" />)}</>);

    expect(screen.getByText("failed")).toBeTruthy();
    for (const marker of REACT_INTERNALS) {
      expect(container.textContent).not.toContain(marker);
    }
  });

  it("keeps plain objects on the structured path", () => {
    const owner = { owner: "ops", retries: 2 };
    const rendered = renderValue(owner);

    expect(rendered).not.toBe(owner);
    render(<>{rendered}</>);
    expect(screen.getByText("ops")).toBeTruthy();
  });

  it("renders empty values as an em dash", () => {
    const { rerender } = render(<>{renderValue(null)}</>);
    expect(screen.getByText("\u2014")).toBeTruthy();

    rerender(<>{renderValue(undefined)}</>);
    expect(screen.getByText("\u2014")).toBeTruthy();

    rerender(<>{renderValue("")}</>);
    expect(screen.getByText("\u2014")).toBeTruthy();
  });

  it("renders booleans, numbers, and strings as text", () => {
    const { rerender, container } = render(<>{renderValue(false)}</>);
    expect(container.textContent).toBe("false");

    rerender(<>{renderValue(0)}</>);
    expect(container.textContent).toBe("0");

    rerender(<>{renderValue("plain")}</>);
    expect(container.textContent).toBe("plain");
  });
});

describe("KV", () => {
  it("renders a status badge entry alongside structured and scalar entries", () => {
    const { container } = render(
      <KV
        entries={[
          ["status", <StatusBadge value="failed" key="s" />],
          ["owner", { name: "ops", retries: 2 }],
          ["count", 3],
          ["flag", true],
          ["note", "hello"],
          ["missing", null],
        ]}
      />,
    );

    expect(screen.getByText("failed")).toBeTruthy();
    expect(screen.getByText("name")).toBeTruthy();
    expect(screen.getByText("ops")).toBeTruthy();
    expect(screen.getByText("hello")).toBeTruthy();
    expect(screen.getByText("\u2014")).toBeTruthy();
    for (const marker of REACT_INTERNALS) {
      expect(container.textContent).not.toContain(marker);
    }
  });
});
