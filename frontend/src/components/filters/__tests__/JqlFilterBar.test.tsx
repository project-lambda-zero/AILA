/**
 * JqlFilterBar tests (Plan 176e).
 *
 * Covers:
 *  - parseFilterToken() handles `field:value`, `field>num`, `field<num`,
 *    plain-text fallback, and empty input.
 *  - filtersToQueryParams() maps operators to backend keys.
 *  - The rendered bar adds chips on Enter, clears on X, and supports
 *    Backspace-on-empty to remove the last chip.
 *  - URL sync writes `?f=` params when urlSync is enabled.
 */
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, useSearchParams } from "react-router";
import { useState } from "react";

import {
  JqlFilterBar,
  parseFilterToken,
  filtersToQueryParams,
  type JqlFieldSpec,
  type JqlFilter,
} from "../JqlFilterBar";

const FIELDS: JqlFieldSpec[] = [
  { key: "module", label: "Module", operators: [":"] },
  { key: "cost", label: "Cost", operators: [">", "<"] },
  { key: "search", label: "Search", operators: [":"] },
];

describe("parseFilterToken", () => {
  it("parses field:value", () => {
    expect(parseFilterToken("module:vulnerability")).toEqual({
      field: "module",
      operator: ":",
      value: "vulnerability",
    });
  });

  it("parses field>num (first operator only)", () => {
    expect(parseFilterToken("cost>0.5")).toEqual({
      field: "cost",
      operator: ">",
      value: "0.5",
    });
  });

  it("parses field<num", () => {
    expect(parseFilterToken("cost<1")).toEqual({
      field: "cost",
      operator: "<",
      value: "1",
    });
  });

  it("falls back to search for plain text", () => {
    expect(parseFilterToken("error occurred")).toEqual({
      field: "search",
      operator: ":",
      value: "error occurred",
    });
  });

  it("returns null for empty input", () => {
    expect(parseFilterToken("   ")).toBeNull();
    expect(parseFilterToken("")).toBeNull();
  });

  it("returns null when value after op is empty", () => {
    expect(parseFilterToken("module:")).toBeNull();
  });
});

describe("filtersToQueryParams", () => {
  it("maps `:` to direct key", () => {
    const params = filtersToQueryParams([
      { field: "module", operator: ":", value: "vuln" },
    ]);
    expect(params).toEqual({ module: "vuln" });
  });

  it("maps `>` to min_{field} and `<` to max_{field}", () => {
    const params = filtersToQueryParams([
      { field: "cost", operator: ">", value: "0.5" },
      { field: "cost", operator: "<", value: "10" },
    ]);
    expect(params).toEqual({ min_cost: "0.5", max_cost: "10" });
  });

  it("collapses multiple same-key chips via comma-OR", () => {
    const params = filtersToQueryParams([
      { field: "stage", operator: ":", value: "ssh" },
      { field: "stage", operator: ":", value: "scan" },
    ]);
    expect(params).toEqual({ stage: "ssh,scan" });
  });
});

function Harness({
  onChangeSpy,
  initialUrl = "/",
}: {
  onChangeSpy: (f: JqlFilter[]) => void;
  initialUrl?: string;
}) {
  return (
    <MemoryRouter initialEntries={[initialUrl]}>
      <JqlFilterBar fields={FIELDS} onChange={onChangeSpy} />
      <UrlProbe />
    </MemoryRouter>
  );
}

function UrlProbe() {
  const [params] = useSearchParams();
  const all = params.getAll("f");
  return (
    <ul data-testid="url-probe">
      {all.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  );
}

describe("<JqlFilterBar>", () => {
  it("adds a chip on Enter", () => {
    const seen: JqlFilter[][] = [];
    render(<Harness onChangeSpy={(f) => seen.push(f)} />);

    const input = screen.getByLabelText("Add filter") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "module:vulnerability" } });
    fireEvent.keyDown(input, { key: "Enter" });

    // Chip renders at least once (text may also appear as a child of the
    // remove-button aria-label -- we just need to confirm it was added).
    expect(screen.getAllByText("module:vulnerability").length).toBeGreaterThan(0);
    const last = seen[seen.length - 1];
    expect(last).toEqual([
      { field: "module", operator: ":", value: "vulnerability" },
    ]);
  });

  it("removes the last chip with backspace on empty input", () => {
    const seen: JqlFilter[][] = [];
    render(<Harness onChangeSpy={(f) => seen.push(f)} />);

    const input = screen.getByLabelText("Add filter") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "module:vuln" } });
    fireEvent.keyDown(input, { key: "Enter" });
    fireEvent.keyDown(input, { key: "Backspace" });

    const last = seen[seen.length - 1];
    expect(last).toEqual([]);
  });

  it("syncs URL ?f= params when a chip is added", () => {
    render(<Harness onChangeSpy={() => {}} />);

    const input = screen.getByLabelText("Add filter") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "cost>0.5" } });
    fireEvent.keyDown(input, { key: "Enter" });

    const probe = screen.getByTestId("url-probe");
    expect(probe.textContent).toContain("cost>0.5");
  });

  it("hydrates from existing ?f= params", () => {
    const seen: JqlFilter[][] = [];
    render(
      <Harness
        onChangeSpy={(f) => seen.push(f)}
        initialUrl="/?f=module:vuln&f=cost>0.5"
      />,
    );

    expect(screen.getAllByText("module:vuln").length).toBeGreaterThan(0);
    expect(screen.getAllByText("cost>0.5").length).toBeGreaterThan(0);
    const last = seen[seen.length - 1];
    expect(last).toHaveLength(2);
  });

  it("supports a plain-text search clause", () => {
    const seen: JqlFilter[][] = [];
    render(<Harness onChangeSpy={(f) => seen.push(f)} />);
    const input = screen.getByLabelText("Add filter") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "web01" } });
    fireEvent.keyDown(input, { key: "Enter" });
    const last = seen[seen.length - 1];
    expect(last).toEqual([{ field: "search", operator: ":", value: "web01" }]);
  });
});

// Small inline sanity check that the component is controllable via the
// React state pattern the real pages use.
describe("<JqlFilterBar> controlled harness", () => {
  function Controlled() {
    const [, setFilters] = useState<JqlFilter[]>([]);
    return (
      <MemoryRouter>
        <JqlFilterBar fields={FIELDS} onChange={setFilters} urlSync={false} />
      </MemoryRouter>
    );
  }

  it("renders with urlSync disabled", () => {
    render(<Controlled />);
    expect(screen.getByLabelText("Add filter")).toBeTruthy();
  });
});
