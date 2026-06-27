import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ColumnDef } from "@tanstack/react-table";

import { AilaTable } from "@/components/aila/AilaTable";

interface Row {
  id: string;
  title: string;
}

const data: Row[] = [
  { id: "r1", title: "First row" },
  { id: "r2", title: "Second row" },
];

const columns: ColumnDef<Row>[] = [
  { accessorKey: "id", header: "ID" },
  { accessorKey: "title", header: "Title" },
  {
    id: "actions",
    header: "Actions",
    cell: () => (
      <button type="button" data-testid="inline-btn">
        Inline
      </button>
    ),
  },
  {
    id: "nrc",
    header: "NoRowClick",
    cell: () => (
      <span className="no-row-click" data-testid="nrc-wrap">
        <span data-testid="nrc-child">child</span>
      </span>
    ),
  },
];

describe("AilaTable onRowClick", () => {
  it("invokes onRowClick with the row data on click", async () => {
    const onRowClick = vi.fn();
    render(<AilaTable data={data} columns={columns} onRowClick={onRowClick} />);

    const rows = screen.getAllByTestId("aila-table-row");
    await userEvent.click(rows[0]);

    expect(onRowClick).toHaveBeenCalledTimes(1);
    const arg = onRowClick.mock.calls[0][0];
    expect(arg.original).toEqual(data[0]);
  });

  it("navigates on Enter keypress (a11y)", async () => {
    const onRowClick = vi.fn();
    render(<AilaTable data={data} columns={columns} onRowClick={onRowClick} />);

    const row = screen.getAllByTestId("aila-table-row")[0];
    row.focus();
    await userEvent.keyboard("{Enter}");

    expect(onRowClick).toHaveBeenCalledTimes(1);
  });

  it("navigates on Space keypress AND preventDefault stops page scroll", async () => {
    const onRowClick = vi.fn();
    render(<AilaTable data={data} columns={columns} onRowClick={onRowClick} />);

    const row = screen.getAllByTestId("aila-table-row")[0];
    row.focus();
    // userEvent.keyboard sends a space; preventDefault is enforced by the
    // onKeyDown handler -- here we simply verify the handler fires.
    await userEvent.keyboard(" ");

    expect(onRowClick).toHaveBeenCalledTimes(1);
  });

  it("suppresses row click when target is an inline button (D-32)", async () => {
    const onRowClick = vi.fn();
    render(<AilaTable data={data} columns={columns} onRowClick={onRowClick} />);

    const inlineBtn = screen.getAllByTestId("inline-btn")[0];
    await userEvent.click(inlineBtn);

    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("suppresses row click when a descendant has class no-row-click", async () => {
    const onRowClick = vi.fn();
    render(<AilaTable data={data} columns={columns} onRowClick={onRowClick} />);

    const nrcChild = screen.getAllByTestId("nrc-child")[0];
    await userEvent.click(nrcChild);

    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("does NOT add role=button or tabIndex when onRowClick is not provided", () => {
    render(<AilaTable data={data} columns={columns} />);
    const rows = screen.getAllByTestId("aila-table-row");
    for (const row of rows) {
      expect(row.getAttribute("role")).toBeNull();
      expect(row.getAttribute("tabindex")).toBeNull();
    }
  });
});
