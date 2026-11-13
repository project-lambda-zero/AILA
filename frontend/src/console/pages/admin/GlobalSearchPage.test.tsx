// @vitest-environment jsdom
/** Issue #367: global search results open the existing window for their record.
 * Only the search hook is faked; the page, its chrome, and the routing run
 * unmodified. Synthetic rows only. */

import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SearchResult } from "../../../api/admin";
import type { ModulePageProps } from "../../contract";
import GlobalSearchPage from "./GlobalSearchPage";

const { ROWS } = vi.hoisted(() => ({
  ROWS: [
    { entity_type: "target", entity_id: "tgt-7", title: "target-007", snippet: "elf -- active", module_id: "malware", score: 1 },
    { entity_type: "investigation", entity_id: "inv-9", title: "case alpha", snippet: "cve -- running", module_id: "vr", score: 1 },
    { entity_type: "finding", entity_id: "fnd-3", title: "unsafe copy", snippet: "high", module_id: "vulnerability", score: 1 },
    { entity_type: "target", entity_id: "tgt-8", title: "orphan target", snippet: "elf -- active", module_id: null, score: 1 },
  ] satisfies SearchResult[],
}));

vi.mock("../../../api/admin", () => ({
  useGlobalSearch: () => ({
    data: { results: ROWS, total: ROWS.length },
    isLoading: false,
    isFetching: false,
    error: null,
  }),
}));

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => {
    root.unmount();
  });
  container.remove();
});

/** Type a query and submit the search form so the results render. */
async function search(text: string): Promise<void> {
  const input = container.querySelector("input");
  const form = container.querySelector("form");
  if (!input || !form) throw new Error("search form not rendered");
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setValue) throw new Error("input value setter unavailable");
  await act(async () => {
    setValue.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}

function resultButton(title: string): HTMLButtonElement {
  const found = Array.from(container.querySelectorAll("button")).find((b) => b.textContent?.includes(title));
  if (!found) throw new Error(`no result row for ${title}`);
  return found;
}

async function renderPage(onOpenPage: ModulePageProps["onOpenPage"]): Promise<void> {
  const props: ModulePageProps = {
    windowId: "global-search",
    title: "search",
    section: null,
    onNavigate: () => undefined,
    onBack: () => undefined,
    onMinimize: () => undefined,
    onOpenPage,
  };
  await act(async () => {
    root.render(<GlobalSearchPage {...props} />);
  });
  await search("target");
}

async function activate(title: string): Promise<void> {
  const button = resultButton(title);
  await act(async () => {
    button.click();
  });
}

describe("GlobalSearchPage result routing", () => {
  it("opens a malware target result in the malware targets window for that record", async () => {
    const onOpenPage = vi.fn();
    await renderPage(onOpenPage);
    await activate("target-007");
    expect(onOpenPage).toHaveBeenCalledWith("malware", "targets", "target-007", "tgt-7");
  });

  it("opens a VR investigation result in the VR x-ray window for that investigation", async () => {
    const onOpenPage = vi.fn();
    await renderPage(onOpenPage);
    await activate("case alpha");
    expect(onOpenPage).toHaveBeenCalledWith("vr", "xray", "x-ray", "inv-9");
  });

  it("still opens a module finding result in that module's findings page", async () => {
    const onOpenPage = vi.fn();
    await renderPage(onOpenPage);
    await activate("unsafe copy");
    const [moduleKey, section, label] = onOpenPage.mock.calls[0] ?? [];
    expect([moduleKey, section, label]).toEqual(["vulnerability", "findings", "vulnerability findings"]);
  });

  it("renders a module-typed result without module_id as disabled and opens nothing", async () => {
    const onOpenPage = vi.fn();
    await renderPage(onOpenPage);
    const button = resultButton("orphan target");
    expect(button.disabled).toBe(true);
    await activate("orphan target");
    expect(onOpenPage).not.toHaveBeenCalled();
  });
});
