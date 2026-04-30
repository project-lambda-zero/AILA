import { describe, expect, it, vi } from "vitest";
import type { RouteObject } from "react-router-dom";
import { isValidElement } from "react";

// Load modules for the extension registry return an empty array so the
// structure test is deterministic.
vi.mock("@platform/extension-registry/loadModuleSpecs", () => ({
  loadModuleFrontendSpecs: () => [],
}));

import { routeObjects } from "@app/router";

function flatten(routes: RouteObject[]): RouteObject[] {
  const out: RouteObject[] = [];
  function walk(rs: RouteObject[]) {
    for (const r of rs) {
      out.push(r);
      if (r.children) walk(r.children as RouteObject[]);
    }
  }
  walk(routes);
  return out;
}

function findRoute(path: string): RouteObject | undefined {
  return flatten(routeObjects).find((r) => r.path === path);
}

function renderToString(element: unknown): string {
  if (!isValidElement(element)) return "";
  // Inspect the element tree without actually mounting.
  const result: string[] = [];
  const visit = (node: unknown): void => {
    if (!isValidElement(node)) return;
    const type = (node.type as { name?: string; displayName?: string } | string);
    const name =
      typeof type === "string"
        ? type
        : type.displayName ?? type.name ?? "Anonymous";
    result.push(name);
    const children = (node.props as { children?: unknown }).children;
    if (Array.isArray(children)) {
      for (const c of children) visit(c);
    } else {
      visit(children);
    }
  };
  visit(element);
  return result.join(">");
}

describe("router structure", () => {
  it("registers /docs as a protected route", () => {
    const route = findRoute("docs");
    expect(route).toBeDefined();
  });

  it("redirects /scans to /console (D-14)", () => {
    const route = findRoute("scans");
    expect(route).toBeDefined();
    // Navigate element type is a ReactElement whose type function is Navigate.
    const tree = renderToString(route!.element);
    expect(tree).toMatch(/Navigate/);
  });

  it("redirects /scans/* to /console preserving sub-path (D-14, C-M7)", () => {
    const route = findRoute("scans/*");
    expect(route).toBeDefined();
    // Element is <ScansRedirect /> — a wrapper that reads useParams()["*"]
    // and renders <Navigate to={`/console/${rest}`}>. Inspect the element
    // type name directly since we cannot mount useParams here.
    const tree = renderToString(route!.element);
    expect(tree).toMatch(/ScansRedirect/);
  });

  it("redirects /sbd_nfr/documents and wildcard to /assessments (D-09)", () => {
    const a = findRoute("sbd_nfr/documents");
    const b = findRoute("sbd_nfr/documents/*");
    expect(a).toBeDefined();
    expect(b).toBeDefined();
    expect(renderToString(a!.element)).toMatch(/Navigate/);
    expect(renderToString(b!.element)).toMatch(/Navigate/);
  });

  it("registers /console and /console/:runId", () => {
    expect(findRoute("console")).toBeDefined();
    expect(findRoute("console/:runId")).toBeDefined();
  });

  it("registers /tasks/:taskId detail route", () => {
    expect(findRoute("tasks/:taskId")).toBeDefined();
  });

  it("wraps feature routes with AppErrorBoundary (D-23)", () => {
    // /docs, /tasks, /systems should all have AppErrorBoundary somewhere in
    // their element tree.
    for (const path of ["docs", "tasks", "systems", "console"]) {
      const route = findRoute(path);
      expect(route, `route ${path} missing`).toBeDefined();
      const tree = renderToString(route!.element);
      expect(tree, `route ${path} tree: ${tree}`).toMatch(/AppErrorBoundary/);
    }
  });

  it("only registers /__test__/crash when import.meta.env.DEV is true", () => {
    const crash = findRoute("__test__/crash");
    if (import.meta.env.DEV) {
      expect(crash).toBeDefined();
    } else {
      expect(crash).toBeUndefined();
    }
  });
});
