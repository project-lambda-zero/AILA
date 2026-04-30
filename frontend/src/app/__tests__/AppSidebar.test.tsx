import { beforeAll, describe, expect, it, vi } from "vitest";
import { render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { SidebarProvider } from "@/components/ui/sidebar";

beforeAll(() => {
  // jsdom does not implement matchMedia; the useIsMobile hook used by
  // SidebarProvider calls it on mount. Stub once for this test file.
  if (!window.matchMedia) {
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      configurable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }
});

// The real auth store pulls in persist + token machinery that is not relevant
// for structural tests. Return a plain admin role so admin nav renders too.
vi.mock("@platform/auth/useAuthStore", () => ({
  useAuthStore: () => ({ role: "admin" }),
}));

// RecentlyViewed uses useRecentlyViewed which depends on localStorage; stub it
// out so the sidebar test focuses on structure, not footer content.
vi.mock("@/components/shell/RecentlyViewed", () => ({
  RecentlyViewed: () => null,
}));

import { AppSidebar } from "@app/layout/AppSidebar";

function renderSidebar() {
  return render(
    <MemoryRouter>
      <SidebarProvider>
        <AppSidebar moduleSpecs={[]} />
      </SidebarProvider>
    </MemoryRouter>,
  );
}

describe("AppSidebar", () => {
  it("renders 'Console' (not 'Scans') in the sidebar text (D-01)", () => {
    const { container } = renderSidebar();
    const text = container.textContent ?? "";
    expect(text).toMatch(/Console/);
    expect(text).not.toMatch(/\bScans\b/);
  });

  it("has a Docs entry routing to /docs (D-03)", () => {
    const { container } = renderSidebar();
    const docsLink = within(container).getByRole("link", { name: /docs/i });
    expect(docsLink).toHaveAttribute("href", "/docs");
  });

  it("does NOT produce nested <li> elements (D-02, D-27)", () => {
    const { container } = renderSidebar();
    // Any <li> that contains another <li> is a hydration error source.
    const nested = container.querySelectorAll("li li");
    expect(nested.length).toBe(0);
  });
});
