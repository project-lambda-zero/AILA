/**
 * OidcProvidersPage smoke tests (Phase 177).
 *
 * Verifies:
 *   - renders empty state when no providers exist
 *   - renders providers table from envelope response
 *   - shows "Add provider" button
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const mockRequest = vi.fn();
vi.mock("@platform/api/http", () => ({
  authorizedRequestJson: (pathname: string) => mockRequest(pathname),
}));

import { OidcProvidersPage } from "../OidcProvidersPage";

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, staleTime: 0 },
    },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <OidcProvidersPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const MICROSOFT_PROVIDER = {
  id: "mp1",
  provider_name: "ms-primary",
  provider_type: "microsoft",
  display_name: "Azure AD",
  tenant_id: "00000000",
  issuer_url: null,
  client_id: "client-id-value",
  scopes: ["openid", "email", "profile"],
  is_enabled: true,
  created_at: "2026-04-12T12:00:00Z",
};

beforeEach(() => {
  mockRequest.mockReset();
});

describe("OidcProvidersPage", () => {
  it("renders the table with providers from the envelope", async () => {
    mockRequest.mockResolvedValue({
      data: [MICROSOFT_PROVIDER],
      error: null,
      meta: {},
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("ms-primary")).toBeTruthy();
    });
    expect(screen.getByText("Azure AD")).toBeTruthy();
    expect(screen.getByText("microsoft")).toBeTruthy();
    expect(screen.getByText("client-id-value")).toBeTruthy();
    // "Enabled" appears both as a metric card label and as the row badge.
    expect(screen.getAllByText("Enabled").length).toBeGreaterThan(0);
  });

  it("shows empty state when no providers exist", async () => {
    mockRequest.mockResolvedValue({
      data: [],
      error: null,
      meta: {},
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("No OIDC providers configured")).toBeTruthy();
    });
  });

  it("renders the Add provider button", async () => {
    mockRequest.mockResolvedValue({
      data: [],
      error: null,
      meta: {},
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /add provider/i })).toBeTruthy();
    });
  });
});
