/**
 * TeamsPage smoke tests (Phase 177).
 *
 * Verifies:
 *   - renders the team list and cross-view metric cards
 *   - shows empty state when no teams exist
 *   - routes /admin/teams and /admin/teams/cross-view are fetched
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const mockRequest = vi.fn();
vi.mock("@platform/api/http", () => ({
  authorizedRequestJson: (pathname: string) => mockRequest(pathname),
}));

import { TeamsPage } from "../TeamsPage";

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, staleTime: 0 },
    },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <TeamsPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const TEAM_ONE = {
  id: "11111111-1111-1111-1111-111111111111",
  name: "security-red",
  description: "red team",
  created_at: "2026-04-12T12:00:00Z",
  updated_at: "2026-04-12T12:00:00Z",
  member_count: 3,
};

beforeEach(() => {
  mockRequest.mockReset();
});

describe("TeamsPage", () => {
  it("renders teams and cross-view aggregates", async () => {
    mockRequest.mockImplementation((pathname: string) => {
      if (pathname === "/admin/teams") {
        return Promise.resolve({ data: [TEAM_ONE], error: null, meta: {} });
      }
      if (pathname === "/admin/teams/cross-view") {
        return Promise.resolve({
          data: [
            {
              team_id: TEAM_ONE.id,
              team_name: TEAM_ONE.name,
              systems_count: 2,
              runs_count: 7,
              members_count: 3,
            },
          ],
          error: null,
          meta: {},
        });
      }
      return Promise.resolve({ data: [], error: null, meta: {} });
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("security-red")).toBeTruthy();
    });
    expect(screen.getByText("red team")).toBeTruthy();
    // member_count badge + cross-view members card both show 3
    expect(screen.getAllByText("3").length).toBeGreaterThan(0);
    // cross-view aggregates: 2 systems, 7 runs
    expect(screen.getAllByText("2").length).toBeGreaterThan(0);
    expect(screen.getAllByText("7").length).toBeGreaterThan(0);
  });

  it("renders empty state with no teams", async () => {
    mockRequest.mockResolvedValue({ data: [], error: null, meta: {} });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("No teams yet")).toBeTruthy();
    });
    expect(screen.getByRole("button", { name: /create team/i })).toBeTruthy();
  });
});
