/**
 * TeamDetailPage smoke tests (Phase 177).
 *
 * Verifies:
 *   - renders team detail and member list from the envelope
 *   - renders the member empty state when no members
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const mockRequest = vi.fn();
vi.mock("@platform/api/http", () => ({
  authorizedRequestJson: (pathname: string) => mockRequest(pathname),
}));

import { TeamDetailPage } from "../TeamDetailPage";

function renderPage(teamId: string) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, staleTime: 0 },
    },
  });
  return render(
    <MemoryRouter initialEntries={[`/admin/teams/${teamId}`]}>
      <QueryClientProvider client={client}>
        <Routes>
          <Route path="/admin/teams/:id" element={<TeamDetailPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const TEAM_ID = "11111111-1111-1111-1111-111111111111";

const TEAM = {
  id: TEAM_ID,
  name: "detail-team",
  description: "detail desc",
  created_at: "2026-04-12T12:00:00Z",
  updated_at: "2026-04-12T12:00:00Z",
  member_count: 1,
};

const MEMBER = {
  id: "m-1",
  user_id: "u-1",
  username: "alice",
  email: "alice@example.com",
  role: "admin",
  created_at: "2026-04-12T13:00:00Z",
};

beforeEach(() => {
  mockRequest.mockReset();
});

describe("TeamDetailPage", () => {
  it("renders the team and members", async () => {
    mockRequest.mockResolvedValue({
      data: { team: TEAM, members: [MEMBER] },
      error: null,
      meta: {},
    });

    renderPage(TEAM_ID);

    await waitFor(() => {
      expect(screen.getByText("detail-team")).toBeTruthy();
    });
    expect(screen.getByText("detail desc")).toBeTruthy();
    expect(screen.getByText("alice")).toBeTruthy();
    expect(screen.getByText("alice@example.com")).toBeTruthy();
    expect(screen.getByText("admin")).toBeTruthy();
  });

  it("renders empty state with no members", async () => {
    mockRequest.mockResolvedValue({
      data: { team: { ...TEAM, member_count: 0 }, members: [] },
      error: null,
      meta: {},
    });

    renderPage(TEAM_ID);

    await waitFor(() => {
      expect(screen.getByText("No members")).toBeTruthy();
    });
  });
});
