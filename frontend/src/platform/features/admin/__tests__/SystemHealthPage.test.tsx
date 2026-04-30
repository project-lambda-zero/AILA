/**
 * SystemHealthPage tests (Phase 176d).
 *
 * Verifies:
 *   - legacy /health status banner renders with overall status
 *   - admin callers trigger a /health/comprehensive fetch and render
 *     the Phase 176d subsystem cards
 *   - non-admin callers do not trigger /health/comprehensive
 *   - handles error envelopes gracefully
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Mock the authorizedRequestJson helper so tests control both endpoints.
const mockRequest = vi.fn();
vi.mock("@platform/api/http", () => ({
  authorizedRequestJson: (pathname: string) => mockRequest(pathname),
}));

// Fake auth store: default to admin, override per-test via useAuthStoreMock.
let useAuthStoreMock: (selector: (s: { role: string | null }) => unknown) => unknown;
vi.mock("@platform/auth/useAuthStore", () => ({
  useAuthStore: (selector: (s: { role: string | null }) => unknown) =>
    useAuthStoreMock(selector),
}));

import { SystemHealthPage } from "../SystemHealthPage";

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, staleTime: 0 },
    },
  });
  return render(
    <QueryClientProvider client={client}>
      <SystemHealthPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mockRequest.mockReset();
  useAuthStoreMock = (selector) => selector({ role: "admin" });
});

describe("SystemHealthPage", () => {
  it("renders the overall status banner from /health", async () => {
    mockRequest.mockImplementation((pathname: string) => {
      if (pathname === "/health") {
        return Promise.resolve({
          status: "healthy",
          checks: {
            database: { status: "up", latency_ms: 1.2, message: null },
          },
        });
      }
      if (pathname === "/health/comprehensive") {
        return Promise.resolve({
          data: {
            overall_status: "healthy",
            checked_at: new Date().toISOString(),
            subsystems: [],
          },
          error: null,
          meta: {},
        });
      }
      return Promise.reject(new Error("unexpected path"));
    });

    renderPage();

    await waitFor(() => {
      // Heading is always present
      expect(screen.getByText("System Health")).toBeInTheDocument();
      // Database check card is rendered
      expect(screen.getByText("Database")).toBeInTheDocument();
    });
  });

  it("renders Phase 176d subsystem cards for admin callers", async () => {
    mockRequest.mockImplementation((pathname: string) => {
      if (pathname === "/health") {
        return Promise.resolve({
          status: "degraded",
          checks: {
            database: { status: "up", latency_ms: 2.0, message: null },
          },
        });
      }
      if (pathname === "/health/comprehensive") {
        return Promise.resolve({
          data: {
            overall_status: "degraded",
            checked_at: new Date().toISOString(),
            subsystems: [
              {
                name: "redis",
                status: "healthy",
                latency_ms: 0.8,
                last_checked_at: new Date().toISOString(),
                message: "PING ok",
                details: null,
              },
              {
                name: "omniroute",
                status: "unreachable",
                latency_ms: null,
                last_checked_at: new Date().toISOString(),
                message: "connection refused",
                details: null,
              },
              {
                name: "ssh_systems",
                status: "degraded",
                latency_ms: null,
                last_checked_at: new Date().toISOString(),
                message: "1/2 systems reachable",
                details: {
                  reachable: 1,
                  total: 2,
                  systems: [
                    {
                      system_id: 1,
                      system_name: "web01",
                      host: "10.0.0.1",
                      port: 22,
                      status: "reachable",
                      latency_ms: 12.3,
                      message: null,
                    },
                  ],
                },
              },
            ],
          },
          error: null,
          meta: {},
        });
      }
      return Promise.reject(new Error("unexpected path"));
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("Redis / Memurai")).toBeInTheDocument();
      expect(screen.getByText("OmniRoute LLM")).toBeInTheDocument();
      expect(
        screen.getByText("Managed Systems (SSH)"),
      ).toBeInTheDocument();
      // Statuses rendered in badges
      expect(
        screen.getAllByText(/HEALTHY|UNREACHABLE|DEGRADED/).length,
      ).toBeGreaterThan(0);
    });
  });

  it("does not fetch /health/comprehensive for non-admin callers", async () => {
    useAuthStoreMock = (selector) => selector({ role: "reader" });
    mockRequest.mockImplementation((pathname: string) => {
      if (pathname === "/health") {
        return Promise.resolve({
          status: "healthy",
          checks: {
            database: { status: "up", latency_ms: 1, message: null },
          },
        });
      }
      return Promise.reject(new Error("should not be called: " + pathname));
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("Database")).toBeInTheDocument();
    });
    const paths = mockRequest.mock.calls.map((c) => c[0]);
    expect(paths).not.toContain("/health/comprehensive");
  });

  it("renders an error banner when /health fails", async () => {
    mockRequest.mockImplementation((pathname: string) => {
      if (pathname === "/health") {
        return Promise.reject(new Error("boom"));
      }
      return Promise.resolve({
        data: {
          overall_status: "healthy",
          checked_at: new Date().toISOString(),
          subsystems: [],
        },
        error: null,
        meta: {},
      });
    });

    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText(/Failed to load health data/),
      ).toBeInTheDocument();
    });
  });
});
