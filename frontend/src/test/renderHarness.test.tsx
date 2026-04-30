import { useQueryClient } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { AppProviders } from "@app/providers";

function ProviderProbe() {
  const { status, role } = useAuthStore();
  const queryClient = useQueryClient();

  return (
    <section>
      <p data-testid="auth-status">{status}</p>
      <p data-testid="query-cache-size">{queryClient.getQueryCache().getAll().length}</p>
      <p data-testid="reader-access">{String(role !== null)}</p>
    </section>
  );
}

describe("render harness", () => {
  it("renders shared providers without requiring a saved session", async () => {
    render(
      <AppProviders>
        <ProviderProbe />
      </AppProviders>,
    );

    await waitFor(() => {
      const status = screen.getByTestId("auth-status").textContent;
      expect(status === "unauthenticated" || status === "bootstrapping").toBe(true);
    });

    expect(screen.getByTestId("query-cache-size")).toHaveTextContent("0");
    expect(screen.getByTestId("reader-access")).toHaveTextContent("false");
  });
});
