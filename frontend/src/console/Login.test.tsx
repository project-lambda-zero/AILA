import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import { useAuth } from "../api/auth";

import Login from "./Login";

const SYNTHETIC_USERNAME = "synthetic-user";
const SYNTHETIC_PASSWORD = "synthetic-secret";

type LoginFn = (username: string, password: string) => Promise<void>;

// A hash-only target: jsdom performs it as a same-document navigation, so the
// test can observe where the browser was sent.
const IDP_AUTHORIZE_URL = "#idp-authorize";

interface ProviderFixture {
  id: string;
  name: string;
  provider_type: string;
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// Serves the public provider list and the OIDC authorize route; records every
// request so tests can check the URL the console builds and wait for settling.
function stubOidcRoutes(providers: ProviderFixture[] | "error"): { requested: URL[]; authorizeUrls: URL[] } {
  const requested: URL[] = [];
  const authorizeUrls: URL[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => {
      const url = new URL(String(input));
      requested.push(url);

      if (url.pathname === "/auth/oidc/providers/public") {
        return providers === "error"
          ? json(500, { detail: "providers unavailable" })
          : json(200, { data: providers });
      }

      if (url.pathname === "/auth/oidc/authorize") {
        authorizeUrls.push(url);

        return json(200, { data: { authorization_url: IDP_AUTHORIZE_URL } });
      }

      return json(404, { detail: "not found" });
    }),
  );

  return { requested, authorizeUrls };
}

// Yields one macrotask so a settled TanStack query has rendered its result.
async function settle(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
}

function renderLogin(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Login />
    </QueryClientProvider>,
  );
}

function usernameInput(): HTMLInputElement {
  return screen.getByLabelText("username") as HTMLInputElement;
}

function passwordInput(): HTMLInputElement {
  return screen.getByLabelText("password") as HTMLInputElement;
}

function submitButton(): HTMLElement {
  return screen.getByRole("button", { name: "sign in" });
}

describe("Login", () => {
  let loginSpy: Mock<LoginFn>;

  beforeEach(() => {
    loginSpy = vi.fn<LoginFn>(async () => {});
    useAuth.setState({ login: loginSpy, busy: false, error: null });
    stubOidcRoutes([]);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    window.history.replaceState(null, "", "/");
  });

  it("starts with empty username and password fields", () => {
    renderLogin();

    expect(usernameInput().value).toBe("");
    expect(passwordInput().value).toBe("");
  });

  it("does not call login when submitted with both fields untouched", () => {
    renderLogin();

    fireEvent.click(submitButton());

    expect(loginSpy).not.toHaveBeenCalled();
  });

  it.each([
    ["empty username and empty password", "", ""],
    ["whitespace username with empty password", "   ", ""],
    ["empty username with whitespace password", "", "\t  "],
    ["whitespace username and whitespace password", " \n ", "   "],
    ["nonempty username with empty password", SYNTHETIC_USERNAME, ""],
    ["nonempty username with whitespace password", SYNTHETIC_USERNAME, "  "],
    ["empty username with nonempty password", "", SYNTHETIC_PASSWORD],
    ["whitespace username with nonempty password", "  ", SYNTHETIC_PASSWORD],
  ])("makes zero login calls for %s", (_label, username, password) => {
    renderLogin();

    fireEvent.change(usernameInput(), { target: { value: username } });
    fireEvent.change(passwordInput(), { target: { value: password } });
    fireEvent.click(submitButton());

    expect(loginSpy).not.toHaveBeenCalled();
  });

  it("submits exactly once with the entered values when both fields are nonempty", () => {
    renderLogin();

    fireEvent.change(usernameInput(), { target: { value: SYNTHETIC_USERNAME } });
    fireEvent.change(passwordInput(), { target: { value: SYNTHETIC_PASSWORD } });
    fireEvent.click(submitButton());

    expect(loginSpy).toHaveBeenCalledTimes(1);
    expect(loginSpy).toHaveBeenCalledWith(SYNTHETIC_USERNAME, SYNTHETIC_PASSWORD);
  });

  it("renders the store error message and keeps the form usable", () => {
    useAuth.setState({ error: "Invalid credentials." });
    renderLogin();

    expect(screen.getByText("Invalid credentials.")).toBeTruthy();
    expect(submitButton().hasAttribute("disabled")).toBe(false);
  });

  it("disables the submit button while a sign-in is in flight", () => {
    useAuth.setState({ busy: true });
    renderLogin();

    expect(screen.getByRole("button", { name: "signing in..." }).hasAttribute("disabled")).toBe(true);
  });

  it("renders one sign-in button per enabled OIDC provider", async () => {
    stubOidcRoutes([
      { id: "p-entra", name: "Entra", provider_type: "microsoft" },
      { id: "p-okta", name: "Okta", provider_type: "oidc" },
    ]);
    renderLogin();

    expect(await screen.findByRole("button", { name: "sign in with Entra" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "sign in with Okta" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "sign in" })).toBeTruthy();
  });

  it("starts OIDC sign-in for the clicked provider and follows the returned URL", async () => {
    const { authorizeUrls } = stubOidcRoutes([{ id: "p-okta", name: "Okta", provider_type: "oidc" }]);
    renderLogin();

    fireEvent.click(await screen.findByRole("button", { name: "sign in with Okta" }));

    await vi.waitFor(() => expect(window.location.hash).toBe("#idp-authorize"));
    expect(authorizeUrls).toHaveLength(1);
    expect(authorizeUrls[0]?.searchParams.get("provider_id")).toBe("p-okta");
    expect(authorizeUrls[0]?.searchParams.get("redirect_uri")).toBe(`${window.location.origin}/auth/callback`);
  });

  it("offers no OIDC buttons when no provider is enabled and keeps the password form", async () => {
    const { requested } = stubOidcRoutes([]);
    renderLogin();

    await vi.waitFor(() => expect(requested.some((u) => u.pathname === "/auth/oidc/providers/public")).toBe(true));
    await settle();

    expect(screen.queryByRole("button", { name: /sign in with/ })).toBeNull();
    expect(usernameInput()).toBeTruthy();
    expect(submitButton().hasAttribute("disabled")).toBe(false);
  });

  it("keeps the password form and hides OIDC buttons when the provider list fails", async () => {
    const { requested } = stubOidcRoutes("error");
    renderLogin();

    await vi.waitFor(() => expect(requested.some((u) => u.pathname === "/auth/oidc/providers/public")).toBe(true));
    await settle();

    expect(screen.queryByRole("button", { name: /sign in with/ })).toBeNull();
    expect(submitButton()).toBeTruthy();
  });
});
