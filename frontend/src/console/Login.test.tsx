import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import { useAuth } from "../api/auth";

import Login from "./Login";

const SYNTHETIC_USERNAME = "synthetic-user";
const SYNTHETIC_PASSWORD = "synthetic-secret";

type LoginFn = (username: string, password: string) => Promise<void>;

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
  });

  afterEach(() => {
    cleanup();
  });

  it("starts with empty username and password fields", () => {
    render(<Login />);

    expect(usernameInput().value).toBe("");
    expect(passwordInput().value).toBe("");
  });

  it("does not call login when submitted with both fields untouched", () => {
    render(<Login />);

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
    render(<Login />);

    fireEvent.change(usernameInput(), { target: { value: username } });
    fireEvent.change(passwordInput(), { target: { value: password } });
    fireEvent.click(submitButton());

    expect(loginSpy).not.toHaveBeenCalled();
  });

  it("submits exactly once with the entered values when both fields are nonempty", () => {
    render(<Login />);

    fireEvent.change(usernameInput(), { target: { value: SYNTHETIC_USERNAME } });
    fireEvent.change(passwordInput(), { target: { value: SYNTHETIC_PASSWORD } });
    fireEvent.click(submitButton());

    expect(loginSpy).toHaveBeenCalledTimes(1);
    expect(loginSpy).toHaveBeenCalledWith(SYNTHETIC_USERNAME, SYNTHETIC_PASSWORD);
  });

  it("renders the store error message and keeps the form usable", () => {
    useAuth.setState({ error: "Invalid credentials." });
    render(<Login />);

    expect(screen.getByText("Invalid credentials.")).toBeTruthy();
    expect(submitButton().hasAttribute("disabled")).toBe(false);
  });

  it("disables the submit button while a sign-in is in flight", () => {
    useAuth.setState({ busy: true });
    render(<Login />);

    expect(screen.getByRole("button", { name: "signing in..." }).hasAttribute("disabled")).toBe(true);
  });
});
