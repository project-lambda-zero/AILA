import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

const renders = vi.hoisted(() => ({
  chat: 0,
  page: 0,
  widget: 0,
}));

vi.mock("./api/auth", () => {
  const state = {
    status: "authed",
    user: { id: "user-1", username: "operator", role: "operator", team_id: "team-1" },
  };

  return {
    useAuth: <T,>(selector: (current: typeof state) => T): T => selector(state),
  };
});

vi.mock("./api/cost", () => ({ useCostRoi: () => ({ data: undefined }) }));
vi.mock("./api/onboarding", () => ({ usePlatformSchema: () => ({ data: { onboardingCompleted: true } }) }));
vi.mock("./api/liveEvents", () => ({
  LiveEventsProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./console/ChatConsole", () => ({
  default: () => {
    renders.chat += 1;
    return <div>chat fixture</div>;
  },
}));

vi.mock("./console/widgets/WidgetHost", () => ({
  default: () => {
    renders.widget += 1;
    return <div>widget fixture</div>;
  },
}));

vi.mock("./console/pages/registry", () => {
  function PageFixture() {
    renders.page += 1;
    return <div data-testid="page-fixture">page fixture</div>;
  }

  return {
    resolvePage: (key: string) => (key === "platform:docs" ? { render: () => <PageFixture /> } : null),
  };
});

vi.mock("./console/IntakeWizard", () => ({ default: () => null }));
vi.mock("./console/LeftRail", () => ({ default: () => <div>left rail fixture</div> }));
vi.mock("./console/Login", () => ({ default: () => <div>login fixture</div> }));
vi.mock("./console/NotificationsCenter", () => ({ default: () => null }));
vi.mock("./console/SettingsOverlay", () => ({ default: () => null }));
vi.mock("./console/toast", () => ({ ToastViewport: () => null }));
vi.mock("./console/CommandPalette", () => ({ default: () => null }));
vi.mock("./console/wizards", () => ({ resolveWizard: () => null }));
vi.mock("./desktop/FaultyTerminal", () => ({ FaultyTerminal: () => null }));

beforeEach(() => {
  renders.chat = 0;
  renders.page = 0;
  renders.widget = 0;
  vi.useFakeTimers();
  vi.setSystemTime(new Date(2026, 0, 1, 10, 20, 30));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("App shell clock rendering", () => {
  it("advances the clock without rerendering the chat and widget subtree", () => {
    render(<App />);

    expect(screen.getByText("10:20:30")).toBeTruthy();
    const chatBefore = renders.chat;
    const widgetBefore = renders.widget;

    act(() => {
      vi.advanceTimersByTime(1000);
    });

    expect(screen.getByText("10:20:31")).toBeTruthy();
    expect(renders.chat).toBe(chatBefore);
    expect(renders.widget).toBe(widgetBefore);

    // A real Console state change must still reach the fixtures; otherwise a
    // broken render counter could make the clock assertion pass vacuously.
    fireEvent.click(screen.getByRole("button", { name: "console" }));
    expect(renders.chat).toBeGreaterThan(chatBefore);
    expect(renders.widget).toBeGreaterThan(widgetBefore);
  });

  it("advances the clock without rerendering an open page window", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "docs" }));
    expect(screen.getByTestId("page-fixture")).toBeTruthy();
    const pageBefore = renders.page;

    act(() => {
      vi.advanceTimersByTime(1000);
    });

    expect(screen.getByText("10:20:31")).toBeTruthy();
    expect(renders.page).toBe(pageBefore);

    // Re-opening the focused page updates real Console window state and must
    // rerender the page, proving the counter is live.
    fireEvent.click(screen.getByRole("button", { name: "docs" }));
    expect(renders.page).toBeGreaterThan(pageBefore);
  });
});
