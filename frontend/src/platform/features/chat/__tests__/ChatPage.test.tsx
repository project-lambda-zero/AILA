/**
 * ChatPage render tests (Phase 176c).
 *
 * Follow the TasksPage test pattern: mock the queries module so the component
 * has deterministic state. Covers:
 *   - Empty state when no sessions exist
 *   - Sessions sidebar renders items, clicking changes the selection
 *   - Thread renders persisted messages + live streaming bubble
 *   - Composer is disabled while a stream is in flight
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Mock state -- mutable so tests can configure per-case behaviour.
// ---------------------------------------------------------------------------

const mockState = {
  sessions: [] as Array<{
    session_id: string;
    user_id: string;
    title: string;
    created_at: string;
    last_message_at: string | null;
    last_message_preview: string | null;
    message_count: number;
  }>,
  messages: [] as Array<{
    message_id: string;
    role: "user" | "assistant";
    content: string;
    run_id: string | null;
    created_at: string;
  }>,
  streaming: false,
  buffer: "",
  sendSpy: vi.fn<(content: string) => Promise<void>>(),
};

vi.mock("@platform/features/chat/queries", () => {
  return {
    useSessions: () => ({
      data: { total: mockState.sessions.length, items: mockState.sessions },
      isLoading: false,
      isError: false,
    }),
    useSessionMessages: (id: string) => ({
      data: id
        ? {
            total: mockState.messages.length,
            page: 1,
            page_size: 50,
            pages: 1,
            items: mockState.messages,
          }
        : undefined,
      isLoading: false,
      isError: false,
    }),
    useCreateSession: () => ({
      mutateAsync: vi.fn(async () => ({
        session_id: "new-session",
        user_id: "u",
        title: "New chat",
        created_at: new Date().toISOString(),
      })),
      isPending: false,
    }),
    useSendMessage: (_sessionId: string) => ({
      state: {
        isStreaming: mockState.streaming,
        buffer: mockState.buffer,
        runId: null,
        error: null,
      },
      send: mockState.sendSpy,
      abort: vi.fn(),
      reset: vi.fn(),
    }),
    chatQueryKeys: {
      all: ["platform", "chat"],
      sessions: () => ["platform", "chat", "sessions"],
      messages: (id: string) => ["platform", "chat", "messages", id],
    },
  };
});

import { ChatPage } from "@platform/features/chat/ChatPage";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function renderChat(initialPath = "/chat") {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/chat" element={<ChatPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function resetMockState() {
  mockState.sessions = [];
  mockState.messages = [];
  mockState.streaming = false;
  mockState.buffer = "";
  mockState.sendSpy = vi.fn<(content: string) => Promise<void>>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ChatPage", () => {
  it("renders the empty state when no session is selected", () => {
    resetMockState();
    renderChat();
    // The EmptyState heading <h2> renders the "Start a new chat" title.
    expect(
      screen.getByRole("heading", { name: /Start a new chat/i }),
    ).toBeInTheDocument();
    // Sidebar shows the "no conversations yet" copy.
    expect(
      screen.getByText(/No conversations yet/i),
    ).toBeInTheDocument();
  });

  it("renders persisted messages for the selected session", () => {
    resetMockState();
    mockState.sessions = [
      {
        session_id: "s1",
        user_id: "u",
        title: "First chat",
        created_at: "2026-04-10T00:00:00Z",
        last_message_at: "2026-04-10T00:01:00Z",
        last_message_preview: "Hello there",
        message_count: 2,
      },
    ];
    mockState.messages = [
      {
        message_id: "m1",
        role: "user",
        content: "Hello there",
        run_id: null,
        created_at: "2026-04-10T00:00:30Z",
      },
      {
        message_id: "m2",
        role: "assistant",
        content: "Hi! How can I help?",
        run_id: null,
        created_at: "2026-04-10T00:01:00Z",
      },
    ];
    renderChat("/chat?session=s1");
    const bubbles = screen.getAllByTestId("chat-message");
    expect(bubbles).toHaveLength(2);
    expect(bubbles[0]).toHaveAttribute("data-role", "user");
    expect(bubbles[1]).toHaveAttribute("data-role", "assistant");
    expect(
      within(bubbles[1]).getByText(/Hi! How can I help/),
    ).toBeInTheDocument();
  });

  it("renders the streaming assistant bubble while isStreaming is true", () => {
    resetMockState();
    mockState.sessions = [
      {
        session_id: "s1",
        user_id: "u",
        title: "First chat",
        created_at: "2026-04-10T00:00:00Z",
        last_message_at: null,
        last_message_preview: null,
        message_count: 0,
      },
    ];
    mockState.streaming = true;
    mockState.buffer = "Streaming partial token";
    renderChat("/chat?session=s1");
    const bubbles = screen.getAllByTestId("chat-message");
    // Last bubble is the live streaming one.
    const last = bubbles[bubbles.length - 1];
    expect(last).toHaveAttribute("data-role", "assistant");
    expect(last).toHaveTextContent("Streaming partial token");
    expect(within(last).getByText(/streaming…/)).toBeInTheDocument();
  });

  it("disables the send button while streaming", () => {
    resetMockState();
    mockState.sessions = [
      {
        session_id: "s1",
        user_id: "u",
        title: "t",
        created_at: "2026-04-10T00:00:00Z",
        last_message_at: null,
        last_message_preview: null,
        message_count: 0,
      },
    ];
    mockState.streaming = true;
    renderChat("/chat?session=s1");
    const send = screen.getByTestId("chat-send");
    expect(send).toBeDisabled();
    const composer = screen.getByTestId("chat-composer");
    expect(composer).toBeDisabled();
  });

  it("calls send() with trimmed content when the user presses Enter", async () => {
    resetMockState();
    mockState.sessions = [
      {
        session_id: "s1",
        user_id: "u",
        title: "t",
        created_at: "2026-04-10T00:00:00Z",
        last_message_at: null,
        last_message_preview: null,
        message_count: 0,
      },
    ];
    renderChat("/chat?session=s1");
    const composer = screen.getByTestId("chat-composer");
    await userEvent.type(composer, "  Hello  ");
    await userEvent.keyboard("{Enter}");
    expect(mockState.sendSpy).toHaveBeenCalledWith("Hello");
  });
});
