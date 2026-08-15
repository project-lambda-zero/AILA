/**
 * ChatPage (Phase 176c).
 *
 * Left: sessions list (new chat button + prior sessions).
 * Right: message thread for the selected session, with a sticky composer.
 *
 * Streams assistant replies via POST /sessions/{id}/messages + SSE tokens
 * (see useSendMessage). Design follows ReportsPage / TasksPage: AilaCard +
 * AilaBadge + LoadingSkeleton + shadcn Button/Textarea, no new CSS classes.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { ChatCircleDots } from "@phosphor-icons/react/dist/csr/ChatCircleDots";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { PaperPlaneRight } from "@phosphor-icons/react/dist/csr/PaperPlaneRight";
import { Robot } from "@phosphor-icons/react/dist/csr/Robot";
import { User as UserIcon } from "@phosphor-icons/react/dist/csr/User";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ApiHttpError } from "@platform/api/http";
import { ChatLauncher } from "./ChatLauncher";
import {
  useCreateSession,
  useSendMessage,
  useSessionMessages,
  useSessions,
  type ChatMessage,
  type SessionSummary,
} from "./queries";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "--";
  return parsed.toLocaleString();
}

function shortTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "--";
  return parsed.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function describeError(err: unknown): string {
  if (!err) return "";
  if (err instanceof ApiHttpError) {
    return err.envelope?.message ?? err.message ?? "Request failed.";
  }
  if (err instanceof Error) return err.message;
  return "An unexpected error occurred.";
}

function describeErrorHint(err: unknown): string | null {
  if (err instanceof ApiHttpError) {
    return err.envelope?.hint ?? null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sessions sidebar
// ---------------------------------------------------------------------------

function SessionsSidebar({
  sessions,
  selectedId,
  isLoading,
  isCreating,
  onSelect,
  onCreate,
}: {
  sessions: SessionSummary[];
  selectedId: string;
  isLoading: boolean;
  isCreating: boolean;
  onSelect: (sessionId: string) => void;
  onCreate: () => void;
}) {
  return (
    <aside className="w-full lg:w-[280px] shrink-0 flex flex-col gap-3">
      <Button
        size="sm"
        variant="default"
        onClick={onCreate}
        disabled={isCreating}
        data-testid="chat-new-session"
        className="justify-start gap-2"
      >
        <Plus size={16} weight="bold" />
        {isCreating ? "Creating…" : "New chat"}
      </Button>

      <AilaCard variant="default" padding="none" className="flex flex-col"><div className="border-b border-border px-3 py-2">
        <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted">
          Conversations
        </h2>
      </div>
      {isLoading ? (
        <div className="p-3">
          <LoadingSkeletonGroup lines={4} />
        </div>
      ) : sessions.length === 0 ? (
        <p className="px-3 py-4 font-mono text-xs text-text-muted">
          No conversations yet. Start a new chat to ask the platform a question.
        </p>
      ) : (
        <ul className="flex flex-col max-h-[60vh] overflow-y-auto">
          {sessions.map((session) => {
            const active = session.session_id === selectedId;
            return (
              <li key={session.session_id}>
                <button
                  type="button"
                  role="option"
                  aria-selected={active}
                  data-testid="chat-session-row"
                  data-session-id={session.session_id}
                  onClick={() => onSelect(session.session_id)}
                  style={
                    active
                      ? { boxShadow: "inset 2px 0 0 var(--color-accent)" }
                      : undefined
                  }
                  className={`w-full text-left flex flex-col gap-1 border-b border-border px-3 py-2.5 transition-colors hover:bg-elevated focus:outline focus:outline-2 focus:outline-accent ${
                    active ? "bg-accent/10" : ""
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`font-mono text-xs font-semibold truncate ${
                        active ? "text-accent" : "text-text"
                      }`}
                    >
                      {session.title || "Untitled"}
                    </span>
                    <span className="font-mono text-[10px] text-text-muted shrink-0">
                      {shortTimestamp(session.last_message_at ?? session.created_at)}
                    </span>
                  </div>
                  {session.last_message_preview ? (
                    <span className="font-mono text-[11px] text-text-muted line-clamp-2">
                      {session.last_message_preview}
                    </span>
                  ) : (
                    <span className="font-mono text-[11px] text-text-muted italic">
                      No messages yet
                    </span>
                  )}
                  <div className="flex items-center gap-2">
                    <AilaBadge severity="neutral" size="sm">
                      {session.message_count} msg
                    </AilaBadge>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      )}</AilaCard>
    </aside>
  );
}

// ---------------------------------------------------------------------------
// Message bubble
// ---------------------------------------------------------------------------

/**
 * Streaming / "thinking" indicator -- three hot-pink dots on a gentle
 * staggered opacity pulse. Hot pink (#ff5f87) is reserved for the live
 * state. The `animate-severity-pulse` utility is switched off under
 * prefers-reduced-motion (globals.css), leaving the dots visible but
 * static, so the affordance still reads without motion.
 */
function StreamingDots() {
  return (
    <span className="inline-flex items-center gap-1 py-0.5" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-accent animate-severity-pulse"
          style={{ animationDelay: `${i * 0.2}s` }}
        />
      ))}
    </span>
  );
}

function MessageBubble({
  role,
  content,
  createdAt,
  isStreaming,
}: {
  role: "user" | "assistant";
  content: string;
  createdAt?: string;
  isStreaming?: boolean;
}) {
  const isUser = role === "user";
  const align = isUser ? "items-end" : "items-start";
  const Icon = isUser ? UserIcon : Robot;
  // Hot pink is reserved for the live/active state, so a streaming turn is
  // the only one that gets the accent treatment. Resting turns sit on the
  // neutral charcoal tiers -- the operator's own turns lifted onto the
  // elevated tier, assistant turns on the surface tier.
  const bubbleTint = isStreaming
    ? "border-accent/50 bg-accent/5"
    : isUser
      ? "border-border bg-elevated"
      : "border-border bg-surface";
  const avatarTint = isStreaming
    ? "border-accent/50 bg-accent/10 text-accent"
    : isUser
      ? "border-border bg-elevated text-text-peach"
      : "border-border bg-elevated text-lavender";

  return (
    <div
      className={`flex flex-col gap-1.5 ${align}`}
      data-testid="chat-message"
      data-role={role}
    >
      {/* Role + metadata row. The operator's own turns mirror to the right
          so the two voices read as distinct columns of the transcript. */}
      <div
        className={`flex items-center gap-2 ${isUser ? "flex-row-reverse" : ""}`}
      >
        <span
          className={`inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-[4px] border ${avatarTint}`}
        >
          <Icon size={13} weight="bold" />
        </span>
        <span className="font-mono text-[11px] font-semibold text-text">
          {isUser ? "You" : "Assistant"}
        </span>
        <span className="font-mono text-[10px] text-text-muted">
          {isStreaming ? "streaming…" : shortTimestamp(createdAt)}
        </span>
      </div>
      <div
        className={`rounded-[4px] border px-3 py-2 max-w-[85%] font-mono text-xs leading-relaxed text-text whitespace-pre-wrap break-words ${bubbleTint}`}
      >
        {content || (isStreaming ? <StreamingDots /> : "")}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Composer
// ---------------------------------------------------------------------------

function Composer({
  value,
  onValueChange,
  onSend,
  disabled,
  textareaRef,
}: {
  value: string;
  onValueChange: (next: string) => void;
  onSend: (content: string) => void;
  disabled: boolean;
  textareaRef: React.RefObject<HTMLTextAreaElement | null>;
}) {
  const submit = () => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    onValueChange("");
    // Restore focus for rapid-fire chatting.
    requestAnimationFrame(() => textareaRef.current?.focus());
  };

  return (
    <div className="border-t border-border bg-surface p-3">
      {/* Input bay -- a recessed console well that lifts to the hot-pink
          accent on focus. The textarea's own frame + ring are neutralised
          so the bay owns a single, clear focus affordance. */}
      <div className="rounded-[4px] border border-border bg-base transition-colors focus-within:border-accent/60">
        <Textarea
          aria-label="Message composer"
          ref={textareaRef}
          value={value}
          onChange={(e) => onValueChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
          placeholder="Ask the platform anything -- Enter to send, Shift+Enter for newline."
          disabled={disabled}
          rows={3}
          data-testid="chat-composer"
          className="resize-none border-transparent bg-transparent font-mono text-xs focus-visible:border-transparent focus-visible:ring-0"
        />
        <div className="flex items-center justify-between gap-2 border-t border-border px-2.5 py-1.5">
          <span className="flex items-center gap-1.5 font-mono text-[10px] text-text-muted">
            {disabled ? (
              <>
                <span
                  className="h-1.5 w-1.5 rounded-full bg-accent animate-severity-pulse"
                  aria-hidden="true"
                />
                Streaming reply…
              </>
            ) : (
              `${value.length} characters`
            )}
          </span>
          <div className="flex items-center gap-2.5">
            <span className="hidden items-center gap-1 font-mono text-[10px] text-text-muted sm:inline-flex">
              <kbd className="rounded-[2px] border border-border bg-elevated px-1 py-px text-text">
                Enter
              </kbd>
              to send
            </span>
            <Button
              size="sm"
              variant="default"
              onClick={submit}
              disabled={disabled || value.trim().length === 0}
              data-testid="chat-send"
              className="gap-2"
            >
              <PaperPlaneRight size={14} weight="bold" />
              Send
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Thread panel
// ---------------------------------------------------------------------------

function ThreadPanel({
  sessionId,
  onCreateAndFocus,
}: {
  sessionId: string;
  onCreateAndFocus: () => void;
}) {
  const messagesQuery = useSessionMessages(sessionId);
  const { state, send } = useSendMessage(sessionId);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const composerRef = useRef<HTMLTextAreaElement | null>(null);
  const [draft, setDraft] = useState("");

  const seedComposer = (prompt: string) => {
    setDraft(prompt);
    // Defer focus so the textarea has the seeded value in the DOM
    // before the caret jump (otherwise selection collapses at index 0
    // which reads oddly for prompts with a <placeholder> token).
    requestAnimationFrame(() => {
      const el = composerRef.current;
      if (!el) return;
      el.focus();
      el.setSelectionRange(prompt.length, prompt.length);
    });
  };

  const persistedMessages: ChatMessage[] = useMemo(
    () => messagesQuery.data?.items ?? [],
    [messagesQuery.data],
  );

  // Auto-scroll to bottom when new messages arrive or tokens stream in.
  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return;
    node.scrollTop = node.scrollHeight;
  }, [persistedMessages.length, state.buffer, state.isStreaming]);

  if (!sessionId) {
    return (
      <div className="flex-1 min-w-0 flex items-center justify-center">
        <EmptyState
          icon={<ChatCircleDots size={40} />}
          title="Start a new chat"
          description="Ask the platform about your scans, findings, or operational posture. Replies stream token-by-token."
          action={{ label: "New chat", onClick: onCreateAndFocus }}
        />
      </div>
    );
  }

  if (messagesQuery.isLoading) {
    return (
      <div className="flex-1 min-w-0">
        <AilaCard variant="default" padding="md"><LoadingSkeletonGroup lines={6} /></AilaCard>
      </div>
    );
  }

  if (messagesQuery.isError) {
    return (
      <div className="flex-1 min-w-0">
        <AilaCard variant="default" padding="md"><div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          <div className="flex items-center gap-2 font-semibold">
            <Warning size={14} weight="bold" />
            {describeError(messagesQuery.error)}
          </div>
          {describeErrorHint(messagesQuery.error) && (
            <p className="mt-1 text-text-muted">
              {describeErrorHint(messagesQuery.error)}
            </p>
          )}
        </div></AilaCard>
      </div>
    );
  }

  const lastPersisted = persistedMessages[persistedMessages.length - 1];
  const userJustSent =
    state.isStreaming &&
    (!lastPersisted || lastPersisted.role !== "user");

  return (
    <div className="flex-1 min-w-0 flex flex-col border border-border rounded-[4px] bg-surface overflow-hidden">
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 flex flex-col gap-5"
        data-testid="chat-thread"
      >
        {persistedMessages.length === 0 && !state.isStreaming ? (
          <ChatLauncher onPick={seedComposer} />
        ) : (
          persistedMessages.map((msg) => (
            <MessageBubble
              key={msg.message_id}
              role={msg.role}
              content={msg.content}
              createdAt={msg.created_at}
            />
          ))
        )}

        {/* Live streaming assistant bubble */}
        {state.isStreaming && (
          <MessageBubble
            role="assistant"
            content={state.buffer}
            isStreaming
          />
        )}

        {/* Optional: show a placeholder while the backend is persisting the user message */}
        {userJustSent && state.buffer.length === 0 && (
          <p className="font-mono text-[10px] italic text-text-muted">
            Waiting for the assistant to respond…
          </p>
        )}

        {state.error && (
          <div
            className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive"
            role="alert" aria-live="assertive"
            data-testid="chat-error"
          >
            <div className="flex items-center gap-2 font-semibold">
              <Warning size={14} weight="bold" />
              {describeError(state.error)}
            </div>
            {describeErrorHint(state.error) && (
              <p className="mt-1 text-text-muted">
                {describeErrorHint(state.error)}
              </p>
            )}
          </div>
        )}
      </div>

      <Composer
        value={draft}
        onValueChange={setDraft}
        onSend={(content) => {
          void send(content);
        }}
        disabled={state.isStreaming}
        textareaRef={composerRef}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ChatPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const sessionParam = searchParams.get("session") ?? "";

  const sessionsQuery = useSessions();
  const createSession = useCreateSession();

  const sessions = sessionsQuery.data?.items ?? [];

  // Auto-select the newest session when the URL has no ?session= and there
  // are sessions available. Run on mount + when sessions list first loads.
  useEffect(() => {
    if (sessionParam || sessions.length === 0) return;
    const next = sessions[0];
    const params = new URLSearchParams(searchParams);
    params.set("session", next.session_id);
    setSearchParams(params, { replace: true });
  }, [sessionParam, sessions, searchParams, setSearchParams]);

  const handleSelect = (sessionId: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("session", sessionId);
    setSearchParams(params);
  };

  const handleCreate = async () => {
    try {
      const created = await createSession.mutateAsync(undefined);
      const params = new URLSearchParams(searchParams);
      params.set("session", created.session_id);
      setSearchParams(params);
    } catch {
      // apiErrorHandler (global) surfaces the toast; no local handling needed.
    }
  };

  return (
    <div className="flex flex-col gap-4 p-3 sm:p-4 lg:p-6">
      {sessionsQuery.isError && (
        <div
          className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive"
          data-testid="chat-sessions-error"
        >
          {describeError(sessionsQuery.error)}
          {describeErrorHint(sessionsQuery.error) && (
            <span className="ml-2 text-text-muted">
              {describeErrorHint(sessionsQuery.error)}
            </span>
          )}
        </div>
      )}
      {sessionParam && (
        <div className="flex items-center gap-2 font-mono text-[10px] text-text-muted">
          <span className="rounded-[2px] border border-border px-1.5 py-0.5 font-semibold uppercase tracking-widest">
            Session
          </span>
          <span>
            Started{" "}
            {formatTimestamp(
              sessions.find((s) => s.session_id === sessionParam)?.created_at,
            )}
          </span>
        </div>
      )}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-stretch min-h-[60vh]">
        <SessionsSidebar
          sessions={sessions}
          selectedId={sessionParam}
          isLoading={sessionsQuery.isLoading}
          isCreating={createSession.isPending}
          onSelect={handleSelect}
          onCreate={() => {
            void handleCreate();
          }}
        />
        <ThreadPanel
          sessionId={sessionParam}
          onCreateAndFocus={() => {
            void handleCreate();
          }}
        />
      </div>
    </div>
  );
}

export default ChatPage;
