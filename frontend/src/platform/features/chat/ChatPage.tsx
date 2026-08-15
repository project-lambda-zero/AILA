/**
 * ChatPage -- the platform Console, rebuilt from the design mock
 * (`AILA Console.dc.html`).
 *
 * Layout (over the shell's FaultyTerminal hero):
 *   Left  -- conversations WindowPanel: new-chat button + prior sessions.
 *   Centre -- CONSOLE WindowPanel: title bar (pink light + "console" +
 *             hatch grip + turn count), thread body (assistant / user
 *             mono bubbles + tag chips), suggestion-chip composer with a
 *             `>` prompt glyph + SEND key.
 *   Right -- vitals rail (hidden below xl).
 *
 * Preserves every hook (useSessions / useSendMessage / useSessionMessages /
 * useCreateSession), every route (search params for ?session=), every
 * `data-testid` and `aria-*`, and never fabricates data. There is NO import
 * from `@/components/ui/*` -- raw styled elements per the mock.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { ChatCircleDots } from "@phosphor-icons/react/dist/csr/ChatCircleDots";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { ApiHttpError } from "@platform/api/http";
import { ChatLauncher, LAUNCHER_CHIPS } from "./ChatLauncher";
import {
  useCreateSession,
  useSendMessage,
  useSessionMessages,
  useSessions,
  type ChatMessage,
  type SessionSummary,
} from "./queries";
import { ConsoleVitalsRail } from "./ConsoleVitalsRail";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function clockTag(value: string | null | undefined): string {
  if (!value) return "--:--:--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "--:--:--";
  const hh = String(parsed.getHours()).padStart(2, "0");
  const mm = String(parsed.getMinutes()).padStart(2, "0");
  const ss = String(parsed.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
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
// Sessions panel -- left column, mock's conversations rail.
// ---------------------------------------------------------------------------

function SessionsPanel({
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
    <WindowPanel
      title="conversations"
      className="hidden md:flex md:flex-col md:self-stretch"
      style={{ flex: "0 0 240px" }}
      flush
      actions={
        <button
          type="button"
          onClick={onCreate}
          disabled={isCreating}
          data-testid="chat-new-session"
          aria-label={isCreating ? "Creating a new chat" : "New chat"}
          className="flex items-center"
          style={{
            gap: 5,
            padding: "0 8px",
            height: 20,
            background: "transparent",
            border: "1px solid var(--border-soft)",
            borderRadius: 2,
            color: "var(--accent)",
            fontFamily: "var(--font-mono)",
            fontSize: 9,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            cursor: isCreating ? "wait" : "pointer",
            opacity: isCreating ? 0.6 : 1,
          }}
        >
          <Plus size={11} weight="bold" />
          <span>{isCreating ? "creating…" : "new"}</span>
        </button>
      }
    >
      {isLoading ? (
        <div style={{ padding: 10 }}>
          <LoadingSkeletonGroup lines={4} />
        </div>
      ) : sessions.length === 0 ? (
        <p
          style={{
            padding: "12px 12px 14px",
            fontFamily: "var(--font-mono)",
            fontSize: 10.5,
            color: "var(--text-muted)",
            lineHeight: 1.4,
            margin: 0,
          }}
        >
          No conversations yet. Start a new chat to ask the platform anything.
        </p>
      ) : (
        <ul
          className="flex flex-col"
          style={{
            listStyle: "none",
            padding: 0,
            margin: 0,
            maxHeight: "60vh",
            overflowY: "auto",
          }}
          role="listbox"
          aria-label="Conversations"
        >
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
                  className="flex w-full flex-col text-left"
                  style={{
                    gap: 4,
                    padding: "8px 11px",
                    borderTop: "1px solid var(--border-faint)",
                    background: active
                      ? "color-mix(in srgb, var(--accent) 10%, transparent)"
                      : "transparent",
                    boxShadow: active ? "inset 2px 0 0 var(--accent)" : "none",
                    border: "0",
                    cursor: "pointer",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <div className="flex items-center" style={{ gap: 6 }}>
                    <span
                      aria-hidden="true"
                      style={{
                        width: 6,
                        height: 6,
                        flex: "0 0 auto",
                        background: active ? "var(--accent)" : "var(--status-ok)",
                        boxShadow: active ? "0 0 6px var(--accent)" : "none",
                      }}
                    />
                    <span
                      className="truncate"
                      style={{
                        fontSize: 11,
                        color: active ? "var(--accent)" : "var(--text-primary)",
                        flex: 1,
                      }}
                      title={session.title || "Untitled"}
                    >
                      {session.title || "Untitled"}
                    </span>
                    <span
                      style={{
                        fontSize: 9,
                        color: "var(--text-faint)",
                        letterSpacing: "0.04em",
                        flex: "0 0 auto",
                      }}
                    >
                      {shortTimestamp(session.last_message_at ?? session.created_at)}
                    </span>
                  </div>
                  {session.last_message_preview ? (
                    <span
                      className="truncate"
                      style={{
                        fontSize: 10,
                        color: "var(--text-muted)",
                        letterSpacing: "0.02em",
                      }}
                      title={session.last_message_preview}
                    >
                      {session.last_message_preview}
                    </span>
                  ) : (
                    <span
                      style={{
                        fontSize: 10,
                        color: "var(--text-faint)",
                        fontStyle: "italic",
                      }}
                    >
                      No messages yet
                    </span>
                  )}
                  <span
                    style={{
                      marginTop: 2,
                      fontSize: 8.5,
                      letterSpacing: "0.14em",
                      textTransform: "uppercase",
                      color: "var(--text-faint)",
                    }}
                  >
                    {session.message_count} msg
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Streaming dots -- three hot-pink dots pulsing during a live turn.
// ---------------------------------------------------------------------------

function StreamingDots() {
  return (
    <span className="inline-flex items-center" aria-hidden="true" style={{ gap: 4, padding: "2px 0" }}>
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="animate-severity-pulse"
          style={{
            width: 5,
            height: 5,
            borderRadius: "50%",
            background: "var(--accent)",
            animationDelay: `${i * 0.2}s`,
          }}
        />
      ))}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Message bubble -- assistant left, user right; mock tag + timestamp + bubble.
// ---------------------------------------------------------------------------

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
  const tag = isUser ? "you" : "aila";
  const tagColor = isUser ? "var(--status-info)" : "var(--accent)";
  const bubbleBorder = isStreaming
    ? "1px solid color-mix(in srgb, var(--accent) 60%, var(--border-soft))"
    : "1px solid var(--border-soft)";
  const bubbleBg = isStreaming
    ? "color-mix(in srgb, var(--accent) 5%, var(--surface-sunk))"
    : "var(--surface-sunk)";

  return (
    <div
      data-testid="chat-message"
      data-role={role}
      className={`flex flex-col ${isUser ? "items-end" : "items-start"}`}
      style={{ gap: 6, fontFamily: "var(--font-mono)" }}
    >
      {/* Meta row -- tag + clock. Mirrors on user rows so the two voices
          read as distinct columns of the transcript. */}
      <div
        className="flex items-center"
        style={{
          gap: 8,
          flexDirection: isUser ? "row-reverse" : "row",
        }}
      >
        <span
          style={{
            padding: "1px 6px",
            fontSize: 9,
            letterSpacing: "0.16em",
            textTransform: "uppercase",
            border: `1px solid ${tagColor}`,
            color: tagColor,
            background: "color-mix(in srgb, currentColor 12%, transparent)",
            borderRadius: 2,
            fontWeight: 700,
          }}
        >
          {tag}
        </span>
        <span
          style={{
            fontSize: 9,
            letterSpacing: "0.08em",
            color: "var(--text-faint)",
          }}
        >
          {isStreaming ? "streaming…" : clockTag(createdAt)}
        </span>
      </div>

      {/* Bubble */}
      <div
        style={{
          maxWidth: "85%",
          padding: "9px 12px",
          border: bubbleBorder,
          background: bubbleBg,
          borderRadius: 3,
          fontFamily: "var(--font-sans)",
          fontSize: 12.5,
          lineHeight: 1.45,
          color: "var(--text-primary)",
          whiteSpace: "pre-wrap",
          overflowWrap: "anywhere",
        }}
      >
        {content || (isStreaming ? <StreamingDots /> : "")}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Composer -- suggestion chips + `>` prompt glyph + send key.
// ---------------------------------------------------------------------------

type ComposerMode = "auto" | "focus";

function Composer({
  value,
  onValueChange,
  onSend,
  disabled,
  inputRef,
  onPickChip,
}: {
  value: string;
  onValueChange: (next: string) => void;
  onSend: (content: string) => void;
  disabled: boolean;
  inputRef: React.RefObject<HTMLInputElement | null>;
  onPickChip: (prompt: string) => void;
}) {
  const [mode, setMode] = useState<ComposerMode>("auto");

  const submit = () => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    onValueChange("");
    requestAnimationFrame(() => inputRef.current?.focus());
  };

  return (
    <div
      style={{
        flex: "0 0 auto",
        padding: "10px 14px 12px",
        borderTop: "1px solid var(--border-soft)",
        background: "color-mix(in srgb, var(--surface-sunk) 60%, transparent)",
      }}
    >
      {/* Suggestion chip rail -- persistent, mirrors the launcher lanes. */}
      <div
        data-testid="chat-composer-chips"
        aria-label="Prompt suggestions"
        className="flex items-center overflow-x-auto"
        style={{ gap: 6, marginBottom: 9, paddingBottom: 2 }}
      >
        <span
          style={{
            flex: "0 0 auto",
            fontFamily: "var(--font-mono)",
            fontSize: 9,
            letterSpacing: "0.16em",
            textTransform: "uppercase",
            color: "var(--text-muted)",
          }}
        >
          lanes
        </span>
        {LAUNCHER_CHIPS.map((chip) => (
          <button
            key={chip.label}
            type="button"
            onClick={() => onPickChip(chip.prompt)}
            disabled={disabled}
            className="flex items-center"
            style={{
              flex: "0 0 auto",
              gap: 5,
              padding: "3px 8px",
              border: "1px solid var(--border-soft)",
              background: "var(--surface-card)",
              borderRadius: 2,
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              fontSize: 9.5,
              letterSpacing: "0.06em",
              cursor: disabled ? "not-allowed" : "pointer",
              opacity: disabled ? 0.5 : 1,
              whiteSpace: "nowrap",
            }}
          >
            <chip.Icon size={11} weight="bold" aria-hidden="true" />
            {chip.label}
          </button>
        ))}
      </div>

      {/* Input bay -- recessed console well framed in accent, `>` glyph left. */}
      <div
        className="flex items-center"
        style={{
          gap: 9,
          padding: "6px 8px 6px 12px",
          background: "var(--surface-card)",
          border: "1px solid color-mix(in srgb, var(--accent) 35%, transparent)",
          borderRadius: 3,
          boxShadow:
            "0 0 30px color-mix(in srgb, var(--accent) 12%, transparent), var(--bevel-raised)",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            flex: "0 0 auto",
            color: "var(--accent)",
            fontSize: 13,
            fontWeight: 700,
          }}
        >
          &gt;
        </span>
        <input
          ref={inputRef}
          aria-label="Message composer"
          value={value}
          onChange={(e) => onValueChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
          placeholder="describe a target or paste a repo / CVE / binary…"
          disabled={disabled}
          data-testid="chat-composer"
          style={{
            flex: 1,
            minWidth: 0,
            background: "transparent",
            border: 0,
            outline: 0,
            color: "var(--text-primary)",
            fontFamily: "var(--font-mono)",
            fontSize: 13,
            letterSpacing: "0.01em",
            height: 26,
          }}
        />

        {/* Mode toggle -- presentational segmented control. Local UI state
            only; routing/streaming is not gated on `mode`. Mirrors the
            mockup's modeBtn on the right of the input bay. */}
        <div
          role="radiogroup"
          aria-label="Composer mode"
          data-testid="chat-composer-mode"
          className="hidden items-center sm:inline-flex"
          style={{
            border: "1px solid var(--border-soft)",
            borderRadius: 2,
            overflow: "hidden",
            background: "var(--surface-sunk)",
            fontFamily: "var(--font-mono)",
          }}
        >
          {(["auto", "focus"] as const).map((m) => {
            const active = mode === m;
            return (
              <button
                key={m}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => setMode(m)}
                style={{
                  padding: "0 8px",
                  height: 22,
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                  background: active
                    ? "color-mix(in srgb, var(--accent) 15%, transparent)"
                    : "transparent",
                  color: active ? "var(--accent)" : "var(--text-muted)",
                  border: 0,
                  cursor: "pointer",
                }}
              >
                {m}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={submit}
          disabled={disabled || value.trim().length === 0}
          data-testid="chat-send"
          className="flex items-center"
          style={{
            gap: 6,
            padding: "0 14px",
            height: 26,
            background: "var(--accent)",
            border: "1px solid var(--accent)",
            borderRadius: 2,
            color: "var(--text-on-accent)",
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            fontWeight: 700,
            cursor: disabled || value.trim().length === 0 ? "not-allowed" : "pointer",
            opacity: disabled || value.trim().length === 0 ? 0.55 : 1,
            boxShadow:
              disabled || value.trim().length === 0
                ? "none"
                : "0 0 16px color-mix(in srgb, var(--accent) 30%, transparent)",
          }}
        >
          <span>send</span>
          <span style={{ fontSize: 11 }}>▸</span>
        </button>
      </div>

      {/* Foot hint */}
      <div
        className="flex items-center"
        style={{
          marginTop: 6,
          gap: 8,
          fontFamily: "var(--font-mono)",
          fontSize: 9,
          letterSpacing: "0.06em",
          color: "var(--text-faint)",
        }}
      >
        {disabled ? (
          <>
            <span
              className="animate-severity-pulse"
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: "var(--accent)",
              }}
              aria-hidden="true"
            />
            <span>streaming reply…</span>
          </>
        ) : (
          <>
            <span
              style={{
                border: "1px solid var(--border-soft)",
                padding: "1px 5px",
                borderRadius: 2,
                color: "var(--text-muted)",
                background: "var(--surface-sunk)",
              }}
            >
              enter
            </span>
            <span>to send · shift+enter newline</span>
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Thread panel -- centre CONSOLE WindowPanel.
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
  const composerRef = useRef<HTMLInputElement | null>(null);
  const [draft, setDraft] = useState("");

  const seedComposer = (prompt: string) => {
    setDraft(prompt);
    // Defer focus so the input has the seeded value before caret placement.
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

  const turnCount = persistedMessages.length + (state.isStreaming ? 1 : 0);

  if (!sessionId) {
    return (
      <WindowPanel
        title="console"
        status="no session bound"
        tone="muted"
        className="flex-1 self-stretch"
        style={{ minWidth: 0 }}
      >
        <div className="flex flex-1 items-center justify-center" style={{ padding: 24 }}>
          <EmptyState
            icon={<ChatCircleDots size={40} />}
            title="Start a new chat"
            description="Ask the platform about your scans, findings, or operational posture. Replies stream token-by-token."
            action={{ label: "New chat", onClick: onCreateAndFocus }}
          />
        </div>
      </WindowPanel>
    );
  }

  if (messagesQuery.isLoading) {
    return (
      <WindowPanel
        title="console"
        status="loading"
        className="flex-1 self-stretch"
        style={{ minWidth: 0 }}
      >
        <div style={{ padding: 12 }}>
          <LoadingSkeletonGroup lines={6} />
        </div>
      </WindowPanel>
    );
  }

  if (messagesQuery.isError) {
    return (
      <WindowPanel
        title="console"
        tone="accent"
        status="error"
        className="flex-1 self-stretch"
        style={{ minWidth: 0 }}
      >
        <div
          role="alert"
          aria-live="assertive"
          style={{
            padding: "9px 12px",
            border: "1px solid var(--accent)",
            background: "color-mix(in srgb, var(--accent) 8%, transparent)",
            borderRadius: 3,
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--accent)",
          }}
        >
          <div className="flex items-center" style={{ gap: 6, fontWeight: 700 }}>
            <Warning size={14} weight="bold" />
            {describeError(messagesQuery.error)}
          </div>
          {describeErrorHint(messagesQuery.error) && (
            <p style={{ marginTop: 4, color: "var(--text-muted)" }}>
              {describeErrorHint(messagesQuery.error)}
            </p>
          )}
        </div>
      </WindowPanel>
    );
  }

  const lastPersisted = persistedMessages[persistedMessages.length - 1];
  const userJustSent = state.isStreaming && (!lastPersisted || lastPersisted.role !== "user");

  return (
    <WindowPanel
      title="console"
      status={`bound · ${sessionId.slice(0, 8)} · ${turnCount} turn${turnCount === 1 ? "" : "s"}`}
      className="flex-1 self-stretch"
      style={{ minWidth: 0 }}
      flush
    >
      {/* Thread body */}
      <div
        ref={scrollRef}
        data-testid="chat-thread"
        className="flex flex-1 flex-col overflow-auto"
        style={{
          minHeight: 0,
          padding: "18px 18px 12px",
          gap: 16,
        }}
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
          <MessageBubble role="assistant" content={state.buffer} isStreaming />
        )}

        {userJustSent && state.buffer.length === 0 && (
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 10,
              fontStyle: "italic",
              color: "var(--text-muted)",
              margin: 0,
            }}
          >
            waiting for the assistant to respond…
          </p>
        )}

        {state.error && (
          <div
            role="alert"
            aria-live="assertive"
            data-testid="chat-error"
            style={{
              padding: "9px 12px",
              border: "1px solid var(--accent)",
              background: "color-mix(in srgb, var(--accent) 8%, transparent)",
              borderRadius: 3,
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--accent)",
            }}
          >
            <div className="flex items-center" style={{ gap: 6, fontWeight: 700 }}>
              <Warning size={14} weight="bold" />
              {describeError(state.error)}
            </div>
            {describeErrorHint(state.error) && (
              <p style={{ marginTop: 4, color: "var(--text-muted)" }}>
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
        inputRef={composerRef}
        onPickChip={seedComposer}
      />
    </WindowPanel>
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
    <div
      className="flex flex-col"
      style={{
        minHeight: "100%",
        padding: 12,
        gap: 10,
        color: "var(--text-primary)",
        fontFamily: "var(--font-mono)",
      }}
    >
      {sessionsQuery.isError && (
        <div
          data-testid="chat-sessions-error"
          style={{
            padding: "8px 12px",
            border: "1px solid var(--accent)",
            background: "color-mix(in srgb, var(--accent) 8%, transparent)",
            borderRadius: 3,
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--accent)",
          }}
        >
          {describeError(sessionsQuery.error)}
          {describeErrorHint(sessionsQuery.error) && (
            <span style={{ marginLeft: 6, color: "var(--text-muted)" }}>
              {describeErrorHint(sessionsQuery.error)}
            </span>
          )}
        </div>
      )}

      <div
        className="flex flex-col lg:flex-row"
        style={{
          gap: 10,
          alignItems: "stretch",
          flex: 1,
          minHeight: "70vh",
        }}
      >
        <SessionsPanel
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
        <ConsoleVitalsRail />
      </div>
    </div>
  );
}

export default ChatPage;
