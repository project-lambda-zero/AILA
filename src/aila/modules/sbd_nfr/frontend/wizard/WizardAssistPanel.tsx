import { useEffect, useRef, useState } from "react";

import { useAssistChat } from "../queries";

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface WizardAssistPanelProps {
  questionId: string;
  questionLabel: string;
  currentAnswer: string | null;
  onClose: () => void;
}

// ──────────────────────────────────────────────────────────────────────────────
// WizardAssistPanel — slide-out LLM assist chat panel (D-10)
//
// Slides in from the right. Width: 400px on wide viewports, 100% on mobile.
// Security: T-137-16 — backend validates message length and history count.
// Privacy: T-137-15 — chat history is local state only, cleared on close.
// ──────────────────────────────────────────────────────────────────────────────

const MESSAGE_BASE = "rounded-md px-3 py-2 text-sm";
const MESSAGE_STYLE = { maxWidth: "85%" } as const;
const MESSAGE_USER = "self-end bg-accent text-badge-text";
const MESSAGE_ASSISTANT = "self-start bg-surface text-text";

export function WizardAssistPanel({
  questionId,
  questionLabel,
  currentAnswer,
  onClose,
}: WizardAssistPanelProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [sendError, setSendError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const assistMutation = useAssistChat(questionId);

  // Auto-scroll to bottom when messages update
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  }

  async function handleSend() {
    const text = inputValue.trim();
    if (!text || assistMutation.isPending) return;

    const userMessage: ChatMessage = { role: "user", content: text };
    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);
    setInputValue("");
    setSendError(null);

    try {
      // Backend enforces max 40 history turns (T-137-16)
      const historyForApi = updatedMessages.slice(-40).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const result = await assistMutation.mutateAsync({
        message: text,
        history: historyForApi,
        current_answer: currentAnswer,
      });

      const assistantMessage: ChatMessage = {
        role: "assistant",
        content: result.reply,
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Could not get a response.";
      setSendError(msg);
    }
  }

  const isPending = assistMutation.isPending;

  return (
    <div
      className="fixed inset-y-0 right-0 z-50 w-80 bg-elevated border-l border-border flex flex-col"
      role="complementary"
      aria-label={`Ask AI about: ${questionLabel}`}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-border">
        <span className="text-xs text-text-muted truncate" title={questionLabel}>
          Ask AI about: <strong>{questionLabel}</strong>
        </span>
        <button
          className="text-text-muted hover:text-text cursor-pointer"
          type="button"
          onClick={onClose}
          aria-label="Close AI assistant"
        >
          ×
        </button>
      </div>

      {/* Message list */}
      <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2" aria-live="polite">
        {messages.length === 0 && (
          <p className="text-sm text-text-muted text-center mt-8">
            Ask a question about this requirement to get AI guidance.
          </p>
        )}
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`${MESSAGE_BASE} ${msg.role === "user" ? MESSAGE_USER : MESSAGE_ASSISTANT}`}
            style={MESSAGE_STYLE}
          >
            {msg.content}
          </div>
        ))}
        {isPending && (
          <div className={`${MESSAGE_BASE} ${MESSAGE_ASSISTANT} opacity-60`} style={MESSAGE_STYLE}>
            <span className="inline-block animate-pulse" aria-label="AI is thinking">
              ···
            </span>
          </div>
        )}
        {sendError && (
          <p className="text-xs text-critical px-3">{sendError}</p>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input area */}
      <div className="p-3 border-t border-border flex gap-2">
        <input
          className="flex-1 p-2 rounded-md border border-border bg-surface text-text text-sm"
          type="text"
          placeholder="Ask a question..."
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isPending}
          aria-label="Your message"
          maxLength={2000}
        />
        <button
          className="px-3 py-2 rounded-md bg-accent text-badge-text font-semibold text-sm disabled:opacity-40"
          type="button"
          onClick={() => void handleSend()}
          disabled={isPending || !inputValue.trim()}
          aria-label="Send message"
        >
          Send
        </button>
      </div>
    </div>
  );
}
