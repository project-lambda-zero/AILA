import { useSyncExternalStore } from "react";

// Transient, non-blocking operator feedback for actions whose result would
// otherwise be silent (exports, downloads, sends, status changes). Persisted
// platform alerts live in NotificationsCenter; this is the in-memory channel
// for "your click did / did not work". Callable from anywhere, including
// react-query onError/onSuccess callbacks, via the `toast` object.

export type ToastTone = "info" | "success" | "error";

export interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
}

const LIFETIME_MS = { info: 4000, success: 4000, error: 8000 } satisfies Record<ToastTone, number>;
const MAX_VISIBLE = 4;

let toasts: readonly Toast[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function emit(): void {
  for (const l of listeners) l();
}

export function dismissToast(id: number): void {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

function push(tone: ToastTone, message: string): number {
  const id = nextId++;
  toasts = [...toasts, { id, tone, message }].slice(-MAX_VISIBLE);
  emit();
  setTimeout(() => dismissToast(id), LIFETIME_MS[tone]);
  return id;
}

// Human-readable text for a thrown value; ApiError and Error carry .message.
export function errorText(err: unknown, fallback = "request failed"): string {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "string" && err) return err;
  return fallback;
}

export const toast = {
  info: (message: string) => push("info", message),
  success: (message: string) => push("success", message),
  error: (message: string) => push("error", message),
  // `label failed: <reason>` for a caught error, e.g. toast.fail("export", e).
  fail: (label: string, err: unknown) => push("error", `${label} failed: ${errorText(err)}`),
};

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function snapshot(): readonly Toast[] {
  return toasts;
}

const TONE_COLOR = {
  info: "var(--status-info)",
  success: "var(--status-ok)",
  error: "var(--accent)",
} satisfies Record<ToastTone, string>;

export function ToastViewport() {
  const items = useSyncExternalStore(subscribe, snapshot, snapshot);
  if (items.length === 0) return null;
  return (
    <div
      aria-live="polite"
      style={{
        position: "fixed",
        right: 16,
        bottom: 40,
        zIndex: 1000,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        maxWidth: 420,
      }}
    >
      {items.map((t) => (
        <div
          key={t.id}
          role={t.tone === "error" ? "alert" : "status"}
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 10,
            padding: "10px 6px 10px 12px",
            background: "var(--surface-card)",
            border: "1px solid var(--border)",
            borderLeft: `3px solid ${TONE_COLOR[t.tone]}`,
            color: "var(--text-primary)",
            fontFamily: "var(--font-sans)",
            fontSize: 13,
            lineHeight: 1.5,
            boxShadow: "0 6px 24px rgba(0,0,0,0.35)",
          }}
        >
          <span style={{ flex: 1, wordBreak: "break-word" }}>{t.message}</span>
          <button
            type="button"
            aria-label="dismiss"
            onClick={() => dismissToast(t.id)}
            style={{
              minWidth: 28,
              minHeight: 28,
              background: "transparent",
              border: 0,
              color: "var(--text-muted)",
              cursor: "pointer",
              fontSize: 14,
            }}
          >
            {"\u2715"}
          </button>
        </div>
      ))}
    </div>
  );
}
