/** Tri-state SSE connection indicator from 08_FRONTEND_UX.md §2.1.
 *  Green = connected, amber = reconnecting, red = disconnected. */
export type LiveStatus = "connected" | "reconnecting" | "disconnected";

const TONE: Record<LiveStatus, { color: string; pulse: boolean }> = {
  connected:    { color: "var(--color-mint)", pulse: false }, // DS mint -- ok
  reconnecting: { color: "var(--color-amber)", pulse: true },  // DS amber -- warn
  disconnected: { color: "var(--color-accent)", pulse: false }, // DS accent -- failed
};

const LABEL: Record<LiveStatus, string> = {
  connected: "live",
  reconnecting: "reconnecting",
  disconnected: "offline",
};

export function LiveDot({
  status,
  showLabel = true,
}: {
  status: LiveStatus;
  showLabel?: boolean;
}) {
  const tone = TONE[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-3xs font-mono uppercase tracking-wide">
      <span
        className={`w-1.5 h-1.5 rounded-full ${tone.pulse ? "animate-pulse motion-reduce:animate-none" : ""}`}
        style={{
          backgroundColor: tone.color,
          boxShadow: `0 0 4px ${tone.color}80`,
        }}
      />
      {showLabel && (
        <span className="text-text-muted">{LABEL[status]}</span>
      )}
    </span>
  );
}
