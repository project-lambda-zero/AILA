/** Tri-state SSE connection indicator, rendered as a mock chip.
 *  connected → LIVE (mint); reconnecting → RECONNECTING (amber, pulsing);
 *  disconnected → OFFLINE (accent). */
export type LiveStatus = "connected" | "reconnecting" | "disconnected";

const TONE: Record<LiveStatus, { color: string; label: string; pulse: boolean }> = {
  connected: { color: "var(--status-ok)", label: "LIVE", pulse: false },
  reconnecting: { color: "var(--status-warn)", label: "RECONNECTING", pulse: true },
  disconnected: { color: "var(--accent)", label: "OFFLINE", pulse: false },
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
    <span
      className="inline-flex items-center font-mono uppercase"
      style={{
        gap: 5,
        padding: "0 6px",
        height: 18,
        border: `1px solid ${tone.color}`,
        background: `color-mix(in srgb, ${tone.color} 12%, transparent)`,
        color: tone.color,
        fontSize: 8.5,
        letterSpacing: "0.14em",
      }}
      aria-label={`SSE ${tone.label.toLowerCase()}`}
    >
      <span
        aria-hidden
        style={{
          width: 5,
          height: 5,
          background: tone.color,
          animation: tone.pulse ? "severity-pulse 1.4s ease-in-out infinite" : undefined,
        }}
      />
      {showLabel && <span>{tone.label}</span>}
    </span>
  );
}
