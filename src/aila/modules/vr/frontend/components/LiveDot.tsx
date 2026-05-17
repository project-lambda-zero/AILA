/** Tri-state SSE connection indicator from 08_FRONTEND_UX.md §2.1.
 *  Green = connected, amber = reconnecting, red = disconnected. */
export type LiveStatus = "connected" | "reconnecting" | "disconnected";

const TONE: Record<LiveStatus, string> = {
  connected: "bg-green-500 shadow-green-500/50",
  reconnecting: "bg-amber-500 shadow-amber-500/50 animate-pulse",
  disconnected: "bg-red-500 shadow-red-500/50",
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
  return (
    <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wide">
      <span
        className={`w-1.5 h-1.5 rounded-full shadow-[0_0_4px] ${TONE[status]}`}
      />
      {showLabel && (
        <span className="text-text-muted">{LABEL[status]}</span>
      )}
    </span>
  );
}
