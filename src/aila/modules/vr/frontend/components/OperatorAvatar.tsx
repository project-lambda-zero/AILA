/**
 * Operator avatar rendered as a mock square logo tile.
 *
 * 24x24 (or `size`), radius 2 (mock square-with-slight-round), initial in
 * mono, background hashed deterministically from operator id across the
 * five status/accent tokens. Unknown operator → sunk surface + text-faint.
 */

// Five mock-token palette entries. Text-on-accent renders legibly on all.
const PALETTE = [
  "var(--status-ok)",
  "var(--status-warn)",
  "var(--status-info)",
  "var(--status-signal)",
  "var(--accent)",
];

function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

export function OperatorAvatar({
  operatorId,
  size = 24,
}: {
  operatorId: string | null | undefined;
  size?: number;
}) {
  const fontSize = Math.max(9, Math.floor(size * 0.42));
  if (!operatorId) {
    return (
      <span
        title="No operator recorded"
        aria-label="No operator"
        className="inline-flex items-center justify-center font-mono uppercase"
        style={{
          width: size,
          height: size,
          fontSize,
          borderRadius: 2,
          background: "var(--surface-sunk)",
          color: "var(--text-faint)",
          border: "1px solid var(--border-faint)",
        }}
      >
        ?
      </span>
    );
  }
  const initial = operatorId.trim().charAt(0).toUpperCase() || "?";
  const colour = PALETTE[hashString(operatorId) % PALETTE.length];
  return (
    <span
      title={`Operator: ${operatorId}`}
      aria-label={`Operator ${operatorId}`}
      className="inline-flex items-center justify-center font-mono uppercase"
      style={{
        width: size,
        height: size,
        fontSize,
        borderRadius: 2,
        background: colour,
        color: "var(--text-on-accent)",
      }}
    >
      {initial}
    </span>
  );
}
