/**
 * Tiny operator avatar (08_FRONTEND_UX.md §1.1).
 *
 * Renders a 24px circle with the operator id's first character + a
 * deterministic background colour derived from the id hash. No
 * profile-image source today (the user record doesn't carry one);
 * this avatar identifies the operator at-a-glance on dense lists.
 */
const PALETTE = [
  "bg-violet-600", "bg-emerald-600", "bg-amber-600", "bg-pink-600",
  "bg-cyan-600", "bg-rose-600", "bg-indigo-600", "bg-teal-600",
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
  if (!operatorId) {
    return (
      <span
        title="No operator recorded"
        className="inline-flex items-center justify-center rounded-full bg-surface border border-border-default text-text-muted font-mono"
        style={{ width: size, height: size, fontSize: Math.floor(size * 0.42) }}
        aria-label="No operator"
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
      className={`inline-flex items-center justify-center rounded-full text-white font-mono ${colour}`}
      style={{ width: size, height: size, fontSize: Math.floor(size * 0.42) }}
      aria-label={`Operator ${operatorId}`}
    >
      {initial}
    </span>
  );
}
