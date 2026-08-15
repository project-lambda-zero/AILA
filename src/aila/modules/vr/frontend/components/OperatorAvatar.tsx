/**
 * Tiny operator avatar (08_FRONTEND_UX.md §1.1).
 *
 * Renders a 24px circle with the operator id's first character + a
 * deterministic background colour derived from the id hash. No
 * profile-image source today (the user record doesn't carry one);
 * this avatar identifies the operator at-a-glance on dense lists.
 */
// DS warm categorical hues hashed to an operator id (dark text on top).
const PALETTE = [
  "#af87d7", "#97dbbe", "#f0a8c7", "#ff5f87",
  "#b092ff", "#ffb85f", "#7bdfd3", "#c43b65",
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
        className="inline-flex items-center justify-center rounded-full bg-surface border border-border text-text-muted font-mono"
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
      className="inline-flex items-center justify-center rounded-full font-mono"
      style={{ width: size, height: size, fontSize: Math.floor(size * 0.42), background: colour, color: "#1a0a12" }}
      aria-label={`Operator ${operatorId}`}
    >
      {initial}
    </span>
  );
}
