import type { UseMutationResult } from "@tanstack/react-query";

/** Reusable destructive-action button.
 *
 *  Pops a native ``window.confirm`` so we don't drag in a dialog library
 *  for a single use case. The mutation hook is created by the caller via
 *  ``useDeleteX()`` from ``mutations.ts`` so the parent owns React Query
 *  cache invalidation.
 *
 *  Props:
 *    - ``id``: the row identifier passed straight to the mutation
 *    - ``label``: operator-visible noun (e.g. "investigation 'CVE-2024-...'")
 *    - ``mutation``: instance of one of the useDeleteX hooks
 *    - ``compact``: render an "×" glyph instead of "delete" text (table rows)
 *    - ``onDeleted``: optional callback fired after the mutation succeeds;
 *      typically used by detail pages to navigate back to the list */
export function DeleteButton({
  id,
  label,
  mutation,
  compact = false,
  onDeleted,
}: {
  id: string;
  label: string;
  mutation: UseMutationResult<unknown, Error, { id: string }>;
  compact?: boolean;
  onDeleted?: () => void;
}) {
  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (!window.confirm(`Delete ${label}? This cannot be undone.`)) return;
    mutation.mutate({ id }, { onSuccess: () => onDeleted?.() });
  };

  if (compact) {
    return (
      <button
        type="button"
        onClick={handleClick}
        disabled={mutation.isPending}
        title={`Delete ${label}`}
        aria-label={`Delete ${label}`}
        className="font-mono inline-flex items-center justify-center"
        style={{
          width: 22,
          height: 22,
          border: "1px solid var(--border-soft)",
          background: "transparent",
          color: "var(--text-muted)",
          fontSize: 12,
          lineHeight: 1,
          cursor: "pointer",
          borderRadius: 2,
          opacity: mutation.isPending ? 0.5 : 1,
        }}
        onMouseOver={(e) => {
          if (mutation.isPending) return;
          e.currentTarget.style.color = "var(--accent)";
          e.currentTarget.style.borderColor = "var(--accent)";
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.color = "var(--text-muted)";
          e.currentTarget.style.borderColor = "var(--border-soft)";
        }}
      >
        ×
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={mutation.isPending}
      className="font-mono uppercase"
      style={{
        height: 26,
        padding: "0 12px",
        border: "1px solid var(--accent)",
        color: "var(--accent)",
        background: "transparent",
        fontSize: 10,
        letterSpacing: "0.08em",
        borderRadius: 2,
        cursor: "pointer",
        opacity: mutation.isPending ? 0.5 : 1,
      }}
      onMouseOver={(e) => {
        if (mutation.isPending) return;
        e.currentTarget.style.background =
          "color-mix(in srgb, var(--accent) 12%, transparent)";
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.background = "transparent";
      }}
    >
      {mutation.isPending ? "deleting…" : "delete"}
    </button>
  );
}
