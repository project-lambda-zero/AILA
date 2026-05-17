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
 *    - ``compact``: render an "✕" icon instead of "Delete" text (table rows)
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
        className="px-2 py-0.5 text-xs font-mono text-text-muted hover:text-text-danger hover:bg-surface-hover rounded transition-colors disabled:opacity-50"
      >
        ✕
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={mutation.isPending}
      className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-danger text-text-danger hover:bg-surface-danger/10 disabled:opacity-50"
    >
      {mutation.isPending ? "Deleting…" : "Delete"}
    </button>
  );
}
