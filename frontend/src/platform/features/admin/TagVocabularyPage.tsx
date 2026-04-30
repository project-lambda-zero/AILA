import { useMemo, useState } from "react";
import { Tag as TagIcon, Plus, Trash } from "@phosphor-icons/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  useTagVocabulary,
  useCreateTagVocab,
  useDeleteTagVocab,
  useSystems,
  type TagVocabEntry,
} from "@platform/features/systems/api";

interface DeleteDialogProps {
  entry: TagVocabEntry | null;
  usageCount: number;
  onClose: () => void;
  onConfirm: (tagKey: string) => Promise<void>;
  isPending: boolean;
}

function DeleteVocabDialog({
  entry,
  usageCount,
  onClose,
  onConfirm,
  isPending,
}: DeleteDialogProps) {
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    if (!entry) return;
    setError(null);
    try {
      await onConfirm(entry.tag_key);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete tag key.");
    }
  }

  function handleOpenChange(open: boolean) {
    if (!open) {
      setError(null);
      onClose();
    }
  }

  return (
    <Dialog open={entry !== null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Delete Tag Key</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-4 py-3">
            <p className="font-mono text-xs text-destructive font-semibold mb-1">
              This action cannot be undone.
            </p>
            <p className="font-mono text-xs text-text-muted">
              Deleting{" "}
              <span className="text-text font-semibold">{entry?.tag_key}</span>{" "}
              removes it from the vocabulary. New systems will not be able to
              use this key.
              {usageCount > 0 && (
                <>
                  {" "}
                  <span className="text-destructive font-semibold">
                    {usageCount} system{usageCount === 1 ? "" : "s"}
                  </span>{" "}
                  currently use this key.
                </>
              )}
            </p>
          </div>

          {entry?.is_system_default && (
            <div className="rounded-[4px] border border-border bg-elevated px-3 py-2 font-mono text-xs text-text-muted">
              System defaults are locked by the backend and will return a 409.
            </div>
          )}

          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              className="flex-1 bg-destructive hover:bg-destructive/90 text-white"
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Deleting…" : "Delete Tag Key"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={onClose}
            >
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const SLUG_PATTERN = /^[a-z0-9_-]+$/i;

/**
 * TagVocabularyPage — admin-only management of asset tag keys (v6.0).
 *
 * Lists every tag key in the vocabulary with a usage count derived from the
 * current systems sample, lets admins add new keys (POST /tags/vocabulary),
 * and delete user-defined keys (DELETE /tags/vocabulary/{tag_key}). System
 * defaults are visible but cannot be deleted; the backend returns 409 and
 * the dialog surfaces that error verbatim.
 *
 * Usage counts are computed client-side from a single page of /systems with
 * page_size=250 (the backend cap). When the fleet exceeds that, the table
 * footer notes the sample size so operators don't read the count as global.
 */
export function TagVocabularyPage() {
  const vocabQuery = useTagVocabulary();
  // page_size=250 is the backend cap (see systems router) — covers the common
  // case while keeping a single round-trip for usage tallying.
  const systemsQuery = useSystems(1, 250);
  const createMutation = useCreateTagVocab();
  const deleteMutation = useDeleteTagVocab();

  const [newKey, setNewKey] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<TagVocabEntry | null>(null);

  const vocabulary = vocabQuery.data ?? [];
  const systems = systemsQuery.data?.items ?? [];
  const totalSystems = systemsQuery.data?.total ?? 0;
  const sampledSystems = systems.length;

  const usageCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const system of systems) {
      const seenKeys = new Set<string>();
      for (const tag of system.tags ?? []) {
        // Count each key once per system — assigning the same key twice with
        // different values (env=prod, env=staging) shouldn't inflate usage.
        if (seenKeys.has(tag.tag_key)) continue;
        seenKeys.add(tag.tag_key);
        counts.set(tag.tag_key, (counts.get(tag.tag_key) ?? 0) + 1);
      }
    }
    return counts;
  }, [systems]);

  const userDefinedCount = vocabulary.filter((entry) => !entry.is_system_default).length;
  const inUseCount = vocabulary.filter(
    (entry) => (usageCounts.get(entry.tag_key) ?? 0) > 0,
  ).length;

  function handleCreate(event: React.FormEvent) {
    event.preventDefault();
    setCreateError(null);
    const trimmedKey = newKey.trim();
    if (!trimmedKey) {
      setCreateError("Tag key is required.");
      return;
    }
    if (!SLUG_PATTERN.test(trimmedKey)) {
      setCreateError("Tag keys may contain only letters, digits, underscores, and dashes.");
      return;
    }
    createMutation.mutate(
      { tag_key: trimmedKey, description: newDescription.trim() },
      {
        onSuccess: () => {
          setNewKey("");
          setNewDescription("");
          setCreateError(null);
        },
        onError: (err) => {
          setCreateError(err instanceof Error ? err.message : "Failed to create tag key.");
        },
      },
    );
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
            <TagIcon className="h-5 w-5 text-accent" />
            Tag Vocabulary
          </h1>
          <p className="font-mono text-sm text-text-muted mt-0.5">
            Admin-managed tag keys. Operators can assign any key listed here to a system.
          </p>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Total Keys
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {vocabQuery.isLoading ? "—" : vocabulary.length}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Defaults + custom
          </p>
        </AilaCard>
        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Custom Keys
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {vocabQuery.isLoading ? "—" : userDefinedCount}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Added by admins
          </p>
        </AilaCard>
        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Keys In Use
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {systemsQuery.isLoading || vocabQuery.isLoading ? "—" : inUseCount}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Assigned to ≥1 system
          </p>
        </AilaCard>
      </div>

      {/* Add tag key form */}
      <AilaCard variant="elevated" padding="md">
        <h2 className="font-mono text-sm font-semibold text-text mb-3">
          Add Tag Key
        </h2>
        <form
          onSubmit={handleCreate}
          className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,200px)_1fr_auto] sm:items-end"
        >
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="vocab-key"
            >
              Tag Key
            </label>
            <Input
              id="vocab-key"
              value={newKey}
              onChange={(e) => setNewKey(e.target.value)}
              placeholder="environment"
              disabled={createMutation.isPending}
              className="font-mono text-sm"
              autoComplete="off"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="vocab-desc"
            >
              Description (optional)
            </label>
            <Input
              id="vocab-desc"
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Deployment environment (prod, staging, dev)"
              disabled={createMutation.isPending}
              className="font-mono text-sm"
              autoComplete="off"
            />
          </div>
          <Button
            type="submit"
            size="sm"
            className="gap-1.5 sm:self-end"
            disabled={createMutation.isPending || !newKey.trim()}
          >
            <Plus className="h-4 w-4" />
            {createMutation.isPending ? "Adding…" : "Add Key"}
          </Button>
        </form>
        {createError && (
          <div className="mt-3 rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {createError}
          </div>
        )}
      </AilaCard>

      {/* Error banner */}
      {vocabQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load tag vocabulary: {(vocabQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {vocabQuery.isLoading && (
        <AilaCard variant="default" padding="md">
          <LoadingSkeletonGroup lines={5} />
        </AilaCard>
      )}

      {/* Empty state */}
      {!vocabQuery.isLoading && !vocabQuery.isError && vocabulary.length === 0 && (
        <EmptyState
          icon={<TagIcon className="h-10 w-10" />}
          title="No tag keys defined"
          description="Add a tag key above so operators can categorize systems."
        />
      )}

      {/* Vocabulary table */}
      {!vocabQuery.isLoading && vocabulary.length > 0 && (
        <AilaCard variant="default" padding="none">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-border bg-elevated">
                <tr>
                  <th className="px-4 py-2 text-left font-mono text-xs uppercase tracking-wider text-text-muted">
                    Tag Key
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-xs uppercase tracking-wider text-text-muted">
                    Description
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-xs uppercase tracking-wider text-text-muted">
                    Source
                  </th>
                  <th className="px-4 py-2 text-right font-mono text-xs uppercase tracking-wider text-text-muted">
                    Usage
                  </th>
                  <th className="px-4 py-2 text-right font-mono text-xs uppercase tracking-wider text-text-muted">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {vocabulary.map((entry) => {
                  const usage = usageCounts.get(entry.tag_key) ?? 0;
                  return (
                    <tr
                      key={entry.id}
                      className="border-b border-border last:border-b-0 hover:bg-elevated/40 transition-colors duration-100"
                    >
                      <td className="px-4 py-2 align-top">
                        <span className="font-mono text-sm font-semibold text-text">
                          {entry.tag_key}
                        </span>
                      </td>
                      <td className="px-4 py-2 align-top">
                        <span className="font-mono text-xs text-text-muted">
                          {entry.description || "—"}
                        </span>
                      </td>
                      <td className="px-4 py-2 align-top">
                        {entry.is_system_default ? (
                          <AilaBadge severity="neutral" size="sm">
                            system default
                          </AilaBadge>
                        ) : (
                          <AilaBadge severity="info" size="sm">
                            custom
                          </AilaBadge>
                        )}
                      </td>
                      <td className="px-4 py-2 align-top text-right">
                        {systemsQuery.isLoading ? (
                          <span className="font-mono text-xs text-text-muted">
                            —
                          </span>
                        ) : (
                          <span
                            className={`font-mono text-xs ${
                              usage > 0 ? "text-text" : "text-text-muted"
                            }`}
                          >
                            {usage}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 align-top text-right">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          className="text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive disabled:opacity-40 gap-1.5"
                          disabled={
                            entry.is_system_default || deleteMutation.isPending
                          }
                          onClick={() => setPendingDelete(entry)}
                          aria-label={`Delete tag key ${entry.tag_key}`}
                        >
                          <Trash className="h-3.5 w-3.5" />
                          Delete
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {totalSystems > sampledSystems && (
            <p className="px-4 py-2 font-mono text-xs text-text-muted border-t border-border">
              Usage counts derived from {sampledSystems} of {totalSystems}{" "}
              systems. Counts may understate global usage when the fleet exceeds
              the page cap.
            </p>
          )}
        </AilaCard>
      )}

      <DeleteVocabDialog
        entry={pendingDelete}
        usageCount={
          pendingDelete ? usageCounts.get(pendingDelete.tag_key) ?? 0 : 0
        }
        onClose={() => setPendingDelete(null)}
        onConfirm={(tagKey) => deleteMutation.mutateAsync(tagKey).then(() => undefined)}
        isPending={deleteMutation.isPending}
      />
    </div>
  );
}
