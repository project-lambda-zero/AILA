import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import {
  useSystemTags,
  useTagVocabulary,
  useAssignTag,
  useRemoveTag,
  type TagVocabEntry,
} from "./api";

interface SystemTagsProps {
  systemId: number;
}

/**
 * SystemTags — tag assignment tab content for system detail page (D-10).
 *
 * Shows current tags as removable AilaBadges (operator+ only for removal).
 * Add tag form: vocabulary-constrained Select + value Input + Add button.
 * 409/422 errors shown inline below the form, not as toast (D-15).
 * Reader role sees tags but cannot add or remove (D-10).
 */
export function SystemTags({ systemId }: SystemTagsProps) {
  const { role } = useAuthStore();
  const canOperate = isAllowedRole(role, "operator");

  const tagsQuery = useSystemTags(systemId);
  const vocabQuery = useTagVocabulary();
  const assignTag = useAssignTag(systemId);
  const removeTag = useRemoveTag(systemId);

  const [selectedKey, setSelectedKey] = useState("");
  const [tagValue, setTagValue] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const tags = tagsQuery.data ?? [];
  const vocabulary: TagVocabEntry[] = vocabQuery.data ?? [];

  function handleAdd(event: React.FormEvent) {
    event.preventDefault();
    setFormError(null);
    if (!selectedKey.trim() || !tagValue.trim()) {
      setFormError("Both tag key and value are required.");
      return;
    }
    assignTag.mutate(
      { tag_key: selectedKey, tag_value: tagValue },
      {
        onSuccess: () => {
          setSelectedKey("");
          setTagValue("");
          setFormError(null);
        },
        onError: (err) => {
          setFormError((err as Error).message ?? "Failed to assign tag.");
        },
      },
    );
  }

  function handleRemove(tagId: number) {
    removeTag.mutate(tagId, {
      onError: (err) => {
        setFormError((err as Error).message ?? "Failed to remove tag.");
      },
    });
  }

  if (tagsQuery.isLoading) {
    return (
      <AilaCard variant="default" padding="md">
        <LoadingSkeletonGroup lines={4} />
      </AilaCard>
    );
  }

  if (tagsQuery.isError) {
    return (
      <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
        {(tagsQuery.error as Error).message}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Current tags */}
      <AilaCard variant="default" padding="md">
        <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">
          Assigned Tags
        </h3>
        {tags.length === 0 ? (
          <p className="font-mono text-sm text-text-muted">
            No tags assigned. {canOperate ? "Add a tag below to organize this system." : ""}
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {tags.map((tag) => (
              <span key={tag.id} className="inline-flex items-center gap-1">
                <AilaBadge severity="info" size="sm">
                  {tag.tag_key}: {tag.tag_value}
                </AilaBadge>
                {canOperate && (
                  <button
                    type="button"
                    onClick={() => handleRemove(tag.id)}
                    disabled={removeTag.isPending}
                    className="ml-0.5 font-mono text-xs text-text-muted hover:text-destructive transition-colors duration-100 disabled:opacity-40"
                    aria-label={`Remove tag ${tag.tag_key}: ${tag.tag_value}`}
                  >
                    ×
                  </button>
                )}
              </span>
            ))}
          </div>
        )}
      </AilaCard>

      {/* Add tag form — operator+ only */}
      {canOperate && (
        <AilaCard variant="elevated" padding="md">
          <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">
            Add Tag
          </h3>
          <form onSubmit={handleAdd} className="flex flex-col gap-3">
            <div className="flex flex-wrap gap-2 items-end">
              <div className="flex flex-col gap-1 min-w-[160px]">
                <label className="font-mono text-xs text-text-muted" htmlFor="tag-key-select">
                  Tag Key
                </label>
                <select
                  id="tag-key-select"
                  value={selectedKey}
                  onChange={(e) => setSelectedKey(e.target.value)}
                  disabled={vocabQuery.isLoading || assignTag.isPending}
                  className="rounded-[2px] border border-border bg-base font-mono text-sm text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100 disabled:opacity-50"
                >
                  <option value="">Select key...</option>
                  {vocabulary.map((entry) => (
                    <option key={entry.id} value={entry.tag_key}>
                      {entry.tag_key}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex flex-col gap-1 min-w-[160px]">
                <label className="font-mono text-xs text-text-muted" htmlFor="tag-value-input">
                  Tag Value
                </label>
                <Input
                  id="tag-value-input"
                  value={tagValue}
                  onChange={(e) => setTagValue(e.target.value)}
                  placeholder="e.g. production"
                  disabled={assignTag.isPending}
                  className="font-mono text-sm"
                />
              </div>
              <Button
                type="submit"
                disabled={assignTag.isPending || !selectedKey || !tagValue.trim()}
                size="sm"
              >
                {assignTag.isPending ? "Adding..." : "Add Tag"}
              </Button>
            </div>

            {formError && (
              <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                {formError}
              </div>
            )}
          </form>
        </AilaCard>
      )}
    </div>
  );
}
