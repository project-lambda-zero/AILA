import { useState } from "react";

import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
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

// Shared inline styles for the mono form controls used in the add-tag row.
const CONTROL_STYLE: React.CSSProperties = {
  height: 28,
  fontSize: 11,
  padding: "0 8px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  borderRadius: 3,
  outline: "none",
};

const BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 15%, transparent)",
  color: "var(--accent)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  borderRadius: 3,
  cursor: "pointer",
};

const ERROR_BOX: React.CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "6px 10px",
  fontSize: 11,
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

/**
 * SystemTags -- tag assignment surface for the system detail page (D-10).
 *
 * Rebuilt to the mock language: a dense mono chip row (MonoBadge with an
 * inline × removal control for operators) plus an operator-only add form.
 * Reader role sees the assigned chips but no add/remove affordances.
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
      <WindowPanel title="tags" status="LOADING" tone="muted">
        <LoadingSkeletonGroup lines={4} />
      </WindowPanel>
    );
  }

  if (tagsQuery.isError) {
    return (
      <WindowPanel title="tags" tone="warn">
        <div style={ERROR_BOX}>{(tagsQuery.error as Error).message}</div>
      </WindowPanel>
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <WindowPanel title="assigned tags" tone="muted">
        {tags.length === 0 ? (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            no tags assigned.
            {canOperate ? " use the form below to organize this system." : ""}
          </p>
        ) : (
          <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
            {tags.map((tag) => (
              <span
                key={tag.id}
                className="inline-flex items-center"
                style={{ gap: 4 }}
              >
                <MonoBadge tone="info">
                  {tag.tag_key}:{tag.tag_value}
                </MonoBadge>
                {canOperate && (
                  <button
                    type="button"
                    onClick={() => handleRemove(tag.id)}
                    disabled={removeTag.isPending}
                    aria-label={`Remove tag ${tag.tag_key}: ${tag.tag_value}`}
                    className="font-mono"
                    style={{
                      height: 19,
                      width: 19,
                      display: "inline-flex",
                      alignItems: "center",
                      justifyContent: "center",
                      border: "1px solid var(--border-soft)",
                      background: "var(--surface-sunk)",
                      color: "var(--text-faint)",
                      fontSize: 11,
                      borderRadius: 2,
                      cursor: removeTag.isPending ? "not-allowed" : "pointer",
                      opacity: removeTag.isPending ? 0.4 : 1,
                    }}
                  >
                    {"\u00d7"}
                  </button>
                )}
              </span>
            ))}
          </div>
        )}
      </WindowPanel>

      {canOperate && (
        <WindowPanel title="add tag" tone="accent">
          <form
            onSubmit={handleAdd}
            className="flex flex-col"
            style={{ gap: 10 }}
          >
            <div className="flex flex-wrap items-end" style={{ gap: 8 }}>
              <div className="flex flex-col" style={{ gap: 4, minWidth: 160 }}>
                <label
                  htmlFor="tag-key-select"
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.14em",
                    color: "var(--text-faint)",
                  }}
                >
                  Tag key
                </label>
                <select
                  id="tag-key-select"
                  value={selectedKey}
                  onChange={(e) => setSelectedKey(e.target.value)}
                  disabled={vocabQuery.isLoading || assignTag.isPending}
                  style={CONTROL_STYLE}
                >
                  <option value="">select key…</option>
                  {vocabulary.map((entry) => (
                    <option key={entry.id} value={entry.tag_key}>
                      {entry.tag_key}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex flex-col" style={{ gap: 4, minWidth: 160 }}>
                <label
                  htmlFor="tag-value-input"
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.14em",
                    color: "var(--text-faint)",
                  }}
                >
                  Tag value
                </label>
                <input
                  id="tag-value-input"
                  value={tagValue}
                  onChange={(e) => setTagValue(e.target.value)}
                  placeholder="e.g. production"
                  disabled={assignTag.isPending}
                  style={CONTROL_STYLE}
                />
              </div>
              <button
                type="submit"
                disabled={
                  assignTag.isPending || !selectedKey || !tagValue.trim()
                }
                style={{
                  ...BUTTON_STYLE,
                  opacity:
                    assignTag.isPending || !selectedKey || !tagValue.trim()
                      ? 0.5
                      : 1,
                  cursor:
                    assignTag.isPending || !selectedKey || !tagValue.trim()
                      ? "not-allowed"
                      : "pointer",
                }}
              >
                {assignTag.isPending ? "adding…" : "add tag"}
              </button>
            </div>

            {formError && <div style={ERROR_BOX}>{formError}</div>}
          </form>
        </WindowPanel>
      )}
    </div>
  );
}
