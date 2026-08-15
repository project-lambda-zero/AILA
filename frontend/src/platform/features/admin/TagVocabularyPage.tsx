/**
 * TagVocabularyPage -- admin-only management of asset tag keys (v6.0).
 *
 * Lists every tag key in the vocabulary with a usage count derived from the
 * current systems sample, lets admins add new keys (POST /tags/vocabulary),
 * and delete user-defined keys (DELETE /tags/vocabulary/{tag_key}). System
 * defaults are visible but cannot be deleted; the backend returns 409 and
 * the modal surfaces that error verbatim.
 *
 * Usage counts are computed client-side from a single page of /systems with
 * page_size=250 (the backend cap). When the fleet exceeds that, the panel
 * footer notes the sample size so operators don't read the count as global.
 *
 * Presentation rebuilt to the AILA mock language. Data hooks, mutations,
 * and testids preserved.
 */
import * as React from "react";
import { useMemo, useState } from "react";

import { SectionHeader, DataGrid, MonoBadge, FilterChip } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  useTagVocabulary,
  useCreateTagVocab,
  useDeleteTagVocab,
  useSystems,
  type TagVocabEntry,
} from "@platform/features/systems/api";

// ---------------------------------------------------------------------------
// Local mock styles
// ---------------------------------------------------------------------------

const btnBase: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  letterSpacing: "0.08em",
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  textTransform: "uppercase",
  fontFamily: "var(--font-mono)",
};

const primaryBtn: React.CSSProperties = {
  ...btnBase,
  background: "var(--accent)",
  color: "var(--text-on-accent)",
  borderColor: "var(--accent)",
};

const dangerBtn: React.CSSProperties = {
  ...btnBase,
  color: "var(--status-warn)",
  borderColor: "color-mix(in srgb, var(--status-warn) 40%, transparent)",
};

const inputStyle: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  width: "100%",
};

const labelStyle: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.12em",
  textTransform: "uppercase",
  color: "var(--text-faint)",
};

function ErrorLine({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
        background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
        color: "var(--status-warn)",
        padding: "8px 12px",
        fontSize: 11,
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

function ModalFrame({
  open,
  onClose,
  title,
  children,
  width = 420,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  width?: number;
}) {
  if (!open) return null;
  return (
    <div
      className="flex items-center justify-center"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
      }}
      onClick={onClose}
      role="presentation"
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width, maxWidth: "94vw" }}>
        <WindowPanel
          title={title}
          tone="accent"
          actions={
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="font-mono"
              style={{
                width: 20,
                height: 20,
                border: 0,
                background: "transparent",
                color: "var(--text-muted)",
                cursor: "pointer",
                fontSize: 13,
                lineHeight: 1,
              }}
            >
              {"\u2715"}
            </button>
          }
        >
          {children}
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Delete modal
// ---------------------------------------------------------------------------

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

  return (
    <ModalFrame
      open={entry !== null}
      onClose={() => {
        setError(null);
        onClose();
      }}
      title="delete tag key"
    >
      {entry && (
        <div className="flex flex-col" style={{ gap: 12 }}>
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            Deleting{" "}
            <span style={{ color: "var(--accent)" }}>{entry.tag_key}</span>{" "}
            removes it from the vocabulary. New systems will not be able to use
            this key.
            {usageCount > 0 && (
              <>
                {" "}
                <span style={{ color: "var(--status-warn)" }}>
                  {usageCount} system{usageCount === 1 ? "" : "s"}
                </span>{" "}
                currently use this key.
              </>
            )}
          </p>
          {entry.is_system_default && (
            <div
              className="font-mono"
              style={{
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                color: "var(--text-muted)",
                padding: "8px 12px",
                fontSize: 10.5,
                borderRadius: 3,
              }}
            >
              system defaults are locked by the backend and will return a 409.
            </div>
          )}
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{
                ...primaryBtn,
                flex: 1,
                background: "var(--status-warn)",
                borderColor: "var(--status-warn)",
              }}
              onClick={handleConfirm}
              disabled={isPending}
              aria-label={`Confirm delete tag key ${entry.tag_key}`}
            >
              {isPending ? "Deleting..." : "Delete Tag Key"}
            </button>
            <button
              type="button"
              style={btnBase}
              onClick={() => {
                setError(null);
                onClose();
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </ModalFrame>
  );
}

// ---------------------------------------------------------------------------
// Add key modal
// ---------------------------------------------------------------------------

const SLUG_PATTERN = /^[a-z0-9_-]+$/i;

function AddKeyButton({
  onCreate,
  isPending,
}: {
  onCreate: (req: { tag_key: string; description: string }) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setNewKey("");
      setNewDescription("");
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const trimmedKey = newKey.trim();
    if (!trimmedKey) {
      setError("Tag key is required.");
      return;
    }
    if (!SLUG_PATTERN.test(trimmedKey)) {
      setError("Tag keys may contain only letters, digits, underscores, and dashes.");
      return;
    }
    try {
      await onCreate({ tag_key: trimmedKey, description: newDescription.trim() });
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create tag key.");
    }
  }

  return (
    <>
      <button type="button" style={primaryBtn} onClick={() => setOpen(true)}>
        {"\u002b"} Add Tag Key
      </button>

      <ModalFrame open={open} onClose={handleClose} title="new tag key">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="vocab-key">tag key</label>
            <input
              id="vocab-key"
              style={inputStyle}
              value={newKey}
              onChange={(e) => setNewKey(e.target.value)}
              placeholder="environment"
              autoComplete="off"
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="vocab-desc">description (optional)</label>
            <input
              id="vocab-desc"
              style={inputStyle}
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Deployment environment (prod, staging, dev)"
              autoComplete="off"
            />
          </div>
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8, marginTop: 4 }}>
            <button
              type="submit"
              style={{ ...primaryBtn, flex: 1 }}
              disabled={isPending || !newKey.trim()}
            >
              {isPending ? "Adding..." : "Add Key"}
            </button>
            <button type="button" style={btnBase} onClick={handleClose}>
              Cancel
            </button>
          </div>
        </form>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type ScopeFilter = "all" | "custom" | "default";

export function TagVocabularyPage() {
  const vocabQuery = useTagVocabulary();
  const systemsQuery = useSystems(1, 250);
  const createMutation = useCreateTagVocab();
  const deleteMutation = useDeleteTagVocab();

  const [pendingDelete, setPendingDelete] = useState<TagVocabEntry | null>(null);
  const [scope, setScope] = useState<ScopeFilter>("all");

  const vocabulary = vocabQuery.data ?? [];
  const systems = systemsQuery.data?.items ?? [];
  const totalSystems = systemsQuery.data?.total ?? 0;
  const sampledSystems = systems.length;

  const usageCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const system of systems) {
      const seen = new Set<string>();
      for (const tag of system.tags ?? []) {
        if (seen.has(tag.tag_key)) continue;
        seen.add(tag.tag_key);
        counts.set(tag.tag_key, (counts.get(tag.tag_key) ?? 0) + 1);
      }
    }
    return counts;
  }, [systems]);

  const userDefinedCount = vocabulary.filter((e) => !e.is_system_default).length;
  const defaultCount = vocabulary.length - userDefinedCount;
  const inUseCount = vocabulary.filter(
    (e) => (usageCounts.get(e.tag_key) ?? 0) > 0,
  ).length;

  const filtered = useMemo(() => {
    return vocabulary.filter((e) => {
      if (scope === "custom" && e.is_system_default) return false;
      if (scope === "default" && !e.is_system_default) return false;
      return true;
    });
  }, [vocabulary, scope]);

  async function handleCreate(req: { tag_key: string; description: string }) {
    await createMutation.mutateAsync(req);
  }

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="tag vocabulary"
        actions={
          <AddKeyButton
            onCreate={handleCreate}
            isPending={createMutation.isPending}
          />
        }
      />

      {/* Metric strip */}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12 }}>
        <WindowPanel title="total keys">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--accent)" }}>
            {vocabulary.length}
          </span>
        </WindowPanel>
        <WindowPanel title="custom">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-info)" }}>
            {userDefinedCount}
          </span>
        </WindowPanel>
        <WindowPanel title="defaults">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--text-faint)" }}>
            {defaultCount}
          </span>
        </WindowPanel>
        <WindowPanel title="in use">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-ok)" }}>
            {inUseCount}
          </span>
        </WindowPanel>
      </div>

      {/* Filter chips */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <FilterChip active={scope === "all"} onClick={() => setScope("all")}>
          ALL ({vocabulary.length})
        </FilterChip>
        <FilterChip
          active={scope === "custom"}
          color="var(--status-info)"
          onClick={() => setScope("custom")}
        >
          CUSTOM ({userDefinedCount})
        </FilterChip>
        <FilterChip
          active={scope === "default"}
          color="var(--text-faint)"
          onClick={() => setScope("default")}
        >
          SYSTEM DEFAULT ({defaultCount})
        </FilterChip>
      </div>

      {vocabQuery.isError && (
        <ErrorLine>
          Failed to load tag vocabulary: {(vocabQuery.error as Error).message}
        </ErrorLine>
      )}

      {vocabQuery.isLoading ? (
        <WindowPanel title="vocabulary" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={5} />
        </WindowPanel>
      ) : vocabulary.length === 0 ? (
        <WindowPanel title="vocabulary" tone="muted">
          <div
            className="flex flex-col items-center"
            style={{ padding: "42px 12px", gap: 10 }}
          >
            <span
              className="font-mono"
              style={{ fontSize: 15, color: "var(--text-primary)", letterSpacing: "0.04em" }}
            >
              No tag keys defined
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", maxWidth: 420 }}
            >
              Add a tag key so operators can categorize systems.
            </span>
          </div>
        </WindowPanel>
      ) : (
        <WindowPanel
          title="vocabulary"
          status={
            totalSystems > sampledSystems
              ? `USAGE FROM ${sampledSystems} / ${totalSystems} SYSTEMS`
              : `${vocabulary.length} KEY${vocabulary.length === 1 ? "" : "S"}`
          }
          flush
        >
          <DataGrid
            columns={[
              { label: "TAG KEY", width: "1fr" },
              { label: "DESCRIPTION", width: "1.6fr" },
              { label: "SOURCE", width: "150px" },
              { label: "USAGE", width: "80px", align: "right" },
              { label: "ACTIONS", width: "110px", align: "right" },
            ]}
            rows={filtered}
            getKey={(e) => e.id}
            renderCells={(entry) => {
              const usage = usageCounts.get(entry.tag_key) ?? 0;
              return [
                <span
                  key="k"
                  className="font-mono"
                  style={{ fontSize: 11.5, color: "var(--text-primary)" }}
                >
                  {entry.tag_key}
                </span>,
                <span
                  key="d"
                  className="font-mono truncate"
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  {entry.description || "--"}
                </span>,
                entry.is_system_default ? (
                  <MonoBadge key="s" tone="muted">system default</MonoBadge>
                ) : (
                  <MonoBadge key="s" tone="info">custom</MonoBadge>
                ),
                <span
                  key="u"
                  className="font-mono"
                  style={{
                    fontSize: 11,
                    color: usage > 0 ? "var(--text-primary)" : "var(--text-faint)",
                  }}
                >
                  {systemsQuery.isLoading ? "--" : usage}
                </span>,
                <button
                  key="a"
                  type="button"
                  style={dangerBtn}
                  disabled={entry.is_system_default || deleteMutation.isPending}
                  onClick={() => setPendingDelete(entry)}
                  aria-label={`Delete tag key ${entry.tag_key}`}
                >
                  Delete
                </button>,
              ];
            }}
          />
        </WindowPanel>
      )}

      <DeleteVocabDialog
        entry={pendingDelete}
        usageCount={pendingDelete ? usageCounts.get(pendingDelete.tag_key) ?? 0 : 0}
        onClose={() => setPendingDelete(null)}
        onConfirm={(tagKey) =>
          deleteMutation.mutateAsync(tagKey).then(() => undefined)
        }
        isPending={deleteMutation.isPending}
      />
    </div>
  );
}
