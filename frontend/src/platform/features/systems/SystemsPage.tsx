import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";

import { SystemCSVImport } from "./SystemCSVImport";
import { SystemTags } from "./SystemTags";
import { SystemsDataGrid } from "./SystemsTable";
import {
  useCreateSystem,
  useSystems,
  useTagVocabulary,
  type SystemMutationInput,
  type SystemSummaryEnriched,
} from "./api";

import {
  SectionHeader,
  FilterChip,
  MonoBadge,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { usePreferences } from "@/providers/PreferencesProvider";
import { SavedViews } from "@platform/features/saved-views";

const DEFAULT_SYSTEM_FORM: SystemMutationInput = {
  name: "",
  host: "",
  username: "root",
  port: 22,
  distro: "unknown",
  description: "",
  private_key: null,
  password: null,
  private_key_passphrase: null,
};

const HEADER_BUTTON: React.CSSProperties = {
  height: 26,
  padding: "0 11px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  borderRadius: 3,
  cursor: "pointer",
};

const ACCENT_BUTTON: React.CSSProperties = {
  ...HEADER_BUTTON,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 15%, transparent)",
  color: "var(--accent)",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 11,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  borderRadius: 3,
  outline: "none",
};

const ERROR_BOX: React.CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "8px 12px",
  fontSize: 11,
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

const METADATA_LABEL: React.CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

function matchesTagFilter(
  system: SystemSummaryEnriched,
  selectedTagKeys: string[],
): boolean {
  if (selectedTagKeys.length === 0) return true;
  const systemTagKeys = (system.tags ?? []).map((t) => t.tag_key);
  return selectedTagKeys.some((key) => systemTagKeys.includes(key));
}

/**
 * SystemsPage -- systems inventory rebuilt to the AILA mock language.
 *
 * Preserves every data hook (useSystems, useTagVocabulary, useCreateSystem,
 * SavedViews) and every URL-persisted filter behavior. Presentation is
 * SectionHeader + FilterChip row + WindowPanel(flush) wrapping a DataGrid.
 */
export function SystemsPage() {
  const { role } = useAuthStore();
  const [searchParams, setSearchParams] = useSearchParams();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showCSVImport, setShowCSVImport] = useState(false);
  const [tagSheetSystemId, setTagSheetSystemId] = useState<number | null>(null);
  const [draftSystem, setDraftSystem] = useState<SystemMutationInput>(
    DEFAULT_SYSTEM_FORM,
  );

  const { defaultPageSize, setDefaultPageSize, allowedPageSizes } =
    usePreferences();
  const systemsQuery = useSystems(1, defaultPageSize);
  const vocabQuery = useTagVocabulary();
  const createSystem = useCreateSystem();
  const canOperate = isAllowedRole(role, "operator");

  const searchQuery = (searchParams.get("q") ?? "").toLowerCase().trim();
  const selectedTagKeys = useMemo(() => {
    const raw = searchParams.get("tags") ?? "";
    return raw ? raw.split(",").filter(Boolean) : [];
  }, [searchParams]);

  const allSystems = systemsQuery.data?.items ?? [];

  const filteredSystems = useMemo(
    () =>
      allSystems.filter((system) => {
        if (searchQuery) {
          const haystack = [
            system.name,
            system.host,
            system.username,
            system.distro,
            system.description,
          ]
            .join(" ")
            .toLowerCase();
          if (!haystack.includes(searchQuery)) return false;
        }
        return matchesTagFilter(system, selectedTagKeys);
      }),
    [allSystems, searchQuery, selectedTagKeys],
  );

  const unreachableCount = useMemo(
    () =>
      allSystems.filter((s) => s.connectivity_status === "unreachable").length,
    [allSystems],
  );

  const vocabulary = vocabQuery.data ?? [];

  function updateTagFilter(key: string) {
    const next = new URLSearchParams(searchParams);
    const current = selectedTagKeys.includes(key)
      ? selectedTagKeys.filter((k) => k !== key)
      : [...selectedTagKeys, key];
    if (current.length > 0) {
      next.set("tags", current.join(","));
    } else {
      next.delete("tags");
    }
    setSearchParams(next, { replace: true });
  }

  function updateSearch(value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set("q", value);
    else next.delete("q");
    setSearchParams(next, { replace: true });
  }

  function clearFilters() {
    const next = new URLSearchParams(searchParams);
    next.delete("q");
    next.delete("tags");
    setSearchParams(next, { replace: true });
  }

  const hasActiveFilter =
    searchQuery.length > 0 || selectedTagKeys.length > 0;
  const total = systemsQuery.data?.total ?? allSystems.length;
  const visible = filteredSystems.length;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25a0"}
        title="systems inventory"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              style={{
                ...HEADER_BUTTON,
                opacity: canOperate ? 1 : 0.4,
                cursor: canOperate ? "pointer" : "not-allowed",
              }}
              disabled={!canOperate}
              title={canOperate ? undefined : "Requires operator+ role"}
              onClick={() => setShowCSVImport(true)}
            >
              import csv
            </button>
            <button
              type="button"
              style={{
                ...ACCENT_BUTTON,
                opacity: canOperate ? 1 : 0.4,
                cursor: canOperate ? "pointer" : "not-allowed",
              }}
              disabled={!canOperate}
              title={canOperate ? undefined : "Requires operator+ role"}
              onClick={() => setShowCreateForm((v) => !v)}
            >
              + add system
            </button>
          </div>
        }
      />

      {/* Metric strip */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title="registered" tone="muted">
          <div
            className="font-mono"
            style={{ fontSize: 26, color: "var(--text-primary)" }}
          >
            {total}
          </div>
          <div
            className="font-mono"
            style={{
              marginTop: 4,
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-faint)",
            }}
          >
            TOTAL IN FLEET
          </div>
        </WindowPanel>
        <WindowPanel title="visible" tone="info">
          <div
            className="font-mono"
            style={{ fontSize: 26, color: "var(--text-primary)" }}
          >
            {visible}
          </div>
          <div
            className="font-mono"
            style={{
              marginTop: 4,
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-faint)",
            }}
          >
            MATCHING FILTERS
          </div>
        </WindowPanel>
        <WindowPanel
          title="unreachable"
          tone={unreachableCount > 0 ? "warn" : "muted"}
        >
          <div
            className="font-mono"
            style={{
              fontSize: 26,
              color:
                unreachableCount > 0
                  ? "var(--status-warn)"
                  : "var(--text-primary)",
            }}
          >
            {unreachableCount}
          </div>
          <div
            className="font-mono"
            style={{
              marginTop: 4,
              fontSize: 9.5,
              letterSpacing: "0.08em",
              color: "var(--text-faint)",
            }}
          >
            SSH OFFLINE
          </div>
        </WindowPanel>
      </div>

      {systemsQuery.isError && (
        <div style={ERROR_BOX}>
          Failed to load systems: {(systemsQuery.error as Error).message}
        </div>
      )}

      {/* Register form (operator+) */}
      {showCreateForm && (
        <WindowPanel title="register a new system" tone="accent">
          <form
            className="flex flex-col"
            style={{ gap: 12 }}
            onSubmit={(e) => {
              e.preventDefault();
              createSystem.mutate(draftSystem, {
                onSuccess: () => {
                  setDraftSystem(DEFAULT_SYSTEM_FORM);
                  setShowCreateForm(false);
                },
              });
            }}
          >
            <div
              className="grid"
              style={{
                gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
                gap: 10,
              }}
            >
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>NAME</span>
                <input
                  style={INPUT_STYLE}
                  value={draftSystem.name}
                  onChange={(e) =>
                    setDraftSystem((d) => ({ ...d, name: e.target.value }))
                  }
                  placeholder="arch-vm"
                  required
                />
              </label>
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>HOST</span>
                <input
                  style={INPUT_STYLE}
                  value={draftSystem.host}
                  onChange={(e) =>
                    setDraftSystem((d) => ({ ...d, host: e.target.value }))
                  }
                  placeholder="192.168.56.129"
                  required
                />
              </label>
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>USERNAME</span>
                <input
                  style={INPUT_STYLE}
                  value={draftSystem.username}
                  onChange={(e) =>
                    setDraftSystem((d) => ({ ...d, username: e.target.value }))
                  }
                />
              </label>
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>PORT</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  style={INPUT_STYLE}
                  value={draftSystem.port}
                  onChange={(e) =>
                    setDraftSystem((d) => ({
                      ...d,
                      port: Number(e.target.value) || 22,
                    }))
                  }
                />
              </label>
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>DISTRO</span>
                <input
                  style={INPUT_STYLE}
                  value={draftSystem.distro}
                  onChange={(e) =>
                    setDraftSystem((d) => ({ ...d, distro: e.target.value }))
                  }
                />
              </label>
            </div>

            <div
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.14em",
                color: "var(--text-faint)",
                borderTop: "1px solid var(--border-faint)",
                paddingTop: 8,
              }}
            >
              SSH CREDENTIALS
            </div>

            <label className="flex flex-col" style={{ gap: 4 }}>
              <span style={METADATA_LABEL}>PRIVATE KEY (PEM)</span>
              <textarea
                rows={4}
                style={{
                  ...INPUT_STYLE,
                  height: "auto",
                  padding: 8,
                  resize: "vertical",
                }}
                value={draftSystem.private_key ?? ""}
                onChange={(e) =>
                  setDraftSystem((d) => ({
                    ...d,
                    private_key: e.target.value || null,
                  }))
                }
                placeholder={
                  "-----BEGIN OPENSSH PRIVATE KEY-----\npaste your private key here…\n-----END OPENSSH PRIVATE KEY-----"
                }
                spellCheck={false}
                autoComplete="off"
              />
            </label>

            <div
              className="grid"
              style={{
                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                gap: 10,
              }}
            >
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>KEY PASSPHRASE</span>
                <input
                  type="password"
                  style={INPUT_STYLE}
                  value={draftSystem.private_key_passphrase ?? ""}
                  onChange={(e) =>
                    setDraftSystem((d) => ({
                      ...d,
                      private_key_passphrase: e.target.value || null,
                    }))
                  }
                  placeholder="passphrase (if key is encrypted)"
                  autoComplete="off"
                />
              </label>
              <label className="flex flex-col" style={{ gap: 4 }}>
                <span style={METADATA_LABEL}>SSH PASSWORD</span>
                <input
                  type="password"
                  style={INPUT_STYLE}
                  value={draftSystem.password ?? ""}
                  onChange={(e) =>
                    setDraftSystem((d) => ({
                      ...d,
                      password: e.target.value || null,
                    }))
                  }
                  placeholder="password (alternative to key)"
                  autoComplete="off"
                />
              </label>
            </div>

            <label className="flex flex-col" style={{ gap: 4 }}>
              <span style={METADATA_LABEL}>DESCRIPTION</span>
              <textarea
                rows={2}
                style={{
                  ...INPUT_STYLE,
                  height: "auto",
                  padding: 8,
                  resize: "vertical",
                }}
                value={draftSystem.description}
                onChange={(e) =>
                  setDraftSystem((d) => ({
                    ...d,
                    description: e.target.value,
                  }))
                }
                placeholder="internet-facing arch linux host in prod"
              />
            </label>

            <div className="flex items-center" style={{ gap: 8 }}>
              <button
                type="submit"
                disabled={createSystem.isPending}
                style={{
                  ...ACCENT_BUTTON,
                  opacity: createSystem.isPending ? 0.5 : 1,
                }}
              >
                {createSystem.isPending ? "registering…" : "create system"}
              </button>
              <button
                type="button"
                style={HEADER_BUTTON}
                onClick={() => {
                  setDraftSystem(DEFAULT_SYSTEM_FORM);
                  setShowCreateForm(false);
                }}
              >
                cancel
              </button>
            </div>

            {createSystem.isError && (
              <div style={ERROR_BOX}>
                {(createSystem.error as Error).message}
              </div>
            )}
          </form>
        </WindowPanel>
      )}

      {/* Filter row: search input + tag chips + saved views + page size */}
      <div
        className="flex flex-wrap items-center"
        style={{ gap: 8, rowGap: 8 }}
      >
        <div className="flex items-center" style={{ gap: 6 }}>
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-faint)",
            }}
          >
            SEARCH
          </span>
          <input
            id="systems-search"
            aria-label="Search systems"
            style={{ ...INPUT_STYLE, width: 220 }}
            value={searchParams.get("q") ?? ""}
            onChange={(e) => updateSearch(e.target.value)}
            placeholder="host, name, distro…"
          />
        </div>

        {vocabulary.length > 0 && (
          <>
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.14em",
                color: "var(--text-faint)",
                marginLeft: 4,
              }}
            >
              TAGS
            </span>
            {vocabulary.map((entry) => (
              <FilterChip
                key={entry.id}
                active={selectedTagKeys.includes(entry.tag_key)}
                color="var(--status-info)"
                onClick={() => updateTagFilter(entry.tag_key)}
              >
                {entry.tag_key}
              </FilterChip>
            ))}
          </>
        )}

        {hasActiveFilter && (
          <button
            type="button"
            onClick={clearFilters}
            className="font-mono uppercase"
            style={{
              background: "transparent",
              border: 0,
              color: "var(--text-muted)",
              fontSize: 9.5,
              letterSpacing: "0.08em",
              cursor: "pointer",
            }}
          >
            clear
          </button>
        )}

        <span style={{ flex: 1 }} />

        <div className="flex items-center" style={{ gap: 6 }}>
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-faint)",
            }}
          >
            PAGE SIZE
          </span>
          <select
            aria-label="Page size"
            value={defaultPageSize}
            onChange={(e) => setDefaultPageSize(Number(e.target.value))}
            style={INPUT_STYLE}
          >
            {allowedPageSizes.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </div>

        <SavedViews<{
          q: string;
          tags: string[];
          pageSize: number;
        }>
          entityType="system"
          entityLabel="Systems list"
          currentState={{
            q: searchQuery,
            tags: selectedTagKeys,
            pageSize: defaultPageSize,
          }}
          onApply={(state) => {
            const next = new URLSearchParams(searchParams);
            if (state.q) next.set("q", state.q);
            else next.delete("q");
            if (Array.isArray(state.tags) && state.tags.length > 0) {
              next.set("tags", state.tags.join(","));
            } else {
              next.delete("tags");
            }
            setSearchParams(next, { replace: true });
            if (
              typeof state.pageSize === "number" &&
              allowedPageSizes.includes(state.pageSize) &&
              state.pageSize !== defaultPageSize
            ) {
              setDefaultPageSize(state.pageSize);
            }
          }}
        />
      </div>

      {/* Status line */}
      <div className="flex items-center" style={{ gap: 8 }}>
        <MonoBadge tone={visible === 0 ? "muted" : "info"}>
          {visible} VISIBLE
        </MonoBadge>
        <MonoBadge tone="muted">{total} TOTAL</MonoBadge>
        {selectedTagKeys.length > 0 && (
          <MonoBadge tone="accent">
            {selectedTagKeys.length} TAG FILTER
            {selectedTagKeys.length === 1 ? "" : "S"}
          </MonoBadge>
        )}
        {searchQuery.length > 0 && (
          <MonoBadge tone="accent">SEARCH: {searchQuery}</MonoBadge>
        )}
      </div>

      {/* Body */}
      {systemsQuery.isLoading ? (
        <WindowPanel title="systems" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={8} />
        </WindowPanel>
      ) : (
        <WindowPanel title="systems" flush tone="muted">
          <SystemsDataGrid
            rows={filteredSystems}
            onManageTags={canOperate ? setTagSheetSystemId : undefined}
            emptyMessage={
              allSystems.length === 0
                ? "no systems registered. register your first host to begin scanning."
                : "no systems match the current filters."
            }
          />
        </WindowPanel>
      )}

      {filteredSystems.length > 0 && (
        <p
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-faint)" }}
        >
          row selection + bulk actions coming in a future release.
        </p>
      )}

      {/* CSV import modal */}
      <SystemCSVImport open={showCSVImport} onOpenChange={setShowCSVImport} />

      {/* Inline tag drawer modal -- WindowPanel over backdrop */}
      {tagSheetSystemId !== null && (
        <TagDrawerModal
          system={allSystems.find((s) => s.id === tagSheetSystemId) ?? null}
          systemId={tagSheetSystemId}
          onClose={() => setTagSheetSystemId(null)}
        />
      )}
    </div>
  );
}

interface TagDrawerModalProps {
  system: SystemSummaryEnriched | null;
  systemId: number;
  onClose: () => void;
}

function TagDrawerModal({ system, systemId, onClose }: TagDrawerModalProps) {
  return (
    <div
      role="dialog"
      aria-label={system ? `Manage tags for ${system.name}` : "Manage tags"}
      className="fixed inset-0 flex justify-end"
      style={{
        zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 70%, transparent)",
        backdropFilter: "blur(2px)",
      }}
      onClick={onClose}
    >
      <div
        className="flex flex-col"
        style={{
          width: "min(420px, 96vw)",
          height: "100%",
          background: "var(--surface-card)",
          borderLeft: "1px solid var(--border-soft)",
          padding: 16,
          gap: 12,
          overflowY: "auto",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center" style={{ gap: 10 }}>
          <SectionHeader
            icon={"\u25c7"}
            title="manage tags"
            size={18}
          />
          <span style={{ flex: 1 }} />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close tag drawer"
            style={{
              ...HEADER_BUTTON,
              width: 26,
              padding: 0,
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {"\u00d7"}
          </button>
        </div>
        {system && (
          <div
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            assign or remove tags on{" "}
            <span style={{ color: "var(--accent)" }}>{system.name}</span> (
            {system.host}).
          </div>
        )}
        <SystemTags systemId={systemId} />
      </div>
    </div>
  );
}
