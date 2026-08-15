/**
 * PlatformConfigPage -- admin view/edit of all platform configuration entries.
 *
 * ADM-03: Fetches GET /config (all namespaces), groups entries by namespace,
 * renders each group as a WindowPanel with a DataGrid. Each row has an inline
 * Edit button that opens a form with value + value_type validation before
 * calling PUT /config/{namespace}/{key}.
 */
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  BigStat,
} from "@/components/aila/mock";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ConfigEntry {
  namespace: string;
  key: string;
  value: string;
  value_type: string;
  updated_at: string | null;
  env_key: string;
  env_value: string | null;
  default_value: string | null;
  effective_value: string;
  effective_source: "env" | "db" | "default";
  overridden_by_env: boolean;
}

interface ConfigListResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: ConfigEntry[];
}

interface ConfigUpdateRequest {
  value: string;
  value_type: "str" | "int" | "float" | "bool";
}

type Tone = "critical" | "high" | "medium" | "low" | "ok" | "info" | "warn" | "muted";

function valueTypeTone(vt: string): Tone {
  if (vt === "bool") return "info";
  if (vt === "int" || vt === "float") return "medium";
  if (vt === "str") return "low";
  return "muted";
}

function sourceTone(source: string): Tone {
  if (source === "env") return "info";
  if (source === "default") return "muted";
  return "ok";
}

function validateConfigValue(value: string, valueType: string): string | null {
  if (!value.trim()) return "Value cannot be empty.";
  if (valueType === "int") {
    if (!/^-?\d+$/.test(value.trim())) return "Must be an integer (e.g. 42).";
  }
  if (valueType === "float") {
    if (Number.isNaN(Number(value.trim()))) return "Must be a number (e.g. 3.14).";
  }
  if (valueType === "bool") {
    if (!["true", "false", "1", "0"].includes(value.trim().toLowerCase())) {
      return "Must be true or false.";
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Mock chrome
// ---------------------------------------------------------------------------

const BTN_STYLE: React.CSSProperties = {
  height: 22,
  fontSize: 9,
  padding: "0 9px",
  letterSpacing: "0.08em",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

const BTN_ACCENT_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 14%, transparent)",
  color: "var(--accent)",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 22,
  fontSize: 10.5,
  padding: "0 8px",
  borderRadius: 2,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  outline: "none",
  fontFamily: "var(--font-mono)",
  minWidth: 120,
};

const SELECT_STYLE: React.CSSProperties = {
  ...INPUT_STYLE,
  minWidth: 68,
};

// ---------------------------------------------------------------------------
// Inline edit form (rendered as expanded row)
// ---------------------------------------------------------------------------

function EditRowForm({
  entry,
  onSave,
  onCancel,
  isPending,
}: {
  entry: ConfigEntry;
  onSave: (req: ConfigUpdateRequest) => Promise<void>;
  onCancel: () => void;
  isPending: boolean;
}) {
  const [value, setValue] = useState(entry.value);
  const [valueType, setValueType] = useState<ConfigUpdateRequest["value_type"]>(
    (entry.value_type as ConfigUpdateRequest["value_type"]) ?? "str",
  );
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const validationError = validateConfigValue(value, valueType);
    if (validationError) {
      setError(validationError);
      return;
    }
    setError(null);
    try {
      await onSave({ value, value_type: valueType });
      setSuccess(true);
      setTimeout(onCancel, 800);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update config");
    }
  }

  if (success) {
    return (
      <div
        className="flex items-center font-mono uppercase"
        style={{
          gap: 6,
          padding: "6px 10px",
          fontSize: 10,
          color: "var(--status-ok)",
          letterSpacing: "0.08em",
        }}
      >
        {"\u2713"} saved
      </div>
    );
  }

  return (
    <form
      className="flex flex-wrap items-start"
      style={{ gap: 6 }}
      onSubmit={handleSubmit}
    >
      {entry.overridden_by_env && (
        <div
          className="font-mono"
          style={{
            flex: "1 1 100%",
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "6px 10px",
            fontSize: 10,
            borderRadius: 3,
          }}
        >
          overridden by env{" "}
          <code style={{ color: "var(--accent)" }}>{entry.env_key}</code>. Save
          updates the stored fallback; live value stays env-sourced until unset.
        </div>
      )}
      <div className="flex flex-col" style={{ gap: 3, minWidth: 140 }}>
        <input
          aria-label="Config value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          style={INPUT_STYLE}
          autoFocus
        />
        {error && (
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--status-warn)" }}
          >
            {error}
          </span>
        )}
      </div>
      <select
        aria-label="Value type"
        value={valueType}
        onChange={(e) =>
          setValueType(e.target.value as ConfigUpdateRequest["value_type"])
        }
        style={SELECT_STYLE}
      >
        <option value="str">str</option>
        <option value="int">int</option>
        <option value="float">float</option>
        <option value="bool">bool</option>
      </select>
      <button type="submit" style={BTN_ACCENT_STYLE} disabled={isPending}>
        {isPending ? "SAVING\u2026" : "SAVE"}
      </button>
      <button type="button" style={BTN_STYLE} onClick={onCancel}>
        {"\u2715"}
      </button>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Namespace group -- WindowPanel with DataGrid
// ---------------------------------------------------------------------------

function NamespaceGroup({
  namespace,
  entries,
  onEdit,
  isEditPending,
}: {
  namespace: string;
  entries: ConfigEntry[];
  onEdit: (entry: ConfigEntry, req: ConfigUpdateRequest) => Promise<void>;
  isEditPending: boolean;
}) {
  const [editingKey, setEditingKey] = useState<string | null>(null);

  return (
    <WindowPanel
      title={namespace}
      actions={
        <MonoBadge tone="muted">
          {entries.length} {entries.length === 1 ? "entry" : "entries"}
        </MonoBadge>
      }
      flush
    >
      <DataGrid
        columns={[
          { label: "KEY", width: "230px" },
          { label: "VALUE", width: "1fr" },
          { label: "TYPE", width: "80px" },
          { label: "SOURCE", width: "90px" },
          { label: "UPDATED", width: "170px" },
          { label: "ACTIONS", width: "180px", align: "right" },
        ]}
        rows={entries}
        getKey={(e) => e.key}
        empty={
          <div
            className="font-mono"
            style={{
              padding: 22,
              textAlign: "center",
              fontSize: 11,
              color: "var(--text-muted)",
            }}
          >
            no entries in this namespace.
          </div>
        }
        renderCells={(entry) => {
          const isEditing = editingKey === entry.key;
          const eff = String(entry.effective_value);
          const effDisplay = eff.length > 60 ? `${eff.slice(0, 60)}\u2026` : eff;
          const stored = String(entry.value);
          const storedDisplay =
            stored.length > 60 ? `${stored.slice(0, 60)}\u2026` : stored;
          return [
            <code
              key="k"
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--text-primary)" }}
            >
              {entry.key}
            </code>,
            isEditing ? (
              <EditRowForm
                key="v"
                entry={entry}
                onSave={(req) => onEdit(entry, req)}
                onCancel={() => setEditingKey(null)}
                isPending={isEditPending}
              />
            ) : (
              <div key="v" className="flex flex-col" style={{ gap: 2 }}>
                <div
                  className="flex items-center"
                  style={{ gap: 6, minWidth: 0 }}
                >
                  <span
                    className="font-mono truncate"
                    title={eff.length > 60 ? eff : undefined}
                    style={{
                      fontSize: 10.5,
                      color: "var(--text-primary)",
                    }}
                  >
                    {effDisplay}
                  </span>
                  {entry.overridden_by_env && (
                    <MonoBadge tone="info" title={entry.env_key}>
                      env
                    </MonoBadge>
                  )}
                </div>
                {entry.overridden_by_env && (
                  <span
                    className="font-mono truncate"
                    title={stored.length > 60 ? stored : undefined}
                    style={{ fontSize: 10, color: "var(--text-faint)" }}
                  >
                    stored: {storedDisplay}
                  </span>
                )}
              </div>
            ),
            <MonoBadge key="t" tone={valueTypeTone(entry.value_type)}>
              {entry.value_type}
            </MonoBadge>,
            <MonoBadge key="s" tone={sourceTone(entry.effective_source)}>
              {entry.effective_source}
            </MonoBadge>,
            <span
              key="u"
              className="font-mono"
              style={{ fontSize: 10, color: "var(--text-faint)" }}
            >
              {entry.updated_at
                ? new Date(entry.updated_at).toLocaleString()
                : "--"}
            </span>,
            <span
              key="a"
              className="flex"
              style={{ gap: 6, justifyContent: "flex-end" }}
            >
              {!isEditing && (
                <button
                  type="button"
                  style={BTN_STYLE}
                  onClick={() => setEditingKey(entry.key)}
                >
                  {"\u270e"} EDIT
                </button>
              )}
            </span>,
          ];
        }}
      />
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function PlatformConfigPage() {
  const queryClient = useQueryClient();

  const configQuery = useQuery({
    queryKey: ["platform", "config"],
    queryFn: () =>
      authorizedRequestJson<ConfigListResponse>("/config?page=1&page_size=250"),
  });

  const updateMutation = useMutation({
    mutationFn: ({
      namespace,
      key,
      req,
    }: {
      namespace: string;
      key: string;
      req: ConfigUpdateRequest;
    }) =>
      authorizedRequestJson<ConfigEntry>(`/config/${namespace}/${key}`, {
        method: "PUT",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "config"] });
    },
  });

  const entries = configQuery.data?.items ?? [];

  const namespaceGroups = useMemo(() => {
    const groups = new Map<string, ConfigEntry[]>();
    for (const entry of entries) {
      const existing = groups.get(entry.namespace) ?? [];
      existing.push(entry);
      groups.set(entry.namespace, existing);
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [entries]);

  const namespaceCount = namespaceGroups.length;
  const totalEntries = configQuery.data?.total ?? entries.length;

  async function handleEdit(entry: ConfigEntry, req: ConfigUpdateRequest) {
    await updateMutation.mutateAsync({
      namespace: entry.namespace,
      key: entry.key,
      req,
    });
  }

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25c7"}
        title="Platform config"
        actions={
          <button
            type="button"
            className="font-mono uppercase"
            style={{ ...BTN_STYLE, height: 26, fontSize: 9.5, padding: "0 11px" }}
            onClick={() => void configQuery.refetch()}
            disabled={configQuery.isFetching}
          >
            {configQuery.isFetching ? "REFRESHING\u2026" : "REFRESH"}
          </button>
        }
      />

      {/* Metric row */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}
      >
        <WindowPanel title="total entries">
          <BigStat value={totalEntries} sub="across all namespaces" />
        </WindowPanel>
        <WindowPanel title="namespaces">
          <BigStat value={namespaceCount} sub="module groups" />
        </WindowPanel>
      </div>

      {configQuery.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          failed to load config: {(configQuery.error as Error).message}
        </div>
      )}

      {configQuery.isLoading && (
        <WindowPanel title="config" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {!configQuery.isLoading && !configQuery.isError && entries.length === 0 && (
        <WindowPanel title="config">
          <div
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 12,
              color: "var(--text-muted)",
            }}
          >
            no configuration entries. entries are created when modules
            initialize.
          </div>
        </WindowPanel>
      )}

      {!configQuery.isLoading &&
        namespaceGroups.map(([namespace, nsEntries]) => (
          <NamespaceGroup
            key={namespace}
            namespace={namespace}
            entries={nsEntries}
            onEdit={handleEdit}
            isEditPending={updateMutation.isPending}
          />
        ))}
    </div>
  );
}
