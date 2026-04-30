/**
 * PlatformConfigPage — admin view/edit of all platform configuration entries.
 *
 * ADM-03: Fetches GET /config (all namespaces), groups entries by namespace,
 * renders each group as an AilaCard with an AilaTable. Each row has an inline
 * Edit button that expands a form with value + value_type validation before
 * calling PUT /config/{namespace}/{key}.
 *
 * No mock data. Empty state if no config entries exist.
 */
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { GearSix, Pencil, X, Check } from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function valueTypeSeverity(vt: string): "info" | "medium" | "neutral" | "low" {
  if (vt === "bool") return "info";
  if (vt === "int" || vt === "float") return "medium";
  if (vt === "str") return "low";
  return "neutral";
}

function validateConfigValue(
  value: string,
  valueType: string,
): string | null {
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
// Inline edit row form
// ---------------------------------------------------------------------------

interface EditRowFormProps {
  entry: ConfigEntry;
  onSave: (req: ConfigUpdateRequest) => Promise<void>;
  onCancel: () => void;
  isPending: boolean;
}

function EditRowForm({ entry, onSave, onCancel, isPending }: EditRowFormProps) {
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
      <div className="flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-mint">
        <Check className="h-3.5 w-3.5" />
        Saved
      </div>
    );
  }

  return (
    <form
      className="flex items-start gap-2 flex-wrap"
      onSubmit={handleSubmit}
    >
      <div className="flex flex-col gap-1 min-w-[140px]">
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="font-mono text-xs h-7 px-2"
          autoFocus
        />
        {error && (
          <span className="font-mono text-xs text-destructive">{error}</span>
        )}
      </div>

      <select
        value={valueType}
        onChange={(e) =>
          setValueType(e.target.value as ConfigUpdateRequest["value_type"])
        }
        className="rounded-[2px] border border-border bg-base font-mono text-xs text-text px-1.5 py-1 outline-none focus:border-border-hover transition-colors duration-100 h-7"
      >
        <option value="str">str</option>
        <option value="int">int</option>
        <option value="float">float</option>
        <option value="bool">bool</option>
      </select>

      <Button type="submit" size="sm" className="h-7 px-2 text-xs" disabled={isPending}>
        {isPending ? "Saving…" : "Save"}
      </Button>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="h-7 px-2 text-xs"
        onClick={onCancel}
      >
        <X className="h-3 w-3" />
      </Button>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Namespace group — AilaCard with AilaTable
// ---------------------------------------------------------------------------

interface NamespaceGroupProps {
  namespace: string;
  entries: ConfigEntry[];
  onEdit: (entry: ConfigEntry, req: ConfigUpdateRequest) => Promise<void>;
  isEditPending: boolean;
}

function NamespaceGroup({
  namespace,
  entries,
  onEdit,
  isEditPending,
}: NamespaceGroupProps) {
  const [editingKey, setEditingKey] = useState<string | null>(null);

  const columns: ColumnDef<ConfigEntry>[] = useMemo(
    () => [
      {
        id: "key",
        header: "Key",
        accessorKey: "key",
        cell: ({ getValue }) => (
          <code className="font-mono text-xs text-text">{String(getValue())}</code>
        ),
      },
      {
        id: "value",
        header: "Value",
        accessorKey: "value",
        cell: ({ row }) => {
          const entry = row.original;
          if (editingKey === entry.key) {
            return (
              <EditRowForm
                entry={entry}
                onSave={(req) => onEdit(entry, req)}
                onCancel={() => setEditingKey(null)}
                isPending={isEditPending}
              />
            );
          }
          const v = String(entry.value);
          const display = v.length > 60 ? `${v.slice(0, 60)}…` : v;
          return (
            <span
              className="font-mono text-xs text-text"
              title={v.length > 60 ? v : undefined}
            >
              {display}
            </span>
          );
        },
      },
      {
        id: "value_type",
        header: "Type",
        accessorKey: "value_type",
        cell: ({ getValue }) => {
          const vt = String(getValue());
          return (
            <AilaBadge severity={valueTypeSeverity(vt)} size="sm">
              {vt}
            </AilaBadge>
          );
        },
      },
      {
        id: "updated_at",
        header: "Updated",
        accessorKey: "updated_at",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs text-text-muted whitespace-nowrap">
            {formatTimestamp(getValue() as string | null)}
          </span>
        ),
      },
      {
        id: "actions",
        header: "Actions",
        enableSorting: false,
        cell: ({ row }) => {
          const entry = row.original;
          const isEditing = editingKey === entry.key;
          return isEditing ? null : (
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 gap-1 text-xs"
              onClick={() => setEditingKey(entry.key)}
            >
              <Pencil className="h-3 w-3" />
              Edit
            </Button>
          );
        },
      },
    ],
    [editingKey, onEdit, isEditPending],
  );

  return (
    <AilaCard variant="elevated" padding="md">
      <div className="flex items-center gap-2 mb-3">
        <h2 className="font-mono text-sm font-semibold text-text capitalize">
          {namespace}
        </h2>
        <AilaBadge severity="neutral" size="sm">
          {entries.length} {entries.length === 1 ? "entry" : "entries"}
        </AilaBadge>
      </div>

      <AilaTable
        data={entries}
        columns={columns}
        pageSize={50}
        enableSorting
        enableFiltering={false}
        className="border-0"
      >
        <AilaTable.Header />
        <AilaTable.Body emptyState="No entries in this namespace." />
        <AilaTable.Pagination pageSizeOptions={[25, 50]} />
      </AilaTable>
    </AilaCard>
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

  // Group entries by namespace
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

  async function handleEdit(entry: ConfigEntry, req: ConfigUpdateRequest) {
    await updateMutation.mutateAsync({
      namespace: entry.namespace,
      key: entry.key,
      req,
    });
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div>
        <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
          <GearSix className="h-5 w-5 text-accent" />
          Platform Config
        </h1>
        <p className="font-mono text-sm text-text-muted mt-0.5">
          View and edit module configuration entries. Values are validated
          against their declared type before saving.
        </p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Total Entries
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {configQuery.data?.total ?? "—"}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            All namespaces
          </p>
        </AilaCard>

        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Namespaces
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {configQuery.isLoading ? "—" : namespaceCount}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Module groups
          </p>
        </AilaCard>
      </div>

      {/* Error banner */}
      {configQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load config: {(configQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {configQuery.isLoading && (
        <AilaCard variant="default" padding="md">
          <LoadingSkeletonGroup lines={6} />
        </AilaCard>
      )}

      {/* Empty state */}
      {!configQuery.isLoading && !configQuery.isError && entries.length === 0 && (
        <EmptyState
          icon={<GearSix className="h-10 w-10" />}
          title="No configuration entries"
          description="No module configuration entries are registered. Entries are created when modules initialize."
        />
      )}

      {/* Namespace groups */}
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
