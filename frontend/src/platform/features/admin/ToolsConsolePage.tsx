/**
 * ToolsConsolePage -- live tool invocation console at /admin/tools.
 *
 * Rebuilt to the AILA mock language: SectionHeader + split of
 * WindowPanel('tool registry', flush) DataGrid on the left and
 * WindowPanel('invoke') form on the right. All chrome via WindowPanel /
 * DataGrid / MonoBadge / raw mock-styled inputs. Preserves data hooks,
 * mutations, ROLE_OPERATOR gate, and the SchemaField-driven form loop.
 *
 * Backend POST /tools/{key} independently enforces ROLE_OPERATOR -- the
 * `canInvoke` gate here is defense-in-depth (bypass yields a 403).
 */

import {
  useState,
  useCallback,
  useMemo,
  type CSSProperties,
} from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Wrench } from "@phosphor-icons/react/dist/csr/Wrench";

import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  FilterChip,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";

import { SchemaField } from "./SchemaField";
import { fetchToolDetail, invokeTool } from "./tools-api";
import type {
  JSONSchema,
  ToolDetail,
  ToolInvokeResponse,
  ToolSummary,
} from "./tools-types";

// ---------------------------------------------------------------------------
// Mock-styled inline primitives (shared across left + right columns)
// ---------------------------------------------------------------------------

const ACTION_BTN: CSSProperties = {
  height: 26,
  padding: "0 12px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  borderRadius: 3,
  cursor: "pointer",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
};

const PRIMARY_BTN: CSSProperties = {
  ...ACTION_BTN,
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  borderColor: "var(--accent)",
};

const INPUT_STYLE: CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Narrow the raw `inputs` dict from the backend to a typed object-schema.
 * Returns null when the tool has no inputs or the schema is not an object type.
 */
function asObjectSchema(
  inputs: ToolDetail["inputs"],
): { properties: Record<string, JSONSchema>; required?: string[] } | null {
  if (
    inputs &&
    typeof inputs === "object" &&
    !Array.isArray(inputs) &&
    "properties" in inputs &&
    inputs.properties !== null &&
    typeof inputs.properties === "object"
  ) {
    return inputs as {
      properties: Record<string, JSONSchema>;
      required?: string[];
    };
  }
  return null;
}

/** Build a blank form values dict from the schema properties. */
function initFormValues(
  schema: { properties: Record<string, JSONSchema> } | null,
): Record<string, unknown> {
  if (!schema) return {};
  const result: Record<string, unknown> = {};
  for (const [key, fieldSchema] of Object.entries(schema.properties)) {
    if (fieldSchema.default !== undefined) {
      result[key] = fieldSchema.default;
    } else if (fieldSchema.type === "boolean") {
      result[key] = false;
    } else if (fieldSchema.type === "array") {
      result[key] = [];
    } else if (fieldSchema.type === "object") {
      result[key] = {};
    } else {
      result[key] = "";
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Tool detail + invoke form (right column)
// ---------------------------------------------------------------------------

interface ToolDetailPanelProps {
  toolKey: string;
  canInvoke: boolean;
}

function ToolDetailPanel({ toolKey, canInvoke }: ToolDetailPanelProps) {
  const detailQuery = useQuery<ToolDetail>({
    queryKey: ["platform", "tool-detail", toolKey],
    queryFn: () => fetchToolDetail(toolKey),
    staleTime: 60_000,
  });

  const [formValues, setFormValues] = useState<Record<string, unknown>>({});
  const [invokeResult, setInvokeResult] = useState<ToolInvokeResponse | null>(
    null,
  );

  const schema = detailQuery.data
    ? asObjectSchema(detailQuery.data.inputs)
    : null;

  // Reset form when tool changes
  useMemo(() => {
    setFormValues(initFormValues(schema));
    setInvokeResult(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- toolKey change triggers reset
  }, [toolKey]);

  const updateFormValue = useCallback((name: string, value: unknown): void => {
    setFormValues((prev) => ({ ...prev, [name]: value }));
  }, []);

  const invokeMutation = useMutation<
    ToolInvokeResponse,
    Error,
    Record<string, unknown>
  >({
    mutationFn: (kwargs) => invokeTool(toolKey, kwargs),
    onSuccess: (data) => {
      setInvokeResult(data);
    },
    onError: (err) => {
      setInvokeResult({
        tool_key: toolKey,
        result: null,
        error: err.message,
      });
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canInvoke) return;
    invokeMutation.mutate(formValues);
  }

  if (detailQuery.isLoading) {
    return (
      <WindowPanel title="invoke" status="LOADING" tone="muted">
        <LoadingSkeletonGroup lines={8} />
      </WindowPanel>
    );
  }

  if (detailQuery.isError) {
    return (
      <WindowPanel title="invoke" tone="warn">
        <p
          className="font-mono"
          style={{ color: "var(--status-warn)", fontSize: 11 }}
        >
          Failed to load tool detail: {(detailQuery.error as Error).message}
        </p>
      </WindowPanel>
    );
  }

  const detail = detailQuery.data;
  if (!detail) return null;

  const hasInputs =
    schema !== null && Object.keys(schema.properties).length > 0;
  const isInvoking = invokeMutation.isPending;

  return (
    <div className="flex flex-col" style={{ gap: 12, minWidth: 0 }}>
      <WindowPanel title="tool">
        <div className="flex items-start justify-between" style={{ gap: 12 }}>
          <div className="flex flex-col" style={{ gap: 6, minWidth: 0 }}>
            <div
              className="font-mono"
              style={{
                fontFamily: "var(--font-display)",
                fontSize: 18,
                letterSpacing: "-0.01em",
                color: "var(--text-primary)",
              }}
            >
              {detail.name}
            </div>
            <div
              className="font-mono"
              style={{
                color: "var(--text-faint)",
                fontSize: 10.5,
                wordBreak: "break-all",
              }}
            >
              {detail.tool_key}
            </div>
            <p
              className="font-mono"
              style={{ color: "var(--text-muted)", fontSize: 11 }}
            >
              {detail.description}
            </p>
          </div>
          <div
            className="flex flex-col items-end"
            style={{ gap: 6, flexShrink: 0 }}
          >
            <MonoBadge tone="muted">{detail.module_id}</MonoBadge>
            <span
              className="font-mono"
              style={{
                color: "var(--text-faint)",
                fontSize: 10,
                letterSpacing: "0.08em",
              }}
            >
              {"\u2192 "}
              {detail.output_type}
            </span>
          </div>
        </div>
      </WindowPanel>

      <WindowPanel title="invoke">
        <form
          onSubmit={handleSubmit}
          className="flex flex-col"
          style={{ gap: 14 }}
        >
          {hasInputs ? (
            Object.entries(schema.properties).map(
              ([fieldName, fieldSchema]) => (
                <SchemaField
                  key={fieldName}
                  name={fieldName}
                  schema={fieldSchema}
                  required={schema.required?.includes(fieldName) ?? false}
                  value={formValues[fieldName]}
                  onChange={updateFormValue}
                />
              ),
            )
          ) : (
            <p
              className="font-mono"
              style={{ color: "var(--text-muted)", fontSize: 11 }}
            >
              This tool takes no inputs.
            </p>
          )}

          <div className="flex items-center" style={{ gap: 10, paddingTop: 4 }}>
            <button
              type="submit"
              className="font-mono uppercase"
              disabled={!canInvoke || isInvoking}
              title={canInvoke ? undefined : "Operator role required"}
              style={{
                ...(canInvoke ? PRIMARY_BTN : ACTION_BTN),
                opacity: canInvoke && !isInvoking ? 1 : 0.6,
                cursor:
                  !canInvoke || isInvoking ? "not-allowed" : "pointer",
              }}
            >
              {canInvoke
                ? isInvoking
                  ? "invoking\u2026"
                  : "invoke"
                : "invoke (locked)"}
            </button>

            {invokeResult !== null && (
              <button
                type="button"
                className="font-mono uppercase"
                onClick={() => {
                  setInvokeResult(null);
                  invokeMutation.reset();
                }}
                style={ACTION_BTN}
              >
                clear result
              </button>
            )}
          </div>
        </form>
      </WindowPanel>

      {invokeResult !== null && (
        <WindowPanel
          title={invokeResult.error ? "invocation error" : "result"}
          tone={invokeResult.error ? "warn" : "ok"}
        >
          {invokeResult.error ? (
            <p
              className="font-mono"
              style={{
                color: "var(--status-warn)",
                fontSize: 11,
                wordBreak: "break-word",
              }}
            >
              {invokeResult.error}
            </p>
          ) : (
            <pre
              className="font-mono"
              style={{
                margin: 0,
                padding: 10,
                fontSize: 11,
                lineHeight: 1.5,
                color: "var(--text-primary)",
                background: "var(--surface-sunk)",
                border: "1px solid var(--border-soft)",
                borderRadius: 3,
                maxHeight: 400,
                overflow: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {JSON.stringify(invokeResult.result, null, 2)}
            </pre>
          )}
        </WindowPanel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page root -- registry grid (left) + detail (right)
// ---------------------------------------------------------------------------

export function ToolsConsolePage() {
  const [selectedToolKey, setSelectedToolKey] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [moduleFilter, setModuleFilter] = useState<string | null>(null);

  const role = useAuthStore((s) => s.role);
  const canInvoke = isAllowedRole(role, "operator");

  const toolsQuery = useQuery<ToolSummary[]>({
    queryKey: ["platform", "tools"],
    queryFn: () =>
      authorizedRequestJson<ToolSummary[]>("/tools", { method: "GET" }),
    staleTime: 60_000,
  });

  const tools = toolsQuery.data ?? [];

  const modules = useMemo(() => {
    const seen = new Set<string>();
    for (const t of tools) seen.add(t.module_id);
    return [...seen].sort();
  }, [tools]);

  const filteredTools = useMemo(() => {
    const q = search.trim().toLowerCase();
    return tools.filter((t) => {
      if (moduleFilter && t.module_id !== moduleFilter) return false;
      if (!q) return true;
      return (
        t.tool_key.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.module_id.toLowerCase().includes(q)
      );
    });
  }, [tools, search, moduleFilter]);

  return (
    <div
      className="flex flex-col"
      style={{ gap: 16, padding: 20, minHeight: "100%" }}
    >
      <SectionHeader
        icon={
          <Wrench
            size={16}
            weight="duotone"
            style={{ color: "var(--text-on-accent)" }}
            aria-hidden="true"
          />
        }
        title="tools console"
        actions={
          <button
            type="button"
            className="font-mono uppercase"
            onClick={() => void toolsQuery.refetch()}
            disabled={toolsQuery.isFetching}
            style={{
              ...ACTION_BTN,
              opacity: toolsQuery.isFetching ? 0.6 : 1,
            }}
          >
            {toolsQuery.isFetching ? "refreshing" : "refresh"}
          </button>
        }
      />

      {/* Filter row */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <input
          type="text"
          placeholder={"search tools\u2026"}
          aria-label="Search tools"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="font-mono"
          style={{ ...INPUT_STYLE, width: 260 }}
        />
        <FilterChip
          active={moduleFilter === null}
          onClick={() => setModuleFilter(null)}
        >
          all modules
        </FilterChip>
        {modules.map((mod) => (
          <FilterChip
            key={mod}
            active={moduleFilter === mod}
            onClick={() =>
              setModuleFilter(moduleFilter === mod ? null : mod)
            }
          >
            {mod}
          </FilterChip>
        ))}
        {!canInvoke && (
          <MonoBadge tone="warn" title="Operator role required for invocation">
            read-only
          </MonoBadge>
        )}
      </div>

      <div
        className="grid"
        style={{
          gridTemplateColumns: "1fr 460px",
          gap: 16,
          minHeight: 0,
        }}
      >
        <WindowPanel
          title={`tool registry \u00b7 ${filteredTools.length}`}
          flush
        >
          {toolsQuery.isLoading ? (
            <div style={{ padding: 16 }}>
              <LoadingSkeletonGroup lines={6} />
            </div>
          ) : toolsQuery.isError ? (
            <div
              className="font-mono"
              style={{
                padding: 16,
                color: "var(--status-warn)",
                fontSize: 11,
              }}
            >
              Failed to load tools. Check backend connectivity.
            </div>
          ) : (
            <DataGrid<ToolSummary>
              columns={[
                { label: "NAME", width: "1fr" },
                { label: "KEY", width: "1.4fr" },
                { label: "MODULE", width: "120px" },
              ]}
              rows={filteredTools}
              getKey={(t) => t.tool_key}
              onRowClick={(t) => setSelectedToolKey(t.tool_key)}
              empty={
                <div
                  className="font-mono"
                  style={{
                    padding: 24,
                    textAlign: "center",
                    fontSize: 11,
                    color: "var(--text-muted)",
                  }}
                >
                  {search || moduleFilter
                    ? "no tools match the filters."
                    : "no tools registered."}
                </div>
              }
              renderCells={(t) => {
                const isSel = t.tool_key === selectedToolKey;
                return [
                  <span
                    key="name"
                    className="font-mono truncate"
                    style={{
                      color: isSel ? "var(--accent)" : "var(--text-primary)",
                      fontSize: 11,
                    }}
                  >
                    {t.name}
                  </span>,
                  <span
                    key="key"
                    className="font-mono truncate"
                    title={t.tool_key}
                    style={{
                      color: "var(--text-muted)",
                      fontSize: 10.5,
                    }}
                  >
                    {t.tool_key}
                  </span>,
                  <MonoBadge key="mod" tone="muted">
                    {t.module_id}
                  </MonoBadge>,
                ];
              }}
            />
          )}
        </WindowPanel>

        {selectedToolKey === null ? (
          <WindowPanel title="invoke" tone="muted">
            <div
              className="flex flex-col items-center justify-center"
              style={{ gap: 8, padding: "36px 12px", textAlign: "center" }}
            >
              <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>
                <Wrench size={28} weight="duotone" />
              </span>
              <span
                className="font-mono"
                style={{ color: "var(--text-primary)", fontSize: 12 }}
              >
                Select a tool
              </span>
              <span
                className="font-mono"
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10.5,
                  maxWidth: 260,
                }}
              >
                Choose a tool from the registry to inspect its schema and invoke.
              </span>
            </div>
          </WindowPanel>
        ) : (
          <ToolDetailPanel toolKey={selectedToolKey} canInvoke={canInvoke} />
        )}
      </div>
    </div>
  );
}
