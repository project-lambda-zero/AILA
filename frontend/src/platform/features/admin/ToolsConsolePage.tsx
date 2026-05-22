/**
 * ToolsConsolePage — live tool invocation console at /admin/tools.
 *
 * Requires operator+ role at the frontend route level (defense-in-depth, GA5).
 * Backend POST /tools/{key} independently enforces ROLE_OPERATOR.
 *
 * Layout:
 * - Left panel: searchable tool list grouped by module_id
 * - Right panel: selected tool detail + dynamic form + invoke + result/error
 */

import { useState, useCallback, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Wrench, Lock, MagnifyingGlass, ArrowClockwise } from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";

import { SchemaField } from "./SchemaField";
import { fetchToolDetail, fetchToolsList, invokeTool } from "./tools-api";
import type { JSONSchema, ToolDetail, ToolInvokeResponse, ToolSummary } from "./tools-types";

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
    return inputs as { properties: Record<string, JSONSchema>; required?: string[] };
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

/** Derive a short module label from a module_id string (e.g. "vuln" → "vuln"). */
function moduleLabel(moduleId: string): string {
  return moduleId;
}

// ---------------------------------------------------------------------------
// Tool list panel
// ---------------------------------------------------------------------------

interface ToolListPanelProps {
  tools: ToolSummary[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
  isLoading: boolean;
  isError: boolean;
  onRefresh: () => void;
}

function ToolListPanel({
  tools,
  selectedKey,
  onSelect,
  isLoading,
  isError,
  onRefresh,
}: ToolListPanelProps) {
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return tools;
    return tools.filter(
      (t) =>
        t.tool_key.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.module_id.toLowerCase().includes(q),
    );
  }, [tools, search]);

  return (
    <div className="flex flex-col h-full gap-3">
      <div className="flex items-center justify-between gap-2">
        <h2 className="font-mono text-sm font-semibold text-foreground">
          Registered Tools
        </h2>
        <Button
          size="sm"
          variant="ghost"
          className="h-7 w-7 p-0"
          onClick={onRefresh}
          aria-label="Refresh tool list"
          title="Refresh tool list"
        >
          <ArrowClockwise className="h-3.5 w-3.5" />
        </Button>
      </div>

      <div className="relative">
        <MagnifyingGlass className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
        <Input
          type="text"
          placeholder="Search tools…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-7 font-mono text-xs"
          aria-label="Search tools"
        />
      </div>

      {isLoading && <LoadingSkeletonGroup lines={6} />}

      {isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          Failed to load tools. Check backend connectivity.
        </div>
      )}

      {!isLoading && !isError && filtered.length === 0 && (
        <p className="font-mono text-xs text-muted-foreground">
          {search ? "No tools match the search." : "No tools registered."}
        </p>
      )}

      <div className="flex flex-col gap-0.5 overflow-y-auto">
        {filtered.map((tool) => {
          const isSelected = tool.tool_key === selectedKey;
          return (
            <button
              key={tool.tool_key}
              type="button"
              onClick={() => onSelect(tool.tool_key)}
              className={[
                "w-full text-left px-3 py-2 rounded-[4px] transition-colors group",
                isSelected
                  ? "bg-accent/15 border border-accent/40"
                  : "hover:bg-elevated border border-transparent hover:border-border",
              ].join(" ")}
            >
              <div className="flex items-start justify-between gap-2">
                <span className="font-mono text-xs text-foreground break-all leading-tight">
                  {tool.name}
                </span>
                <AilaBadge severity="neutral" size="sm">
                  {moduleLabel(tool.module_id)}
                </AilaBadge>
              </div>
              <p className="font-mono text-[10px] text-muted-foreground mt-0.5 truncate">
                {tool.tool_key}
              </p>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tool detail + form panel
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
  const [invokeResult, setInvokeResult] = useState<ToolInvokeResponse | null>(null);

  const schema = detailQuery.data ? asObjectSchema(detailQuery.data.inputs) : null;

  // Reset form when tool changes
  useMemo(() => {
    setFormValues(initFormValues(schema));
    setInvokeResult(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- toolKey change triggers reset
  }, [toolKey]);

  const updateFormValue = useCallback((name: string, value: unknown): void => {
    setFormValues((prev) => ({ ...prev, [name]: value }));
  }, []);

  const invokeMutation = useMutation<ToolInvokeResponse, Error, Record<string, unknown>>({
    mutationFn: (kwargs) => invokeTool(toolKey, kwargs),
    onSuccess: (data) => {
      setInvokeResult(data);
    },
    onError: (err) => {
      // Network/HTTP error (non-tool error) — surface as a synthetic invoke response
      setInvokeResult({
        tool_key: toolKey,
        result: null,
        error: err.message,
      });
    },
  });

  function handleSubmit(e: React.FormEvent): void {
    e.preventDefault();
    // Defense-in-depth: backend POST /tools/{key} enforces ROLE_OPERATOR.
    // This `disabled` check is UX only — bypassing it yields a 403, not unauthorized access.
    if (!canInvoke) return;
    invokeMutation.mutate(formValues);
  }

  if (detailQuery.isLoading) {
    return (
      <AilaCard variant="elevated" padding="md" className="h-full" techBorder glow><LoadingSkeletonGroup lines={8} /></AilaCard>
    );
  }

  if (detailQuery.isError) {
    return (
      <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs text-destructive">
        Failed to load tool detail: {(detailQuery.error as Error).message}
      </p></AilaCard>
    );
  }

  const detail = detailQuery.data;
  if (!detail) return null;

  const hasInputs = schema !== null && Object.keys(schema.properties).length > 0;
  const isInvoking = invokeMutation.isPending;

  return (
    <div className="flex flex-col gap-4">
      {/* Tool header */}
      <AilaCard variant="elevated" padding="md" techBorder glow><div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1 min-w-0">
          <h2 className="font-mono text-base font-semibold text-foreground">
            {detail.name}
          </h2>
          <p className="font-mono text-[10px] text-muted-foreground break-all">
            {detail.tool_key}
          </p>
          <p className="font-mono text-xs text-muted-foreground mt-1">
            {detail.description}
          </p>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0">
          <AilaBadge severity="neutral" size="sm">
            {moduleLabel(detail.module_id)}
          </AilaBadge>
          <span className="font-mono text-[10px] text-muted-foreground">
            → {detail.output_type}
          </span>
        </div>
      </div></AilaCard>

      {/* Invoke form */}
      <AilaCard variant="elevated" padding="md" techBorder glow><h3 className="font-mono text-sm font-semibold text-foreground mb-3">
        Inputs
      </h3>
      
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {hasInputs ? (
          Object.entries(schema.properties).map(([fieldName, fieldSchema]) => (
            <SchemaField
              key={fieldName}
              name={fieldName}
              schema={fieldSchema}
              required={schema.required?.includes(fieldName) ?? false}
              value={formValues[fieldName]}
              onChange={updateFormValue}
            />
          ))
        ) : (
          <p className="font-mono text-xs text-muted-foreground">
            This tool takes no inputs.
          </p>
        )}
      
        <div className="flex items-center gap-3 pt-2">
          {canInvoke ? (
            <Button type="submit" size="sm" disabled={isInvoking}>
              <Wrench className="h-3.5 w-3.5 mr-1.5" />
              {isInvoking ? "Invoking…" : "Invoke"}
            </Button>
          ) : (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger>
                  <Button type="button" size="sm" disabled className="gap-1.5 opacity-60">
                    <Lock className="h-3.5 w-3.5" />
                    Invoke
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <span className="font-mono text-xs">Operator role required</span>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
      
          {invokeResult !== null && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                setInvokeResult(null);
                invokeMutation.reset();
              }}
            >
              Clear result
            </Button>
          )}
        </div>
      </form></AilaCard>

      {/* Result pane */}
      {invokeResult !== null && (
        <AilaCard variant="elevated"
        padding="md"
        className={
          invokeResult.error
            ? "border-destructive/40 bg-destructive/5"
            : "border-border"
        } techBorder glow><h3 className="font-mono text-sm font-semibold text-foreground mb-2">
          {invokeResult.error ? "Invocation Error" : "Result"}
        </h3>
        
        {invokeResult.error ? (
          <p className="font-mono text-xs text-destructive break-words">
            {invokeResult.error}
          </p>
        ) : (
          <pre className="font-mono text-xs text-foreground whitespace-pre-wrap break-words bg-surface rounded-[4px] border border-border p-3 overflow-auto max-h-[400px]">
            {JSON.stringify(invokeResult.result, null, 2)}
          </pre>
        )}</AilaCard>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page root
// ---------------------------------------------------------------------------

export function ToolsConsolePage() {
  const [selectedToolKey, setSelectedToolKey] = useState<string | null>(null);

  const role = useAuthStore((s) => s.role);
  const canInvoke = isAllowedRole(role, "operator");

  const toolsQuery = useQuery<ToolSummary[]>({
    queryKey: ["platform", "tools"],
    queryFn: () => authorizedRequestJson<ToolSummary[]>("/tools", { method: "GET" }),
    staleTime: 60_000,
  });

  const tools = toolsQuery.data ?? [];

  function handleSelectTool(key: string): void {
    setSelectedToolKey(key);
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6 h-full">
      {/* Page header */}
      <div className="flex flex-col gap-1">
        <h1 className="font-mono text-xl font-semibold text-foreground flex items-center gap-2">
          <Wrench className="h-5 w-5 text-accent" />
          Tools Console
        </h1>
        <p className="font-mono text-sm text-muted-foreground">
          Live invocation of registered platform tools. Invoke requires operator role.
        </p>
      </div>

      {/* Two-column split */}
      <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-4 min-h-0 flex-1">
        {/* Left: tool list */}
        <AilaCard variant="default" padding="md" className="overflow-hidden" techBorder glow><ToolListPanel
          tools={tools}
          selectedKey={selectedToolKey}
          onSelect={handleSelectTool}
          isLoading={toolsQuery.isLoading}
          isError={toolsQuery.isError}
          onRefresh={() => void toolsQuery.refetch()}
        /></AilaCard>

        {/* Right: tool detail */}
        <div className="min-w-0">
          {selectedToolKey === null ? (
            <EmptyState
              icon={<Wrench className="h-10 w-10" />}
              title="Select a tool"
              description="Choose a tool from the left panel to view its schema and invoke it."
            />
          ) : (
            <ToolDetailPanel toolKey={selectedToolKey} canInvoke={canInvoke} />
          )}
        </div>
      </div>
    </div>
  );
}
