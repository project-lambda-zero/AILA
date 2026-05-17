import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useDeletePattern } from "../mutations";
import { usePatterns, useWorkspaces } from "../queries";
import type { PatternKind, PatternScope, PatternStatus } from "../types";

const KINDS: PatternKind[] = [
  "exploitation_technique",
  "fuzzing_strategy",
  "search_heuristic",
  "tool_recipe",
  "triage_rule",
];
const STATUSES: PatternStatus[] = ["draft", "active", "archived"];
const SCOPES: PatternScope[] = ["local", "workspace", "team", "global"];

const statusColor: Record<
  PatternStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  draft: "info",
  active: "low",
  archived: "high",
};

const scopeColor: Record<
  PatternScope,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  local: "info",
  workspace: "medium",
  team: "high",
  global: "critical",
};

export function PatternsPage() {
  const navigate = useNavigate();
  const { data: workspacesResult } = useWorkspaces();
  const workspaces = workspacesResult?.data ?? [];
  const deleteMut = useDeletePattern();

  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const [kindFilter, setKindFilter] = useState<PatternKind | "">("");
  const [statusFilter, setStatusFilter] = useState<PatternStatus | "">("");
  const [scopeFilter, setScopeFilter] = useState<PatternScope | "">("");

  const { data: result, isLoading, isError } = usePatterns({
    workspaceId: workspaceFilter || undefined,
    kind: kindFilter || undefined,
    status: statusFilter || undefined,
    scope: scopeFilter || undefined,
  });
  const patterns = result?.data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">Patterns</h1>
        <p className="text-sm text-text-muted mt-1">
          Knowledge Transfer catalog (GA-41). Auto-extracted patterns enter
          status:draft scope:local; operator reviews + promotes to wider scope
          via the detail page.
        </p>
      </div>

      <AilaCard>
        <div className="flex items-center gap-2 flex-wrap">
          <label className="text-sm text-text-muted">Workspace:</label>
          <select
            value={workspaceFilter}
            onChange={(e) => setWorkspaceFilter(e.target.value)}
            className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
          >
            <option value="">— all —</option>
            {workspaces.map((ws) => (
              <option key={ws.id} value={ws.id}>
                {ws.name}
              </option>
            ))}
          </select>

          <label className="text-sm text-text-muted ml-2">Kind:</label>
          <select
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value as PatternKind | "")}
            className="px-3 py-1.5 text-sm font-mono rounded-md bg-surface border border-border-default"
          >
            <option value="">— all —</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>

          <label className="text-sm text-text-muted ml-2">Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as PatternStatus | "")}
            className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
          >
            <option value="">— all —</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <label className="text-sm text-text-muted ml-2">Scope:</label>
          <select
            value={scopeFilter}
            onChange={(e) => setScopeFilter(e.target.value as PatternScope | "")}
            className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
          >
            <option value="">— all —</option>
            {SCOPES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <span className="text-xs text-text-muted ml-auto">
            {patterns.length} pattern{patterns.length === 1 ? "" : "s"}
          </span>
        </div>
      </AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load patterns.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && patterns.length === 0 && (
        <AilaCard>
          <p className="text-center py-6 text-text-muted">
            No patterns. Auto-extraction runs when investigations complete
            successfully; you can also create patterns manually via the API.
          </p>
        </AilaCard>
      )}

      {!isLoading && !isError && patterns.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Summary</th>
                <th className="px-4 py-2 font-semibold">Kind</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold">Scope</th>
                <th className="px-4 py-2 font-semibold">Confidence</th>
                <th className="px-4 py-2 font-semibold text-right">Used</th>
                <th className="px-4 py-2 font-semibold">Created</th>
                <th className="px-2 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {patterns.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => navigate(`/vr/patterns/${p.id}`)}
                  className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
                >
                  <td className="px-4 py-2 font-semibold text-foreground max-w-md truncate">
                    {p.summary}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
                    {p.kind}
                  </td>
                  <td className="px-4 py-2">
                    <AilaBadge severity={statusColor[p.status]} size="sm">
                      {p.status}
                    </AilaBadge>
                  </td>
                  <td className="px-4 py-2">
                    <AilaBadge severity={scopeColor[p.scope]} size="sm">
                      {p.scope}
                    </AilaBadge>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">
                    {p.confidence}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-right">
                    {p.times_retrieved}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
                    {p.created_at
                      ? new Date(p.created_at).toLocaleDateString()
                      : "—"}
                  </td>
                  <td className="px-2 py-2 text-right">
                    <DeleteButton
                      id={p.id}
                      label={`pattern "${p.summary.slice(0, 40)}"`}
                      mutation={deleteMut}
                      compact
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}
