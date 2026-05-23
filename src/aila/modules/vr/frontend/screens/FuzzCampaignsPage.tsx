import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useDeleteFuzzCampaign } from "../mutations";
import { useFuzzCampaigns, useWorkspaces } from "../queries";
import type { CampaignStatus } from "../types";

const STATUS_COLOR: Record<
  CampaignStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  created: "info",
  running: "medium",
  paused: "info",
  completed: "low",
  failed: "high",
  aborted: "high",
};

const STATUSES: CampaignStatus[] = [
  "created", "running", "paused", "completed", "failed", "aborted",
];

export function FuzzCampaignsPage() {
  const navigate = useNavigate();
  const { data: workspacesResult } = useWorkspaces();
  const workspaces = workspacesResult?.data ?? [];
  const deleteMut = useDeleteFuzzCampaign();

  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<CampaignStatus | "">("");

  const { data: result, isLoading, isError } = useFuzzCampaigns({
    workspaceId: workspaceFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = result?.data ?? [];

  return (
    <div className="space-y-4">

      <AilaCard  techBorder glow><div className="flex items-center gap-2 flex-wrap">
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
      
        <label className="text-sm text-text-muted ml-2">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as CampaignStatus | "")}
          className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
        >
          <option value="">— all —</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      
        <span className="text-xs text-text-muted ml-auto">
          {rows.length} campaign{rows.length === 1 ? "" : "s"}
        </span>
      </div></AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load campaigns.</p></AilaCard>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <AilaCard  techBorder glow><p className="text-center py-6 text-text-muted">
          No fuzz campaigns. Create via POST /vr/fuzz/campaigns referencing a
          target_id + workspace_id.
        </p></AilaCard>
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow><table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
              <th className="px-4 py-2 font-semibold">Name</th>
              <th className="px-4 py-2 font-semibold">Engine</th>
              <th className="px-4 py-2 font-semibold">Strategy</th>
              <th className="px-4 py-2 font-semibold">Status</th>
              <th className="px-4 py-2 font-semibold text-right">Execs</th>
              <th className="px-4 py-2 font-semibold text-right">Corpus</th>
              <th className="px-4 py-2 font-semibold text-right">Cov %</th>
              <th className="px-4 py-2 font-semibold text-right">Crashes</th>
              <th className="px-4 py-2 font-semibold">Last progress</th>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr
                key={c.id}
                onClick={() => navigate(`/vr/fuzz/campaigns/${c.id}`)}
                className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
              >
                <td className="px-4 py-2 font-semibold text-foreground">
                  {c.name}
                </td>
                <td className="px-4 py-2 font-mono text-xs">{c.engine_id}</td>
                <td className="px-4 py-2 font-mono text-xs">
                  {c.strategy_id}
                </td>
                <td className="px-4 py-2">
                  <AilaBadge severity={STATUS_COLOR[c.status]} size="sm">
                    {c.status}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.total_execs.toLocaleString()}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.corpus_size.toLocaleString()}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.coverage_pct != null
                    ? `${c.coverage_pct.toFixed(2)}%`
                    : "—"}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.crashes_found}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {c.last_progress_at
                    ? new Date(c.last_progress_at).toLocaleString()
                    : "—"}
                </td>
                <td className="px-2 py-2 text-right">
                  <DeleteButton
                    id={c.id}
                    label={`fuzz campaign "${c.name}"`}
                    mutation={deleteMut}
                    compact
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table></AilaCard>
      )}
    </div>
  );
}
