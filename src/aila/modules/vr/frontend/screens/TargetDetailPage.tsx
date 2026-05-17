import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useAnalyzeTarget, useRankTarget } from "../mutations";
import { useTarget, useWorkspaces } from "../queries";
import type {
  AnalysisState,
  TargetKind,
  TargetStatus,
} from "../types";

const statusColor: Record<
  TargetStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  active: "low",
  archived: "info",
  quarantined: "high",
};

const analysisColor: Record<
  AnalysisState,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  pending: "info",
  ingesting: "medium",
  ready: "low",
  failed: "critical",
};

/** Per-kind operator-readable label for each AnalysisState. */
function analysisLabel(state: AnalysisState, kind: TargetKind): string {
  if (state === "ready") return "Ready";
  if (state === "failed") return "Failed";
  if (state === "pending") return "Queued";
  // ingesting
  if (kind === "source_repo") return "Cloning + indexing source…";
  if (kind === "cve") return "Resolving CVE record…";
  if (
    kind === "kernel_image" ||
    kind === "kernel_module" ||
    kind === "hypervisor_image" ||
    kind === "apk" ||
    kind === "ipa" ||
    kind === "jar" ||
    kind === "dotnet_assembly"
  ) {
    return "Uploading + analyzing in IDA…";
  }
  return "Uploading + analyzing…";
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

interface RankedFunction {
  name?: string;
  address?: string;
  file_path?: string;
  line?: number | null;
  score?: number;
  rank?: number;
  reasons?: string[];
}

interface FunctionRanking {
  source?: string;
  produced_at?: string;
  total_candidates?: number;
  top_k?: RankedFunction[];
}

interface MitigationFlags {
  nx?: boolean | null;
  aslr?: boolean | null;
  canary?: boolean | null;
  cet?: boolean | null;
  cfi?: boolean | null;
  relro_partial?: boolean | null;
  relro_full?: boolean | null;
  pie?: boolean | null;
  sanitizers?: string[];
  notes?: string;
}

function fmtFlag(v?: boolean | null): { label: string; severity: "info" | "low" | "high" } {
  if (v === true) return { label: "ON", severity: "low" };
  if (v === false) return { label: "OFF", severity: "high" };
  return { label: "?", severity: "info" };
}

export function TargetDetailPage() {
  const { targetId } = useParams<{ targetId: string }>();
  const tid = targetId ?? "";

  const { data: target, isLoading } = useTarget(tid);
  const { data: workspacesResult } = useWorkspaces();
  const workspaceName =
    workspacesResult?.data.find((w) => w.id === target?.workspace_id)?.name ??
    null;

  const analyzeMut = useAnalyzeTarget(tid);
  const rankMut = useRankTarget(tid);

  if (isLoading || !target) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  const capability =
    (target.capability_profile as Record<string, unknown>) || {};
  const mitigations = (capability.mitigations as MitigationFlags) || {};
  const ranking = (capability.function_ranking as FunctionRanking) || {};

  const applicableEngines =
    (capability.applicable_fuzzing_engines as string[]) || [];
  const applicableStrategies =
    (capability.applicable_strategies as string[]) || [];
  const applicableMcp = (capability.applicable_mcp_servers as string[]) || [];
  const defaultDisclosure =
    (capability.default_disclosure_tracks as string[]) || [];

  return (
    <div className="space-y-4">
      {/* Header — humans, not IDs */}
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          {target.display_name}
        </h1>
        <p className="text-sm text-text-muted mt-1">
          {workspaceName ? (
            <span>
              {workspaceName} <span className="text-text-muted">·</span>{" "}
              {target.kind.replace(/_/g, " ")}
            </span>
          ) : (
            <span>{target.kind.replace(/_/g, " ")}</span>
          )}
        </p>
      </div>

      {/* Status banner */}
      <AilaCard
        className={
          target.analysis_state === "failed"
            ? "border-border-danger"
            : undefined
        }
      >
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <AilaBadge severity={analysisColor[target.analysis_state]} size="sm">
              {analysisLabel(target.analysis_state, target.kind)}
            </AilaBadge>
            <AilaBadge severity={statusColor[target.status] ?? "info"} size="sm">
              {target.status}
            </AilaBadge>
            {target.primary_language && (
              <AilaBadge severity="info" size="sm">
                {target.primary_language}
              </AilaBadge>
            )}
          </div>
          <div className="flex items-center gap-2">
            {(target.analysis_state === "failed" ||
              target.analysis_state === "ready") && (
              <button
                type="button"
                onClick={() => analyzeMut.mutate()}
                disabled={analyzeMut.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50"
              >
                {analyzeMut.isPending ? "Re-analyzing…" : "Re-analyze"}
              </button>
            )}
            {target.analysis_state === "ready" && (
              <button
                type="button"
                onClick={() => rankMut.mutate()}
                disabled={rankMut.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
              >
                {rankMut.isPending ? "Ranking…" : "Rank functions"}
              </button>
            )}
          </div>
        </div>
        {target.analysis_state_message && (
          <p
            className={`text-xs mt-2 ${
              target.analysis_state === "failed"
                ? "text-text-danger"
                : "text-text-muted"
            }`}
          >
            {target.analysis_state_message}
          </p>
        )}
        {target.analysis_state === "ingesting" && (
          <p className="text-xs text-text-muted mt-2">
            Started{" "}
            {target.analysis_started_at
              ? new Date(target.analysis_started_at).toLocaleTimeString()
              : "—"}
            . This usually takes 30s–10min depending on artifact size.
          </p>
        )}
      </AilaCard>

      {/* Capability profile */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Capability profile
        </h2>
        {target.analysis_state !== "ready" ? (
          <p className="text-sm text-text-muted">
            Available once analysis completes.
          </p>
        ) : (
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt className="text-text-muted text-xs">Applicable MCP servers</dt>
              <dd className="font-mono text-xs">
                {applicableMcp.length > 0 ? applicableMcp.join(", ") : "—"}
              </dd>
            </div>
            <div>
              <dt className="text-text-muted text-xs">Applicable fuzzing engines</dt>
              <dd className="font-mono text-xs">
                {applicableEngines.length > 0 ? applicableEngines.join(", ") : "—"}
              </dd>
            </div>
            <div>
              <dt className="text-text-muted text-xs">Applicable strategies</dt>
              <dd className="font-mono text-xs">
                {applicableStrategies.length > 0
                  ? applicableStrategies.join(", ")
                  : "—"}
              </dd>
            </div>
            <div>
              <dt className="text-text-muted text-xs">Default disclosure tracks</dt>
              <dd className="font-mono text-xs">
                {defaultDisclosure.length > 0 ? defaultDisclosure.join(", ") : "—"}
              </dd>
            </div>
            <div>
              <dt className="text-text-muted text-xs">Default reasoning strategy</dt>
              <dd className="font-mono text-xs">
                {(capability.default_reasoning_strategy as string) ?? "—"}
              </dd>
            </div>
            <div>
              <dt className="text-text-muted text-xs">Est. cost / investigation</dt>
              <dd className="font-mono text-xs">
                ${(capability.estimated_cost_per_investigation_usd as number) ?? "—"}
              </dd>
            </div>
          </dl>
        )}
      </AilaCard>

      {/* Mitigations */}
      {target.analysis_state === "ready" && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Mitigations
          </h2>
          <div className="flex flex-wrap gap-2 text-xs">
            {(["nx", "aslr", "canary", "cet", "cfi", "pie"] as const).map((k) => {
              const f = fmtFlag(mitigations[k]);
              return (
                <AilaBadge key={k} severity={f.severity} size="sm">
                  {k.toUpperCase()}:{f.label}
                </AilaBadge>
              );
            })}
            {(mitigations.relro_full || mitigations.relro_partial) && (
              <AilaBadge severity="low" size="sm">
                RELRO:{mitigations.relro_full ? "full" : "partial"}
              </AilaBadge>
            )}
            {(mitigations.sanitizers ?? []).map((s) => (
              <AilaBadge key={s} severity="medium" size="sm">
                {s}
              </AilaBadge>
            ))}
          </div>
          {mitigations.notes && (
            <p className="text-xs text-text-muted mt-2">{mitigations.notes}</p>
          )}
        </AilaCard>
      )}

      {/* Function ranking */}
      {target.analysis_state === "ready" && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Function ranking ({ranking.top_k?.length ?? 0} of{" "}
            {ranking.total_candidates ?? 0})
          </h2>
          {!ranking.top_k || ranking.top_k.length === 0 ? (
            <p className="text-sm text-text-muted">
              No ranking yet. Click <strong>Rank functions</strong> above.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border-default text-left text-text-muted">
                    <th className="px-2 py-1 font-semibold w-10">#</th>
                    <th className="px-2 py-1 font-semibold">Function</th>
                    <th className="px-2 py-1 font-semibold w-20 text-right">Score</th>
                    <th className="px-2 py-1 font-semibold">Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {ranking.top_k.slice(0, 50).map((f, i) => (
                    <tr
                      key={`${f.address ?? f.file_path ?? "_"}-${i}`}
                      className="border-b border-border-default last:border-b-0"
                    >
                      <td className="px-2 py-1 font-mono text-text-muted">
                        {f.rank ?? i + 1}
                      </td>
                      <td className="px-2 py-1 font-mono text-foreground">
                        {f.name ?? "<unnamed>"}
                        {f.address && (
                          <span className="text-text-muted ml-2">@ {f.address}</span>
                        )}
                        {f.file_path && (
                          <span className="text-text-muted ml-2">
                            {f.file_path}
                            {f.line != null ? `:${f.line}` : ""}
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-1 font-mono text-right text-foreground">
                        {f.score?.toFixed(2) ?? "—"}
                      </td>
                      <td className="px-2 py-1 text-text-muted">
                        {(f.reasons ?? []).join("; ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {ranking.produced_at && (
            <p className="text-xs text-text-muted mt-2 font-mono">
              produced_at: {formatDate(ranking.produced_at)}
              {ranking.source && ` · source: ${ranking.source}`}
            </p>
          )}
        </AilaCard>
      )}

      {/* Descriptor — collapsed for debugging only */}
      <AilaCard>
        <details>
          <summary className="text-sm font-semibold text-foreground cursor-pointer">
            Operator-supplied descriptor
          </summary>
          <pre className="text-xs font-mono text-text-muted whitespace-pre-wrap overflow-x-auto mt-2">
            {JSON.stringify(target.descriptor, null, 2)}
          </pre>
        </details>
      </AilaCard>
    </div>
  );
}
