import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useEnrichTarget, useRankTarget } from "../mutations";
import { useTarget } from "../queries";
import type { EnrichmentStatus, TargetStatus } from "../types";

const statusColor: Record<
  TargetStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  active: "low",
  archived: "info",
  quarantined: "high",
};

const enrichmentColor: Record<
  EnrichmentStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  unenriched: "info",
  running: "medium",
  complete: "low",
  failed: "critical",
};

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
  target_id?: string;
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
  const rankMut = useRankTarget(tid);
  const enrichMut = useEnrichTarget(tid);

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
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          {target.display_name}
        </h1>
        <p className="text-sm text-text-muted mt-1 font-mono">
          {target.kind} · workspace:{target.workspace_id}
        </p>
      </div>

      <div className="flex gap-2 items-center flex-wrap">
        <AilaBadge severity={statusColor[target.status] ?? "info"} size="sm">
          {target.status}
        </AilaBadge>
        <AilaBadge
          severity={enrichmentColor[target.enrichment_status] ?? "info"}
          size="sm"
        >
          enrichment:{target.enrichment_status}
        </AilaBadge>
        {target.primary_language && (
          <AilaBadge severity="info" size="sm">
            {target.primary_language}
          </AilaBadge>
        )}
      </div>

      {/* Action bar */}
      <div className="flex gap-2 flex-wrap">
        <button
          type="button"
          onClick={() => enrichMut.mutate()}
          disabled={enrichMut.isPending}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
        >
          {enrichMut.isPending ? "Enqueuing…" : "Run enrichment"}
        </button>
        <button
          type="button"
          onClick={() => rankMut.mutate()}
          disabled={rankMut.isPending}
          className="px-4 py-2 text-sm font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover transition-colors disabled:opacity-50"
        >
          {rankMut.isPending ? "Enqueuing…" : "Run function ranking"}
        </button>
      </div>

      {/* Capability profile */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Capability profile
        </h2>
        {target.enrichment_status === "unenriched" ? (
          <p className="text-sm text-text-muted">
            Not enriched yet. Click <strong>Run enrichment</strong> above.
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
                {applicableEngines.length > 0
                  ? applicableEngines.join(", ")
                  : "—"}
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
                {defaultDisclosure.length > 0
                  ? defaultDisclosure.join(", ")
                  : "—"}
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

      {/* Function ranking */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Function ranking ({ranking.top_k?.length ?? 0} of{" "}
          {ranking.total_candidates ?? 0})
        </h2>
        {!ranking.top_k || ranking.top_k.length === 0 ? (
          <p className="text-sm text-text-muted">
            No ranking yet. Click <strong>Run function ranking</strong> above.
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

      {/* Descriptor (raw JSON) */}
      <AilaCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">Descriptor</h2>
        <pre className="text-xs font-mono text-text-muted whitespace-pre-wrap overflow-x-auto">
          {JSON.stringify(target.descriptor, null, 2)}
        </pre>
      </AilaCard>
    </div>
  );
}
