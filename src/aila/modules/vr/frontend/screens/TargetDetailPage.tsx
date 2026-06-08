import { useRef, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import {
  MitigationsRibbon,
  type MitigationFlags,
} from "../components/MitigationsRibbon";
import { DeleteButton } from "../components/DeleteButton";
import { UploadDropzone } from "../components/UploadDropzone";
import {
  useAnalyzeTarget,
  useDeleteTarget,
  useRankTarget,
  useUploadTargetArtifact,
} from "../mutations";
import {
  useTarget,
  useTargetHypotheses,
  useWorkspaces,
} from "../queries";
import { Link } from "react-router";
import type {
  AnalysisState,
  TargetKind,
  TargetStatus,
} from "../types";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

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
    kind === "ipa" ||
    kind === "jar" ||
    kind === "dotnet_assembly"
  ) {
    return "Uploading + analyzing in IDA…";
  }
  if (kind === "android_apk") {
    return "APK_DECODE → JADX_DECOMPILE → INDEX_DECOMPILED → STATIC_SUMMARY → MOBSF_SCAN…";
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

const UPLOAD_KINDS = new Set<TargetKind>([
  "native_binary",
  "kernel_image",
  "kernel_module",
  "hypervisor_image",
  "ipa",
  "jar",
  "dotnet_assembly",
]);

function isUploadableKind(kind: TargetKind): boolean {
  return UPLOAD_KINDS.has(kind);
}

/** Operator-visible filename for an uploaded artifact, or null. The
 *  backend projects this onto VRTargetSummary from mcp_handles_json. */
function currentUploadedFilename(target: {
  uploaded_filename?: string | null;
}): string | null {
  return target.uploaded_filename ?? null;
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

// MitigationFlags interface lives in MitigationsRibbon (shared component).


// ─── Tabs for §1.4 ────────────────────────────────────────────────────────

type TargetTab =
  | "functions"
  | "attack_surface"
  | "hypotheses"
  | "imports"
  | "notes";

const TARGET_TABS: ReadonlyArray<{ id: TargetTab; label: string }> = [
  { id: "functions", label: "Functions of interest" },
  { id: "attack_surface", label: "Attack surface" },
  { id: "hypotheses", label: "Hypotheses" },
  { id: "imports", label: "Imports / exports" },
  { id: "notes", label: "Notes" },
];

function AttackSurfaceTab({
  capability,
}: {
  capability: Record<string, unknown>;
}) {
  // capability_profile.attack_surface is a list of
  // {kind, name, location, severity_hint} populated by the
  // CapabilityProfileBuilder (08_FRONTEND_UX.md §1.4).
  const items = (capability.attack_surface as Array<{
    kind: string;
    name: string;
    location?: string;
    severity_hint?: string;
  }> | undefined) ?? [];
  if (items.length === 0) {
    return (
      <AilaCard  techBorder glow><EmptyState
        title="No attack-surface entries enumerated yet"
        description="audit-mcp `attack_surface` + IDA `classify_behavior` populate this on analyze. Re-run analysis if you expected entries."
      /></AilaCard>
    );
  }
  return (
    <AilaCard  techBorder glow><ul className="space-y-1 text-xs font-mono">
      {items.map((it, i) => (
        <li
          key={`${it.kind}-${it.name}-${i}`}
          className="border border-border-default rounded px-2 py-1 flex items-center justify-between gap-2"
        >
          <div>
            <span className="text-text-muted">{it.kind}</span>{" "}
            <span className="text-foreground">{it.name}</span>
            {it.location && (
              <span className="text-text-muted ml-2">@ {it.location}</span>
            )}
          </div>
          {it.severity_hint && (
            <AilaBadge
              severity={
                it.severity_hint === "high"
                  ? "high"
                  : it.severity_hint === "medium"
                    ? "medium"
                    : "info"
              }
              size="sm"
            >
              {it.severity_hint}
            </AilaBadge>
          )}
        </li>
      ))}
    </ul></AilaCard>
  );
}

function HypothesesTab({ targetId }: { targetId: string }) {
  // Per-target aggregated hypothesis table. Replaces the prior
  // "one card per investigation" rail which (a) drowned real data
  // under 24+ empty cards for status=created investigations and
  // (b) had no investigation context on each card so users couldn't
  // tell which inv any hypothesis belonged to.
  const { rows, isLoading, isError, investigationCount, skippedCreatedCount } =
    useTargetHypotheses(targetId);
  const [filter, setFilter] = useState<
    "all" | "live" | "rejected" | "resolved" | "mixed"
  >("all");

  const visible = rows.filter((r) => filter === "all" || r.state === filter);
  const sorted = visible.slice().sort((a, b) => {
    // live first, then mixed, then resolved, then rejected
    const rank: Record<string, number> = {
      live: 0, mixed: 1, resolved: 2, rejected: 3,
    };
    const rs = (rank[a.state] ?? 9) - (rank[b.state] ?? 9);
    if (rs !== 0) return rs;
    return a.investigation_title.localeCompare(b.investigation_title);
  });

  const counts = {
    all: rows.length,
    live: rows.filter((r) => r.state === "live").length,
    mixed: rows.filter((r) => r.state === "mixed").length,
    resolved: rows.filter((r) => r.state === "resolved").length,
    rejected: rows.filter((r) => r.state === "rejected").length,
  };

  if (isLoading && rows.length === 0) {
    return <LoadingSkeleton size="md" width="full" />;
  }

  if (!isLoading && rows.length === 0) {
    return (
      <AilaCard  techBorder glow><EmptyState
        title="No hypotheses on this target yet"
        description={
          investigationCount === 0
            ? "No investigation on this target has produced hypotheses yet. Start one — agents populate hypotheses as evidence lands."
            : `Aggregated across ${investigationCount} investigation(s) that have run. Hypotheses are emitted by the reasoning engine as it processes evidence.`
        }
      /></AilaCard>
    );
  }

  return (
    <div className="space-y-3 min-w-0">
      <AilaCard  techBorder glow><div className="flex items-center justify-between gap-3 flex-wrap min-w-0">
        <div className="text-sm font-semibold text-foreground">
          {rows.length} hypotheses across {investigationCount} investigation
          {investigationCount === 1 ? "" : "s"}
          {skippedCreatedCount > 0 && (
            <span className="ml-2 text-xs text-text-muted font-normal">
              ({skippedCreatedCount} pending investigation
              {skippedCreatedCount === 1 ? "" : "s"} not yet running)
            </span>
          )}
        </div>
        <div className="flex items-center gap-1 flex-wrap">
          {(["all", "live", "mixed", "resolved", "rejected"] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={
                "px-2 py-1 text-xs rounded-md border transition-colors " +
                (filter === f
                  ? "border-accent bg-accent/10 text-foreground"
                  : "border-border-default text-text-muted hover:text-foreground")
              }
            >
              {f} ({counts[f]})
            </button>
          ))}
        </div>
      </div>
      {isError && (
        <p className="mt-2 text-xs text-text-danger">
          One or more per-investigation fetches failed; partial data shown.
        </p>
      )}</AilaCard>

      <AilaCard className="p-0 overflow-x-auto" techBorder glow><table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="px-3 py-2 font-semibold">State</th>
            <th className="px-3 py-2 font-semibold">Investigation</th>
            <th className="px-3 py-2 font-semibold">Hypothesis</th>
            <th className="px-3 py-2 font-semibold">Detail</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <tr
              key={`${r.investigation_id}:${r.id}:${i}`}
              className="border-b border-border-default last:border-b-0 align-top hover:bg-surface transition-colors"
            >
              <td className="px-3 py-2 whitespace-nowrap">
                <AilaBadge
                  severity={
                    r.state === "live"
                      ? "info"
                      : r.state === "rejected"
                        ? "low"
                        : "medium"
                  }
                  size="sm"
                >
                  {r.state}
                </AilaBadge>
              </td>
              <td className="px-3 py-2 min-w-0" style={{ maxWidth: 260 }}>
                <Link
                  to={`/vr/investigations/${r.investigation_id}`}
                  className="text-foreground hover:underline break-words text-xs"
                >
                  {r.investigation_title}
                </Link>
                <div className="text-3xs font-mono text-text-muted mt-0.5">
                  {r.investigation_kind} · {r.investigation_status}
                </div>
              </td>
              <td className="px-3 py-2 min-w-0 break-words">
                <div className="text-foreground">{r.claim}</div>
                <div className="text-3xs font-mono text-text-muted mt-0.5">
                  {r.id}
                </div>
              </td>
              <td className="px-3 py-2 min-w-0 break-words text-xs">
                {r.rejection_reason ? (
                  <div className="text-text-muted">
                    <span className="text-text-danger">rejected:</span>{" "}
                    {r.rejection_reason}
                  </div>
                ) : r.resolution_note ? (
                  <div className="text-text-muted">
                    <span className="text-amber-400">resolved:</span>{" "}
                    {r.resolution_note}
                  </div>
                ) : r.why_plausible ? (
                  <div className="text-text-muted">{r.why_plausible}</div>
                ) : r.kill_criterion ? (
                  <div className="text-text-muted">
                    <span className="text-text-muted">kill if:</span>{" "}
                    {r.kill_criterion}
                  </div>
                ) : (
                  <span className="text-text-muted italic">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table></AilaCard>
    </div>
  );
}

function ImportsExportsTab({
  capability,
}: {
  capability: Record<string, unknown>;
}) {
  const imports = (capability.imports as Array<{ name: string; module?: string; dangerous?: boolean }> | undefined) ?? [];
  const exports_ = (capability.exports as Array<{ name: string; reachable?: boolean }> | undefined) ?? [];
  if (imports.length === 0 && exports_.length === 0) {
    return (
      <AilaCard  techBorder glow><EmptyState
        title="No imports / exports recorded yet"
        description="capability_profile.imports + exports backend wiring pending. Spec §1.4: dangerous imports (strcpy, sprintf, system, gets) get a yellow border; reachable exports get a 'reachable' badge."
      /></AilaCard>
    );
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <AilaCard  techBorder glow><h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
        Imports ({imports.length})
      </h3>
      <ul className="text-xs font-mono space-y-1 max-h-96 overflow-y-auto">
        {imports.map((im) => (
          <li
            key={im.name}
            className={
              "px-2 py-1 rounded border " +
              (im.dangerous
                ? "border-amber-500 text-amber-300"
                : "border-border-default text-foreground")
            }
          >
            {im.name}
            {im.module && <span className="text-text-muted ml-2">{im.module}</span>}
          </li>
        ))}
      </ul></AilaCard>
      <AilaCard  techBorder glow><h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
        Exports ({exports_.length})
      </h3>
      <ul className="text-xs font-mono space-y-1 max-h-96 overflow-y-auto">
        {exports_.map((ex) => (
          <li
            key={ex.name}
            className="px-2 py-1 rounded border border-border-default text-foreground flex items-center justify-between gap-2"
          >
            <span>{ex.name}</span>
            {ex.reachable && (
              <AilaBadge severity="medium" size="sm">reachable</AilaBadge>
            )}
          </li>
        ))}
      </ul></AilaCard>
    </div>
  );
}

function NotesTab({ targetId }: { targetId: string }) {
  const STORAGE_KEY = `vr.target.notes.${targetId}`;
  const initial =
    typeof window === "undefined" ? "" : window.localStorage.getItem(STORAGE_KEY) ?? "";
  const [text, setText] = useState(initial);
  const [savedAt, setSavedAt] = useState<string | null>(initial ? "loaded from local" : null);
  function save() {
    try {
      window.localStorage.setItem(STORAGE_KEY, text);
      setSavedAt(new Date().toLocaleTimeString());
    } catch {
      setSavedAt("save failed");
    }
  }
  return (
    <AilaCard  techBorder glow><h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
      Operator notes
    </h3>
    <textarea
      value={text}
      onChange={(e) => setText(e.target.value)}
      onBlur={save}
      rows={10}
      placeholder="Free-text notes about this target. Stays in your browser until the backend per-target notes API ships."
      aria-label="Operator notes"
      className="w-full px-3 py-2 text-sm font-mono rounded bg-surface border border-border-default focus:border-accent focus:outline-none"
    />
    <p className="text-3xs text-text-muted mt-1">
      Saved locally in your browser ({savedAt ?? "not saved yet"}). Spec §1.4
      wants project-scoped sync — backend pending.
    </p></AilaCard>
  );
}

export function TargetDetailPage() {
  const { targetId } = useParams<{ targetId: string }>();
  const tid = targetId ?? "";

  const { data: target, isLoading } = useTarget(tid);
  const { data: workspacesResult } = useWorkspaces();
  const workspaceName =
    workspacesResult?.data.find((w) => w.id === target?.workspace_id)?.name ??
    null;

  useUpdatePageHeader({
    title: target?.display_name,
    subtitle: target ? (workspaceName ? `${workspaceName} · ${target.kind.replace(/_/g, ' ')}` : target.kind.replace(/_/g, ' ')) : undefined,
    status: null,
  });

  const analyzeMut = useAnalyzeTarget(tid);
  const rankMut = useRankTarget(tid);
  const uploadMut = useUploadTargetArtifact(tid);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const deleteMut = useDeleteTarget();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get("tab") as TargetTab) || "functions";
  function setActiveTab(t: TargetTab) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", t);
    setSearchParams(next, { replace: true });
  }
  const navigate = useNavigate();

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
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <DeleteButton
          id={target.id}
          label={`target "${target.display_name}"`}
          mutation={deleteMut}
          onDeleted={() => navigate("/vr/targets")}
        />
      </div>

      {/* Status banner */}
      <AilaCard className={
        target.analysis_state === "failed"
          ? "border-border-danger"
          : undefined
      } techBorder glow><div className="flex items-center justify-between flex-wrap gap-2">
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
      )}</AilaCard>

      {/* Upload widget — only for upload-capable kinds. AILA streams the
          file through to the IDA MCP; nothing is stored on the platform. */}
      {isUploadableKind(target.kind) && (
        <AilaCard  techBorder glow><div className="space-y-3">
          <div>
            <h2 className="text-sm font-semibold text-foreground">
              Binary artifact
            </h2>
            <p className="text-xs text-text-muted mt-1">
              Upload the {target.kind.replace(/_/g, " ")} from your
              workstation. AILA streams it to the IDA MCP
              (no copy stays on the platform) and re-runs analysis.
              {currentUploadedFilename(target) ? (
                <>
                  {" "}
                  Current:{" "}
                  <span className="font-mono text-foreground">
                    {currentUploadedFilename(target)}
                  </span>
                </>
              ) : null}
            </p>
          </div>
          <UploadDropzone
            onFile={(f) => uploadMut.mutate(f)}
            disabled={uploadMut.isPending}
            hint={
              uploadMut.isPending
                ? "uploading…"
                : currentUploadedFilename(target)
                  ? "drop a different file to replace"
                  : "drag a binary here or click pick from disk"
            }
          />
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            aria-label="Upload target file"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) uploadMut.mutate(f);
              e.target.value = "";
            }}
          />
        </div></AilaCard>
      )}

      {/* Capability profile */}
      <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
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
      )}</AilaCard>

      {/* Mitigations — uses shared MitigationsRibbon (§1.4 promise) */}
      {target.analysis_state === "ready" && (
        <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
          Mitigations
        </h2>
        <MitigationsRibbon mitigations={mitigations} /></AilaCard>
      )}

      {/* Tabs per 08_FRONTEND_UX.md §1.4. URL state via ?tab= so the
          operator can deep-link a teammate to "look at this tab." */}
      {target.analysis_state === "ready" && (
        <>
          <div className="border-b border-border-default flex gap-1 overflow-x-auto">
            {TARGET_TABS.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={
                    "px-3 py-2 text-xs font-mono whitespace-nowrap border-b-2 transition-colors " +
                    (isActive
                      ? "border-accent text-foreground"
                      : "border-transparent text-text-muted hover:text-foreground")
                  }
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          {activeTab === "attack_surface" && (
            <AttackSurfaceTab capability={capability} />
          )}
          {activeTab === "hypotheses" && <HypothesesTab targetId={target.id} />}
          {activeTab === "imports" && <ImportsExportsTab capability={capability} />}
          {activeTab === "notes" && <NotesTab targetId={target.id} />}
        </>
      )}


      {/* Functions of interest tab content */}
      {target.analysis_state === "ready" && activeTab === "functions" && (
        <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
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
        )}</AilaCard>
      )}

      {/* Descriptor — collapsed for debugging only */}
      <AilaCard  techBorder glow><details>
        <summary className="text-sm font-semibold text-foreground cursor-pointer">
          Operator-supplied descriptor
        </summary>
        <pre className="text-xs font-mono text-text-muted whitespace-pre-wrap overflow-x-auto mt-2">
          {JSON.stringify(target.descriptor, null, 2)}
        </pre>
      </details></AilaCard>
    </div>
  );
}
