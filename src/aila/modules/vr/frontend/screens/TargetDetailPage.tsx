import { Fragment, useRef, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { AilaChart } from "@/components/aila/AilaChart";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

import {
  MitigationsRibbon,
  type MitigationFlags,
} from "../components/MitigationsRibbon";
import { DeleteButton } from "../components/DeleteButton";
import { UploadDropzone } from "../components/UploadDropzone";
import { TargetConnectedCard } from "../components/TargetConnectedCard";
import {
  APK_STATIC_CHECK_COUNT_ESTIMATE,
  APK_STATIC_DEFAULT_CHILD_BUDGET_USD,
  MASVS_DEFAULT_CHILD_BUDGET_USD,
  MASVS_L1_CONTROL_COUNT_ESTIMATE,
  useAnalyzeTarget,
  useApkStaticAudit,
  useDeleteTarget,
  useMasvsAudit,
  useResumeTargetAnalysis,
  useRankTarget,
  useUploadTargetArtifact,
} from "../mutations";
import {
  useApkStaticAuditAggregate,
  useInvestigationsForTarget,
  useMasvsAuditAggregate,
  useTarget,
  useTargetHypotheses,
  useWorkspaces,
} from "../queries";
import { requestBlob } from "@platform/api/http";
import { saveBlobResponse } from "@platform/api/download";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { Link } from "react-router";
import type {
  AnalysisState,
  ApkOverview,
  ApkStaticControlVerdict,
  ApkStaticVerdict,
  MasvsControlVerdict,
  MasvsVerdict,
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
    return "APK_DECODE → JADX_DECOMPILE → INDEX_DECOMPILED → STATIC_SUMMARY…";
  }
  return "Uploading + analyzing…";
}

function formatDate(value?: string | null): string {
  if (!value) return "--";
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
          className="border border-border rounded px-2 py-1 flex items-center justify-between gap-2"
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
            ? "No investigation on this target has produced hypotheses yet. Start one -- agents populate hypotheses as evidence lands."
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
                  : "border-border text-text-muted hover:text-foreground")
              }
            >
              {f} ({counts[f]})
            </button>
          ))}
        </div>
      </div>
      {isError && (
        <p className="mt-2 text-xs text-critical">
          One or more per-investigation fetches failed; partial data shown.
        </p>
      )}</AilaCard>

      <AilaCard className="p-0 overflow-x-auto" techBorder glow><table className="w-full text-sm">
        <caption className="sr-only">Cross-investigation hypotheses for this target</caption>
        <thead>
          <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
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
              className="border-b border-border last:border-b-0 align-top hover:bg-surface transition-colors"
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
                    <span className="text-critical">rejected:</span>{" "}
                    {r.rejection_reason}
                  </div>
                ) : r.resolution_note ? (
                  <div className="text-text-muted">
                    <span style={{ color: "var(--color-amber)" }}>resolved:</span>{" "}
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
                  <span className="text-text-muted italic">--</span>
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
      <AilaCard  techBorder glow><h3 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
        Imports ({imports.length})
      </h3>
      <ul className="text-xs font-mono space-y-1 max-h-96 overflow-y-auto">
        {imports.map((im) => (
          <li
            key={im.name}
            className={
              "px-2 py-1 rounded border " +
              (im.dangerous ? "" : "border-border text-foreground")
            }
            style={
              im.dangerous
                ? { borderColor: "var(--color-amber)", color: "var(--color-amber)" }
                : undefined
            }
          >
            {im.name}
            {im.module && <span className="text-text-muted ml-2">{im.module}</span>}
          </li>
        ))}
      </ul></AilaCard>
      <AilaCard  techBorder glow><h3 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
        Exports ({exports_.length})
      </h3>
      <ul className="text-xs font-mono space-y-1 max-h-96 overflow-y-auto">
        {exports_.map((ex) => (
          <li
            key={ex.name}
            className="px-2 py-1 rounded border border-border text-foreground flex items-center justify-between gap-2"
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
    <AilaCard  techBorder glow><h3 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
      Operator notes
    </h3>
    <textarea
      value={text}
      onChange={(e) => setText(e.target.value)}
      onBlur={save}
      rows={10}
      placeholder="Free-text notes about this target. Stays in your browser until the backend per-target notes API ships."
      aria-label="Operator notes"
      className="w-full px-3 py-2 text-sm font-mono rounded bg-surface border border-border focus:border-accent focus:outline-none"
    />
    <p className="text-3xs text-text-muted mt-1">
      Saved locally in your browser ({savedAt ?? "not saved yet"}). Spec §1.4
      wants project-scoped sync -- backend pending.
    </p></AilaCard>
  );
}

/** Per-bucket renderer for the apk_overview projection. The static
 * summary is the in-repo static summary; we read only the
 * keys we recognise and defensively skip anything else so an upstream
 * tool version bump doesn't crash the page.
 */
function AndroidApkOverview({ overview }: { overview: ApkOverview }) {
  const summary = (overview.static_summary ?? {}) as Record<string, unknown>;

  const asStringArray = (v: unknown): string[] => {
    if (!Array.isArray(v)) return [];
    return v.filter((x): x is string => typeof x === "string");
  };
  const asString = (v: unknown): string | null =>
    typeof v === "string" && v.length > 0 ? v : null;
  const asNumber = (v: unknown): number | null =>
    typeof v === "number" && Number.isFinite(v) ? v : null;

  const pkg = asString(summary.package);
  const versionName = asString(summary.version_name);
  const versionCode = asNumber(summary.version_code);
  const minSdk = asNumber(summary.min_sdk);
  const targetSdk = asNumber(summary.target_sdk);
  const permissions = asStringArray(summary.permissions);
  const dangerousPerms = asStringArray(
    (summary.dangerous_permissions ?? summary.permissions_dangerous) as unknown,
  );
  const activities = asStringArray(
    (summary.exported_activities ?? summary.activities) as unknown,
  );
  const services = asStringArray(
    (summary.exported_services ?? summary.services) as unknown,
  );
  const receivers = asStringArray(
    (summary.exported_receivers ?? summary.receivers) as unknown,
  );
  const providers = asStringArray(
    (summary.exported_providers ?? summary.providers) as unknown,
  );
  const nativeLibs = asStringArray(
    (summary.native_libs ?? summary.native_libraries ?? summary.so_files) as unknown,
  );
  const certificates = Array.isArray(summary.certificates)
    ? (summary.certificates as Array<Record<string, unknown>>)
    : [];
  const signingScheme = asString(summary.signing_scheme);

  return (
    <AilaCard techBorder glow>
      <h2 className="text-sm font-semibold text-foreground mb-3">
        Android APK
      </h2>

      {/* Package metadata block. Two-column grid keeps scan-the-list ergonomic
          for the operator. Hyphen renders when the static summary didn't
          surface a field (older APK or pipeline incomplete). */}
      <dl className="grid grid-cols-2 gap-3 text-sm mb-4">
        <div>
          <dt className="text-text-muted text-xs">Package</dt>
          <dd className="font-mono text-xs">{pkg ?? "--"}</dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Version</dt>
          <dd className="font-mono text-xs">
            {versionName ?? "--"}
            {versionCode != null && ` (${versionCode})`}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">SDK range</dt>
          <dd className="font-mono text-xs">
            {minSdk != null ? `min ${minSdk}` : "--"}
            {targetSdk != null ? ` · target ${targetSdk}` : ""}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Signing scheme</dt>
          <dd className="font-mono text-xs">{signingScheme ?? "--"}</dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">SHA-256</dt>
          <dd className="font-mono text-[10px] break-all">
            {overview.sha256 ?? "--"}
          </dd>
        </div>
        <div>
          <dt className="text-text-muted text-xs">Jadx classes</dt>
          <dd className="font-mono text-xs">
            {overview.jadx_class_count?.toLocaleString() ?? "--"}
          </dd>
        </div>
      </dl>

      {/* Native libraries -- single most-asked APK question (".so files").
          Surfaced prominently because operator's complaint specifically
          named these. */}
      {nativeLibs.length > 0 && (
        <div className="mb-4">
          <h3 className="text-xs font-semibold text-foreground mb-1">
            Native libraries ({nativeLibs.length})
          </h3>
          <ul className="text-xs font-mono text-text-muted space-y-0.5 max-h-40 overflow-y-auto">
            {nativeLibs.map((lib) => (
              <li key={lib}>{lib}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Permissions -- dangerous called out separately. */}
      {permissions.length > 0 && (
        <div className="mb-4">
          <h3 className="text-xs font-semibold text-foreground mb-1">
            Permissions ({permissions.length})
            {dangerousPerms.length > 0 && (
              <span className="ml-2 text-critical">
                {dangerousPerms.length} dangerous
              </span>
            )}
          </h3>
          <details>
            <summary className="text-xs text-text-muted cursor-pointer">
              show list
            </summary>
            <ul className="text-xs font-mono text-text-muted space-y-0.5 mt-2 max-h-60 overflow-y-auto">
              {permissions.map((p) => (
                <li
                  key={p}
                  className={
                    dangerousPerms.includes(p) ? "text-critical" : undefined
                  }
                >
                  {p}
                </li>
              ))}
            </ul>
          </details>
        </div>
      )}

      {/* Exported components -- attack surface, by definition. */}
      {(activities.length + services.length + receivers.length + providers.length) > 0 && (
        <div className="mb-4">
          <h3 className="text-xs font-semibold text-foreground mb-1">
            Exported components
          </h3>
          <dl className="grid grid-cols-4 gap-2 text-xs">
            <div>
              <dt className="text-text-muted">Activities</dt>
              <dd className="font-mono">{activities.length}</dd>
            </div>
            <div>
              <dt className="text-text-muted">Services</dt>
              <dd className="font-mono">{services.length}</dd>
            </div>
            <div>
              <dt className="text-text-muted">Receivers</dt>
              <dd className="font-mono">{receivers.length}</dd>
            </div>
            <div>
              <dt className="text-text-muted">Providers</dt>
              <dd className="font-mono">{providers.length}</dd>
            </div>
          </dl>
        </div>
      )}

      {/* Certificates -- signing identity. SHA-1 / SHA-256 fingerprints +
          subject DN are the fields operators actually compare. */}
      {certificates.length > 0 && (
        <div className="mb-4">
          <h3 className="text-xs font-semibold text-foreground mb-1">
            Certificates ({certificates.length})
          </h3>
          <ul className="text-xs space-y-2">
            {certificates.map((cert, idx) => (
              <li
                key={`${(cert.sha256 as string) ?? idx}`}
                className="border-l-2 border-border pl-2"
              >
                <div className="font-mono text-foreground">
                  {(cert.subject as string) ?? (cert.issuer as string) ?? "--"}
                </div>
                {cert.sha256 != null && (
                  <div className="font-mono text-[10px] text-text-muted break-all">
                    SHA-256 {String(cert.sha256)}
                  </div>
                )}
                {cert.sha1 != null && (
                  <div className="font-mono text-[10px] text-text-muted break-all">
                    SHA-1 {String(cert.sha1)}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Backend handles -- operator-facing path strings. Useful for
          spelunking via the audit-mcp index id or running ad-hoc
          jadx-tree queries from a shell. */}
      <div className="mb-3">
        <h3 className="text-xs font-semibold text-foreground mb-1">
          Backend handles
        </h3>
        <dl className="grid grid-cols-1 gap-1 text-xs">
          {overview.decoded_dir && (
            <div className="flex gap-2">
              <dt className="text-text-muted shrink-0">apktool</dt>
              <dd className="font-mono text-[10px] break-all">
                {overview.decoded_dir}
              </dd>
            </div>
          )}
          {overview.decompiled_dir && (
            <div className="flex gap-2">
              <dt className="text-text-muted shrink-0">jadx</dt>
              <dd className="font-mono text-[10px] break-all">
                {overview.decompiled_dir}
              </dd>
            </div>
          )}
          {overview.manifest_path && (
            <div className="flex gap-2">
              <dt className="text-text-muted shrink-0">manifest</dt>
              <dd className="font-mono text-[10px] break-all">
                {overview.manifest_path}
              </dd>
            </div>
          )}
          {overview.audit_mcp_index_id && (
            <div className="flex gap-2">
              <dt className="text-text-muted shrink-0">audit_mcp idx</dt>
              <dd className="font-mono text-[10px] break-all">
                {overview.audit_mcp_index_id}
              </dd>
            </div>
          )}
        </dl>
      </div>

    </AilaCard>
  );
}

/** D-4b dispatcher card. Appears on android_apk targets once the
 * STATIC_SUMMARY ingestion stage has populated `apk_overview` with
 * a non-empty static_summary dict (the same gate the backend
 * enforces in `vr/api_router.py::dispatch_masvs_audit`).
 *
 * The button shows the estimated total spend (≈ N × per-child
 * budget) before confirming so the operator knows what they're
 * committing to. The dispatcher is idempotent -- re-clicking with
 * an active parent for the same catalog version returns the
 * existing ids verbatim. */
function MasvsAuditCard({
  targetId,
  packageLabel,
}: {
  targetId: string;
  packageLabel: string | null;
}) {
  const masvsMut = useMasvsAudit(targetId);
  const estimatedTotal =
    MASVS_DEFAULT_CHILD_BUDGET_USD * MASVS_L1_CONTROL_COUNT_ESTIMATE;
  const packageDisplay = packageLabel ?? "this APK";

  const handleClick = () => {
    const ok = window.confirm(
      `Dispatch OWASP MASVS L1 audit against ${packageDisplay}?\n\n` +
        `≈ ${MASVS_L1_CONTROL_COUNT_ESTIMATE} child investigations, ` +
        `~$${MASVS_DEFAULT_CHILD_BUDGET_USD} budget each ` +
        `(~$${estimatedTotal} total expected spend).\n\n` +
        "Each child runs the full vuln_researcher scout / critic / " +
        "verifier chain. The dispatcher is idempotent -- re-clicking " +
        "with an active audit for this catalog version returns the " +
        "existing parent without re-dispatching.",
    );
    if (!ok) return;
    masvsMut.mutate();
  };

  return (
    <AilaCard variant="elevated">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-sm font-semibold text-text-muted">
              MASVS audit
            </h2>
            <AilaBadge severity="neutral" size="sm">
              LEGACY COMPLIANCE
            </AilaBadge>
          </div>
          <p className="text-xs text-text-muted mt-1">
            Broad OWASP MASVS L1 compliance sweep, kept for regulated
            audits that still require the L1 control list verbatim.
            Prefer the APK static audit above for evidence-backed
            findings on this APK. Fans out \u2248 {MASVS_L1_CONTROL_COUNT_ESTIMATE}
            parallel child investigations (one per L1 control), each
            driving the standard vuln_researcher workflow against the
            jadx-decompiled tree. Estimated total spend \u2248 $
            {estimatedTotal} (~${MASVS_DEFAULT_CHILD_BUDGET_USD}
            per child \u00d7 {MASVS_L1_CONTROL_COUNT_ESTIMATE} controls).
          </p>
        </div>
        <button
          type="button"
          onClick={handleClick}
          disabled={masvsMut.isPending}
          className="px-3 py-1.5 text-xs font-medium rounded-md border border-border text-text-muted hover:bg-elevated hover:text-foreground disabled:opacity-50 shrink-0"
        >
          {masvsMut.isPending
            ? "Dispatching\u2026"
            : `Run legacy MASVS audit (~$${estimatedTotal})`}
        </button>
      </div>
    </AilaCard>
  );
}

/** APK static-analysis dispatcher card. Sibling of MasvsAuditCard,
 * gated identically (android_apk + STATIC_SUMMARY populated). Fans one
 * child investigation per STATIC catalog check -- sharp, evidence-backed
 * checks with a definite file:line source, complementary to the broader
 * MASVS compliance audit. Idempotent on (target, catalog version). */
function ApkStaticAuditCard({
  targetId,
  packageLabel,
}: {
  targetId: string;
  packageLabel: string | null;
}) {
  const apkMut = useApkStaticAudit(targetId);
  const estimatedTotal =
    APK_STATIC_DEFAULT_CHILD_BUDGET_USD * APK_STATIC_CHECK_COUNT_ESTIMATE;
  const packageDisplay = packageLabel ?? "this APK";

  const handleClick = () => {
    const ok = window.confirm(
      `Dispatch APK static-analysis audit against ${packageDisplay}?\n\n` +
        `\u2248 ${APK_STATIC_CHECK_COUNT_ESTIMATE} child investigations, ` +
        `~$${APK_STATIC_DEFAULT_CHILD_BUDGET_USD} budget each ` +
        `(~$${estimatedTotal} total expected spend).\n\n` +
        "Each child runs the full vuln_researcher scout / critic / " +
        "verifier chain against one concrete static check. The " +
        "dispatcher is idempotent -- re-clicking with an active audit " +
        "for this catalog version returns the existing parent.",
    );
    if (!ok) return;
    apkMut.mutate();
  };

  return (
    <AilaCard techBorder glow>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-sm font-semibold text-foreground">
              APK static audit
            </h2>
            <AilaBadge severity="info" size="sm">
              RECOMMENDED -- EVIDENCE-BACKED
            </AilaBadge>
          </div>
          <p className="text-xs text-text-muted mt-1">
            Primary APK audit. Runs the APK static-analysis check
            catalog -- sharp, evidence-backed investigations each with
            a definite file:line source in the decompiled tree. Fans
            out \u2248 {APK_STATIC_CHECK_COUNT_ESTIMATE} parallel child
            investigations (one per concrete static check -- manifest,
            secrets, crypto, WebView, IPC, storage, exploit chains),
            each driving the standard vuln_researcher workflow against
            the jadx-decompiled tree. Estimated total spend \u2248 $
            {estimatedTotal} (~${APK_STATIC_DEFAULT_CHILD_BUDGET_USD}
            per child \u00d7 {APK_STATIC_CHECK_COUNT_ESTIMATE} checks).
          </p>
        </div>
        <button
          type="button"
          onClick={handleClick}
          disabled={apkMut.isPending}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-background hover:bg-accent/90 disabled:opacity-50 shrink-0"
        >
          {apkMut.isPending
            ? "Dispatching\u2026"
            : `Run APK static audit (~$${estimatedTotal})`}
        </button>
      </div>
    </AilaCard>
  );
}

/** U-1 progress card. Sibling of MasvsAuditCard / MasvsReportCard:
 * appears once the operator has dispatched a MASVS audit for this
 * target. Surfaces total / completed / running / failed counts plus
 * an ETA estimate derived from the median per-child wall-clock of
 * terminal siblings.
 *
 * Reuses the same `useInvestigationsForTarget` query the report card
 * polls -- React Query dedupes the 8s refresh across cards so all
 * three (dispatcher, progress, report) share one network round.
 *
 * ETA is intentionally serial-upper-bound: median × remaining. The
 * dispatcher fans children through ARQ workers in parallel, so the
 * real wall-clock will be lower depending on the live vr-queue
 * concurrency the operator owns. We surface the per-control median
 * + the worst-case sum so the operator can scale mentally to their
 * own worker count rather than reading a fabricated point estimate.
 * If no terminal child has both timestamps yet, both numbers render
 * as "--" -- partial signals beat fake confidence.
 *
 * Same `inv.kind as string` workaround as MasvsReportCard -- the
 * InvestigationKind union doesn't yet include "masvs_audit" because
 * InvestigationsListPage.tsx has an exhaustive `Record<Kind, Icon>`
 * that would also need an icon assignment. Out of scope for U-1. */
function MasvsProgressCard({
  targetId,
  packageLabel,
}: {
  targetId: string;
  packageLabel: string | null;
}) {
  const { data: investigationsResult, isLoading } =
    useInvestigationsForTarget(targetId);
  const investigations = investigationsResult?.data ?? [];

  // Mirror MasvsReportCard's parent-resolution rule: pick the most
  // recent kind=masvs_audit parent for this target. created_at is
  // an ISO-8601 string from the wire so localeCompare orders it
  // chronologically without parsing dates.
  const masvsParents = investigations
    .filter(
      (inv) =>
        (inv.kind as string) === "masvs_audit" &&
        inv.parent_investigation_id == null,
    )
    .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
  const parent = masvsParents[0] ?? null;

  if (isLoading || parent == null) return null;

  const children = investigations.filter(
    (inv) => inv.parent_investigation_id === parent.id,
  );
  const totalChildren = children.length;

  // Status buckets. Terminal = completed | failed | abandoned per
  // InvestigationStatus in types.ts. Anything else (created, running,
  // paused) bucketizes as "running" for the operator's overview --
  // they don't need to distinguish the three at this card's level.
  let completedCount = 0;
  let runningCount = 0;
  let failedCount = 0;
  const terminalDurationsSec: number[] = [];
  for (const c of children) {
    if (c.status === "completed") completedCount++;
    else if (c.status === "failed" || c.status === "abandoned")
      failedCount++;
    else runningCount++;

    // Median wall-time signal -- include every terminal child with
    // both timestamps, including failures (they consumed worker
    // time too). A failed child that timed out at the cost cap is
    // a legitimate data point for the per-control distribution.
    const isTerminal =
      c.status === "completed" ||
      c.status === "failed" ||
      c.status === "abandoned";
    if (!isTerminal || !c.started_at || !c.stopped_at) continue;
    const start = new Date(c.started_at).getTime();
    const stop = new Date(c.stopped_at).getTime();
    if (!Number.isFinite(start) || !Number.isFinite(stop) || stop <= start)
      continue;
    terminalDurationsSec.push((stop - start) / 1000);
  }
  const terminalCount = completedCount + failedCount;
  const remainingCount = totalChildren - terminalCount;
  const percentComplete =
    totalChildren > 0 ? Math.round((terminalCount / totalChildren) * 100) : 0;

  // P50 of terminal-child wall-times.
  let medianSec: number | null = null;
  if (terminalDurationsSec.length > 0) {
    const sorted = [...terminalDurationsSec].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    medianSec =
      sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  }

  const medianLabel =
    medianSec != null ? formatDurationCompact(medianSec) : "--";
  let etaLabel: string;
  if (remainingCount === 0) etaLabel = "0s (all terminal)";
  else if (medianSec == null) etaLabel = "--";
  else etaLabel = formatDurationCompact(medianSec * remainingCount);

  const packageDisplay = packageLabel ?? "this APK";

  return (
    <AilaCard techBorder glow>
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-foreground">
              MASVS audit progress · {packageDisplay}
            </h2>
            <p className="text-xs text-text-muted mt-1 font-mono break-all">
              parent {parent.id.slice(0, 8)} · {parent.status}
            </p>
          </div>
          <AilaBadge severity="info" size="sm">
            {percentComplete}% complete
          </AilaBadge>
        </div>

        {/* Linear progress bar -- terminalCount/total. */}
        <div
          className="w-full h-2 bg-surface rounded overflow-hidden border border-border"
          role="progressbar"
          aria-valuenow={percentComplete}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="MASVS audit child completion"
        >
          <div
            className="h-full bg-accent transition-all duration-500"
            style={{ width: `${percentComplete}%` }}
          />
        </div>

        {/* Count tiles */}
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
          <div>
            <dt className="text-text-muted">Total</dt>
            <dd className="font-mono text-foreground text-sm">
              {totalChildren}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted">Completed</dt>
            <dd className="font-mono text-foreground text-sm">
              {completedCount}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted">Running</dt>
            <dd className="font-mono text-foreground text-sm">
              {runningCount}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted">Failed</dt>
            <dd className="font-mono text-foreground text-sm">
              {failedCount}
            </dd>
          </div>
        </dl>

        {/* Timing block -- separated by a divider so the operator's
            eye groups counts vs estimates. */}
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs border-t border-border pt-3">
          <div>
            <dt className="text-text-muted">
              Median wall-time per child
            </dt>
            <dd className="font-mono text-foreground">{medianLabel}</dd>
          </div>
          <div>
            <dt className="text-text-muted">ETA (serial upper bound)</dt>
            <dd className="font-mono text-foreground">{etaLabel}</dd>
          </div>
        </dl>
        <p className="text-xs text-text-muted">
          ETA = median × remaining. Children run through ARQ workers
          in parallel, so actual wall-clock scales down with the live
          vr-queue concurrency on this host.
        </p>
      </div>
    </AilaCard>
  );
}

/** Render seconds as `Ns` / `Nm Ss` / `Nh Nm`. Used by U-1's progress
 * card for the per-child median and ETA cells -- kept compact so the
 * AilaBadge-style tiles don't wrap on narrow viewports. */
function formatDurationCompact(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "--";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds % 60);
    return s > 0 ? `${m}m ${s}s` : `${m}m`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

/** R-4 report-download card. Sibling of MasvsAuditCard: appears once
 * the operator has dispatched a MASVS audit for this target. The
 * dispatcher (D-1) creates one parent VRInvestigation with
 * kind=masvs_audit and N children with parent_investigation_id
 * pointing at it; the parent transitions to COMPLETED only once
 * every child reaches a terminal state (D-5 reconciler).
 *
 * The PDF endpoint (R-3) accepts partial aggregates -- children
 * still in flight render as INCONCLUSIVE rows so the operator can
 * hand the CISO a checkpoint copy without waiting for the full
 * ~60min batch. Following that, the button enables once at least
 * one child has reached a terminal state and stays enabled for the
 * rest of the audit lifetime. If no terminal children exist yet,
 * the button stays disabled with a tooltip explaining why.
 *
 * No new mutation hook -- the download is a one-shot read-only side
 * effect that bypasses React Query (matches ExportReportButton).
 *
 * Note: VRInvestigationSummary.kind is currently typed as the
 * pre-MASVS union (discovery | variant_hunt | triage | n_day |
 * audit) in `types.ts`. The runtime payload now also carries
 * "masvs_audit" for parent records -- the `as string` cast below
 * acknowledges that drift without expanding the type system in
 * this iteration. Update `InvestigationKind` when U-1 / U-2 land,
 * which will need the narrowing anyway. */
function MasvsReportCard({
  targetId,
  packageLabel,
}: {
  targetId: string;
  packageLabel: string | null;
}) {
  const { data: investigationsResult, isLoading } =
    useInvestigationsForTarget(targetId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const investigations = investigationsResult?.data ?? [];

  // Pick the most recent MASVS_AUDIT parent for this target. The
  // dispatcher is idempotent on (target, catalog_version) for ACTIVE
  // parents (D-3) -- once that parent reaches a terminal state the
  // operator can fire a fresh batch, so we sort created_at desc and
  // pick the head. created_at is an ISO-8601 string from the wire so
  // localeCompare orders it chronologically without parsing dates.
  const masvsParents = investigations
    .filter(
      (inv) =>
        (inv.kind as string) === "masvs_audit" &&
        inv.parent_investigation_id == null,
    )
    .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
  const parent = masvsParents[0] ?? null;

  // No parent means the operator hasn't dispatched yet -- surface
  // nothing here so the MasvsAuditCard above is the only CTA. The
  // download card appears the moment a parent row exists, even
  // before any child has finished, so the operator sees the
  // disabled control with a clear "waiting on children" status.
  if (isLoading || parent == null) return null;

  const children = investigations.filter(
    (inv) => inv.parent_investigation_id === parent.id,
  );
  // VRInvestigation terminal statuses per types.ts InvestigationStatus.
  // R-3 docstring confirms the PDF tolerates non-terminal children --
  // they render as INCONCLUSIVE rows in the per-control table.
  const terminalChildren = children.filter(
    (c) =>
      c.status === "completed" ||
      c.status === "failed" ||
      c.status === "abandoned",
  );
  const totalChildren = children.length;
  const terminalCount = terminalChildren.length;
  const allTerminal = totalChildren > 0 && terminalCount === totalChildren;
  const canDownload = terminalCount > 0;

  async function handleClick() {
    if (parent == null) return;
    setBusy(true);
    setError(null);
    try {
      const token = await getAuthTokenStandalone();
      // Cache-buster query param: backend sets Cache-Control:
      // no-store but entries already in the browser disk cache from
      // earlier visits would otherwise survive. ts changes per
      // click so each request hits a unique URL.
      const params = new URLSearchParams({
        audit_id: parent.id,
        ts: String(Date.now()),
      });
      const payload = await requestBlob(
        `/vr/targets/${encodeURIComponent(targetId)}/masvs-report?${params.toString()}`,
        { method: "GET", token },
      );
      // Filename fallback -- the backend's Content-Disposition is
      // authoritative when present (masvs_<pkg>_<YYYYMMDD>.pdf per
      // R-3's _masvs_report_filename). The fallback covers the
      // unlikely case where the header is dropped by a proxy.
      const safePackage = (packageLabel ?? "android-apk")
        .replace(/[^a-zA-Z0-9_-]+/g, "_")
        .slice(0, 80);
      const fallback = `masvs_${safePackage}_${parent.id.slice(0, 8)}.pdf`;
      saveBlobResponse(payload, payload.fileName ?? fallback);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg.slice(0, 200));
    } finally {
      setBusy(false);
    }
  }

  const buttonLabel = busy
    ? "Downloading…"
    : allTerminal
      ? "Download MASVS report"
      : `Download partial report (${terminalCount}/${totalChildren})`;
  const buttonTitle = canDownload
    ? allTerminal
      ? "Download the full PDF aggregate"
      : "Download a partial PDF -- children still running render as INCONCLUSIVE"
    : "Disabled until at least one child investigation reaches a terminal state";

  return (
    <AilaCard techBorder glow>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <h2 className="text-sm font-semibold text-foreground">
            MASVS report
          </h2>
          <p className="text-xs text-text-muted mt-1">
            ReportLab PDF aggregating every child investigation
            outcome through the S-4 verdict mapper, grouped by MASVS
            control group with per-control evidence excerpts. Children
            still in flight render as INCONCLUSIVE rows -- partial
            reports are valid handoffs for an interim checkpoint.
          </p>
          <p className="text-xs text-text-muted mt-2 font-mono">
            {terminalCount} / {totalChildren} child investigation
            {totalChildren === 1 ? "" : "s"} terminal
            {allTerminal
              ? " · all complete"
              : totalChildren === 0
                ? " · waiting on dispatch"
                : " · in progress"}
          </p>
          {error && (
            <p className="text-xs text-critical mt-2 break-all">
              {error}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={handleClick}
          disabled={!canDownload || busy}
          title={buttonTitle}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-background hover:bg-accent/90 disabled:opacity-50 shrink-0"
        >
          {buttonLabel}
        </button>
      </div>
    </AilaCard>
  );
}

/** U-2 per-control table. Sibling of MasvsAuditCard / MasvsProgressCard
 * / MasvsReportCard. Once a parent masvs_audit row exists for this
 * target the card fetches the JSON aggregate from
 * `GET /vr/targets/{id}/masvs-audit-aggregate?audit_id=<parent>` and
 * renders one row per child investigation: control id, group, title,
 * status, verdict + confidence (when terminal), and a link out to the
 * child investigation detail page so the operator can drill into the
 * underlying evidence + branch tree.
 *
 * The table self-hides until a parent exists (so a fresh APK only
 * surfaces the dispatcher card above). Polling cadence (8s) matches
 * the investigations list + progress card, so a child landing a new
 * verdict appears within one tick.
 *
 * Resolution of the active parent mirrors MasvsReportCard /
 * MasvsProgressCard verbatim: most-recent kind=masvs_audit parent
 * for this target, picked by created_at desc (ISO-8601 strings sort
 * correctly via localeCompare). The dispatcher is idempotent on the
 * active parent (D-3), so under normal operation there is exactly
 * one parent at a time.
 */
function MasvsControlTable({
  targetId,
  packageLabel,
}: {
  targetId: string;
  packageLabel: string | null;
}) {
  const { data: investigationsResult, isLoading: isLoadingInvs } =
    useInvestigationsForTarget(targetId);
  const investigations = investigationsResult?.data ?? [];

  const masvsParents = investigations
    .filter(
      (inv) =>
        (inv.kind as string) === "masvs_audit" &&
        inv.parent_investigation_id == null,
    )
    .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
  const parent = masvsParents[0] ?? null;

  const {
    data: aggregate,
    isLoading: isLoadingAgg,
    error: aggError,
  } = useMasvsAuditAggregate(targetId, parent?.id ?? null);

  if (isLoadingInvs || parent == null) return null;

  // Cross-reference per-child status from the investigations list so
  // the table can show a live status badge even when the aggregate
  // omits an entry (e.g. a child whose secondary_target_refs_json
  // failed to encode a masvs_control_id -- server-side this surfaces
  // as a logged warning and a missing verdict row).
  const childById = new Map<string, (typeof investigations)[number]>();
  for (const inv of investigations) {
    if (inv.parent_investigation_id === parent.id) childById.set(inv.id, inv);
  }
  const totalChildren = childById.size;

  const packageDisplay = packageLabel ?? "this APK";
  const verdicts: MasvsControlVerdict[] = aggregate?.verdicts ?? [];

  return (
    <AilaCard techBorder glow>
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-foreground">
              MASVS controls · {packageDisplay}
            </h2>
            <p className="text-xs text-text-muted mt-1 font-mono break-all">
              parent {parent.id.slice(0, 8)} · {totalChildren} child
              investigation{totalChildren === 1 ? "" : "s"}
              {aggregate?.masvs_spec_version
                ? ` · catalog ${aggregate.masvs_spec_version}`
                : ""}
            </p>
          </div>
        </div>

        {isLoadingAgg && verdicts.length === 0 ? (
          <p className="text-xs text-text-muted">Loading aggregate…</p>
        ) : aggError ? (
          <p className="text-xs text-critical break-all">
            Aggregate fetch failed:{" "}
            {aggError instanceof Error
              ? aggError.message.slice(0, 200)
              : String(aggError).slice(0, 200)}
          </p>
        ) : verdicts.length === 0 ? (
          <p className="text-xs text-text-muted">
            No verdicts resolved yet -- children still in CREATED /
            RUNNING with no primary outcome. The table will populate
            as each child reaches a terminal state.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <caption className="sr-only">MASVS control verdicts</caption>
              <thead>
                <tr className="border-b border-border text-left text-text-muted">
                  <th className="px-2 py-1 font-semibold">Control</th>
                  <th className="px-2 py-1 font-semibold w-20">Group</th>
                  <th className="px-2 py-1 font-semibold w-24">Status</th>
                  <th className="px-2 py-1 font-semibold w-28">Verdict</th>
                  <th className="px-2 py-1 font-semibold w-20 text-right">
                    Confidence
                  </th>
                  <th className="px-2 py-1 font-semibold w-16 text-right">
                    Link
                  </th>
                </tr>
              </thead>
              <tbody>
                {verdicts.map((v) => {
                  const child = childById.get(v.child_investigation_id);
                  const childStatus = child?.status ?? "unknown";
                  // Group prefix lives inside the control id --
                  // ``MSTG-STORAGE-1`` \u2192 ``STORAGE``,
                  // ``MASVS-PRIVACY-1`` \u2192 ``PRIVACY``. The aggregate's
                  // ``by_group`` map carries the canonical mapping but
                  // is keyed by group, not by control; recovering the
                  // single-row group via id parsing avoids an O(N)
                  // reverse lookup per row.
                  const groupLabel = _extractGroupFromControlId(v.control_id);
                  // Panel-summary projection carried from the child
                  // investigation's canonical outcome. All three fields
                  // are optional -- historical rows written before the
                  // synthesis-scope contract landed leave them unset, as
                  // do children that never resolved a panel_summary
                  // (timeout, cost cap, no primary outcome). Only
                  // render the details row when at least one field has
                  // content, so legacy aggregates keep the compact one-
                  // row-per-control layout.
                  const scope = v.scope?.trim() || null;
                  const headline = v.headline?.trim() || null;
                  const keyPoints = (v.key_points ?? []).filter(
                    (p) => p && p.trim().length > 0,
                  );
                  const hasPanelSummary =
                    scope != null || headline != null || keyPoints.length > 0;
                  return (
                    <Fragment key={v.child_investigation_id}>
                      <tr
                        className={
                          hasPanelSummary
                            ? ""
                            : "border-b border-border last:border-b-0"
                        }
                      >
                        <td className="px-2 py-1 font-mono text-foreground break-all">
                          {v.control_id}
                        </td>
                        <td className="px-2 py-1 font-mono text-text-muted">
                          {groupLabel}
                        </td>
                        <td className="px-2 py-1">
                          <AilaBadge severity="info" size="sm">
                            {childStatus}
                          </AilaBadge>
                        </td>
                        <td className="px-2 py-1">
                          <AilaBadge
                            severity={_verdictSeverity(v.verdict)}
                            size="sm"
                          >
                            {_verdictLabel(v.verdict)}
                          </AilaBadge>
                          {v.reason && v.verdict === "inconclusive" && (
                            <span className="text-text-muted text-[10px] ml-1 font-mono">
                              {v.reason}
                            </span>
                          )}
                        </td>
                        <td className="px-2 py-1 font-mono text-right text-foreground">
                          {v.verdict === "inconclusive" && v.confidence === 0
                            ? "--"
                            : v.confidence.toFixed(2)}
                        </td>
                        <td className="px-2 py-1 text-right">
                          <Link
                            to={`/vr/investigations/${encodeURIComponent(
                              v.child_investigation_id,
                            )}`}
                            className="text-accent hover:underline font-mono"
                          >
                            open
                          </Link>
                        </td>
                      </tr>
                      {hasPanelSummary && (
                        <tr className="border-b border-border last:border-b-0">
                          <td
                            colSpan={6}
                            className="px-2 pb-2 pt-0 align-top"
                          >
                            <div className="space-y-1.5 text-xs">
                              {scope && (
                                <div>
                                  <span className="text-text-muted font-mono uppercase tracking-wider text-[10px] mr-1">
                                    Scope:
                                  </span>
                                  <span className="text-foreground whitespace-pre-wrap break-words">
                                    {scope}
                                  </span>
                                </div>
                              )}
                              {headline && (
                                <div>
                                  <span className="text-text-muted font-mono uppercase tracking-wider text-[10px] mr-1">
                                    Headline:
                                  </span>
                                  <span className="text-foreground whitespace-pre-wrap break-words">
                                    {headline}
                                  </span>
                                </div>
                              )}
                              {keyPoints.length > 0 && (
                                <div>
                                  <div className="text-text-muted font-mono uppercase tracking-wider text-[10px]">
                                    Key points:
                                  </div>
                                  <ul className="list-disc pl-4 mt-0.5 space-y-0.5">
                                    {keyPoints.map((point, idx) => (
                                      <li
                                        key={idx}
                                        className="text-foreground whitespace-pre-wrap break-words"
                                      >
                                        {point}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {aggregate?.generated_at && (
          <p className="text-xs text-text-muted font-mono">
            generated_at:{" "}
            {new Date(aggregate.generated_at).toLocaleString()}
          </p>
        )}
      </div>
    </AilaCard>
  );
}

/** Recover the MASVS group token from a control id. Both legacy
 * MASVS v1.4.2 ids (`MSTG-<GROUP>-N`) and v2.1.0 ids
 * (`MASVS-<GROUP>-N`) share the same `-<GROUP>-` middle segment, so a
 * single split rule handles both vintages. Returns "--" for ids the
 * pattern can't parse (defensive -- the catalog enforces the format
 * but a stray entry shouldn't crash the table). */
function _extractGroupFromControlId(controlId: string): string {
  const parts = controlId.split("-");
  return parts.length >= 2 ? parts[1] : "--";
}

/** Verdict → AilaBadge severity. FINDING is the audit signal worth
 * flagging in red; INCONCLUSIVE warns; NO_FINDING is the
 * compliance-clear baseline; NOT_APPLICABLE is purely informational. */
function _verdictSeverity(
  verdict: MasvsVerdict,
): "critical" | "high" | "medium" | "low" | "info" {
  switch (verdict) {
    case "finding":
      return "critical";
    case "inconclusive":
      return "medium";
    case "no_finding":
      return "low";
    case "not_applicable":
    default:
      return "info";
  }
}

/** Verdict → stable uppercase label so a screen reader / copy-paste
 * always lands on the same string regardless of source enum value. */
function _verdictLabel(verdict: MasvsVerdict): string {
  switch (verdict) {
    case "finding":
      return "FINDING";
    case "not_applicable":
      return "N/A";
    case "no_finding":
      return "NO FINDING";
    case "inconclusive":
    default:
      return "INCONCLUSIVE";
  }
}

/** Additive analytics section for android_apk targets. Renders donut +
 *  by-group bar charts sourced from the MASVS and APK static-audit
 *  aggregate endpoints. Silently omits either half if its parent
 *  investigation hasn't been dispatched yet -- so on a fresh APK the
 *  section is empty; once one dispatcher fires the matching charts
 *  appear beside the existing tables above (which stay intact).
 *
 *  Reads the exact same `useMasvsAuditAggregate` /
 *  `useApkStaticAuditAggregate` hooks the dispatcher cards use, so the
 *  charts share the 8s poll cadence and settle in lock-step with the
 *  per-control tables. Uses `useThemeChartColors()` for verdict fills
 *  (CSS variables do not resolve in Recharts SVG presentation attrs). */
function AuditAggregateAnalytics({ targetId }: { targetId: string }) {
  const colors = useThemeChartColors();
  const { data: investigationsResult, isLoading: isLoadingInvs } =
    useInvestigationsForTarget(targetId);
  const investigations = investigationsResult?.data ?? [];

  const masvsParent =
    investigations
      .filter(
        (inv) =>
          (inv.kind as string) === "masvs_audit" &&
          inv.parent_investigation_id == null,
      )
      .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0]
      ?? null;

  const apkStaticParent =
    investigations
      .filter(
        (inv) =>
          (inv.kind as string) === "apk_static_audit" &&
          inv.parent_investigation_id == null,
      )
      .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0]
      ?? null;

  const { data: masvsAgg } = useMasvsAuditAggregate(
    targetId,
    masvsParent?.id ?? null,
  );
  const { data: apkStaticAgg } = useApkStaticAuditAggregate(
    targetId,
    apkStaticParent?.id ?? null,
  );

  if (isLoadingInvs) return null;
  // Nothing dispatched -- keep the page unchanged from before this
  // section landed. The dispatcher cards above already display the
  // "not dispatched yet" empty-state pattern; no need to repeat it.
  if (masvsParent == null && apkStaticParent == null) return null;

  const masvsVerdictData = masvsAgg
    ? _buildVerdictBuckets(masvsAgg.verdicts)
    : [];
  const masvsGroupData = masvsAgg
    ? _buildMasvsGroupBuckets(masvsAgg.verdicts)
    : [];
  const apkVerdictData = apkStaticAgg
    ? _buildVerdictBuckets(apkStaticAgg.verdicts)
    : [];
  const apkGroupData = apkStaticAgg
    ? _buildApkStaticGroupBuckets(apkStaticAgg.verdicts)
    : [];

  const verdictColors = [
    colors.critical, // finding
    colors.medium, // inconclusive
    colors.low, // no_finding
    colors.textMuted, // not_applicable
  ];
  const findingColor = [colors.critical];

  return (
    <AilaCard techBorder glow>
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground">
            Analytics
          </h2>
          <p className="text-xs text-text-muted mt-1">
            Verdict distribution across MASVS controls and APK static
            checks, plus per-group finding density. Updates live as
            child investigations resolve.
          </p>
        </div>

        {masvsAgg && (
          <div className="space-y-2">
            <div className="flex items-baseline justify-between flex-wrap gap-2">
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide">
                MASVS verdicts
              </h3>
              <span className="text-3xs text-text-muted font-mono">
                {masvsAgg.verdicts.length} verdict
                {masvsAgg.verdicts.length === 1 ? "" : "s"} · catalog{" "}
                {masvsAgg.masvs_spec_version}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {_hasChartData(masvsVerdictData) ? (
                <AilaChart
                  type="pie"
                  data={masvsVerdictData}
                  dataKey="count"
                  xKey="name"
                  colors={verdictColors}
                  size="sm"
                  ariaLabel="MASVS verdict distribution"
                />
              ) : (
                <p className="text-xs text-text-muted">
                  No verdicts resolved yet.
                </p>
              )}
              {_hasChartData(masvsGroupData) ? (
                <AilaChart
                  type="bar"
                  data={masvsGroupData}
                  dataKey="findings"
                  xKey="group"
                  colors={findingColor}
                  size="sm"
                  ariaLabel="MASVS findings per group"
                />
              ) : (
                <p className="text-xs text-text-muted">
                  No group breakdown yet.
                </p>
              )}
            </div>
          </div>
        )}

        {apkStaticAgg && (
          <div className="space-y-2">
            <div className="flex items-baseline justify-between flex-wrap gap-2">
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide">
                APK static verdicts
              </h3>
              <span className="text-3xs text-text-muted font-mono">
                {apkStaticAgg.verdicts.length} verdict
                {apkStaticAgg.verdicts.length === 1 ? "" : "s"} · catalog{" "}
                {apkStaticAgg.apk_static_spec_version}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {_hasChartData(apkVerdictData) ? (
                <AilaChart
                  type="pie"
                  data={apkVerdictData}
                  dataKey="count"
                  xKey="name"
                  colors={verdictColors}
                  size="sm"
                  ariaLabel="APK static verdict distribution"
                />
              ) : (
                <p className="text-xs text-text-muted">
                  No verdicts resolved yet.
                </p>
              )}
              {_hasChartData(apkGroupData) ? (
                <AilaChart
                  type="bar"
                  data={apkGroupData}
                  dataKey="findings"
                  xKey="group"
                  colors={findingColor}
                  size="sm"
                  ariaLabel="APK static findings per group"
                />
              ) : (
                <p className="text-xs text-text-muted">
                  No group breakdown yet.
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </AilaCard>
  );
}

/** Verdict → display label preserved from the per-control table so a
 *  screen reader hits the same string in both places. Kept internal --
 *  the chart only needs `{ name, count }` rows. */
const _VERDICT_ORDER: ReadonlyArray<{
  key: MasvsVerdict | ApkStaticVerdict;
  label: string;
}> = [
  { key: "finding", label: "FINDING" },
  { key: "inconclusive", label: "INCONCLUSIVE" },
  { key: "no_finding", label: "NO FINDING" },
  { key: "not_applicable", label: "N/A" },
];

function _buildVerdictBuckets(
  verdicts: ReadonlyArray<MasvsControlVerdict | ApkStaticControlVerdict>,
): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const v of verdicts) {
    counts.set(v.verdict, (counts.get(v.verdict) ?? 0) + 1);
  }
  return _VERDICT_ORDER.map(({ key, label }) => ({
    name: label,
    count: counts.get(key) ?? 0,
  }));
}

function _buildMasvsGroupBuckets(
  verdicts: ReadonlyArray<MasvsControlVerdict>,
): Array<{ group: string; findings: number; total: number }> {
  const acc = new Map<string, { findings: number; total: number }>();
  for (const v of verdicts) {
    const g = _extractGroupFromControlId(v.control_id);
    const row = acc.get(g) ?? { findings: 0, total: 0 };
    row.total += 1;
    if (v.verdict === "finding") row.findings += 1;
    acc.set(g, row);
  }
  return Array.from(acc.entries())
    .map(([group, row]) => ({ group, ...row }))
    .sort((a, b) => b.findings - a.findings || a.group.localeCompare(b.group));
}

function _buildApkStaticGroupBuckets(
  verdicts: ReadonlyArray<ApkStaticControlVerdict>,
): Array<{ group: string; findings: number; total: number }> {
  // APK static ids share the ``APK-<GROUP>-<check>`` shape -- reuse the
  // same split rule as MASVS so a stray non-conforming id renders under
  // "--" instead of crashing.
  const acc = new Map<string, { findings: number; total: number }>();
  for (const v of verdicts) {
    const g = _extractGroupFromControlId(v.control_id);
    const row = acc.get(g) ?? { findings: 0, total: 0 };
    row.total += 1;
    if (v.verdict === "finding") row.findings += 1;
    acc.set(g, row);
  }
  return Array.from(acc.entries())
    .map(([group, row]) => ({ group, ...row }))
    .sort((a, b) => b.findings - a.findings || a.group.localeCompare(b.group));
}

function _hasChartData(rows: ReadonlyArray<Record<string, unknown>>): boolean {
  return rows.some((r) => {
    for (const v of Object.values(r)) {
      if (typeof v === "number" && v > 0) return true;
    }
    return false;
  });
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
  const resumeAnalysisMut = useResumeTargetAnalysis(tid);
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
      {/* Header -- humans, not IDs */}
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
          ? "border-critical"
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
          {target.analysis_state === "failed" && (
            <button
              type="button"
              onClick={() => resumeAnalysisMut.mutate()}
              disabled={resumeAnalysisMut.isPending}
              title="Reset any FAILED stages back to PENDING and re-enqueue the ingest → profile → ranking pipeline. Stages already DONE are skipped (StageTracker idempotence). Distinct from Re-analyze, which resubmits everything unconditionally."
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border hover:bg-elevated disabled:opacity-50"
            >
              {resumeAnalysisMut.isPending ? "Resuming…" : "Resume analysis"}
            </button>
          )}
          {(target.analysis_state === "failed" ||
            target.analysis_state === "ready") && (
            <button
              type="button"
              onClick={() => analyzeMut.mutate()}
              disabled={analyzeMut.isPending}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border hover:bg-elevated disabled:opacity-50"
            >
              {analyzeMut.isPending ? "Re-analyzing…" : "Re-analyze"}
            </button>
          )}
          {target.analysis_state === "ready" && (
            <button
              type="button"
              onClick={() => rankMut.mutate()}
              disabled={rankMut.isPending}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-background hover:bg-accent/90 disabled:opacity-50"
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
              ? "text-critical"
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
            : "--"}
          . This usually takes 30s–10min depending on artifact size.
        </p>
      )}</AilaCard>

      {/* Upload widget -- only for upload-capable kinds. AILA streams the
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
      <AilaCard  techBorder glow><h2 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
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
              {applicableMcp.length > 0 ? applicableMcp.join(", ") : "--"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Applicable fuzzing engines</dt>
            <dd className="font-mono text-xs">
              {applicableEngines.length > 0 ? applicableEngines.join(", ") : "--"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Applicable strategies</dt>
            <dd className="font-mono text-xs">
              {applicableStrategies.length > 0
                ? applicableStrategies.join(", ")
                : "--"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Default disclosure tracks</dt>
            <dd className="font-mono text-xs">
              {defaultDisclosure.length > 0 ? defaultDisclosure.join(", ") : "--"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Default reasoning strategy</dt>
            <dd className="font-mono text-xs">
              {(capability.default_reasoning_strategy as string) ?? "--"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Est. cost / investigation</dt>
            <dd className="font-mono text-xs">
              ${(capability.estimated_cost_per_investigation_usd as number) ?? "--"}
            </dd>
          </div>
        </dl>
      )}</AilaCard>

      {/* Connected -- workspace + reverse lookups for investigations
          and projects (target_id / patched_target_id). Purely derived
          from cached list queries; hides itself when nothing links to
          this target. */}
      <TargetConnectedCard target={target} />

      {/* Android APK overview -- only shown for android_apk targets that
          have at least one stage handle. Each section inside the card
          gates on its own data, so the operator sees what's ready as
          the 5-stage pipeline progresses. */}
      {target.kind === "android_apk" && target.apk_overview && (
        <AndroidApkOverview overview={target.apk_overview} />
      )}

      {/* Primary APK audit dispatcher. Gated to android_apk targets
          whose ingestion pipeline has reached STATIC_SUMMARY (matches
          the backend precondition in dispatch_apk_static_audit). Sits
          ABOVE the legacy MASVS card so operators land on the
          evidence-backed catalog by default; MASVS is kept below for
          regulated audits that require the L1 compliance list
          verbatim. */}
      {target.kind === "android_apk"
        && target.apk_overview?.static_summary
        && Object.keys(target.apk_overview.static_summary).length > 0 && (
        <ApkStaticAuditCard
          targetId={target.id}
          packageLabel={
            typeof target.apk_overview.static_summary.package === "string"
              ? (target.apk_overview.static_summary.package as string)
              : target.android_package_name ?? null
          }
        />
      )}

      {/* Legacy MASVS L1 compliance dispatcher. Same STATIC_SUMMARY
          gate as the primary card above. Kept available but rendered
          in secondary styling -- see MasvsAuditCard for the LEGACY
          COMPLIANCE badge and elevated (non-glow) surface. */}
      {target.kind === "android_apk"
        && target.apk_overview?.static_summary
        && Object.keys(target.apk_overview.static_summary).length > 0 && (
        <MasvsAuditCard
          targetId={target.id}
          packageLabel={
            typeof target.apk_overview.static_summary.package === "string"
              ? (target.apk_overview.static_summary.package as string)
              : target.android_package_name ?? null
          }
        />
      )}

      {/* U-1 progress card. Same gate as the dispatcher (above) and
          the report card (below) -- APK kinds with STATIC_SUMMARY.
          The card self-hides until a parent masvs_audit row exists,
          so on a fresh APK only the dispatcher renders. Once a
          dispatch has fired, the card surfaces live counts +
          per-child median wall-time + serial-upper-bound ETA. */}
      {target.kind === "android_apk"
        && target.apk_overview?.static_summary
        && Object.keys(target.apk_overview.static_summary).length > 0 && (
        <MasvsProgressCard
          targetId={target.id}
          packageLabel={
            typeof target.apk_overview.static_summary.package === "string"
              ? (target.apk_overview.static_summary.package as string)
              : target.android_package_name ?? null
          }
        />
      )}

      {/* R-4 "Download MASVS report" card. Gated identically to the
          dispatcher above so the report card only ever shows up for
          APK targets whose ingestion has reached STATIC_SUMMARY.
          The card itself self-hides until a parent masvs_audit
          investigation exists for this target, so on a fresh APK
          only the dispatcher above renders. Disabled until at least
          one child reaches a terminal state (partial reports are
          valid per R-3). */}
      {target.kind === "android_apk"
        && target.apk_overview?.static_summary
        && Object.keys(target.apk_overview.static_summary).length > 0 && (
        <MasvsReportCard
          targetId={target.id}
          packageLabel={
            typeof target.apk_overview.static_summary.package === "string"
              ? (target.apk_overview.static_summary.package as string)
              : target.android_package_name ?? null
          }
        />
      )}

      {/* U-2 per-control table. Same APK + STATIC_SUMMARY gate as
          the dispatcher / progress / report cards above. The table
          self-hides until a parent masvs_audit row exists, so on a
          fresh APK only the dispatcher renders. Once a dispatch has
          fired, the table surfaces one row per child investigation
          (control id + group + status + verdict + confidence) with
          a deep-link to the child's detail page. */}
      {target.kind === "android_apk"
        && target.apk_overview?.static_summary
        && Object.keys(target.apk_overview.static_summary).length > 0 && (
        <MasvsControlTable
          targetId={target.id}
          packageLabel={
            typeof target.apk_overview.static_summary.package === "string"
              ? (target.apk_overview.static_summary.package as string)
              : target.android_package_name ?? null
          }
        />
      )}

      {/* Additive analytics -- verdict distributions + per-group finding
          density derived from the MASVS and APK-static audit aggregates.
          Self-hides on non-APK targets and when neither audit has been
          dispatched yet, so nothing above this line changes when a
          fresh target loads. */}
      {target.kind === "android_apk"
        && target.apk_overview?.static_summary
        && Object.keys(target.apk_overview.static_summary).length > 0 && (
        <AuditAggregateAnalytics targetId={target.id} />
      )}

      {/* Mitigations -- uses shared MitigationsRibbon (§1.4 promise) */}
      {target.analysis_state === "ready" && (
        <AilaCard  techBorder glow><h2 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
          Mitigations
        </h2>
        <MitigationsRibbon mitigations={mitigations} /></AilaCard>
      )}

      {/* Tabs per 08_FRONTEND_UX.md §1.4. URL state via ?tab= so the
          operator can deep-link a teammate to "look at this tab." */}
      {target.analysis_state === "ready" && (
        <>
          <div className="border-b border-border flex gap-1 overflow-x-auto">
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
        <AilaCard  techBorder glow><h2 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
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
              <caption className="sr-only">Top-ranked candidate functions</caption>
              <thead>
                <tr className="border-b border-border text-left text-text-muted">
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
                    className="border-b border-border last:border-b-0"
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
                      {f.score?.toFixed(2) ?? "--"}
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

      {/* Descriptor -- collapsed for debugging only */}
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
