import { Fragment, useRef, useState } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  FilterChip,
  MonoBadge,
  SectionHeader,
  Segmented,
  StatBar,
  toneColor,
  type GridColumn,
} from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { saveBlobResponse } from "@platform/api/download";
import { requestBlob } from "@platform/api/http";

import { DeleteButton } from "../components/DeleteButton";
import {
  MitigationsRibbon,
  type MitigationFlags,
} from "../components/MitigationsRibbon";
import { TargetConnectedCard } from "../components/TargetConnectedCard";
import { UploadDropzone } from "../components/UploadDropzone";
import {
  APK_STATIC_CHECK_COUNT_ESTIMATE,
  APK_STATIC_DEFAULT_CHILD_BUDGET_USD,
  MASVS_DEFAULT_CHILD_BUDGET_USD,
  MASVS_L1_CONTROL_COUNT_ESTIMATE,
  useAnalyzeTarget,
  useApkStaticAudit,
  useDeleteTarget,
  useMasvsAudit,
  useRankTarget,
  useResumeTargetAnalysis,
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

// ---------------------------------------------------------------------------
// Local tone maps (severity -> mock kit tone)
// ---------------------------------------------------------------------------
type Tone = "critical" | "high" | "medium" | "low" | "accent" | "ok" | "info" | "warn" | "muted";
type PanelTone = "accent" | "ok" | "info" | "warn" | "muted";

const analysisTone: Record<AnalysisState, Tone> = {
  pending: "info",
  ingesting: "warn",
  ready: "ok",
  failed: "critical",
};

const statusTone: Record<TargetStatus, Tone> = {
  active: "ok",
  archived: "muted",
  quarantined: "warn",
};

/** Per-kind operator-readable label for each AnalysisState. */
function analysisLabel(state: AnalysisState, kind: TargetKind): string {
  if (state === "ready") return "ready";
  if (state === "failed") return "failed";
  if (state === "pending") return "queued";
  // ingesting
  if (kind === "source_repo") return "cloning + indexing source";
  if (kind === "cve") return "resolving cve record";
  if (
    kind === "kernel_image" ||
    kind === "kernel_module" ||
    kind === "hypervisor_image" ||
    kind === "ipa" ||
    kind === "jar" ||
    kind === "dotnet_assembly"
  ) {
    return "uploading + analyzing in ida";
  }
  if (kind === "android_apk") {
    return "apk_decode \u2192 jadx_decompile \u2192 index \u2192 static_summary";
  }
  return "uploading + analyzing";
}

function formatDate(value?: string | null): string {
  if (!value) return "--";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

const UPLOADABLE_KINDS: Partial<Record<TargetKind, true>> = {
  native_binary: true,
  kernel_image: true,
  kernel_module: true,
  hypervisor_image: true,
  ipa: true,
  jar: true,
  dotnet_assembly: true,
};

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

// ---------------------------------------------------------------------------
// Shared inline primitives
// ---------------------------------------------------------------------------

const HEADER_BTN_BASE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

function HeaderButton({
  label,
  onClick,
  disabled,
  primary,
  title,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  primary?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="font-mono uppercase"
      style={{
        ...HEADER_BTN_BASE,
        background: primary ? "var(--accent)" : "var(--surface-sunk)",
        border: `1px solid ${primary ? "var(--accent)" : "var(--border-soft)"}`,
        color: primary ? "var(--text-on-accent)" : "var(--text-primary)",
        opacity: disabled ? 0.5 : 1,
      }}
    >
      {label}
    </button>
  );
}

/** Uppercase mono label above value, border-bottom rule. Mirrors
 *  ProjectDetailPage's `BriefRow`. */
function BriefRow({
  label,
  children,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
    </div>
  );
}

function MonoEmpty({
  children,
  tone = "muted",
}: {
  children: React.ReactNode;
  tone?: "muted" | "error";
}) {
  return (
    <div
      className="font-mono"
      style={{
        padding: 34,
        textAlign: "center",
        fontSize: 11.5,
        color: tone === "error" ? "var(--accent)" : "var(--text-muted)",
        letterSpacing: "0.04em",
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

type TargetTab =
  | "functions"
  | "attack_surface"
  | "hypotheses"
  | "imports"
  | "notes";

const TARGET_TABS: ReadonlyArray<{ value: TargetTab; label: string }> = [
  { value: "functions", label: "functions" },
  { value: "attack_surface", label: "attack surface" },
  { value: "hypotheses", label: "hypotheses" },
  { value: "imports", label: "imports / exports" },
  { value: "notes", label: "notes" },
];

// ---------------------------------------------------------------------------
// Attack surface tab
// ---------------------------------------------------------------------------

function AttackSurfaceTab({
  capability,
}: {
  capability: Record<string, unknown>;
}) {
  const items =
    (capability.attack_surface as
      | Array<{
          kind: string;
          name: string;
          location?: string;
          severity_hint?: string;
        }>
      | undefined) ?? [];

  if (items.length === 0) {
    return (
      <WindowPanel title="attack surface" tone="muted">
        <MonoEmpty>
          no entries enumerated. audit-mcp attack_surface + ida classify_behavior
          populate this on analyze -- re-run analysis if you expected entries.
        </MonoEmpty>
      </WindowPanel>
    );
  }

  return (
    <WindowPanel title={`attack surface (${items.length})`} tone="accent" flush>
      <div>
        {items.map((it, i) => {
          const sevTone: Tone =
            it.severity_hint === "high"
              ? "high"
              : it.severity_hint === "medium"
                ? "medium"
                : "info";
          return (
            <div
              key={`${it.kind}-${it.name}-${i}`}
              className="font-mono"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
                padding: "8px 12px",
                borderBottom: "1px solid var(--border-faint)",
                background: "var(--surface-card)",
                fontSize: 11,
              }}
            >
              <div
                style={{
                  minWidth: 0,
                  display: "flex",
                  alignItems: "baseline",
                  gap: 8,
                  flexWrap: "wrap",
                }}
              >
                <span
                  className="uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.12em",
                    color: "var(--text-faint)",
                  }}
                >
                  {it.kind}
                </span>
                <span style={{ color: "var(--text-primary)" }}>{it.name}</span>
                {it.location && (
                  <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                    @ {it.location}
                  </span>
                )}
              </div>
              {it.severity_hint && (
                <MonoBadge tone={sevTone}>{it.severity_hint}</MonoBadge>
              )}
            </div>
          );
        })}
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Hypotheses tab
// ---------------------------------------------------------------------------

type HypoFilter = "all" | "live" | "rejected" | "resolved" | "mixed";

const HYPO_COLUMNS: GridColumn[] = [
  { label: "state", width: "90px" },
  { label: "investigation", width: "minmax(0, 1fr)" },
  { label: "hypothesis", width: "minmax(0, 1.4fr)" },
  { label: "detail", width: "minmax(0, 1.2fr)" },
];

const HYPO_STATE_TONE: Record<string, Tone> = {
  live: "info",
  rejected: "muted",
  resolved: "ok",
  mixed: "warn",
};

function HypothesesTab({ targetId }: { targetId: string }) {
  const { rows, isLoading, isError, investigationCount, skippedCreatedCount } =
    useTargetHypotheses(targetId);
  const [filter, setFilter] = useState<HypoFilter>("all");

  const visible = rows.filter((r) => filter === "all" || r.state === filter);
  const sorted = visible.slice().sort((a, b) => {
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
    return (
      <WindowPanel title="hypotheses" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
  }

  if (!isLoading && rows.length === 0) {
    return (
      <WindowPanel title="hypotheses" tone="muted">
        <MonoEmpty>
          {investigationCount === 0
            ? "no investigation on this target has produced hypotheses yet. start one -- agents populate hypotheses as evidence lands."
            : `aggregated across ${investigationCount} investigation(s). hypotheses are emitted by the reasoning engine as it processes evidence.`}
        </MonoEmpty>
      </WindowPanel>
    );
  }

  const filterRow = (
    <div className="flex items-center" style={{ gap: 6, flexWrap: "wrap" }}>
      {(["all", "live", "mixed", "resolved", "rejected"] as const).map((f) => (
        <FilterChip key={f} active={filter === f} onClick={() => setFilter(f)}>
          {f} ({counts[f]})
        </FilterChip>
      ))}
    </div>
  );

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      <WindowPanel
        title={`${rows.length} across ${investigationCount} investigation${investigationCount === 1 ? "" : "s"}`}
        tone="info"
        actions={
          skippedCreatedCount > 0 ? (
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                color: "var(--text-faint)",
                letterSpacing: "0.08em",
              }}
            >
              {skippedCreatedCount} pending
            </span>
          ) : null
        }
      >
        {filterRow}
        {isError && (
          <p
            className="font-mono"
            style={{
              marginTop: 8,
              fontSize: 10,
              color: "var(--accent)",
              letterSpacing: "0.06em",
            }}
          >
            one or more per-investigation fetches failed; partial data shown.
          </p>
        )}
      </WindowPanel>

      <WindowPanel
        title="rows"
        tone="accent"
        flush
        actions={
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              color: "var(--text-faint)",
              letterSpacing: "0.08em",
            }}
          >
            {sorted.length}
          </span>
        }
      >
        <DataGrid
          columns={HYPO_COLUMNS}
          rows={sorted}
          getKey={(r, i) => `${r.investigation_id}:${r.id}:${i}`}
          empty={<MonoEmpty>no rows match the current filter.</MonoEmpty>}
          renderCells={(r) => [
            <MonoBadge tone={HYPO_STATE_TONE[r.state] ?? "muted"}>
              {r.state}
            </MonoBadge>,
            <div style={{ minWidth: 0 }}>
              <Link
                to={`/vr/investigations/${r.investigation_id}`}
                style={{
                  color: "var(--text-primary)",
                  textDecoration: "none",
                  fontSize: 11,
                  display: "block",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {r.investigation_title}
              </Link>
              <div
                style={{
                  marginTop: 2,
                  fontSize: 9,
                  color: "var(--text-faint)",
                  letterSpacing: "0.06em",
                }}
              >
                {r.investigation_kind} \u00b7 {r.investigation_status}
              </div>
            </div>,
            <div style={{ minWidth: 0 }}>
              <div
                style={{
                  color: "var(--text-primary)",
                  fontSize: 11,
                  overflowWrap: "anywhere",
                }}
              >
                {r.claim}
              </div>
              <div
                style={{
                  marginTop: 2,
                  fontSize: 9,
                  color: "var(--text-faint)",
                }}
              >
                {r.id}
              </div>
            </div>,
            <div
              style={{
                minWidth: 0,
                fontSize: 10.5,
                color: "var(--text-muted)",
                overflowWrap: "anywhere",
              }}
            >
              {r.rejection_reason ? (
                <span>
                  <span style={{ color: "var(--accent)" }}>rejected:</span>{" "}
                  {r.rejection_reason}
                </span>
              ) : r.resolution_note ? (
                <span>
                  <span style={{ color: "var(--status-warn)" }}>resolved:</span>{" "}
                  {r.resolution_note}
                </span>
              ) : r.why_plausible ? (
                r.why_plausible
              ) : r.kill_criterion ? (
                <span>
                  <span style={{ color: "var(--text-faint)" }}>kill if:</span>{" "}
                  {r.kill_criterion}
                </span>
              ) : (
                <span style={{ color: "var(--text-faint)" }}>--</span>
              )}
            </div>,
          ]}
        />
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Imports / exports tab
// ---------------------------------------------------------------------------

function ImportsExportsTab({
  capability,
}: {
  capability: Record<string, unknown>;
}) {
  const imports =
    (capability.imports as
      | Array<{ name: string; module?: string; dangerous?: boolean }>
      | undefined) ?? [];
  const exports_ =
    (capability.exports as
      | Array<{ name: string; reachable?: boolean }>
      | undefined) ?? [];

  if (imports.length === 0 && exports_.length === 0) {
    return (
      <WindowPanel title="imports / exports" tone="muted">
        <MonoEmpty>
          no imports / exports recorded yet. dangerous imports (strcpy, sprintf,
          system, gets) render highlighted; reachable exports carry a
          "reachable" chip.
        </MonoEmpty>
      </WindowPanel>
    );
  }

  return (
    <div
      className="grid"
      style={{
        gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
        gap: 12,
      }}
    >
      <WindowPanel title={`imports (${imports.length})`} tone="warn">
        <ul
          className="font-mono"
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 4,
            maxHeight: 384,
            overflowY: "auto",
            fontSize: 11,
            paddingRight: 4,
          }}
        >
          {imports.map((im) => {
            const danger = !!im.dangerous;
            return (
              <li
                key={im.name}
                style={{
                  padding: "4px 8px",
                  borderRadius: 2,
                  border: `1px solid ${danger ? "var(--status-warn)" : "var(--border-faint)"}`,
                  color: danger ? "var(--status-warn)" : "var(--text-primary)",
                  background: danger
                    ? "color-mix(in srgb, var(--status-warn) 8%, transparent)"
                    : "var(--surface-card)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                }}
              >
                <span style={{ overflowWrap: "anywhere" }}>{im.name}</span>
                {im.module && (
                  <span
                    style={{
                      fontSize: 9.5,
                      color: "var(--text-faint)",
                      letterSpacing: "0.06em",
                    }}
                  >
                    {im.module}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      </WindowPanel>

      <WindowPanel title={`exports (${exports_.length})`} tone="info">
        <ul
          className="font-mono"
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 4,
            maxHeight: 384,
            overflowY: "auto",
            fontSize: 11,
            paddingRight: 4,
          }}
        >
          {exports_.map((ex) => (
            <li
              key={ex.name}
              style={{
                padding: "4px 8px",
                borderRadius: 2,
                border: "1px solid var(--border-faint)",
                color: "var(--text-primary)",
                background: "var(--surface-card)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
              }}
            >
              <span style={{ overflowWrap: "anywhere" }}>{ex.name}</span>
              {ex.reachable && <MonoBadge tone="medium">reachable</MonoBadge>}
            </li>
          ))}
        </ul>
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Notes tab
// ---------------------------------------------------------------------------

function NotesTab({ targetId }: { targetId: string }) {
  const STORAGE_KEY = `vr.target.notes.${targetId}`;
  const initial =
    typeof window === "undefined"
      ? ""
      : window.localStorage.getItem(STORAGE_KEY) ?? "";
  const [text, setText] = useState(initial);
  const [savedAt, setSavedAt] = useState<string | null>(
    initial ? "loaded from local" : null,
  );
  function save() {
    try {
      window.localStorage.setItem(STORAGE_KEY, text);
      setSavedAt(new Date().toLocaleTimeString());
    } catch {
      setSavedAt("save failed");
    }
  }
  return (
    <WindowPanel
      title="operator notes"
      tone="info"
      status={
        <span>
          saved locally in your browser ({savedAt ?? "not saved yet"}).
          project-scoped sync -- backend pending.
        </span>
      }
    >
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={save}
        rows={10}
        placeholder="free-text notes about this target. stays in your browser until the backend per-target notes api ships."
        aria-label="Operator notes"
        className="font-mono"
        style={{
          width: "100%",
          padding: "8px 10px",
          fontSize: 11,
          lineHeight: 1.55,
          color: "var(--text-primary)",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
          resize: "vertical",
          outline: "none",
        }}
      />
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Android APK overview
// ---------------------------------------------------------------------------

function AndroidApkOverview({ overview }: { overview: ApkOverview }) {
  const summary = (overview.static_summary ?? {}) as Record<string, unknown>;

  const asStringArray = (v: unknown): string[] =>
    !Array.isArray(v) ? [] : v.filter((x): x is string => typeof x === "string");
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

  const exportedTotal =
    activities.length + services.length + receivers.length + providers.length;

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <WindowPanel title="android apk" tone="accent">
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "0 20px",
          }}
        >
          <BriefRow label="package">{pkg ?? "--"}</BriefRow>
          <BriefRow label="version">
            {versionName ?? "--"}
            {versionCode != null ? ` (${versionCode})` : ""}
          </BriefRow>
          <BriefRow label="sdk range">
            {minSdk != null ? `min ${minSdk}` : "--"}
            {targetSdk != null ? ` \u00b7 target ${targetSdk}` : ""}
          </BriefRow>
          <BriefRow label="signing scheme">{signingScheme ?? "--"}</BriefRow>
          <BriefRow label="sha-256">
            <span style={{ fontSize: 10 }}>{overview.sha256 ?? "--"}</span>
          </BriefRow>
          <BriefRow label="jadx classes">
            {overview.jadx_class_count?.toLocaleString() ?? "--"}
          </BriefRow>
        </div>
      </WindowPanel>

      {nativeLibs.length > 0 && (
        <WindowPanel title={`native libraries (${nativeLibs.length})`} tone="info">
          <ul
            className="font-mono"
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 2,
              maxHeight: 220,
              overflowY: "auto",
              fontSize: 10.5,
              color: "var(--text-muted)",
              paddingRight: 4,
            }}
          >
            {nativeLibs.map((lib) => (
              <li key={lib}>{lib}</li>
            ))}
          </ul>
        </WindowPanel>
      )}

      {permissions.length > 0 && (
        <WindowPanel
          title={`permissions (${permissions.length})`}
          tone={dangerousPerms.length > 0 ? "warn" : "info"}
          actions={
            dangerousPerms.length > 0 ? (
              <MonoBadge tone="critical">
                {dangerousPerms.length} dangerous
              </MonoBadge>
            ) : null
          }
        >
          <details>
            <summary
              className="font-mono uppercase"
              style={{
                fontSize: 9.5,
                letterSpacing: "0.1em",
                color: "var(--text-muted)",
                cursor: "pointer",
              }}
            >
              show list
            </summary>
            <ul
              className="font-mono"
              style={{
                marginTop: 8,
                display: "flex",
                flexDirection: "column",
                gap: 2,
                maxHeight: 320,
                overflowY: "auto",
                fontSize: 10.5,
                color: "var(--text-muted)",
                paddingRight: 4,
              }}
            >
              {permissions.map((p) => (
                <li
                  key={p}
                  style={{
                    color: dangerousPerms.includes(p)
                      ? "var(--accent)"
                      : "var(--text-muted)",
                  }}
                >
                  {p}
                </li>
              ))}
            </ul>
          </details>
        </WindowPanel>
      )}

      {exportedTotal > 0 && (
        <WindowPanel title="exported components" tone="info">
          <div
            className="grid"
            style={{
              gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
              gap: 1,
              background: "var(--border-faint)",
              border: "1px solid var(--border-faint)",
              borderRadius: 3,
            }}
          >
            <StatusCell label="activities" value={activities.length} />
            <StatusCell label="services" value={services.length} />
            <StatusCell label="receivers" value={receivers.length} />
            <StatusCell label="providers" value={providers.length} />
          </div>
        </WindowPanel>
      )}

      {certificates.length > 0 && (
        <WindowPanel title={`certificates (${certificates.length})`} tone="info">
          <ul
            className="font-mono"
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 10,
              fontSize: 11,
            }}
          >
            {certificates.map((cert, idx) => (
              <li
                key={`${(cert.sha256 as string) ?? idx}`}
                style={{
                  borderLeft: "2px solid var(--border-soft)",
                  paddingLeft: 10,
                }}
              >
                <div style={{ color: "var(--text-primary)" }}>
                  {(cert.subject as string) ??
                    (cert.issuer as string) ??
                    "--"}
                </div>
                {cert.sha256 != null && (
                  <div
                    style={{
                      fontSize: 9.5,
                      color: "var(--text-muted)",
                      overflowWrap: "anywhere",
                    }}
                  >
                    sha-256 {String(cert.sha256)}
                  </div>
                )}
                {cert.sha1 != null && (
                  <div
                    style={{
                      fontSize: 9.5,
                      color: "var(--text-muted)",
                      overflowWrap: "anywhere",
                    }}
                  >
                    sha-1 {String(cert.sha1)}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </WindowPanel>
      )}

      <WindowPanel title="backend handles" tone="muted">
        {overview.decoded_dir && (
          <BriefRow label="apktool">{overview.decoded_dir}</BriefRow>
        )}
        {overview.decompiled_dir && (
          <BriefRow label="jadx">{overview.decompiled_dir}</BriefRow>
        )}
        {overview.manifest_path && (
          <BriefRow label="manifest">{overview.manifest_path}</BriefRow>
        )}
        {overview.audit_mcp_index_id && (
          <BriefRow label="audit_mcp idx">
            {overview.audit_mcp_index_id}
          </BriefRow>
        )}
        {!overview.decoded_dir &&
          !overview.decompiled_dir &&
          !overview.manifest_path &&
          !overview.audit_mcp_index_id && (
            <MonoEmpty>no backend handles projected yet.</MonoEmpty>
          )}
      </WindowPanel>
    </div>
  );
}

function StatusCell({
  label,
  value,
}: {
  label: string;
  value: number | string;
}) {
  return (
    <div
      className="font-mono"
      style={{
        background: "var(--surface-sunk)",
        padding: "10px 12px",
        display: "flex",
        flexDirection: "column",
        gap: 4,
      }}
    >
      <span
        className="uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: 20,
          color: "var(--text-primary)",
          letterSpacing: "-0.02em",
        }}
      >
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// APK static / MASVS dispatcher, progress, report, control-table, analytics
// ---------------------------------------------------------------------------

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
        `\u2248 ${MASVS_L1_CONTROL_COUNT_ESTIMATE} child investigations, ` +
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

  const action = (
    <HeaderButton
      label={
        masvsMut.isPending
          ? "dispatching\u2026"
          : `run legacy masvs audit (~$${estimatedTotal})`
      }
      onClick={handleClick}
      disabled={masvsMut.isPending}
    />
  );

  return (
    <WindowPanel
      title="masvs audit"
      tone="muted"
      actions={
        <div className="flex items-center" style={{ gap: 8 }}>
          <MonoBadge tone="muted">legacy compliance</MonoBadge>
          {action}
        </div>
      }
    >
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
      >
        broad owasp masvs l1 compliance sweep, kept for regulated audits that
        still require the l1 control list verbatim. prefer the apk static audit
        above for evidence-backed findings on this apk. fans out{" "}
        {MASVS_L1_CONTROL_COUNT_ESTIMATE} parallel child investigations (one
        per l1 control), each driving the standard vuln_researcher workflow
        against the jadx-decompiled tree. estimated total spend \u2248 $
        {estimatedTotal} (~${MASVS_DEFAULT_CHILD_BUDGET_USD} per child
        \u00d7 {MASVS_L1_CONTROL_COUNT_ESTIMATE} controls).
      </p>
    </WindowPanel>
  );
}

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

  const action = (
    <HeaderButton
      label={
        apkMut.isPending
          ? "dispatching\u2026"
          : `run apk static audit (~$${estimatedTotal})`
      }
      onClick={handleClick}
      disabled={apkMut.isPending}
      primary
    />
  );

  return (
    <WindowPanel
      title="apk static audit"
      tone="accent"
      actions={
        <div className="flex items-center" style={{ gap: 8 }}>
          <MonoBadge tone="info">recommended \u00b7 evidence-backed</MonoBadge>
          {action}
        </div>
      }
    >
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
      >
        primary apk audit. runs the apk static-analysis check catalog -- sharp,
        evidence-backed investigations each with a definite file:line source in
        the decompiled tree. fans out {APK_STATIC_CHECK_COUNT_ESTIMATE}
        parallel child investigations (manifest, secrets, crypto, webview, ipc,
        storage, exploit chains). estimated total spend \u2248 ${estimatedTotal}{" "}
        (~${APK_STATIC_DEFAULT_CHILD_BUDGET_USD} per child \u00d7{" "}
        {APK_STATIC_CHECK_COUNT_ESTIMATE} checks).
      </p>
    </WindowPanel>
  );
}

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

  let completedCount = 0;
  let runningCount = 0;
  let failedCount = 0;
  const terminalDurationsSec: number[] = [];
  for (const c of children) {
    if (c.status === "completed") completedCount++;
    else if (c.status === "failed" || c.status === "abandoned") failedCount++;
    else runningCount++;

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

  let medianSec: number | null = null;
  if (terminalDurationsSec.length > 0) {
    const sorted = [...terminalDurationsSec].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    medianSec =
      sorted.length % 2 === 0
        ? (sorted[mid - 1] + sorted[mid]) / 2
        : sorted[mid];
  }

  const medianLabel =
    medianSec != null ? formatDurationCompact(medianSec) : "--";
  let etaLabel: string;
  if (remainingCount === 0) etaLabel = "0s (all terminal)";
  else if (medianSec == null) etaLabel = "--";
  else etaLabel = formatDurationCompact(medianSec * remainingCount);

  const packageDisplay = packageLabel ?? "this APK";

  return (
    <WindowPanel
      title={`masvs progress \u00b7 ${packageDisplay}`}
      tone="info"
      actions={<MonoBadge tone="info">{percentComplete}% complete</MonoBadge>}
      status={
        <span>
          parent {parent.id.slice(0, 8)} \u00b7 {parent.status}
        </span>
      }
    >
      <div className="flex flex-col" style={{ gap: 12 }}>
        <div
          role="progressbar"
          aria-valuenow={percentComplete}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="MASVS audit child completion"
          style={{
            width: "100%",
            height: 8,
            background: "var(--surface-sunk)",
            border: "1px solid var(--border-soft)",
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              height: "100%",
              width: `${percentComplete}%`,
              background: "var(--accent)",
              transition: "width 500ms",
            }}
          />
        </div>

        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: 1,
            background: "var(--border-faint)",
            border: "1px solid var(--border-faint)",
            borderRadius: 3,
          }}
        >
          <StatusCell label="total" value={totalChildren} />
          <StatusCell label="completed" value={completedCount} />
          <StatusCell label="running" value={runningCount} />
          <StatusCell label="failed" value={failedCount} />
        </div>

        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 12,
            paddingTop: 8,
            borderTop: "1px solid var(--border-faint)",
          }}
        >
          <BriefRow label="median wall-time per child">{medianLabel}</BriefRow>
          <BriefRow label="eta (serial upper bound)">{etaLabel}</BriefRow>
        </div>

        <p
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-faint)", lineHeight: 1.5 }}
        >
          eta = median \u00d7 remaining. children run through arq workers in
          parallel, so actual wall-clock scales down with the live vr-queue
          concurrency on this host.
        </p>
      </div>
    </WindowPanel>
  );
}

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
      const params = new URLSearchParams({
        audit_id: parent.id,
        ts: String(Date.now()),
      });
      const payload = await requestBlob(
        `/vr/targets/${encodeURIComponent(targetId)}/masvs-report?${params.toString()}`,
        { method: "GET", token },
      );
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
    ? "downloading\u2026"
    : allTerminal
      ? "download masvs report"
      : `download partial (${terminalCount}/${totalChildren})`;
  const buttonTitle = canDownload
    ? allTerminal
      ? "Download the full PDF aggregate"
      : "Download a partial PDF -- children still running render as INCONCLUSIVE"
    : "Disabled until at least one child investigation reaches a terminal state";

  return (
    <WindowPanel
      title="masvs report"
      tone={allTerminal ? "ok" : "info"}
      actions={
        <HeaderButton
          label={buttonLabel}
          onClick={handleClick}
          disabled={!canDownload || busy}
          primary={canDownload}
          title={buttonTitle}
        />
      }
    >
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
      >
        reportlab pdf aggregating every child investigation outcome through the
        s-4 verdict mapper, grouped by masvs control group with per-control
        evidence excerpts. children still in flight render as inconclusive rows
        -- partial reports are valid handoffs for an interim checkpoint.
      </p>
      <p
        className="font-mono"
        style={{
          marginTop: 8,
          fontSize: 10.5,
          color: "var(--text-primary)",
        }}
      >
        {terminalCount} / {totalChildren} child
        {totalChildren === 1 ? "" : "ren"} terminal
        {allTerminal
          ? " \u00b7 all complete"
          : totalChildren === 0
            ? " \u00b7 waiting on dispatch"
            : " \u00b7 in progress"}
      </p>
      {error && (
        <p
          className="font-mono"
          style={{
            marginTop: 8,
            fontSize: 10,
            color: "var(--accent)",
            overflowWrap: "anywhere",
          }}
        >
          {error}
        </p>
      )}
    </WindowPanel>
  );
}

/** Verdict -> mock kit tone. Used at 3 call sites (analytics bars,
 *  control table row, distribution renderer). */
const VERDICT_TONE: Record<MasvsVerdict, Tone> = {
  finding: "critical",
  inconclusive: "warn",
  no_finding: "ok",
  not_applicable: "muted",
};

const VERDICT_LABEL: Record<MasvsVerdict, string> = {
  finding: "finding",
  inconclusive: "inconclusive",
  no_finding: "no finding",
  not_applicable: "n/a",
};

const MASVS_TABLE_COLUMNS: GridColumn[] = [
  { label: "control", width: "minmax(0, 1.6fr)" },
  { label: "group", width: "110px" },
  { label: "status", width: "100px" },
  { label: "verdict", width: "120px" },
  { label: "conf", width: "70px", align: "right" },
  { label: "link", width: "60px", align: "right" },
];

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

  const childById = new Map<string, (typeof investigations)[number]>();
  for (const inv of investigations) {
    if (inv.parent_investigation_id === parent.id) childById.set(inv.id, inv);
  }
  const totalChildren = childById.size;
  const packageDisplay = packageLabel ?? "this APK";
  const verdicts: MasvsControlVerdict[] = aggregate?.verdicts ?? [];

  const bodyPanel = (body: React.ReactNode, flush = false) => (
    <WindowPanel
      title={`masvs controls \u00b7 ${packageDisplay}`}
      tone="accent"
      flush={flush}
      status={
        <span>
          parent {parent.id.slice(0, 8)} \u00b7 {totalChildren} child
          {totalChildren === 1 ? "" : "ren"}
          {aggregate?.masvs_spec_version
            ? ` \u00b7 catalog ${aggregate.masvs_spec_version}`
            : ""}
          {aggregate?.generated_at
            ? ` \u00b7 generated ${new Date(aggregate.generated_at).toLocaleString()}`
            : ""}
        </span>
      }
    >
      {body}
    </WindowPanel>
  );

  if (isLoadingAgg && verdicts.length === 0) {
    return bodyPanel(<LoadingSkeleton size="lg" width="full" />);
  }
  if (aggError) {
    return bodyPanel(
      <MonoEmpty tone="error">
        aggregate fetch failed:{" "}
        {aggError instanceof Error
          ? aggError.message.slice(0, 200)
          : String(aggError).slice(0, 200)}
      </MonoEmpty>,
    );
  }
  if (verdicts.length === 0) {
    return bodyPanel(
      <MonoEmpty>
        no verdicts resolved yet -- children still in created / running with no
        primary outcome. the table populates as each child reaches a terminal
        state.
      </MonoEmpty>,
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      {bodyPanel(
        <DataGrid
          columns={MASVS_TABLE_COLUMNS}
          rows={verdicts}
          getKey={(v) => v.child_investigation_id}
          renderCells={(v) => {
            const child = childById.get(v.child_investigation_id);
            const childStatus = child?.status ?? "unknown";
            // MASVS v1.4.2 (MSTG-...) + v2.1.0 (MASVS-...) share the
            // ``<PREFIX>-<GROUP>-<N>`` shape; the same split rule handles both.
            const groupParts = v.control_id.split("-");
            const groupLabel = groupParts.length >= 2 ? groupParts[1] : "--";
            const scope = v.scope?.trim() || null;
            const headline = v.headline?.trim() || null;
            const keyPoints = (v.key_points ?? []).filter(
              (p) => p && p.trim().length > 0,
            );
            const hasPanelSummary =
              scope != null || headline != null || keyPoints.length > 0;
            return [
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    color: "var(--text-primary)",
                    fontSize: 11,
                    overflowWrap: "anywhere",
                  }}
                >
                  {v.control_id}
                </div>
                {hasPanelSummary && (
                  <div
                    style={{
                      marginTop: 4,
                      fontSize: 10,
                      color: "var(--text-muted)",
                      lineHeight: 1.5,
                    }}
                  >
                    {scope && (
                      <div>
                        <span
                          className="uppercase"
                          style={{
                            color: "var(--text-faint)",
                            fontSize: 9,
                            letterSpacing: "0.12em",
                            marginRight: 4,
                          }}
                        >
                          scope:
                        </span>
                        {scope}
                      </div>
                    )}
                    {headline && (
                      <div>
                        <span
                          className="uppercase"
                          style={{
                            color: "var(--text-faint)",
                            fontSize: 9,
                            letterSpacing: "0.12em",
                            marginRight: 4,
                          }}
                        >
                          headline:
                        </span>
                        {headline}
                      </div>
                    )}
                    {keyPoints.length > 0 && (
                      <div>
                        <span
                          className="uppercase"
                          style={{
                            color: "var(--text-faint)",
                            fontSize: 9,
                            letterSpacing: "0.12em",
                          }}
                        >
                          key points:
                        </span>
                        <ul
                          style={{
                            listStyle: "disc",
                            paddingLeft: 16,
                            marginTop: 2,
                          }}
                        >
                          {keyPoints.map((p, i) => (
                            <li key={i}>{p}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>,
              <span style={{ color: "var(--text-muted)", fontSize: 10.5 }}>
                {groupLabel}
              </span>,
              <MonoBadge
                tone={
                  childStatus === "completed"
                    ? "ok"
                    : childStatus === "failed" || childStatus === "abandoned"
                      ? "critical"
                      : childStatus === "running"
                        ? "info"
                        : childStatus === "paused"
                          ? "warn"
                          : "muted"
                }
              >
                {childStatus}
              </MonoBadge>,
              <MonoBadge
                tone={VERDICT_TONE[v.verdict]}
                title={
                  v.reason && v.verdict === "inconclusive"
                    ? v.reason
                    : undefined
                }
              >
                {VERDICT_LABEL[v.verdict]}
              </MonoBadge>,
              <span
                style={{
                  color: "var(--text-primary)",
                  fontSize: 10.5,
                  textAlign: "right",
                }}
              >
                {v.verdict === "inconclusive" && v.confidence === 0
                  ? "--"
                  : v.confidence.toFixed(2)}
              </span>,
              <span
                onClick={(e) => e.stopPropagation()}
                style={{
                  display: "inline-flex",
                  justifyContent: "flex-end",
                }}
              >
                <Link
                  to={`/vr/investigations/${encodeURIComponent(
                    v.child_investigation_id,
                  )}`}
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.08em",
                    color: "var(--accent)",
                    textDecoration: "none",
                  }}
                >
                  open
                </Link>
              </span>,
            ];
          }}
        />,
        true,
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Analytics -- StatBar rows instead of Recharts
// ---------------------------------------------------------------------------

interface VerdictBucket {
  key: MasvsVerdict;
  label: string;
  count: number;
}

interface GroupBucket {
  group: string;
  findings: number;
  total: number;
}

const _VERDICT_ORDER: ReadonlyArray<{ key: MasvsVerdict; label: string }> = [
  { key: "finding", label: "finding" },
  { key: "inconclusive", label: "inconclusive" },
  { key: "no_finding", label: "no finding" },
  { key: "not_applicable", label: "n/a" },
];

function _buildVerdictBuckets(
  verdicts: ReadonlyArray<MasvsControlVerdict | ApkStaticControlVerdict>,
): VerdictBucket[] {
  const counts: Partial<Record<MasvsVerdict, number>> = {};
  for (const v of verdicts) {
    counts[v.verdict] = (counts[v.verdict] ?? 0) + 1;
  }
  return _VERDICT_ORDER.map(({ key, label }) => ({
    key,
    label,
    count: counts[key] ?? 0,
  }));
}

function _buildGroupBuckets(
  verdicts: ReadonlyArray<MasvsControlVerdict | ApkStaticControlVerdict>,
): GroupBucket[] {
  const acc = new Map<string, { findings: number; total: number }>();
  for (const v of verdicts) {
    const parts = v.control_id.split("-");
    const g = parts.length >= 2 ? parts[1] : "--";
    const row = acc.get(g) ?? { findings: 0, total: 0 };
    row.total += 1;
    if (v.verdict === "finding") row.findings += 1;
    acc.set(g, row);
  }
  return Array.from(acc.entries())
    .map(([group, row]) => ({ group, ...row }))
    .sort((a, b) => b.findings - a.findings || a.group.localeCompare(b.group));
}

function VerdictDistribution({
  title,
  buckets,
  spec,
}: {
  title: string;
  buckets: VerdictBucket[];
  spec?: string | null;
}) {
  const max = buckets.reduce((m, b) => Math.max(m, b.count), 0);
  const hasData = buckets.some((b) => b.count > 0);
  return (
    <WindowPanel
      title={title}
      tone="info"
      actions={
        spec ? (
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              color: "var(--text-faint)",
              letterSpacing: "0.08em",
            }}
          >
            catalog {spec}
          </span>
        ) : null
      }
    >
      {!hasData ? (
        <MonoEmpty>no verdicts resolved yet.</MonoEmpty>
      ) : (
        <div className="flex flex-col" style={{ gap: 6 }}>
          {buckets.map((b) => (
            <StatBar
              key={b.key}
              label={b.label}
              color={toneColor(VERDICT_TONE[b.key])}
              value={b.count}
              max={max}
            />
          ))}
        </div>
      )}
    </WindowPanel>
  );
}

function GroupFindingDistribution({
  title,
  groups,
}: {
  title: string;
  groups: GroupBucket[];
}) {
  const max = groups.reduce((m, g) => Math.max(m, g.findings), 0);
  const hasData = groups.some((g) => g.findings > 0);
  return (
    <WindowPanel title={title} tone="warn">
      {!hasData ? (
        <MonoEmpty>no group breakdown yet.</MonoEmpty>
      ) : (
        <div className="flex flex-col" style={{ gap: 6 }}>
          {groups.map((g) => (
            <StatBar
              key={g.group}
              label={g.group}
              color={toneColor("critical")}
              value={g.findings}
              max={max}
            />
          ))}
        </div>
      )}
    </WindowPanel>
  );
}

function AuditAggregateAnalytics({ targetId }: { targetId: string }) {
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
      .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0] ??
    null;

  const apkStaticParent =
    investigations
      .filter(
        (inv) =>
          (inv.kind as string) === "apk_static_audit" &&
          inv.parent_investigation_id == null,
      )
      .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0] ??
    null;

  const { data: masvsAgg } = useMasvsAuditAggregate(
    targetId,
    masvsParent?.id ?? null,
  );
  const { data: apkStaticAgg } = useApkStaticAuditAggregate(
    targetId,
    apkStaticParent?.id ?? null,
  );

  if (isLoadingInvs) return null;
  if (masvsParent == null && apkStaticParent == null) return null;

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <SectionHeader icon="\u25a4" title="analytics" size={18} />
      <p
        className="font-mono"
        style={{
          fontSize: 10.5,
          color: "var(--text-muted)",
          lineHeight: 1.55,
          marginTop: -6,
        }}
      >
        verdict distribution across masvs controls and apk static checks, plus
        per-group finding density. updates live as child investigations resolve.
      </p>

      {masvsAgg && (
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
            gap: 12,
          }}
        >
          <VerdictDistribution
            title={`masvs verdicts (${masvsAgg.verdicts.length})`}
            buckets={_buildVerdictBuckets(masvsAgg.verdicts)}
            spec={masvsAgg.masvs_spec_version}
          />
          <GroupFindingDistribution
            title="masvs findings by group"
            groups={_buildGroupBuckets(masvsAgg.verdicts)}
          />
        </div>
      )}

      {apkStaticAgg && (
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
            gap: 12,
          }}
        >
          <VerdictDistribution
            title={`apk static verdicts (${apkStaticAgg.verdicts.length})`}
            buckets={_buildVerdictBuckets(apkStaticAgg.verdicts)}
            spec={apkStaticAgg.apk_static_spec_version}
          />
          <GroupFindingDistribution
            title="apk static findings by group"
            groups={_buildGroupBuckets(apkStaticAgg.verdicts)}
          />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Function ranking table
// ---------------------------------------------------------------------------

const RANK_COLUMNS: GridColumn[] = [
  { label: "#", width: "40px", align: "right" },
  { label: "function", width: "minmax(0, 2fr)" },
  { label: "score", width: "70px", align: "right" },
  { label: "reasons", width: "minmax(0, 1.4fr)" },
];

function FunctionRankingPanel({
  ranking,
}: {
  ranking: FunctionRanking;
}) {
  const rows = (ranking.top_k ?? []).slice(0, 50);
  const statusFooter = ranking.produced_at ? (
    <span>
      produced_at: {formatDate(ranking.produced_at)}
      {ranking.source ? ` \u00b7 source: ${ranking.source}` : ""}
    </span>
  ) : null;

  if (rows.length === 0) {
    return (
      <WindowPanel title="function ranking" tone="muted" status={statusFooter}>
        <MonoEmpty>
          no ranking yet. click "rank functions" above to trigger the reranker.
        </MonoEmpty>
      </WindowPanel>
    );
  }

  return (
    <WindowPanel
      title={`function ranking (${rows.length} of ${ranking.total_candidates ?? 0})`}
      tone="accent"
      flush
      status={statusFooter}
    >
      <DataGrid
        columns={RANK_COLUMNS}
        rows={rows}
        getKey={(f, i) => `${f.address ?? f.file_path ?? "_"}-${i}`}
        renderCells={(f, i) => [
          <span style={{ color: "var(--text-faint)", fontSize: 10.5 }}>
            {f.rank ?? i + 1}
          </span>,
          <div style={{ minWidth: 0 }}>
            <span style={{ color: "var(--text-primary)", fontSize: 11 }}>
              {f.name ?? "<unnamed>"}
            </span>
            {f.address && (
              <span
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10,
                  marginLeft: 8,
                }}
              >
                @ {f.address}
              </span>
            )}
            {f.file_path && (
              <div
                style={{
                  color: "var(--text-muted)",
                  fontSize: 9.5,
                  marginTop: 2,
                  overflowWrap: "anywhere",
                }}
              >
                {f.file_path}
                {f.line != null ? `:${f.line}` : ""}
              </div>
            )}
          </div>,
          <span style={{ color: "var(--text-primary)", fontSize: 10.5 }}>
            {f.score?.toFixed(2) ?? "--"}
          </span>,
          <span
            style={{
              color: "var(--text-muted)",
              fontSize: 10,
              overflowWrap: "anywhere",
            }}
          >
            {(f.reasons ?? []).join("; ")}
          </span>,
        ]}
      />
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Top-level page
// ---------------------------------------------------------------------------

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
    subtitle: target
      ? workspaceName
        ? `${workspaceName} \u00b7 ${target.kind.replace(/_/g, " ")}`
        : target.kind.replace(/_/g, " ")
      : undefined,
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
    return (
      <WindowPanel title="target" tone="muted">
        <LoadingSkeleton size="lg" width="full" />
      </WindowPanel>
    );
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

  const isApk =
    target.kind === "android_apk" &&
    !!target.apk_overview?.static_summary &&
    Object.keys(target.apk_overview.static_summary).length > 0;
  const packageLabel = isApk
    ? typeof target.apk_overview!.static_summary!.package === "string"
      ? (target.apk_overview!.static_summary!.package as string)
      : target.android_package_name ?? null
    : null;

  const headerActions = (
    <div className="flex items-center" style={{ gap: 8, flexWrap: "wrap" }}>
      {target.analysis_state === "failed" && (
        <HeaderButton
          label={resumeAnalysisMut.isPending ? "resuming\u2026" : "resume"}
          onClick={() => resumeAnalysisMut.mutate()}
          disabled={resumeAnalysisMut.isPending}
          title="Reset any FAILED stages back to PENDING and re-enqueue the ingest \u2192 profile \u2192 ranking pipeline. Stages already DONE are skipped."
        />
      )}
      {(target.analysis_state === "failed" ||
        target.analysis_state === "ready") && (
        <HeaderButton
          label={analyzeMut.isPending ? "re-analyzing\u2026" : "re-analyze"}
          onClick={() => analyzeMut.mutate()}
          disabled={analyzeMut.isPending}
        />
      )}
      {target.analysis_state === "ready" && (
        <HeaderButton
          label={rankMut.isPending ? "ranking\u2026" : "rank functions"}
          onClick={() => rankMut.mutate()}
          disabled={rankMut.isPending}
          primary
        />
      )}
      <DeleteButton
        id={target.id}
        label={`target "${target.display_name}"`}
        mutation={deleteMut}
        onDeleted={() => navigate("/vr/targets")}
      />
    </div>
  );

  const primaryLangTone: Tone = "info";

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <h2 className="sr-only">Target sections</h2>
      <SectionHeader
        icon="\u25c8"
        title={target.display_name}
        actions={headerActions}
      />

      <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
        <MonoBadge tone={analysisTone[target.analysis_state]}>
          {analysisLabel(target.analysis_state, target.kind)}
        </MonoBadge>
        <MonoBadge tone={statusTone[target.status] ?? "muted"}>
          {target.status}
        </MonoBadge>
        <MonoBadge tone="muted">
          kind {target.kind.replace(/_/g, " ")}
        </MonoBadge>
        {workspaceName && (
          <MonoBadge tone="muted">ws {workspaceName}</MonoBadge>
        )}
        {target.primary_language && (
          <MonoBadge tone={primaryLangTone}>{target.primary_language}</MonoBadge>
        )}
      </div>

      {(target.analysis_state_message || target.analysis_state === "ingesting") && (
        <WindowPanel
          title="analysis message"
          tone={target.analysis_state === "failed" ? "warn" : "muted"}
        >
          {target.analysis_state_message && (
            <p
              className="font-mono"
              style={{
                fontSize: 11,
                color:
                  target.analysis_state === "failed"
                    ? "var(--accent)"
                    : "var(--text-primary)",
                lineHeight: 1.55,
                overflowWrap: "anywhere",
              }}
            >
              {target.analysis_state_message}
            </p>
          )}
          {target.analysis_state === "ingesting" && (
            <p
              className="font-mono"
              style={{
                marginTop: target.analysis_state_message ? 6 : 0,
                fontSize: 10.5,
                color: "var(--text-muted)",
              }}
            >
              started{" "}
              {target.analysis_started_at
                ? new Date(target.analysis_started_at).toLocaleTimeString()
                : "--"}
              . this usually takes 30s\u201310min depending on artifact size.
            </p>
          )}
        </WindowPanel>
      )}

      {UPLOADABLE_KINDS[target.kind] && (
        <WindowPanel
          title="binary artifact"
          tone="info"
          status={
            target.uploaded_filename ? (
              <span>
                current:{" "}
                <span style={{ color: "var(--text-primary)" }}>
                  {target.uploaded_filename}
                </span>
              </span>
            ) : null
          }
        >
          <p
            className="font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              lineHeight: 1.55,
              marginBottom: 10,
            }}
          >
            upload the {target.kind.replace(/_/g, " ")} from your workstation.
            aila streams it to the ida mcp (no copy stays on the platform) and
            re-runs analysis.
          </p>
          <UploadDropzone
            onFile={(f) => uploadMut.mutate(f)}
            disabled={uploadMut.isPending}
            hint={
              uploadMut.isPending
                ? "uploading\u2026"
                : target.uploaded_filename
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
        </WindowPanel>
      )}

      <WindowPanel title="capability profile" tone="accent">
        {target.analysis_state !== "ready" ? (
          <MonoEmpty>available once analysis completes.</MonoEmpty>
        ) : (
          <div
            className="grid"
            style={{
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: "0 20px",
            }}
          >
            <BriefRow label="applicable mcp servers">
              {applicableMcp.length > 0 ? applicableMcp.join(", ") : "--"}
            </BriefRow>
            <BriefRow label="applicable fuzzing engines">
              {applicableEngines.length > 0
                ? applicableEngines.join(", ")
                : "--"}
            </BriefRow>
            <BriefRow label="applicable strategies">
              {applicableStrategies.length > 0
                ? applicableStrategies.join(", ")
                : "--"}
            </BriefRow>
            <BriefRow label="default disclosure tracks">
              {defaultDisclosure.length > 0
                ? defaultDisclosure.join(", ")
                : "--"}
            </BriefRow>
            <BriefRow label="default reasoning strategy">
              {(capability.default_reasoning_strategy as string) ?? "--"}
            </BriefRow>
            <BriefRow label="est. cost / investigation">
              $
              {(capability.estimated_cost_per_investigation_usd as number) ??
                "--"}
            </BriefRow>
          </div>
        )}
      </WindowPanel>

      <TargetConnectedCard target={target} />

      {target.kind === "android_apk" && target.apk_overview && (
        <AndroidApkOverview overview={target.apk_overview} />
      )}

      {isApk && (
        <>
          <ApkStaticAuditCard
            targetId={target.id}
            packageLabel={packageLabel}
          />
          <MasvsAuditCard targetId={target.id} packageLabel={packageLabel} />
          <MasvsProgressCard
            targetId={target.id}
            packageLabel={packageLabel}
          />
          <MasvsReportCard targetId={target.id} packageLabel={packageLabel} />
          <MasvsControlTable
            targetId={target.id}
            packageLabel={packageLabel}
          />
          <AuditAggregateAnalytics targetId={target.id} />
        </>
      )}

      {target.analysis_state === "ready" && (
        <WindowPanel title="mitigations" tone="info">
          <MitigationsRibbon mitigations={mitigations} />
        </WindowPanel>
      )}

      {target.analysis_state === "ready" && (
        <Fragment>
          <Segmented<TargetTab>
            options={TARGET_TABS.map((t) => ({
              value: t.value,
              label: t.label,
            }))}
            value={activeTab}
            onChange={setActiveTab}
          />
          {activeTab === "functions" && (
            <FunctionRankingPanel ranking={ranking} />
          )}
          {activeTab === "attack_surface" && (
            <AttackSurfaceTab capability={capability} />
          )}
          {activeTab === "hypotheses" && (
            <HypothesesTab targetId={target.id} />
          )}
          {activeTab === "imports" && (
            <ImportsExportsTab capability={capability} />
          )}
          {activeTab === "notes" && <NotesTab targetId={target.id} />}
        </Fragment>
      )}

      <WindowPanel title="operator-supplied descriptor" tone="muted">
        <details>
          <summary
            className="font-mono uppercase"
            style={{
              fontSize: 10,
              letterSpacing: "0.1em",
              color: "var(--text-muted)",
              cursor: "pointer",
            }}
          >
            show descriptor json
          </summary>
          <pre
            className="font-mono"
            style={{
              marginTop: 10,
              padding: 12,
              fontSize: 11,
              lineHeight: 1.5,
              color: "var(--text-primary)",
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              borderRadius: 3,
              overflow: "auto",
              maxHeight: 400,
              whiteSpace: "pre",
            }}
          >
            {JSON.stringify(target.descriptor, null, 2)}
          </pre>
        </details>
      </WindowPanel>
    </div>
  );
}
