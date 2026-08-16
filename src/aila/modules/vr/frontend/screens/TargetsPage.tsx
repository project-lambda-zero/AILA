import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/csr/ArrowsClockwise";
import { DeviceMobile } from "@phosphor-icons/react/dist/csr/DeviceMobile";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  FilterChip,
  MonoBadge,
  SectionHeader,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
import { SavedViews } from "../components/SavedViews";
import {
  useCreateTarget,
  useDeleteTarget,
  useRefreshTargetSource,
  useUploadApkTarget,
  useUploadArtifactByTargetId,
} from "../mutations";
import { useTargets, useWorkspaces } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type {
  AnalysisState,
  TargetKind,
  TargetStatus,
  VRTargetSummary,
} from "../types";

// ─────────────────────────────────────────────────────────────────────
// Descriptor schema (unchanged from prior file). Each kind lists the
// text / file inputs its create form needs. android_apk goes through
// the dedicated /vr/targets/upload-apk multipart endpoint; every
// other binary kind chains POST /vr/targets → POST /vr/targets/{id}/upload.
// ─────────────────────────────────────────────────────────────────────
interface DescriptorField {
  key: string;
  label: string;
  placeholder?: string;
  required?: boolean;
  type: "text" | "file";
  accept?: string;
}

const DESCRIPTOR_SCHEMA: Record<TargetKind, DescriptorField[]> = {
  native_binary: [
    { key: "file", label: "Binary file", type: "file", required: true },
  ],
  android_apk: [
    { key: "file", label: "APK file", type: "file", required: true,
      accept: ".apk,application/vnd.android.package-archive" },
  ],
  ipa: [
    { key: "file", label: "IPA file", type: "file", required: true,
      accept: ".ipa" },
  ],
  jar: [
    { key: "file", label: "JAR file", type: "file", required: true,
      accept: ".jar" },
  ],
  dotnet_assembly: [
    { key: "file", label: "DLL / .NET assembly", type: "file", required: true,
      accept: ".dll,.exe" },
  ],
  kernel_image: [
    { key: "file", label: "Kernel image (vmlinuz / bzImage)", type: "file", required: true },
    { key: "kernel_version", label: "Kernel version", placeholder: "6.10", type: "text" },
    { key: "arch", label: "Arch", placeholder: "x86_64", type: "text" },
  ],
  kernel_module: [
    { key: "file", label: "Kernel module (.ko)", type: "file", required: true,
      accept: ".ko" },
    { key: "module_name", label: "Module name", placeholder: "buggy", type: "text" },
  ],
  hypervisor_image: [
    { key: "file", label: "Hypervisor binary", type: "file", required: true },
    { key: "hypervisor_kind", label: "Hypervisor kind", placeholder: "qemu", type: "text" },
    { key: "version", label: "Version", placeholder: "9.1.0", type: "text" },
  ],
  protocol_capture: [
    { key: "file", label: "PCAP file", type: "file", required: true,
      accept: ".pcap,.pcapng" },
    { key: "protocol", label: "Protocol", placeholder: "http", type: "text" },
  ],
  crash_input: [
    { key: "file", label: "Crash input file", type: "file", required: true },
  ],
  source_repo: [
    { key: "repo_url", label: "Repo URL", placeholder: "https://github.com/owner/repo", type: "text", required: true },
    { key: "ref", label: "Ref", placeholder: "main", type: "text" },
  ],
  cve: [
    { key: "cve_id", label: "CVE ID", placeholder: "CVE-YYYY-NNNN", type: "text", required: true },
  ],
  patch_diff: [
    { key: "repo_url", label: "Repo URL", placeholder: "https://github.com/owner/repo", type: "text", required: true },
    { key: "vulnerable_ref", label: "Vulnerable ref", placeholder: "abc123", type: "text", required: true },
    { key: "patched_ref", label: "Patched ref", placeholder: "def456", type: "text", required: true },
  ],
};

function kindRequiresFile(kind: TargetKind): boolean {
  return DESCRIPTOR_SCHEMA[kind].some((f) => f.type === "file");
}

const TARGET_KINDS: TargetKind[] = [
  "native_binary",
  "source_repo",
  "cve",
  "protocol_capture",
  "crash_input",
  "patch_diff",
  "android_apk",
  "ipa",
  "jar",
  "dotnet_assembly",
  "kernel_image",
  "kernel_module",
  "hypervisor_image",
];

const STATUS_ORDER: TargetStatus[] = ["active", "archived", "quarantined"];
const ANALYSIS_ORDER: AnalysisState[] = [
  "pending",
  "ingesting",
  "ready",
  "failed",
];

// MonoBadge tone map. Translation of the prior severity-key palette
// into mock tone keys: low → ok, everything else identity.
const statusTone: Record<TargetStatus, string> = {
  active: "ok",
  archived: "info",
  quarantined: "high",
};

const analysisTone: Record<AnalysisState, string> = {
  pending: "info",
  ingesting: "medium",
  ready: "ok",
  failed: "critical",
};

function analysisLabel(state: AnalysisState): string {
  return state === "pending"
    ? "queued"
    : state === "ingesting"
      ? "analyzing"
      : state === "ready"
        ? "ready"
        : "failed";
}

function formatDate(value?: string | null): string {
  if (!value) return "--";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

// Per-kind icon glyph. android_apk shows the phone icon; every other
// kind returns null so the column stays compact.
function KindIcon({ kind }: { kind: TargetKind }) {
  if (kind === "android_apk") {
    return (
      <DeviceMobile
        aria-label="Android APK"
        weight="duotone"
        style={{
          width: 12,
          height: 12,
          marginRight: 6,
          verticalAlign: -1,
          color: "var(--text-muted)",
        }}
      />
    );
  }
  return null;
}

// Row label: android_apk targets display their discovered package
// name once STATIC_SUMMARY has landed; falls back to display_name
// otherwise.
function targetRowLabel(t: VRTargetSummary): string {
  if (t.kind === "android_apk" && t.android_package_name) {
    return t.android_package_name;
  }
  return t.display_name;
}

// Mock chrome for raw <input>/<select> controls -- keeps the filter
// shelf visually coherent with FilterChip / Segmented.
const CTRL: React.CSSProperties = {
  height: 26,
  padding: "0 8px",
  fontSize: 10.5,
  letterSpacing: "0.06em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
  outline: "none",
};

export function TargetsPage() {
  const navigate = useNavigate();
  useVRListInvalidation("targets");
  const { data: workspacesResult } = useWorkspaces();
  const workspaces = workspacesResult?.data ?? [];

  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const { data: result, isLoading, isError } = useTargets({
    workspaceId: workspaceFilter || undefined,
  });

  const createMut = useCreateTarget();
  const uploadApkMut = useUploadApkTarget();
  const uploadArtifactMut = useUploadArtifactByTargetId();
  const deleteMut = useDeleteTarget();
  const [showForm, setShowForm] = useState(false);
  const [formWorkspaceId, setFormWorkspaceId] = useState("");
  const [formDisplayName, setFormDisplayName] = useState("");
  const [formKind, setFormKind] = useState<TargetKind>("source_repo");
  // Per-text-field descriptor values keyed by field.key. Reset on kind
  // change. Submit handler assembles them into the descriptor object.
  const [descriptorValues, setDescriptorValues] = useState<Record<string, string>>({});
  // Single shared file-picker state (each kind has at most one file
  // field; kind change resets it).
  const [pickedFile, setPickedFile] = useState<File | null>(null);
  // Chained-upload progress message when create→upload runs.
  const [chainMessage, setChainMessage] = useState<string | null>(null);

  function assembleDescriptor(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const field of DESCRIPTOR_SCHEMA[formKind]) {
      if (field.type !== "text") continue;
      const v = (descriptorValues[field.key] ?? "").trim();
      if (v) out[field.key] = v;
    }
    return out;
  }

  function descriptorValid(): boolean {
    return DESCRIPTOR_SCHEMA[formKind]
      .filter((f) => f.required)
      .every((f) =>
        f.type === "file"
          ? pickedFile !== null
          : (descriptorValues[f.key] ?? "").trim().length > 0,
      );
  }

  function resetForm() {
    setShowForm(false);
    setFormDisplayName("");
    setDescriptorValues({});
    setPickedFile(null);
    setChainMessage(null);
  }

  const targets = result?.data ?? [];

  // /vr/targets has no `q` server-side param -- quick-filter runs
  // client-side over display_name / kind / language / android package.
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"" | TargetStatus>("");
  const [analysisFilter, setAnalysisFilter] = useState<"" | AnalysisState>("");
  const [androidOnly, setAndroidOnly] = useState(false);
  const [readyOnly, setReadyOnly] = useState(false);

  const workspaceMap = useMemo(
    () => new Map(workspaces.map((w) => [w.id, w])),
    [workspaces],
  );

  const filteredTargets = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let rows: VRTargetSummary[] = targets;
    if (needle) {
      rows = rows.filter(
        (t) =>
          (t.display_name ?? "").toLowerCase().includes(needle) ||
          t.kind.toLowerCase().includes(needle) ||
          (t.primary_language ?? "").toLowerCase().includes(needle) ||
          (t.android_package_name ?? "").toLowerCase().includes(needle) ||
          t.status.toLowerCase().includes(needle) ||
          t.analysis_state.toLowerCase().includes(needle) ||
          targetRowLabel(t).toLowerCase().includes(needle),
      );
    }
    if (statusFilter) rows = rows.filter((t) => t.status === statusFilter);
    if (analysisFilter)
      rows = rows.filter((t) => t.analysis_state === analysisFilter);
    if (androidOnly) rows = rows.filter((t) => t.kind === "android_apk");
    if (readyOnly) rows = rows.filter((t) => t.analysis_state === "ready");
    return rows;
  }, [targets, query, statusFilter, analysisFilter, androidOnly, readyOnly]);

  // Saved-view round-trip. Stable key order so a saved view compares
  // equal against aria-pressed on the same state a second later.
  const currentViewJson = JSON.stringify({
    v: 1,
    q: query,
    workspace: workspaceFilter,
    status: statusFilter,
    analysis: analysisFilter,
    androidOnly,
    readyOnly,
  });

  function applyView(filterJson: string) {
    try {
      const p = JSON.parse(filterJson) as {
        q?: unknown;
        workspace?: unknown;
        status?: unknown;
        analysis?: unknown;
        androidOnly?: unknown;
        readyOnly?: unknown;
      };
      setQuery(typeof p.q === "string" ? p.q : "");
      setWorkspaceFilter(typeof p.workspace === "string" ? p.workspace : "");
      setStatusFilter(
        typeof p.status === "string" &&
          (STATUS_ORDER as string[]).includes(p.status)
          ? (p.status as TargetStatus)
          : "",
      );
      setAnalysisFilter(
        typeof p.analysis === "string" &&
          (ANALYSIS_ORDER as string[]).includes(p.analysis)
          ? (p.analysis as AnalysisState)
          : "",
      );
      setAndroidOnly(p.androidOnly === true);
      setReadyOnly(p.readyOnly === true);
    } catch {
      // Malformed view -- ignore rather than blank the operator's screen.
    }
  }

  const hasActiveFilters =
    !!query ||
    !!workspaceFilter ||
    !!statusFilter ||
    !!analysisFilter ||
    androidOnly ||
    readyOnly;

  // ─── Header actions: workspace select + create toggle ───
  const headerActions = (
    <div className="flex items-center" style={{ gap: 8 }}>
      <select
        value={workspaceFilter}
        onChange={(e) => setWorkspaceFilter(e.target.value)}
        aria-label="Filter workspace"
        title="Filter by workspace"
        className="font-mono uppercase"
        style={CTRL}
      >
        <option value="">all workspaces</option>
        {workspaces
          .slice()
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((ws) => (
            <option key={ws.id} value={ws.id}>
              {ws.name}
            </option>
          ))}
      </select>
      <button
        type="button"
        onClick={() => setShowForm((v) => !v)}
        disabled={workspaces.length === 0}
        title={workspaces.length === 0 ? "Create a workspace first" : ""}
        className="font-mono uppercase"
        style={{
          height: 28,
          padding: "0 12px",
          fontSize: 10,
          letterSpacing: "0.08em",
          background: showForm ? "var(--surface-sunk)" : "var(--accent)",
          border:
            "1px solid " +
            (showForm ? "var(--border-soft)" : "var(--accent)"),
          color: showForm
            ? "var(--text-primary)"
            : "var(--text-on-accent)",
          borderRadius: 3,
          cursor: workspaces.length === 0 ? "not-allowed" : "pointer",
          opacity: workspaces.length === 0 ? 0.5 : 1,
        }}
      >
        {showForm ? "cancel" : "+ new target"}
      </button>
    </div>
  );

  // ─── Create form (mock language) ───
  const createFormPanel =
    showForm && workspaces.length > 0 ? (
      <WindowPanel title="create target" tone="accent">
        <div className="flex flex-col" style={{ gap: 10 }}>
          <div
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            fill the kind-specific fields below. backend handles all
            MCP-internal IDs transparently. analysis runs automatically
            after create.
          </div>

          <select
            value={formWorkspaceId}
            onChange={(e) => setFormWorkspaceId(e.target.value)}
            aria-label="Workspace"
            className="font-mono uppercase"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          >
            <option value="">-- select workspace --</option>
            {workspaces.map((ws) => (
              <option key={ws.id} value={ws.id}>
                {ws.name} ({ws.slug})
              </option>
            ))}
          </select>

          <input
            type="text"
            value={formDisplayName}
            onChange={(e) => setFormDisplayName(e.target.value)}
            placeholder="display name"
            aria-label="Display name"
            className="font-mono"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          />

          <select
            value={formKind}
            onChange={(e) => {
              const newKind = e.target.value as TargetKind;
              setFormKind(newKind);
              setDescriptorValues({});
              setPickedFile(null);
            }}
            aria-label="Target kind"
            className="font-mono uppercase"
            style={{ ...CTRL, height: 30, fontSize: 11 }}
          >
            {TARGET_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>

          {/* Schema-driven field rendering: file picker for type=file,
              text input for type=text. Per-kind labels + accept hints
              come from DESCRIPTOR_SCHEMA. No raw paths anywhere. */}
          <div className="flex flex-col" style={{ gap: 8 }}>
            {DESCRIPTOR_SCHEMA[formKind].map((field) => {
              const labelText = (
                <label
                  htmlFor={`descriptor-${field.key}`}
                  className="font-mono uppercase"
                  style={{
                    display: "block",
                    fontSize: 9.5,
                    letterSpacing: "0.1em",
                    color: "var(--text-muted)",
                  }}
                >
                  {field.label}
                  {field.required ? (
                    <span style={{ color: "var(--accent)" }}> *</span>
                  ) : null}
                </label>
              );
              if (field.type === "file") {
                return (
                  <div
                    key={field.key}
                    className="flex flex-col"
                    style={{ gap: 4 }}
                  >
                    {labelText}
                    <input
                      id={`descriptor-${field.key}`}
                      type="file"
                      accept={field.accept}
                      onChange={(e) => {
                        const f = e.target.files?.[0] ?? null;
                        setPickedFile(f);
                        // Auto-route: an .apk picked into any binary-kind
                        // slot is almost always a misclick. Force-switch
                        // to android_apk so the 5-stage pipeline fires
                        // instead of IDA grinding through a ZIP.
                        if (
                          f &&
                          formKind !== "android_apk" &&
                          f.name.toLowerCase().endsWith(".apk")
                        ) {
                          setFormKind("android_apk");
                          setDescriptorValues({});
                        }
                      }}
                      aria-label={field.label}
                      className="font-mono"
                      style={{
                        fontSize: 10.5,
                        color: "var(--text-muted)",
                        padding: 4,
                        background: "var(--surface-sunk)",
                        border: "1px solid var(--border-soft)",
                        borderRadius: 3,
                      }}
                    />
                    {pickedFile ? (
                      <div
                        className="font-mono"
                        style={{
                          fontSize: 10,
                          color: "var(--text-muted)",
                          letterSpacing: "0.04em",
                        }}
                      >
                        {pickedFile.name} (
                        {(pickedFile.size / (1024 * 1024)).toFixed(1)} MB)
                      </div>
                    ) : null}
                  </div>
                );
              }
              return (
                <div
                  key={field.key}
                  className="flex flex-col"
                  style={{ gap: 4 }}
                >
                  {labelText}
                  <input
                    id={`descriptor-${field.key}`}
                    type="text"
                    value={descriptorValues[field.key] ?? ""}
                    onChange={(e) =>
                      setDescriptorValues((prev) => ({
                        ...prev,
                        [field.key]: e.target.value,
                      }))
                    }
                    placeholder={field.placeholder}
                    aria-label={field.label}
                    className="font-mono"
                    style={{ ...CTRL, height: 28, fontSize: 11 }}
                  />
                </div>
              );
            })}
          </div>

          {formKind === "android_apk" ? (
            <div
              className="font-mono"
              style={{
                fontSize: 10,
                color: "var(--text-faint)",
                letterSpacing: "0.06em",
              }}
            >
              backend pipeline: APK_DECODE → JADX_DECOMPILE →
              INDEX_DECOMPILED → STATIC_SUMMARY.
            </div>
          ) : null}

          {chainMessage ? (
            <div
              className="font-mono"
              style={{
                fontSize: 10.5,
                color: "var(--accent)",
                letterSpacing: "0.04em",
              }}
            >
              {chainMessage}
            </div>
          ) : null}

          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              disabled={
                !formWorkspaceId ||
                !formDisplayName.trim() ||
                !descriptorValid() ||
                createMut.isPending ||
                uploadApkMut.isPending ||
                uploadArtifactMut.isPending
              }
              onClick={async () => {
                // android_apk: dedicated single-shot multipart endpoint.
                if (formKind === "android_apk") {
                  if (!pickedFile) return;
                  uploadApkMut.mutate(
                    {
                      workspace_id: formWorkspaceId,
                      display_name: formDisplayName.trim(),
                      file: pickedFile,
                    },
                    {
                      onSuccess: (r) => {
                        resetForm();
                        navigate(`/vr/targets/${r.data.id}`);
                      },
                    },
                  );
                  return;
                }

                // URL-only kinds (source_repo / cve / patch_diff):
                // single POST /vr/targets with descriptor.
                if (!kindRequiresFile(formKind)) {
                  createMut.mutate(
                    {
                      workspace_id: formWorkspaceId,
                      display_name: formDisplayName.trim(),
                      kind: formKind,
                      descriptor: assembleDescriptor(),
                    },
                    {
                      onSuccess: (r) => {
                        resetForm();
                        navigate(`/vr/targets/${r.data.id}`);
                      },
                    },
                  );
                  return;
                }

                // Binary kinds with file: create-then-upload chain.
                if (!pickedFile) return;
                setChainMessage("creating target…");
                try {
                  const createResult = await createMut.mutateAsync({
                    workspace_id: formWorkspaceId,
                    display_name: formDisplayName.trim(),
                    kind: formKind,
                    descriptor: assembleDescriptor(),
                  });
                  const targetId = createResult.data.id;
                  setChainMessage(
                    `uploading ${pickedFile.name} (${(pickedFile.size / (1024 * 1024)).toFixed(1)} MB)…`,
                  );
                  await uploadArtifactMut.mutateAsync({
                    target_id: targetId,
                    file: pickedFile,
                  });
                  resetForm();
                  navigate(`/vr/targets/${targetId}`);
                } catch (err) {
                  setChainMessage(
                    `failed: ${err instanceof Error ? err.message : String(err)}`,
                  );
                }
              }}
              className="font-mono uppercase"
              style={{
                marginLeft: "auto",
                height: 28,
                padding: "0 14px",
                fontSize: 10,
                letterSpacing: "0.08em",
                background: "var(--accent)",
                border: "1px solid var(--accent)",
                color: "var(--text-on-accent)",
                borderRadius: 3,
                cursor:
                  createMut.isPending ||
                  uploadApkMut.isPending ||
                  uploadArtifactMut.isPending
                    ? "wait"
                    : "pointer",
                opacity:
                  createMut.isPending ||
                  uploadApkMut.isPending ||
                  uploadArtifactMut.isPending
                    ? 0.7
                    : 1,
              }}
            >
              {uploadApkMut.isPending
                ? "uploading apk…"
                : uploadArtifactMut.isPending
                  ? "uploading…"
                  : createMut.isPending
                    ? "creating…"
                    : formKind === "android_apk"
                      ? "upload apk"
                      : kindRequiresFile(formKind)
                        ? "create + upload"
                        : "create target"}
            </button>
          </div>
        </div>
      </WindowPanel>
    ) : null;

  // ─── Filter shelf ───
  const filterPanel = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="search (name / kind / language / package)…"
            aria-label="Filter targets"
            className="font-mono"
            style={{ ...CTRL, width: 280 }}
          />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as "" | TargetStatus)}
            aria-label="Filter by status"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all status</option>
            {STATUS_ORDER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={analysisFilter}
            onChange={(e) =>
              setAnalysisFilter(e.target.value as "" | AnalysisState)
            }
            aria-label="Filter by analysis state"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all analysis</option>
            {ANALYSIS_ORDER.map((s) => (
              <option key={s} value={s}>
                {analysisLabel(s)}
              </option>
            ))}
          </select>
          <FilterChip
            active={androidOnly}
            color="var(--status-ok)"
            onClick={() => setAndroidOnly((v) => !v)}
          >
            android only
          </FilterChip>
          <FilterChip
            active={readyOnly}
            color="var(--status-info)"
            onClick={() => setReadyOnly((v) => !v)}
          >
            ready only
          </FilterChip>
          {hasActiveFilters ? (
            <FilterChip
              active={false}
              onClick={() => {
                setQuery("");
                setStatusFilter("");
                setAnalysisFilter("");
                setAndroidOnly(false);
                setReadyOnly(false);
              }}
            >
              ✕ clear
            </FilterChip>
          ) : null}
        </div>
        <div style={{ minHeight: 26 }}>
          <SavedViews
            entityType="vr_target"
            entityLabel="targets"
            currentFilterJson={currentViewJson}
            onApply={applyView}
          />
        </div>
      </div>
    </WindowPanel>
  );

  // ─── Table cells ───
  const columns = [
    { label: "name", width: "1.6fr" },
    { label: "workspace", width: "140px" },
    { label: "kind", width: "130px" },
    { label: "status", width: "100px" },
    { label: "analysis", width: "110px" },
    { label: "analyzed at", width: "160px", align: "right" as const },
    { label: "surface", width: "110px" },
    { label: "", width: "72px", align: "right" as const },
  ];

  function renderCells(t: VRTargetSummary): React.ReactNode[] {
    const ws = workspaceMap.get(t.workspace_id);
    const wsName = ws?.name ?? "--";
    return [
      <span
        className="font-mono"
        title={t.display_name}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        <KindIcon kind={t.kind} />
        {targetRowLabel(t)}
      </span>,
      <span
        className="font-mono"
        title={wsName}
        style={{
          fontSize: 10.5,
          color: "var(--text-muted)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {wsName}
      </span>,
      <MonoBadge tone="muted">{t.kind}</MonoBadge>,
      <MonoBadge tone={statusTone[t.status] ?? "muted"}>{t.status}</MonoBadge>,
      <MonoBadge tone={analysisTone[t.analysis_state] ?? "muted"}>
        {analysisLabel(t.analysis_state)}
      </MonoBadge>,
      <span
        className="font-mono"
        style={{
          fontSize: 10,
          color: "var(--text-faint)",
          whiteSpace: "nowrap",
        }}
      >
        {formatDate(t.analysis_completed_at)}
      </span>,
      <span
        className="font-mono"
        title={t.primary_language ?? ""}
        style={{
          fontSize: 10.5,
          color: "var(--text-muted)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {t.primary_language ?? "--"}
      </span>,
      <span
        onClick={(e) => e.stopPropagation()}
        className="inline-flex items-center"
        style={{ gap: 4, justifyContent: "flex-end" }}
      >
        <RefreshSourceButton
          targetId={t.id}
          kind={t.kind}
          analysisState={t.analysis_state}
        />
        <DeleteButton
          id={t.id}
          label={`target "${t.display_name}"`}
          mutation={deleteMut}
          compact
        />
      </span>,
    ];
  }

  const tableActions = (
    <span
      className="font-mono"
      style={{
        fontSize: 10,
        letterSpacing: "0.06em",
        color: "var(--text-faint)",
      }}
    >
      {filteredTargets.length}
      {filteredTargets.length !== targets.length ? (
        <span style={{ opacity: 0.5 }}> / {targets.length}</span>
      ) : null}
    </span>
  );

  let tableBody: React.ReactNode;
  if (isLoading) {
    tableBody = (
      <div style={{ padding: 12 }}>
        <LoadingSkeleton size="lg" width="full" />
      </div>
    );
  } else if (isError) {
    tableBody = (
      <div
        className="font-mono"
        style={{
          padding: 24,
          textAlign: "center",
          color: "var(--accent)",
          fontSize: 11,
          letterSpacing: "0.06em",
        }}
      >
        failed to load targets.
      </div>
    );
  } else if (targets.length === 0) {
    tableBody = (
      <div
        className="font-mono"
        style={{
          padding: 34,
          textAlign: "center",
          fontSize: 11.5,
          color: "var(--text-muted)",
          letterSpacing: "0.04em",
        }}
      >
        {workspaces.length === 0
          ? "a workspace is the precondition for a target -- create one first."
          : "no targets yet -- register a source repo or upload a binary from the header."}
      </div>
    );
  } else {
    tableBody = (
      <DataGrid<VRTargetSummary>
        columns={columns}
        rows={filteredTargets}
        renderCells={renderCells}
        getKey={(t) => t.id}
        onRowClick={(t) => navigate(`/vr/targets/${t.id}`)}
        empty={
          <div
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no targets match the current filters.
          </div>
        }
      />
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="◈" title="Targets" actions={headerActions} />
      {createFormPanel}
      {filterPanel}
      <WindowPanel
        title="targets"
        tone="accent"
        actions={tableActions}
        flush
      >
        {tableBody}
      </WindowPanel>
    </div>
  );
}

// ─── RefreshSourceButton ────────────────────────────────────────────
//
// Per-row action: re-run a target's ingestion. For git-backed kinds
// (source_repo / patch_diff / cve) this hits audit-mcp's
// refresh_index -- idempotent when upstream did not move. For
// android_apk targets it resets apktool / jadx / index-decompiled /
// static-summary stages back to PENDING and re-enqueues the staged-
// analysis worker. Only enabled when analysis_state == "ready".
// Backend returns HTTP 409 if a git-backed target lacks an
// audit_mcp_index_id; the toast surfaces that message verbatim.
//
// Shift-click forces a full rebuild even when the SHA did not change
// (use after a trailmark/semble upgrade where the on-disk format
// shifted). For android_apk the force flag is informational only --
// the staged-analysis worker always re-runs every reset stage.

const REFRESHABLE_KINDS: Partial<Record<TargetKind, true>> = {
  source_repo: true,
  patch_diff: true,
  cve: true,
  android_apk: true,
};

interface RefreshSourceButtonProps {
  targetId: string;
  kind: TargetKind;
  analysisState: AnalysisState;
}

function RefreshSourceButton({
  targetId,
  kind,
  analysisState,
}: RefreshSourceButtonProps) {
  const refreshMut = useRefreshTargetSource(targetId);
  const refreshable = REFRESHABLE_KINDS[kind] === true;
  const eligible = refreshable && analysisState === "ready";
  const isPending = refreshMut.isPending;

  const title = !eligible
    ? refreshable
      ? `refresh unavailable: analysis_state=${analysisState}`
      : `refresh unavailable: ${kind} has no refresh path`
    : kind === "android_apk"
      ? "re-run apktool / jadx / static-summary"
      : "refresh source from upstream git (shift-click = force rebuild)";

  return (
    <button
      type="button"
      title={title}
      aria-label="Refresh source from upstream"
      disabled={!eligible || isPending}
      onClick={(e) => {
        e.stopPropagation();
        const force = e.shiftKey;
        refreshMut.mutate({ force });
      }}
      className="inline-flex items-center justify-center"
      style={{
        width: 22,
        height: 22,
        borderRadius: 3,
        background: "transparent",
        border: `1px solid ${isPending ? "var(--accent)" : "var(--border-soft)"}`,
        color: isPending ? "var(--accent)" : "var(--text-muted)",
        cursor: eligible && !isPending ? "pointer" : "not-allowed",
        opacity: eligible ? 1 : 0.4,
      }}
    >
      <ArrowsClockwise
        style={{
          width: 12,
          height: 12,
          animation: isPending ? "spin 1s linear infinite" : undefined,
        }}
      />
    </button>
  );
}
