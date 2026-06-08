import { useState } from "react";
import { useNavigate } from "react-router";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/csr/ArrowsClockwise";
import { DeviceMobile } from "@phosphor-icons/react/dist/csr/DeviceMobile";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import {
  useCreateTarget,
  useDeleteTarget,
  useRefreshTargetSource,
  useUploadApkTarget,
  useUploadArtifactByTargetId,
} from "../mutations";
import { useTargets, useWorkspaces } from "../queries";
import type { AnalysisState, TargetKind, TargetStatus, VRTargetSummary } from "../types";

// Per-kind input-field schema. Each field becomes a labeled <input>
// in the create form; values get assembled into the descriptor JSON
// the backend expects. android_apk has no fields here — it uses the
// multipart upload-apk endpoint with a file picker, handled separately.
// Per-kind input-field schema. Each field is either a labeled <input>
// (type="text") or a <input type="file"> file picker. The submit
// handler assembles text fields into the descriptor JSON; file fields
// are POSTed via a follow-up call to the matching upload endpoint
// (android_apk -> /targets/upload-apk in one shot, every other binary
// kind -> create-then-upload via POST /targets + POST /targets/{id}/upload).
interface DescriptorField {
  key: string;
  label: string;
  placeholder?: string;
  required?: boolean;
  type: "text" | "file";
  accept?: string;  // for type=file: HTML accept attribute
}

const DESCRIPTOR_SCHEMA: Record<TargetKind, DescriptorField[]> = {
  // Binary kinds: file picker is the primary input. No more
  // server-side path text boxes — the operator never knew what
  // paths exist on the backend filesystem.
  native_binary: [
    { key: "file", label: "Binary file", type: "file", required: true },
  ],
  // android_apk: file picker only; routed through the dedicated
  // /targets/upload-apk endpoint that fires the 5-stage pipeline.
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
  // URL-based kinds: text only.
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

// Helper: file-required kinds (use 2-step create-then-upload OR
// dedicated upload-apk endpoint).
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

function analysisLabel(state: AnalysisState): string {
  return state === "pending"
    ? "Queued"
    : state === "ingesting"
      ? "Analyzing…"
      : state === "ready"
        ? "Ready"
        : "Failed";
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

// Per-kind icon glyph. Empty for kinds without a curated icon — keeps
// the column compact rather than padding every row with a default
// shape. `android_apk` is the first kind with its own icon; future
// kinds can extend this map without growing the row signature.
function KindIcon({ kind }: { kind: TargetKind }) {
  if (kind === "android_apk") {
    return (
      <DeviceMobile
        className="inline-block h-3.5 w-3.5 mr-1.5 text-text-muted"
        style={{ verticalAlign: -2 }}
        weight="duotone"
        aria-label="Android APK"
      />
    );
  }
  return null;
}

// Row label resolver. For `android_apk` targets, once STATIC_SUMMARY
// completes the androguard-discovered package name is the most useful
// identifier (`com.vodafone.selfservis` beats whatever the operator
// typed for `display_name`). Falls back to `display_name` for every
// other kind, and for `android_apk` rows whose static summary hasn't
// landed yet.
function targetRowLabel(t: VRTargetSummary): string {
  if (t.kind === "android_apk" && t.android_package_name) {
    return t.android_package_name;
  }
  return t.display_name;
}

export function TargetsPage() {
  const navigate = useNavigate();
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
  // Per-text-field descriptor values, keyed by the field's `key`.
  // Reset on kind change. The submit handler assembles them into the
  // descriptor object that the backend expects.
  const [descriptorValues, setDescriptorValues] = useState<Record<string, string>>({});
  // Single shared file-picker state (each kind has at most one file
  // field; kind change resets it).
  const [pickedFile, setPickedFile] = useState<File | null>(null);
  // Chained-upload progress message when create→upload runs.
  const [chainMessage, setChainMessage] = useState<string | null>(null);

  // Helper: assemble the descriptor object from per-TEXT-field values,
  // dropping empty strings so the backend's strict descriptor shape
  // doesn't reject them as "unexpected empty string". File fields are
  // NOT included here — they're posted to the matching upload endpoint
  // in the submit handler.
  function assembleDescriptor(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const field of DESCRIPTOR_SCHEMA[formKind]) {
      if (field.type !== "text") continue;
      const v = (descriptorValues[field.key] ?? "").trim();
      if (v) out[field.key] = v;
    }
    return out;
  }

  // Validation: all required fields filled? Required file fields require
  // pickedFile; required text fields require a non-empty trimmed value.
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

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          disabled={workspaces.length === 0}
          title={workspaces.length === 0 ? "Create a workspace first" : ""}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
        >
          {showForm ? "Cancel" : "New Target"}
        </button>
      </div>

      {showForm && workspaces.length > 0 && (
        <AilaCard techBorder glow>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Create target
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Fill the kind-specific fields below. Backend handles all
            MCP-internal IDs transparently. Analysis runs automatically
            after create.
          </p>
          <div className="space-y-2">
            <select
              value={formWorkspaceId}
              onChange={(e) => setFormWorkspaceId(e.target.value)}
              aria-label="Workspace"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default"
            >
              <option value="">— select workspace —</option>
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
              placeholder="Display name"
              aria-label="Display name"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
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
              className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default"
            >
              {TARGET_KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>

            {/* Schema-driven field rendering: file picker for type=file,
                text input for type=text. Per-kind labels and accept
                hints come from DESCRIPTOR_SCHEMA. No raw paths anywhere. */}
            <div className="grid grid-cols-1 gap-2">
              {DESCRIPTOR_SCHEMA[formKind].map((field) => {
                const labelText = (
                  <label
                    htmlFor={`descriptor-${field.key}`}
                    className="block text-xs text-text-muted"
                  >
                    {field.label}
                    {field.required && <span className="text-critical"> *</span>}
                  </label>
                );
                if (field.type === "file") {
                  return (
                    <div key={field.key} className="space-y-1">
                      {labelText}
                      <input
                        id={`descriptor-${field.key}`}
                        type="file"
                        accept={field.accept}
                        onChange={(e) => {
                          const f = e.target.files?.[0] ?? null;
                          setPickedFile(f);
                          // Auto-route: a .apk picked into any binary-kind
                          // slot is almost always a misclick. Force-switch
                          // to android_apk so the 5-stage pipeline fires
                          // instead of IDA grinding through a ZIP and
                          // returning "no parser-sink callsites".
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
                        className="w-full text-xs text-text-muted file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-sm file:bg-accent file:text-white hover:file:bg-accent/90 file:cursor-pointer"
                      />
                      {pickedFile && (
                        <p className="text-xs text-text-muted">
                          {pickedFile.name} (
                          {(pickedFile.size / (1024 * 1024)).toFixed(1)} MB)
                        </p>
                      )}
                    </div>
                  );
                }
                return (
                  <div key={field.key} className="space-y-1">
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
                      className="w-full px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
                    />
                  </div>
                );
              })}
            </div>

            {formKind === "android_apk" && (
              <p className="text-xs text-text-muted">
                Backend pipeline: APK_DECODE → JADX_DECOMPILE →
                INDEX_DECOMPILED → STATIC_SUMMARY → MOBSF_SCAN.
              </p>
            )}

            {chainMessage && (
              <p className="text-xs text-accent">{chainMessage}</p>
            )}

            <div className="flex gap-2">
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
                        onSuccess: (result) => {
                          resetForm();
                          navigate(`/vr/targets/${result.data.id}`);
                        },
                      },
                    );
                    return;
                  }

                  // URL-only kinds (source_repo / cve / patch_diff): single
                  // POST /vr/targets with descriptor.
                  if (!kindRequiresFile(formKind)) {
                    createMut.mutate(
                      {
                        workspace_id: formWorkspaceId,
                        display_name: formDisplayName.trim(),
                        kind: formKind,
                        descriptor: assembleDescriptor(),
                      },
                      {
                        onSuccess: (result) => {
                          resetForm();
                          navigate(`/vr/targets/${result.data.id}`);
                        },
                      },
                    );
                    return;
                  }

                  // Binary kinds with file: create-then-upload chain.
                  if (!pickedFile) return;
                  setChainMessage("Creating target…");
                  try {
                    const createResult = await createMut.mutateAsync({
                      workspace_id: formWorkspaceId,
                      display_name: formDisplayName.trim(),
                      kind: formKind,
                      descriptor: assembleDescriptor(),
                    });
                    const targetId = createResult.data.id;
                    setChainMessage(
                      `Uploading ${pickedFile.name} (${(pickedFile.size / (1024 * 1024)).toFixed(1)} MB)…`,
                    );
                    await uploadArtifactMut.mutateAsync({
                      target_id: targetId,
                      file: pickedFile,
                    });
                    resetForm();
                    navigate(`/vr/targets/${targetId}`);
                  } catch (err) {
                    setChainMessage(
                      `Failed: ${err instanceof Error ? err.message : String(err)}`,
                    );
                  }
                }}
                className="ml-auto px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
              >
                {uploadApkMut.isPending
                  ? "Uploading APK…"
                  : uploadArtifactMut.isPending
                    ? "Uploading…"
                    : createMut.isPending
                      ? "Creating…"
                      : formKind === "android_apk"
                        ? "Upload APK"
                        : kindRequiresFile(formKind)
                          ? "Create + upload"
                          : "Create target"}
              </button>
            </div>
          </div>
        </AilaCard>
      )}

      <AilaCard  techBorder glow><div className="flex items-center gap-2">
        <label htmlFor="target-workspace-filter" className="text-sm text-text-muted">Filter workspace:</label>
        <select
          id="target-workspace-filter"
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
        <span className="text-xs text-text-muted ml-auto">
          {targets.length} target{targets.length === 1 ? "" : "s"}
        </span>
      </div></AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load targets.</p></AilaCard>
      )}

      {!isLoading && !isError && targets.length === 0 && (
        <AilaCard  techBorder glow><p className="text-center py-6 text-text-muted">No targets yet.</p></AilaCard>
      )}

      {!isLoading && !isError && targets.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow><table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
              <th className="px-4 py-2 font-semibold">Name</th>
              <th className="px-4 py-2 font-semibold">Kind</th>
              <th className="px-4 py-2 font-semibold">Language</th>
              <th className="px-4 py-2 font-semibold">Status</th>
              <th className="px-4 py-2 font-semibold">Analysis</th>
              <th className="px-4 py-2 font-semibold">Analyzed at</th>
              <th className="px-4 py-2 font-semibold">Created</th>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody className="scroll-virtual-row">
            {targets.map((t) => (
              <tr
                key={t.id}
                onClick={() => navigate(`/vr/targets/${t.id}`)}
                className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
              >
                <td className="px-4 py-2 font-semibold text-foreground">
                  {targetRowLabel(t)}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  <KindIcon kind={t.kind} />
                  {t.kind}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {t.primary_language ?? "—"}
                </td>
                <td className="px-4 py-2">
                  <AilaBadge
                    severity={statusColor[t.status] ?? "info"}
                    size="sm"
                  >
                    {t.status}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2">
                  <AilaBadge
                    severity={analysisColor[t.analysis_state] ?? "info"}
                    size="sm"
                  >
                    {analysisLabel(t.analysis_state)}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {formatDate(t.analysis_completed_at)}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {formatDate(t.created_at)}
                </td>
                <td className="px-2 py-2 text-right">
                  <div className="flex items-center justify-end gap-1">
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
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table></AilaCard>
      )}
    </div>
  );
}

// ─── RefreshSourceButton ────────────────────────────────────────────
//
// Per-row action: re-run a target's ingestion. For git-backed kinds
// (source_repo / patch_diff / cve) this hits audit-mcp's refresh_index
// — idempotent when upstream did not move. For android_apk targets
// it resets the apktool / jadx / index-decompiled / static-summary /
// mobsf stages back to PENDING and re-enqueues the staged-analysis
// worker. Only enabled when analysis_state == "ready". Backend
// returns HTTP 409 if a git-backed target lacks an
// audit_mcp_index_id; the toast surfaces that message verbatim.
//
// Shift-click forces a full rebuild even when the SHA didn't change
// (use after a trailmark/semble upgrade where the on-disk format
// shifted). For android_apk the force flag is informational only —
// the staged-analysis worker always re-runs every reset stage.

const GIT_BACKED_KINDS: ReadonlySet<TargetKind> = new Set([
  "source_repo",
  "patch_diff",
  "cve",
]);

// Union with android_apk so the refresh button is enabled for APK
// targets too, with a different action path (stage reset + analyze
// re-enqueue) wired in the backend's refresh-source endpoint.
const REFRESHABLE_KINDS: ReadonlySet<TargetKind> = new Set<TargetKind>([
  ...GIT_BACKED_KINDS,
  "android_apk",
]);

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
  const eligible =
    REFRESHABLE_KINDS.has(kind) && analysisState === "ready";
  const isPending = refreshMut.isPending;

  const title = !eligible
    ? kind === "native_binary" ||
      kind === "ipa" ||
      kind === "jar" ||
      kind === "dotnet_assembly" ||
      kind === "kernel_image" ||
      kind === "kernel_module" ||
      kind === "hypervisor_image" ||
      kind === "protocol_capture" ||
      kind === "crash_input"
      ? `Refresh unavailable: ${kind} has no refresh path`
      : `Refresh unavailable: analysis_state=${analysisState}`
    : kind === "android_apk"
      ? "Re-run apktool / jadx / static-summary / mobsf"
      : "Refresh source from upstream git (shift-click = force rebuild)";

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
      className={[
        "inline-flex items-center justify-center",
        "h-6 w-6 rounded border border-border-default",
        "text-text-muted transition-colors",
        eligible
          ? "hover:border-accent hover:text-accent cursor-pointer"
          : "opacity-40 cursor-not-allowed",
        isPending ? "border-accent text-accent" : "",
      ].join(" ")}
    >
      <ArrowsClockwise
        className={`h-3.5 w-3.5 ${isPending ? "animate-spin" : ""}`}
      />
    </button>
  );
}
