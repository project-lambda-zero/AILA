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
} from "../mutations";
import { useTargets, useWorkspaces } from "../queries";
import type { AnalysisState, TargetKind, TargetStatus, VRTargetSummary } from "../types";

// Per-kind descriptor templates. Operator only provides what they
// actually know — repo URL, file path, version, arch. Backend
// (TargetAnalysisService) handles all MCP-internal ids transparently.
const DESCRIPTOR_TEMPLATES: Record<TargetKind, string> = {
  native_binary: '{"binary_path": "/path/on/workstation"}',
  source_repo: '{"repo_url": "https://github.com/owner/repo", "ref": "main"}',
  cve: '{"cve_id": "CVE-YYYY-NNNN"}',
  protocol_capture: '{"pcap_path": "/path/to/capture.pcap", "protocol": "http"}',
  crash_input: '{"crash_input_path": "/path/to/input.bin"}',
  patch_diff: '{"vulnerable_ref": "abc123", "patched_ref": "def456", "repo_url": "https://github.com/owner/repo"}',
  apk: '{"apk_path": "/path/to/app.apk"}',
  android_apk: '{"apk_path": "/path/to/app.apk"}',
  ipa: '{"ipa_path": "/path/to/app.ipa"}',
  jar: '{"jar_path": "/path/to/app.jar"}',
  dotnet_assembly: '{"dll_path": "/path/to/assembly.dll"}',
  kernel_image: '{"image_path": "/path/vmlinuz", "kernel_version": "6.10", "arch": "x86_64"}',
  kernel_module: '{"ko_path": "/path/buggy.ko", "module_name": "buggy"}',
  hypervisor_image: '{"binary_path": "/usr/bin/qemu-system-x86_64", "hypervisor_kind": "qemu", "version": "9.1.0"}',
};

const TARGET_KINDS: TargetKind[] = [
  "native_binary",
  "source_repo",
  "cve",
  "protocol_capture",
  "crash_input",
  "patch_diff",
  "apk",
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
        className="inline-block h-3.5 w-3.5 mr-1.5 text-text-muted align-[-2px]"
        weight="duotone"
        aria-label="Android APK"
      />
    );
  }
  return null;
}

// Row label resolver. For `android_apk` targets, once STATIC_SUMMARY
// completes the androguard-discovered package name is the most useful
// identifier (`com.examplecorp.selfservis` beats whatever the operator
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
  const deleteMut = useDeleteTarget();
  const [showForm, setShowForm] = useState(false);
  const [formWorkspaceId, setFormWorkspaceId] = useState("");
  const [formDisplayName, setFormDisplayName] = useState("");
  const [formKind, setFormKind] = useState<TargetKind>("native_binary");
  const [formPrimaryLanguage, setFormPrimaryLanguage] = useState("");
  const [formDescriptorJson, setFormDescriptorJson] = useState(
    '{"binary_path": "/path/on/workstation"}',
  );

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
        <AilaCard  techBorder glow><h2 className="text-sm font-semibold text-foreground mb-2">
          Create target
        </h2>
        <p className="text-xs text-text-muted mb-3">
          descriptor is kind-specific JSON.
          <br /><strong>native_binary</strong>: <code>{`{"binary_path": "/path/on/workstation"}`}</code>
          <br /><strong>source_repo</strong>: <code>{`{"repo_url": "https://github.com/owner/repo", "ref": "main"}`}</code>
          <br /><strong>kernel_image</strong>: <code>{`{"image_path": "/path/vmlinuz", "kernel_version": "6.10", "arch": "x86_64"}`}</code>
          <br /><strong>kernel_module</strong>: <code>{`{"ko_path": "/path/buggy.ko", "module_name": "buggy"}`}</code>
          <br /><strong>hypervisor_image</strong>: <code>{`{"binary_path": "/path/qemu-system-x86_64", "hypervisor_kind": "qemu", "version": "9.1.0"}`}</code>
          <br /><strong>android_apk</strong>: <code>{`{"apk_path": "/path/to/app.apk"}`}</code> — staged ingestion: apktool → jadx → androguard (+ MobSF if configured)
          <br /><em>Analysis runs automatically after create. No manual MCP wiring.</em>
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
            placeholder="Display name (e.g. 'V8 d8 (chromium 148)')"
            aria-label="Display name"
            className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
          />
          <div className="flex gap-2">
            <select
              value={formKind}
              onChange={(e) => {
                const newKind = e.target.value as TargetKind;
                setFormKind(newKind);
                setFormDescriptorJson(DESCRIPTOR_TEMPLATES[newKind]);
              }}
              aria-label="Target kind"
              className="px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default"
            >
              {TARGET_KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <input
              type="text"
              value={formPrimaryLanguage}
              onChange={(e) => setFormPrimaryLanguage(e.target.value)}
              placeholder="primary_language (c / c++ / rust / go / javascript / java / kotlin / python / …)"
              aria-label="Primary language"
              className="flex-1 px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
          </div>
          <textarea
            value={formDescriptorJson}
            onChange={(e) => setFormDescriptorJson(e.target.value)}
            placeholder='descriptor JSON, e.g. {"binary_path": "/var/lib/aila/uploads/d8"}'
            rows={3}
            aria-label="Descriptor JSON"
            className="w-full px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
          />
          <div className="flex gap-2">
            <button
              type="button"
              disabled={
                !formWorkspaceId ||
                !formDisplayName.trim() ||
                createMut.isPending
              }
              onClick={() => {
                let descriptor: Record<string, unknown> = {};
                if (formDescriptorJson.trim()) {
                  try {
                    descriptor = JSON.parse(formDescriptorJson);
                  } catch {
                    alert("descriptor JSON is invalid — fix or leave empty");
                    return;
                  }
                }
                createMut.mutate(
                  {
                    workspace_id: formWorkspaceId,
                    display_name: formDisplayName.trim(),
                    kind: formKind,
                    descriptor,
                    primary_language: formPrimaryLanguage.trim() || undefined,
                  },
                  {
                    onSuccess: (result) => {
                      setShowForm(false);
                      setFormDisplayName("");
                      setFormPrimaryLanguage("");
                      navigate(`/vr/targets/${result.data.id}`);
                    },
                  },
                );
              }}
              className="ml-auto px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
            >
              {createMut.isPending ? "Creating…" : "Create target"}
            </button>
          </div>
        </div></AilaCard>
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
// Per-row action: re-fetch upstream git for the target's audit-mcp
// index and rebuild when HEAD moved. Only enabled for git-backed
// target kinds (source_repo / patch_diff / cve) that have a complete
// ingestion (analysis_state == "ready"). Backend returns HTTP 409 if
// the target lacks an audit_mcp_index_id; the toast surfaces that
// message verbatim.
//
// Shift-click forces a full rebuild even when the SHA didn't change
// (use after a trailmark/semble upgrade where the on-disk format
// shifted). Default click = normal idempotent refresh.

const GIT_BACKED_KINDS: ReadonlySet<TargetKind> = new Set([
  "source_repo",
  "patch_diff",
  "cve",
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
    GIT_BACKED_KINDS.has(kind) && analysisState === "ready";
  const isPending = refreshMut.isPending;

  const title = !eligible
    ? kind === "native_binary" ||
      kind === "apk" ||
      kind === "ipa" ||
      kind === "jar" ||
      kind === "dotnet_assembly" ||
      kind === "kernel_image" ||
      kind === "kernel_module" ||
      kind === "hypervisor_image" ||
      kind === "protocol_capture" ||
      kind === "crash_input"
      ? `Refresh unavailable: ${kind} is not git-backed`
      : `Refresh unavailable: analysis_state=${analysisState}`
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
