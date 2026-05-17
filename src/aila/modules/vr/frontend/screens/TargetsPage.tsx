import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useCreateTarget } from "../mutations";
import { useTargets, useWorkspaces } from "../queries";
import type { AnalysisState, TargetKind, TargetStatus } from "../types";

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

export function TargetsPage() {
  const navigate = useNavigate();
  const { data: workspacesResult } = useWorkspaces();
  const workspaces = workspacesResult?.data ?? [];

  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const { data: result, isLoading, isError } = useTargets({
    workspaceId: workspaceFilter || undefined,
  });

  const createMut = useCreateTarget();
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
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            Targets
          </h1>
          <p className="text-sm text-text-muted mt-1">
            Persistent target identities (D-50). Each lives in a workspace
            and carries a capability_profile populated by M3.T enrichment.
          </p>
        </div>
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
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Create target
          </h2>
          <p className="text-xs text-text-muted mb-3">
            descriptor is kind-specific JSON.
            <br /><strong>native_binary</strong>: <code>{`{"binary_path": "/path/on/workstation"}`}</code>
            <br /><strong>source_repo</strong>: <code>{`{"repo_url": "https://github.com/owner/repo", "ref": "main"}`}</code>
            <br /><strong>kernel_image</strong>: <code>{`{"image_path": "/path/vmlinuz", "kernel_version": "6.10", "arch": "x86_64"}`}</code>
            <br /><strong>kernel_module</strong>: <code>{`{"ko_path": "/path/buggy.ko", "module_name": "buggy"}`}</code>
            <br /><strong>hypervisor_image</strong>: <code>{`{"binary_path": "/path/qemu-system-x86_64", "hypervisor_kind": "qemu", "version": "9.1.0"}`}</code>
            <br /><em>Analysis runs automatically after create. No manual MCP wiring.</em>
          </p>
          <div className="space-y-2">
            <select
              value={formWorkspaceId}
              onChange={(e) => setFormWorkspaceId(e.target.value)}
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
                className="flex-1 px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
              />
            </div>
            <textarea
              value={formDescriptorJson}
              onChange={(e) => setFormDescriptorJson(e.target.value)}
              placeholder='descriptor JSON, e.g. {"binary_path": "/var/lib/aila/uploads/d8"}'
              rows={3}
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
          </div>
        </AilaCard>
      )}

      <AilaCard>
        <div className="flex items-center gap-2">
          <label className="text-sm text-text-muted">Filter workspace:</label>
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
          <span className="text-xs text-text-muted ml-auto">
            {targets.length} target{targets.length === 1 ? "" : "s"}
          </span>
        </div>
      </AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load targets.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && targets.length === 0 && (
        <AilaCard>
          <p className="text-center py-6 text-text-muted">No targets yet.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && targets.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Name</th>
                <th className="px-4 py-2 font-semibold">Kind</th>
                <th className="px-4 py-2 font-semibold">Language</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold">Analysis</th>
                <th className="px-4 py-2 font-semibold">Analyzed at</th>
                <th className="px-4 py-2 font-semibold">Created</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr
                  key={t.id}
                  onClick={() => navigate(`/vr/targets/${t.id}`)}
                  className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
                >
                  <td className="px-4 py-2 font-semibold text-foreground">
                    {t.display_name}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-muted">
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
                </tr>
              ))}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}
