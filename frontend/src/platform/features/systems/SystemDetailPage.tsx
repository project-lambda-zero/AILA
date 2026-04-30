import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";
import type { PanelContribution } from "@platform/extension-registry/types";

import {
  useSystemDetail,
  useSystemConnectivity,
  useUpdateSystem,
  useDeleteSystem,
  formatRelativeTime,
  type SystemMutationInput,
} from "./api";
import { ConnectivityBadge } from "./ConnectivityBadge";
import { SystemTags } from "./SystemTags";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeSystemForm(detail: SystemMutationInput): SystemMutationInput {
  return {
    name: detail.name,
    host: detail.host,
    username: detail.username,
    port: detail.port,
    distro: detail.distro,
    description: detail.description,
  };
}

// Load module panel contributions for system.detail slot once at module scope.
// Zero panels are registered in Phase 142 — vulnerability module contributes in Phase 143.
const moduleSpecs = loadModuleFrontendSpecs();
const systemDetailPanels: PanelContribution[] = moduleSpecs
  .flatMap((spec) => spec.panels ?? [])
  .filter((panel) => panel.slot === "system.detail")
  .sort((a, b) => a.order - b.order);

// ---------------------------------------------------------------------------
// SystemDetailPage
// ---------------------------------------------------------------------------

/**
 * SystemDetailPage — tabbed system detail with URL-persisted tab state (D-05/D-06).
 *
 * Tabs: Overview, Tags, plus dynamic module-contributed tabs.
 * Tab state in ?tab= URL param. Each tab content shows LoadingSkeleton while loading.
 * Edit/delete in Overview tab. 404 redirects to /systems.
 */
export function SystemDetailPage() {
  const { role } = useAuthStore();
  const navigate = useNavigate();
  const { systemId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();

  const parsedSystemId = Number(systemId);
  const isValidSystemId = Number.isInteger(parsedSystemId) && parsedSystemId > 0;

  const activeTab = searchParams.get("tab") ?? "overview";

  const systemQuery = useSystemDetail(isValidSystemId ? parsedSystemId : null);
  const connectivityQuery = useSystemConnectivity(isValidSystemId ? parsedSystemId : null);
  const updateSystem = useUpdateSystem(isValidSystemId ? parsedSystemId : null);
  const deleteSystem = useDeleteSystem(isValidSystemId ? parsedSystemId : null);

  const [editDraft, setEditDraft] = useState<SystemMutationInput | null>(null);
  const canOperate = isAllowedRole(role, "operator");

  const system = systemQuery.data;

  const editValue = useMemo(
    () => editDraft ?? (system ? normalizeSystemForm(system) : null),
    [editDraft, system],
  );

  function setTab(tab: string) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    setSearchParams(next, { replace: true });
  }

  if (!isValidSystemId) {
    return (
      <div className="p-4 lg:p-6">
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Invalid system ID. <Link to="/systems" className="underline">Back to systems</Link>
        </div>
      </div>
    );
  }

  // 404 — redirect to /systems
  if (systemQuery.isError) {
    return (
      <div className="p-4 lg:p-6 flex flex-col gap-4">
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          {(systemQuery.error as Error).message}
        </div>
        <Link to="/systems">
          <Button variant="outline" size="sm">Back to Systems</Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <Link to="/systems">
            <Button variant="outline" size="sm">← Systems</Button>
          </Link>
          {systemQuery.isLoading ? (
            <div className="h-5 w-40 skeleton-aila rounded-[2px]" />
          ) : (
            <h1 className="font-mono text-xl font-semibold text-text">{system?.name}</h1>
          )}
        </div>
      </div>

      {/* Loading skeleton for entire page while first load */}
      {systemQuery.isLoading && (
        <AilaCard variant="default" padding="md">
          <LoadingSkeletonGroup lines={6} />
        </AilaCard>
      )}

      {/* Tabbed layout (D-05) */}
      {system && (
        <Tabs value={activeTab} onValueChange={setTab}>
          <div className="overflow-x-auto">
            <TabsList variant="line" className="mb-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="tags">Tags</TabsTrigger>
              {systemDetailPanels.map((panel) => (
                <TabsTrigger key={panel.id} value={panel.id}>
                  {panel.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </div>

          {/* Overview tab */}
          <TabsContent value="overview">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {/* Left: connectivity + tags */}
              <div className="flex flex-col gap-4">
                <AilaCard variant="default" padding="md">
                  <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">SSH Connectivity</h3>
                  {connectivityQuery.isLoading ? (
                    <LoadingSkeletonGroup lines={2} />
                  ) : (
                    <div className="flex flex-col gap-2">
                      <ConnectivityBadge status={connectivityQuery.data?.status ?? null} />
                      {connectivityQuery.data?.last_checked && (
                        <p className="font-mono text-xs text-text-muted">
                          Last checked: {formatRelativeTime(connectivityQuery.data.last_checked)}
                        </p>
                      )}
                    </div>
                  )}
                </AilaCard>

                <AilaCard variant="default" padding="md">
                  <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">Tags</h3>
                  <p className="font-mono text-xs text-text-muted">
                    Manage tags in the <button type="button" onClick={() => setTab("tags")} className="text-accent hover:underline">Tags tab</button>.
                  </p>
                </AilaCard>
              </div>

              {/* Right: metadata + edit form */}
              <div className="flex flex-col gap-4">
                <AilaCard variant="default" padding="md">
                  <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">System Metadata</h3>
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-sm">
                    <dt className="text-text-muted">Host</dt>
                    <dd className="text-text">{system.host}:{system.port}</dd>
                    <dt className="text-text-muted">Username</dt>
                    <dd className="text-text">{system.username}</dd>
                    <dt className="text-text-muted">Distro</dt>
                    <dd className="text-text">{system.distro}</dd>
                    <dt className="text-text-muted">Scan count</dt>
                    <dd className="text-text">{system.scan_count}</dd>
                    <dt className="text-text-muted">Registered</dt>
                    <dd className="text-text">{formatRelativeTime(system.created_at)}</dd>
                    <dt className="text-text-muted">Updated</dt>
                    <dd className="text-text">{formatRelativeTime(system.updated_at)}</dd>
                  </dl>
                  {system.description && (
                    <p className="font-mono text-xs text-text-muted mt-3 border-t border-border pt-3">
                      {system.description}
                    </p>
                  )}
                </AilaCard>

                {/* Edit form */}
                {canOperate && (
                  <AilaCard variant="elevated" padding="md">
                    <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">Edit System</h3>
                    <form
                      className="flex flex-col gap-3"
                      onSubmit={(e) => {
                        e.preventDefault();
                        if (!editValue) return;
                        updateSystem.mutate(editValue, {
                          onSuccess: () => setEditDraft(null),
                        });
                      }}
                    >
                      <div className="grid grid-cols-2 gap-2">
                        <div className="flex flex-col gap-1">
                          <label className="font-mono text-xs text-text-muted">Name</label>
                          <Input
                            value={editValue?.name ?? ""}
                            onChange={(e) =>
                              setEditDraft((cur) => ({ ...(cur ?? normalizeSystemForm(system)), name: e.target.value }))
                            }
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <label className="font-mono text-xs text-text-muted">Host</label>
                          <Input
                            value={editValue?.host ?? ""}
                            onChange={(e) =>
                              setEditDraft((cur) => ({ ...(cur ?? normalizeSystemForm(system)), host: e.target.value }))
                            }
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <label className="font-mono text-xs text-text-muted">Username</label>
                          <Input
                            value={editValue?.username ?? ""}
                            onChange={(e) =>
                              setEditDraft((cur) => ({ ...(cur ?? normalizeSystemForm(system)), username: e.target.value }))
                            }
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <label className="font-mono text-xs text-text-muted">Port</label>
                          <Input
                            type="number"
                            min={1}
                            max={65535}
                            value={editValue?.port ?? 22}
                            onChange={(e) =>
                              setEditDraft((cur) => ({ ...(cur ?? normalizeSystemForm(system)), port: Number(e.target.value) || 22 }))
                            }
                          />
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button type="submit" size="sm" disabled={updateSystem.isPending}>
                          {updateSystem.isPending ? "Saving..." : "Save Changes"}
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => setEditDraft(normalizeSystemForm(system))}
                        >
                          Reset
                        </Button>
                      </div>
                      {updateSystem.isError && (
                        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                          {(updateSystem.error as Error).message}
                        </div>
                      )}
                    </form>
                  </AilaCard>
                )}

                {/* Delete */}
                {canOperate && (
                  <AilaCard variant="default" padding="md">
                    <h3 className="font-mono text-xs uppercase tracking-wider text-text-muted mb-3">Danger Zone</h3>
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={deleteSystem.isPending}
                      onClick={() => {
                        if (!window.confirm(`Delete system ${system.name}? This cannot be undone.`)) return;
                        deleteSystem.mutate(undefined, {
                          onSuccess: () => void navigate("/systems"),
                        });
                      }}
                    >
                      {deleteSystem.isPending ? "Deleting..." : "Delete System"}
                    </Button>
                    {deleteSystem.isError && (
                      <div className="mt-2 rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                        {(deleteSystem.error as Error).message}
                      </div>
                    )}
                  </AilaCard>
                )}
              </div>
            </div>
          </TabsContent>

          {/* Tags tab */}
          <TabsContent value="tags">
            <SystemTags systemId={parsedSystemId} />
          </TabsContent>

          {/* Module-contributed tabs (D-06) — slot: system.detail */}
          {systemDetailPanels.map((panel) => {
            const PanelComponent = panel.render;
            return (
              <TabsContent key={panel.id} value={panel.id}>
                <PanelComponent systemId={parsedSystemId} />
              </TabsContent>
            );
          })}
        </Tabs>
      )}
    </div>
  );
}
