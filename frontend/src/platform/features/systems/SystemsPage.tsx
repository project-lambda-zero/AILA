import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Monitor, Plus, Upload } from "lucide-react";

import { SystemCSVImport } from "./SystemCSVImport";
import { SystemTags } from "./SystemTags";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole } from "@platform/auth/roles";
import { usePreferences } from "@/providers/PreferencesProvider";
import { SavedViews } from "@platform/features/saved-views";
import {
  useCreateSystem,
  useSystems,
  useTagVocabulary,
  type SystemMutationInput,
  type SystemSummaryEnriched,
} from "./api";
import { useSystemColumns } from "./SystemsTable";

const DEFAULT_SYSTEM_FORM: SystemMutationInput = {
  name: "",
  host: "",
  username: "root",
  port: 22,
  distro: "unknown",
  description: "",
  private_key: null,
  password: null,
  private_key_passphrase: null,
};

function matchesTagFilter(system: SystemSummaryEnriched, selectedTagKeys: string[]): boolean {
  if (selectedTagKeys.length === 0) return true;
  const systemTagKeys = (system.tags ?? []).map((t) => t.tag_key);
  return selectedTagKeys.some((key) => systemTagKeys.includes(key));
}

/**
 * Row quick-peek body -- renders inside the AilaTable-managed Sheet when the
 * operator activates the row's peek button. Purely reads the enriched summary
 * that the list query already carries; no extra fetches.
 */
function SystemRowPeek({ system }: { system: SystemSummaryEnriched }) {
  const tags = system.tags ?? [];
  return (
    <div className="flex flex-col gap-3 font-mono text-xs text-text">
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1.5">
        <dt className="text-text-muted uppercase tracking-wider">Host</dt>
        <dd>{system.host}:{system.port}</dd>
        <dt className="text-text-muted uppercase tracking-wider">User</dt>
        <dd>{system.username}</dd>
        <dt className="text-text-muted uppercase tracking-wider">Distro</dt>
        <dd>{system.distro}</dd>
        <dt className="text-text-muted uppercase tracking-wider">SSH</dt>
        <dd>{system.connectivity_status ?? "unknown"}</dd>
        <dt className="text-text-muted uppercase tracking-wider">Severity</dt>
        <dd>{system.top_severity ? system.top_severity.toUpperCase() : "N/A"}</dd>
        <dt className="text-text-muted uppercase tracking-wider">Last scan</dt>
        <dd>{system.last_scan_at ? new Date(system.last_scan_at).toLocaleString() : "never"}</dd>
        <dt className="text-text-muted uppercase tracking-wider">Last status</dt>
        <dd>{system.last_scan_status ?? "--"}</dd>
      </dl>
      {system.description && (
        <p className="text-text-muted whitespace-pre-wrap border-t border-border pt-2">
          {system.description}
        </p>
      )}
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1 border-t border-border pt-2">
          {tags.map((t) => (
            <AilaBadge key={`${t.tag_key}:${t.tag_value}`} severity="info" size="sm">
              {t.tag_key}:{t.tag_value}
            </AilaBadge>
          ))}
        </div>
      )}
      <div className="border-t border-border pt-3">
        <Link
          to={`/systems/${system.id}`}
          className="font-semibold text-accent hover:text-accent/80 transition-colors duration-100"
        >
          Open full detail →
        </Link>
      </div>
    </div>
  );
}

/**
 * SystemsPage -- systems list with AilaTable, metric cards, filtering (D-01, D-02, D-13-17).
 *
 * Rebuilds the PatternFly-era page with:
 * - Three AilaCard metric cards (total, visible, unreachable)
 * - AilaTable with enriched columns (connectivity, tags, last scan, severity)
 * - Tag multi-select filter + text search persisted in URL (?q=, ?tags=)
 * - Loading skeleton, empty states, error banner (D-13/D-14/D-15)
 * - Responsive column hiding via useIsMobile() (D-17)
 */
export function SystemsPage() {
  const { role } = useAuthStore();
  const [searchParams, setSearchParams] = useSearchParams();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showCSVImport, setShowCSVImport] = useState(false);
  const [tagSheetSystemId, setTagSheetSystemId] = useState<number | null>(null);
  const [draftSystem, setDraftSystem] = useState<SystemMutationInput>(DEFAULT_SYSTEM_FORM);
  // Operator preference (settings > default page size) drives both the initial
  // page fetch and the AilaTable pagination window so the client's rendered
  // slice never exceeds the fetched slice for any value in
  // ALLOWED_PAGE_SIZES (10 / 25 / 50 / 100 -- all under the 250 backend cap).
  const { defaultPageSize, setDefaultPageSize, allowedPageSizes } = usePreferences();
  const systemsQuery = useSystems(1, defaultPageSize);
  const vocabQuery = useTagVocabulary();
  const createSystem = useCreateSystem();
  const canOperate = isAllowedRole(role, "operator");
  const columns = useSystemColumns(canOperate ? setTagSheetSystemId : undefined);

  // URL-persisted filter state (D-16)
  const searchQuery = (searchParams.get("q") ?? "").toLowerCase().trim();
  const selectedTagKeys = useMemo(() => {
    const raw = searchParams.get("tags") ?? "";
    return raw ? raw.split(",").filter(Boolean) : [];
  }, [searchParams]);

  const allSystems = systemsQuery.data?.items ?? [];

  const filteredSystems = useMemo(
    () =>
      allSystems.filter((system) => {
        if (searchQuery) {
          const haystack = [system.name, system.host, system.username, system.distro, system.description]
            .join(" ")
            .toLowerCase();
          if (!haystack.includes(searchQuery)) return false;
        }
        return matchesTagFilter(system, selectedTagKeys);
      }),
    [allSystems, searchQuery, selectedTagKeys],
  );

  const unreachableCount = useMemo(
    () => allSystems.filter((s) => s.connectivity_status === "unreachable").length,
    [allSystems],
  );

  const vocabulary = vocabQuery.data ?? [];

  function updateTagFilter(key: string) {
    const next = new URLSearchParams(searchParams);
    const current = selectedTagKeys.includes(key)
      ? selectedTagKeys.filter((k) => k !== key)
      : [...selectedTagKeys, key];
    if (current.length > 0) {
      next.set("tags", current.join(","));
    } else {
      next.delete("tags");
    }
    setSearchParams(next, { replace: true });
  }

  function clearFilters() {
    const next = new URLSearchParams(searchParams);
    next.delete("q");
    next.delete("tags");
    setSearchParams(next, { replace: true });
  }

  const hasActiveFilter = searchQuery.length > 0 || selectedTagKeys.length > 0;

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex gap-2">
          {canOperate ? (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowCreateForm((v) => !v)}
                className="gap-1.5"
              >
                <Plus className="h-4 w-4" />
                Register System
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowCSVImport(true)}
                className="gap-1.5"
              >
                <Upload className="h-4 w-4" />
                Import CSV
              </Button>
            </>
          ) : (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger>
                  <Button size="sm" variant="outline" disabled className="gap-1.5 opacity-50">
                    <Plus className="h-4 w-4" />
                    Register System
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <span className="font-mono text-xs">Requires operator+ role</span>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
      </div>

      {/* Metric cards (D-02) */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <WindowPanel title="Registered Systems" tone="muted">
          <p className="font-mono text-2xl font-semibold text-text">
            {systemsQuery.data?.total ?? "--"}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">Total in fleet</p>
        </WindowPanel>
        <WindowPanel title="Visible Systems" tone="info">
          <p className="font-mono text-2xl font-semibold text-text">{filteredSystems.length}</p>
          <p className="font-mono text-xs text-text-muted mt-0.5">Matching active filters</p>
        </WindowPanel>
        <WindowPanel title="Unreachable" tone={unreachableCount > 0 ? "warn" : "muted"}>
          <p className="font-mono text-2xl font-semibold text-critical">{unreachableCount}</p>
          <p className="font-mono text-xs text-text-muted mt-0.5">SSH connectivity offline</p>
        </WindowPanel>
      </div>

      {/* Error banner (D-15) */}
      {systemsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load systems: {(systemsQuery.error as Error).message}
        </div>
      )}

      {/* Register System form */}
      {showCreateForm && (
        <WindowPanel title="Register a New System" tone="accent">
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            createSystem.mutate(draftSystem, {
              onSuccess: () => {
                setDraftSystem(DEFAULT_SYSTEM_FORM);
                setShowCreateForm(false);
              },
            });
          }}
        >
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-name">Name</label>
              <Input
                id="sys-name"
                value={draftSystem.name}
                onChange={(e) => setDraftSystem((d) => ({ ...d, name: e.target.value }))}
                placeholder="arch-vm"
                required
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-host">Host</label>
              <Input
                id="sys-host"
                value={draftSystem.host}
                onChange={(e) => setDraftSystem((d) => ({ ...d, host: e.target.value }))}
                placeholder="192.168.56.129"
                required
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-user">Username</label>
              <Input
                id="sys-user"
                value={draftSystem.username}
                onChange={(e) => setDraftSystem((d) => ({ ...d, username: e.target.value }))}
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-port">Port</label>
              <Input
                id="sys-port"
                type="number"
                min={1}
                max={65535}
                value={draftSystem.port}
                onChange={(e) => setDraftSystem((d) => ({ ...d, port: Number(e.target.value) || 22 }))}
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-distro">Distro</label>
              <Input
                id="sys-distro"
                value={draftSystem.distro}
                onChange={(e) => setDraftSystem((d) => ({ ...d, distro: e.target.value }))}
              />
            </div>
          </div>
        
          <h3 className="font-mono text-xs font-semibold uppercase text-text-muted mt-2 border-t border-border pt-3" style={{ letterSpacing: "0.14em" }}>SSH Credentials</h3>
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="sys-privkey">Private Key (PEM)</label>
            <textarea
              id="sys-privkey"
              className="rounded-[2px] border border-border bg-base font-mono text-xs text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100 resize-none"
              rows={4}
              value={draftSystem.private_key ?? ""}
              onChange={(e) => setDraftSystem((d) => ({ ...d, private_key: e.target.value || null }))}
              placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\nPaste your private key here...\n-----END OPENSSH PRIVATE KEY-----"}
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-passphrase">Key Passphrase</label>
              <Input
                id="sys-passphrase"
                type="password"
                value={draftSystem.private_key_passphrase ?? ""}
                onChange={(e) => setDraftSystem((d) => ({ ...d, private_key_passphrase: e.target.value || null }))}
                placeholder="Passphrase (if key is encrypted)"
                autoComplete="off"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="sys-password">SSH Password</label>
              <Input
                id="sys-password"
                type="password"
                value={draftSystem.password ?? ""}
                onChange={(e) => setDraftSystem((d) => ({ ...d, password: e.target.value || null }))}
                placeholder="Password (alternative to key)"
                autoComplete="off"
              />
            </div>
          </div>
        
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="sys-desc">Description</label>
            <textarea
              id="sys-desc"
              className="rounded-[2px] border border-border bg-base font-mono text-sm text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100 resize-none"
              rows={2}
              value={draftSystem.description}
              onChange={(e) => setDraftSystem((d) => ({ ...d, description: e.target.value }))}
              placeholder="Internet-facing Arch Linux host in prod"
            />
          </div>
          <div className="flex gap-2">
            <Button type="submit" size="sm" disabled={createSystem.isPending}>
              {createSystem.isPending ? "Registering..." : "Create System"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => {
                setDraftSystem(DEFAULT_SYSTEM_FORM);
                setShowCreateForm(false);
              }}
            >
              Cancel
            </Button>
          </div>
          {createSystem.isError && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {(createSystem.error as Error).message}
            </div>
          )}
        </form></WindowPanel>
      )}

      {/* Saved views -- persists the current search, tag filter, and default
          page size under entity_type='system' via /saved-filters. Applying a
          view rewrites the URL search params so shareable links keep working
          exactly as before. */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-col gap-1">
          <label
            htmlFor="systems-search"
            className="font-mono text-[10px] text-text-muted uppercase tracking-wider"
          >
            Search
          </label>
          <Input
            id="systems-search"
            value={searchParams.get("q") ?? ""}
            onChange={(e) => {
              const next = new URLSearchParams(searchParams);
              if (e.target.value) next.set("q", e.target.value);
              else next.delete("q");
              setSearchParams(next, { replace: true });
            }}
            placeholder="host, name, distro…"
            className="font-mono text-xs h-8 w-56"
          />
        </div>
        <SavedViews<{
          q: string;
          tags: string[];
          pageSize: number;
        }>
          entityType="system"
          entityLabel="Systems list"
          currentState={{
            q: searchQuery,
            tags: selectedTagKeys,
            pageSize: defaultPageSize,
          }}
          onApply={(state) => {
            const next = new URLSearchParams(searchParams);
            if (state.q) next.set("q", state.q);
            else next.delete("q");
            if (Array.isArray(state.tags) && state.tags.length > 0) {
              next.set("tags", state.tags.join(","));
            } else {
              next.delete("tags");
            }
            setSearchParams(next, { replace: true });
            if (
              typeof state.pageSize === "number" &&
              allowedPageSizes.includes(state.pageSize) &&
              state.pageSize !== defaultPageSize
            ) {
              setDefaultPageSize(state.pageSize);
            }
          }}
          className="ml-auto"
        />
      </div>

      {/* Tag filter bar */}
      {vocabulary.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono uppercase text-muted-foreground" style={{ fontSize: "11px", letterSpacing: "0.14em" }}>Filter by tag</span>
          {vocabulary.map((entry) => {
            const active = selectedTagKeys.includes(entry.tag_key);
            return (
              <button
                key={entry.id}
                type="button"
                onClick={() => updateTagFilter(entry.tag_key)}
                className="cursor-pointer"
              >
                <AilaBadge severity={active ? "info" : "neutral"} size="sm" solid={active}>
                  {entry.tag_key}
                </AilaBadge>
              </button>
            );
          })}
          {hasActiveFilter && (
            <button
              type="button"
              onClick={clearFilters}
              className="font-mono text-xs text-text-muted hover:text-text transition-colors duration-100"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* Loading skeleton (D-13) */}
      {systemsQuery.isLoading && (
        <WindowPanel title="Systems ; Fleet" status="LOADING" tone="muted"><LoadingSkeletonGroup lines={8} /></WindowPanel>
      )}

      {/* Empty state -- no systems at all (D-14) */}
      {!systemsQuery.isLoading && !systemsQuery.isError && allSystems.length === 0 && (
        <EmptyState
          icon={<Monitor className="h-10 w-10" />}
          title="No systems registered"
          description="Register your first SSH-reachable system to start scanning."
          action={canOperate ? { label: "Register System", onClick: () => setShowCreateForm(true) } : undefined}
          secondaryAction={!canOperate ? { label: "Contact an operator to register systems." } : undefined}
        />
      )}

      {/* Empty state -- filter matches nothing (D-14) */}
      {!systemsQuery.isLoading && !systemsQuery.isError && allSystems.length > 0 && filteredSystems.length === 0 && (
        <EmptyState
          title="No systems match current filters"
          description="Try adjusting your search or tag filters."
          action={{ label: "Clear filters", onClick: clearFilters }}
        />
      )}

      {/* Systems table (D-01) */}
      {!systemsQuery.isLoading && filteredSystems.length > 0 && (
        <WindowPanel
          title="Systems ; Fleet"
          status={`${filteredSystems.length} VISIBLE ; ${systemsQuery.data?.total ?? filteredSystems.length} TOTAL`}
          tone="muted"
          flush
        >
        <div className="overflow-x-auto">
          <AilaTable
            data={filteredSystems}
            columns={columns}
            pageSize={defaultPageSize}
            enableSorting
            enableFiltering
            exportFilename="aila-systems"
            peekLabel={(row) => `System summary for ${row.name}`}
            peekTitle={(row) => row.name}
            peekDescription={(row) => `${row.username}@${row.host}:${row.port} · ${row.distro}`}
            renderRowPeek={(row) => (
              <SystemRowPeek system={row} />
            )}
          >
            <AilaTable.Header />
            <AilaTable.Body
              emptyState="No systems match the current search."
            />
            <AilaTable.Pagination pageSizeOptions={[10, 25, 50, 100]} />
          </AilaTable>
        </div>
        </WindowPanel>
      )}

      {/* Bulk action stub notice (D-19) */}
      {filteredSystems.length > 0 && (
        <p className="font-mono text-xs text-text-muted">
          Row selection available. Bulk actions coming in a future release.
        </p>
      )}

      {/* CSV import dialog (D-07) */}
      <SystemCSVImport open={showCSVImport} onOpenChange={setShowCSVImport} />

      {/* Inline tag management drawer -- opened from the per-row "+" button on
          the Tags column. Reuses SystemTags so the assignment form stays in
          one place. */}
      <Sheet
        open={tagSheetSystemId !== null}
        onOpenChange={(open) => {
          if (!open) setTagSheetSystemId(null);
        }}
      >
        <SheetContent side="right" className="w-full max-w-md sm:max-w-md">
          <SheetHeader>
            <SheetTitle className="font-mono text-text">Manage Tags</SheetTitle>
            <SheetDescription className="font-mono text-xs text-text-muted">
              {tagSheetSystemId !== null && (() => {
                const target = allSystems.find((s) => s.id === tagSheetSystemId);
                return target
                  ? `Assign or remove tags on ${target.name} (${target.host}).`
                  : `System ${tagSheetSystemId}`;
              })()}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto px-4 pb-4">
            {tagSheetSystemId !== null && (
              <SystemTags systemId={tagSheetSystemId} />
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
