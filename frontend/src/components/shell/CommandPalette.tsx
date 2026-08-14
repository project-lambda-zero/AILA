import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";

import { Desktop } from "@phosphor-icons/react/dist/csr/Desktop";
import { Bug } from "@phosphor-icons/react/dist/csr/Bug";
import { ShieldWarning } from "@phosphor-icons/react/dist/csr/ShieldWarning";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { ArrowSquareOut } from "@phosphor-icons/react/dist/csr/ArrowSquareOut";
import { ClockCounterClockwise } from "@phosphor-icons/react/dist/csr/ClockCounterClockwise";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { Crosshair } from "@phosphor-icons/react/dist/csr/Crosshair";
import { Gauge } from "@phosphor-icons/react/dist/csr/Gauge";
import { ChartBar } from "@phosphor-icons/react/dist/csr/ChartBar";
import { Key } from "@phosphor-icons/react/dist/csr/Key";
import { FileText } from "@phosphor-icons/react/dist/csr/FileText";
import { X } from "@phosphor-icons/react/dist/csr/X";
import { Compass } from "@phosphor-icons/react/dist/csr/Compass";
import { Lightning } from "@phosphor-icons/react/dist/csr/Lightning";
import { PlusCircle } from "@phosphor-icons/react/dist/csr/PlusCircle";
import { ChatCircleDots } from "@phosphor-icons/react/dist/csr/ChatCircleDots";
import { Pause } from "@phosphor-icons/react/dist/csr/Pause";
import { ArrowsCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowsCounterClockwise";
import { Files } from "@phosphor-icons/react/dist/csr/Files";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";
import { Wrench } from "@phosphor-icons/react/dist/csr/Wrench";
import { Calendar } from "@phosphor-icons/react/dist/csr/Calendar";
import { Palette } from "@phosphor-icons/react/dist/csr/Palette";
import { SignOut } from "@phosphor-icons/react/dist/csr/SignOut";

import {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
  CommandSeparator,
} from "@/components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { toast } from "@/components/ui/sonner";

import { ApiHttpError, authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole, type AppRole } from "@platform/auth/roles";
import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";

import { useTheme } from "@/providers/ThemeProvider";
import { useRecentlyViewed } from "@/hooks/useRecentlyViewed";
import { useSearchHistory } from "@/hooks/useSearchHistory";

import {
  entityRoute,
  entityTypeLabel,
  entityTypeSeverity,
  useGlobalSearch,
  type SearchResult,
} from "@platform/features/search/searchQueries";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NavEntry {
  id: string;
  label: string;
  to: string;
  icon: React.ReactNode;
  section?: "platform" | "admin" | "module";
  minRole?: AppRole;
  moduleId?: string;
}

interface ActionEntry {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  minRole?: AppRole;
  /** When set the action asks for a modal confirm before firing. */
  confirm?: { title: string; body: string; destructive?: boolean };
  /** When set the action asks the user for a value before firing. */
  prompt?: { title: string; body: string; label: string; placeholder: string };
  /** Executes the action. Returns a status string surfaced via toast. */
  run: (args: {
    navigate: (to: string) => void;
    input: string | null;
  }) => Promise<string | void> | string | void;
}

interface PendingAction {
  action: ActionEntry;
  input: string;
}

// ---------------------------------------------------------------------------
// Static platform routes exposed in Navigate. Detail routes with :params
// are intentionally omitted -- the Search group is how you land on a row.
// ---------------------------------------------------------------------------

const PLATFORM_ROUTES: readonly NavEntry[] = [
  { id: "nav.chat", label: "Chat", to: "/", icon: <ChatCircleDots size={16} />, section: "platform" },
  { id: "nav.dashboard", label: "Dashboard", to: "/dashboard", icon: <Gauge size={16} />, section: "platform" },
  { id: "nav.systems", label: "Systems", to: "/systems", icon: <Desktop size={16} />, section: "platform" },
  { id: "nav.radar", label: "Network Radar", to: "/radar", icon: <ChartBar size={16} />, section: "platform", minRole: "operator" },
  { id: "nav.viz", label: "Data Visualization", to: "/viz", icon: <ChartBar size={16} />, section: "platform" },
  { id: "nav.console", label: "Console", to: "/console", icon: <Crosshair size={16} />, section: "platform" },
  { id: "nav.tasks", label: "Tasks", to: "/tasks", icon: <ClipboardText size={16} />, section: "platform" },
  { id: "nav.docs", label: "Docs", to: "/docs", icon: <FileText size={16} />, section: "platform" },
  { id: "nav.search", label: "Search", to: "/search", icon: <MagnifyingGlass size={16} />, section: "platform" },
  { id: "nav.settings", label: "Settings", to: "/settings", icon: <ClipboardText size={16} />, section: "platform" },
  { id: "nav.sessions", label: "Sessions", to: "/settings/sessions", icon: <ClipboardText size={16} />, section: "platform" },
  { id: "nav.admin.users", label: "Users", to: "/admin/users", icon: <ClipboardText size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.api-keys", label: "API Keys", to: "/admin/api-keys", icon: <Key size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.audit", label: "Audit Logs", to: "/admin/audit", icon: <FileText size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.tools", label: "Tools Console", to: "/admin/tools", icon: <Wrench size={16} />, section: "admin", minRole: "operator" },
  { id: "nav.admin.workflows", label: "Workflow Inspector", to: "/admin/workflows", icon: <Compass size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.llm-log", label: "LLM Log", to: "/admin/llm-log", icon: <Files size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.config", label: "Platform Config", to: "/admin/config", icon: <Wrench size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.platform-ops", label: "Platform Ops", to: "/admin/platform-ops", icon: <Wrench size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.tags", label: "Tag Vocabulary", to: "/admin/tags", icon: <ClipboardText size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.health", label: "System Health", to: "/admin/health", icon: <ShieldWarning size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.oidc", label: "OIDC Providers", to: "/admin/auth/oidc-providers", icon: <Key size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.teams", label: "Teams", to: "/admin/teams", icon: <ClipboardText size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.saved-filters", label: "Saved Filters", to: "/admin/saved-filters", icon: <ClipboardText size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.task-queue", label: "Task Queue", to: "/admin/task-queue", icon: <ClipboardText size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.dead-letter", label: "Dead Letter Queue", to: "/admin/dead-letter", icon: <Skull size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.automation", label: "Automation Schedules", to: "/admin/automation", icon: <ArrowsCounterClockwise size={16} />, section: "admin" },
  { id: "nav.admin.scheduled-reports", label: "Scheduled Reports", to: "/admin/scheduled-reports", icon: <Calendar size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.cost", label: "Cost Intelligence", to: "/admin/cost", icon: <ChartBar size={16} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.executive", label: "Executive Dashboard", to: "/admin/executive", icon: <ChartBar size={16} />, section: "admin", minRole: "admin" },
];

// ---------------------------------------------------------------------------
// Module route enumeration. Only nav-eligible routes (no :params) are
// surfaced; module detail pages are reached through Search.
// ---------------------------------------------------------------------------

function collectModuleRoutes(): NavEntry[] {
  const specs = loadModuleFrontendSpecs();
  const entries: NavEntry[] = [];
  for (const spec of specs) {
    for (const route of spec.routes ?? []) {
      if (route.path.includes(":")) continue;
      if (route.nav === false) continue;
      entries.push({
        id: `nav.module.${route.id}`,
        label: route.title,
        to: route.path.startsWith("/") ? route.path : `/${route.path}`,
        icon: <ArrowSquareOut size={16} />,
        section: "module",
        moduleId: spec.moduleId,
        minRole: route.minRole,
      });
    }
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Action catalog. `run` is called only after any confirm/prompt dialog.
// Role gating is enforced in the render pass via useAuthStore().role.
// ---------------------------------------------------------------------------

const ACTIONS: readonly ActionEntry[] = [
  {
    id: "action.new-scan",
    label: "New scan",
    description: "Open the Console to submit a scan run",
    icon: <Crosshair size={16} />,
    run: ({ navigate }) => {
      navigate("/console?new=1");
    },
  },
  {
    id: "action.new-chat",
    label: "New chat session",
    description: "Create a session and jump into Chat",
    icon: <PlusCircle size={16} />,
    run: async ({ navigate }) => {
      const session = await authorizedRequestJson<{ session_id: string }>(
        "/sessions",
        { method: "POST", body: { title: "New chat" } },
      );
      navigate(`/?session=${encodeURIComponent(session.session_id)}`);
      return `Session ${session.session_id.slice(0, 8)} created`;
    },
  },
  {
    id: "action.scheduled-reports",
    label: "Trigger scheduled report",
    description: "Open the Scheduled Reports page",
    icon: <Calendar size={16} />,
    minRole: "admin",
    run: ({ navigate }) => {
      navigate("/admin/scheduled-reports");
    },
  },
  {
    id: "action.drain-queue",
    label: "Drain task queue",
    description: "Pause new submissions to the task queue",
    icon: <Pause size={16} />,
    minRole: "admin",
    confirm: {
      title: "Drain task queue?",
      body: "Pauses new task submissions across every worker. Existing runs continue to completion. Undo via Task Queue admin.",
    },
    run: async () => {
      const env = await authorizedRequestJson<{
        data: { pending: number; draining: boolean };
      }>("/tasks/drain", { method: "POST" });
      return `Draining -- ${env.data.pending} pending`;
    },
  },
  {
    id: "action.requeue-failed",
    label: "Requeue failed tasks (24h)",
    description: "Re-submit tasks that failed in the last 24 hours",
    icon: <ArrowsCounterClockwise size={16} />,
    minRole: "admin",
    confirm: {
      title: "Requeue failed tasks?",
      body: "Every task that failed in the last 24 hours will be re-submitted. Long-running or expensive tasks will run again.",
    },
    run: async () => {
      const env = await authorizedRequestJson<{
        data: { requeued: number };
      }>("/tasks/requeue-failed?max_age_hours=24", { method: "POST" });
      return `Requeued ${env.data.requeued} task${env.data.requeued === 1 ? "" : "s"}`;
    },
  },
  {
    id: "action.export-corpus",
    label: "Export eval corpus",
    description: "Enqueue a corpus export job (SFT + DPO manifests)",
    icon: <Files size={16} />,
    minRole: "admin",
    confirm: {
      title: "Export eval corpus?",
      body: "Enqueues a background job to rebuild the SFT + DPO manifests from every recorded investigation. This can take several minutes.",
    },
    run: async () => {
      const env = await authorizedRequestJson<{
        data: { task_id: string };
      }>("/platform/eval/corpus/export", { method: "POST", body: {} });
      return `Export enqueued -- task ${env.data.task_id.slice(0, 8)}`;
    },
  },
  {
    id: "action.replay-deadletter",
    label: "Replay journal deadletters",
    description: "Drain un-replayed journal deadletter rows back into chains",
    icon: <Skull size={16} />,
    minRole: "admin",
    confirm: {
      title: "Replay journal deadletters?",
      body: "Attempts to replay every un-replayed row in `journal_deadletter`. Rows that still fail stay in the deadletter table with a fresh error.",
      destructive: true,
    },
    run: async () => {
      const env = await authorizedRequestJson<{
        data: { scanned: number; replayed: number; failed: number };
      }>("/admin/journal/deadletter/replay", { method: "POST", body: {} });
      return `Scanned ${env.data.scanned} -- replayed ${env.data.replayed}, failed ${env.data.failed}`;
    },
  },
  {
    id: "action.reconcile",
    label: "Reconcile task state",
    description: "Heal drift between TaskRecord, workflow cursor, and ARQ lock",
    icon: <Wrench size={16} />,
    minRole: "admin",
    prompt: {
      title: "Reconcile task",
      body: "Runs one StateReconciler.reconcile() pass for the given task_id. Idempotent -- a consistent row returns healed=false.",
      label: "Task ID",
      placeholder: "e.g. 01HZ9M…",
    },
    run: async ({ input }) => {
      const taskId = (input ?? "").trim();
      if (!taskId) {
        throw new Error("task_id is required");
      }
      const env = await authorizedRequestJson<{
        data: { healed: boolean; action_kinds: string[] };
      }>("/admin/reconcile", {
        method: "POST",
        body: { task_id: taskId },
      });
      const actions = env.data.action_kinds.length
        ? ` -- actions: ${env.data.action_kinds.join(", ")}`
        : "";
      return env.data.healed
        ? `Healed ${taskId.slice(0, 8)}${actions}`
        : `Already consistent -- ${taskId.slice(0, 8)}`;
    },
  },
  {
    id: "action.cycle-theme",
    label: "Cycle theme",
    description: "Rotate through the installed theme palette",
    icon: <Palette size={16} />,
    run: () => {
      // Wired via ThemeProvider in the palette body; overridden below.
    },
  },
  {
    id: "action.sign-out",
    label: "Sign out",
    description: "End the current session",
    icon: <SignOut size={16} />,
    run: () => {
      // Wired via useAuthStore in the palette body; overridden below.
    },
  },
];

// ---------------------------------------------------------------------------
// Debounce hook -- keeps typing snappy; only the search fetch is throttled.
// ---------------------------------------------------------------------------

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const handle = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(handle);
  }, [value, delayMs]);
  return debounced;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const { cycleTheme } = useTheme();
  const { items: recentItems } = useRecentlyViewed();
  const { items: searchHistory, addSearch, clearHistory } = useSearchHistory();
  const role = useAuthStore((s) => s.role);

  // `>` prefix is the classic command-mode filter: only Navigate + Actions,
  // no server search fetch. Bare queries fan out to all three groups.
  const isCommandMode = query.startsWith(">");
  const rawQuery = isCommandMode ? query.slice(1).trimStart() : query;
  const lowered = rawQuery.trim().toLowerCase();
  const debouncedSearch = useDebouncedValue(rawQuery.trim(), 200);

  // Dialog state for the pending action prompt/confirm.
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [actionBusy, setActionBusy] = useState(false);

  // ---------------------------------------------------------------------------
  // Open on Cmd/Ctrl+K -- AppHeader also dispatches the custom event.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    function handleOpen() {
      setOpen((prev) => !prev);
    }
    window.addEventListener("open-command-palette", handleOpen);
    return () => window.removeEventListener("open-command-palette", handleOpen);
  }, []);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  // ---------------------------------------------------------------------------
  // Route list: static platform routes + enumerated module routes, gated
  // by the caller's role. Memoised because module enumeration walks every
  // spec.
  // ---------------------------------------------------------------------------
  const allRoutes = useMemo(
    () => [...PLATFORM_ROUTES, ...collectModuleRoutes()],
    [],
  );

  const visibleRoutes = useMemo(
    () => allRoutes.filter((entry) => isAllowedRole(role, entry.minRole)),
    [allRoutes, role],
  );

  const filteredRoutes = useMemo(() => {
    if (lowered.length === 0) return visibleRoutes;
    return visibleRoutes.filter(
      (entry) =>
        entry.label.toLowerCase().includes(lowered) ||
        entry.to.toLowerCase().includes(lowered) ||
        (entry.moduleId?.toLowerCase().includes(lowered) ?? false),
    );
  }, [visibleRoutes, lowered]);

  const visibleActions = useMemo(
    () => ACTIONS.filter((action) => isAllowedRole(role, action.minRole)),
    [role],
  );

  const filteredActions = useMemo(() => {
    if (lowered.length === 0) return visibleActions;
    return visibleActions.filter(
      (action) =>
        action.label.toLowerCase().includes(lowered) ||
        action.description.toLowerCase().includes(lowered),
    );
  }, [visibleActions, lowered]);

  // ---------------------------------------------------------------------------
  // Server search -- only fires in bare-query mode, min 2 chars.
  // ---------------------------------------------------------------------------
  const searchResults = useGlobalSearch({
    q: debouncedSearch,
    limit: 8,
    enabled: !isCommandMode && debouncedSearch.length >= 2,
  });

  // ---------------------------------------------------------------------------
  // Action runner. Uses a mutation so its lifecycle is observable and
  // per-run errors surface consistently via toast.
  // ---------------------------------------------------------------------------
  const runMutation = useMutation({
    mutationFn: async ({ action, input }: PendingAction) => {
      return action.run({ navigate, input: input || null });
    },
  });

  const executeAction = useCallback(
    async (action: ActionEntry, input: string) => {
      setActionBusy(true);
      try {
        const message = await runMutation.mutateAsync({ action, input });
        if (message) toast.success(message);
      } catch (err) {
        const msg =
          err instanceof ApiHttpError
            ? err.envelope?.message ?? err.detail
            : err instanceof Error
              ? err.message
              : "Action failed.";
        toast.error(msg);
      } finally {
        setActionBusy(false);
        setPending(null);
      }
    },
    [runMutation],
  );

  const invokeAction = useCallback(
    (action: ActionEntry) => {
      setOpen(false);
      // Local overrides for actions that use React-hook APIs (theme, auth).
      if (action.id === "action.cycle-theme") {
        cycleTheme();
        toast.success("Theme cycled");
        return;
      }
      if (action.id === "action.sign-out") {
        void useAuthStore.getState().logout();
        navigate("/login");
        return;
      }
      if (action.confirm || action.prompt) {
        setPending({ action, input: "" });
        return;
      }
      void executeAction(action, "");
    },
    [cycleTheme, executeAction, navigate],
  );

  // ---------------------------------------------------------------------------
  // Selection helpers.
  // ---------------------------------------------------------------------------
  function closeAndNavigate(url: string) {
    navigate(url);
    setOpen(false);
  }

  function selectSearchResult(result: SearchResult) {
    addSearch(rawQuery.trim());
    closeAndNavigate(entityRoute(result));
  }

  // ---------------------------------------------------------------------------
  // Derived flags.
  // ---------------------------------------------------------------------------
  const isEmptyQuery = query === "";
  const searchList = searchResults.data?.results ?? [];
  const showSearchGroup = !isCommandMode && debouncedSearch.length >= 2;
  const placeholderText = isCommandMode
    ? "> Command…"
    : "Navigate, search, or run an action…";

  return (
    <>
      <CommandDialog open={open} onOpenChange={(next) => setOpen(next)}>
        {/*
          shouldFilter={false} -- Navigate and Actions are filtered manually
          against the query text; Search results come from the server already
          filtered. This keeps the three groups consistent and prevents cmdk
          from re-ordering server-side results by client-side score.
        */}
        <Command shouldFilter={false}>
          <CommandInput
            placeholder={placeholderText}
            value={query}
            onValueChange={setQuery}
          />
          <CommandList>
            {/* Empty query: preserve recent + history behavior. */}
            {isEmptyQuery && (
              <>
                {recentItems.length > 0 && (
                  <CommandGroup heading="Recently viewed">
                    {recentItems.map((item) => (
                      <CommandItem
                        key={item.path}
                        value={`recent:${item.path}`}
                        onSelect={() => closeAndNavigate(item.path)}
                      >
                        <ClockCounterClockwise size={16} className="text-text-muted" />
                        <span>{item.label}</span>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                )}
                {searchHistory.length > 0 && (
                  <>
                    {recentItems.length > 0 && <CommandSeparator />}
                    <CommandGroup heading="Recent searches">
                      {searchHistory.map((item) => (
                        <CommandItem
                          key={`${item.query}-${item.searchedAt}`}
                          value={`history:${item.query}`}
                          onSelect={() => setQuery(item.query)}
                        >
                          <MagnifyingGlass size={16} className="text-text-muted" />
                          <span>{item.query}</span>
                        </CommandItem>
                      ))}
                      <CommandItem
                        value="clear-history"
                        onSelect={() => clearHistory()}
                        className="text-text-muted"
                      >
                        <X size={16} />
                        <span>Clear search history</span>
                      </CommandItem>
                    </CommandGroup>
                  </>
                )}
                {recentItems.length === 0 && searchHistory.length === 0 && (
                  <CommandEmpty>
                    Type to search, prefix with &ldquo;&gt;&rdquo; for command mode.
                  </CommandEmpty>
                )}
              </>
            )}

            {/* Non-empty query: three groups. */}
            {!isEmptyQuery && (
              <>
                {filteredRoutes.length === 0 &&
                  filteredActions.length === 0 &&
                  (!showSearchGroup ||
                    (searchList.length === 0 && !searchResults.isFetching)) && (
                    <CommandEmpty>
                      {isCommandMode
                        ? "No matching commands"
                        : `No matches for "${rawQuery}"`}
                    </CommandEmpty>
                  )}

                {/* Navigate */}
                {filteredRoutes.length > 0 && (
                  <CommandGroup heading="Navigate">
                    {filteredRoutes.slice(0, 12).map((entry) => (
                      <CommandItem
                        key={entry.id}
                        value={`nav:${entry.id}`}
                        onSelect={() => closeAndNavigate(entry.to)}
                      >
                        {entry.icon}
                        <span>{entry.label}</span>
                        <CommandShortcut>{entry.to}</CommandShortcut>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                )}

                {/* Search */}
                {showSearchGroup && (
                  <>
                    {filteredRoutes.length > 0 && <CommandSeparator />}
                    <CommandGroup heading="Search">
                      {searchResults.isFetching && searchList.length === 0 && (
                        <CommandItem value="search:loading" disabled>
                          <MagnifyingGlass size={16} className="text-text-muted" />
                          <span className="text-text-muted">Searching…</span>
                        </CommandItem>
                      )}
                      {!searchResults.isFetching && searchList.length === 0 && (
                        <CommandItem
                          value="search:open"
                          onSelect={() =>
                            closeAndNavigate(
                              `/search?q=${encodeURIComponent(rawQuery.trim())}`,
                            )
                          }
                        >
                          <MagnifyingGlass size={16} className="text-text-muted" />
                          <span>Open full search for &ldquo;{rawQuery.trim()}&rdquo;</span>
                        </CommandItem>
                      )}
                      {searchList.map((result) => (
                        <CommandItem
                          key={`${result.entity_type}:${result.entity_id}:${result.module_id ?? "-"}`}
                          value={`search:${result.entity_type}:${result.entity_id}`}
                          onSelect={() => selectSearchResult(result)}
                        >
                          <AilaBadge
                            severity={entityTypeSeverity(result.entity_type)}
                            size="sm"
                          >
                            {entityTypeLabel(result.entity_type)}
                          </AilaBadge>
                          <span className="truncate">
                            {result.title || result.entity_id}
                          </span>
                          {result.snippet && (
                            <span className="ml-2 truncate text-text-muted">
                              {result.snippet}
                            </span>
                          )}
                        </CommandItem>
                      ))}
                      {searchList.length > 0 && (
                        <CommandItem
                          value="search:more"
                          onSelect={() =>
                            closeAndNavigate(
                              `/search?q=${encodeURIComponent(rawQuery.trim())}`,
                            )
                          }
                        >
                          <MagnifyingGlass size={16} className="text-text-muted" />
                          <span className="text-text-muted">
                            See all results…
                          </span>
                        </CommandItem>
                      )}
                    </CommandGroup>
                  </>
                )}

                {/* Actions */}
                {filteredActions.length > 0 && (
                  <>
                    {(filteredRoutes.length > 0 || showSearchGroup) && (
                      <CommandSeparator />
                    )}
                    <CommandGroup heading="Actions">
                      {filteredActions.map((action) => (
                        <CommandItem
                          key={action.id}
                          value={`action:${action.id}`}
                          onSelect={() => invokeAction(action)}
                        >
                          {action.icon}
                          <span>{action.label}</span>
                          {action.confirm?.destructive && (
                            <CommandShortcut>destructive</CommandShortcut>
                          )}
                          {!action.confirm?.destructive && action.minRole && (
                            <CommandShortcut>{action.minRole}</CommandShortcut>
                          )}
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </>
                )}
              </>
            )}

            {/* Hint footer -- only when empty state is showing a real hint */}
            {isEmptyQuery && (recentItems.length > 0 || searchHistory.length > 0) && (
              <>
                <CommandSeparator />
                <CommandGroup heading="Tips">
                  <CommandItem value="tip:command" disabled>
                    <Lightning size={16} className="text-text-muted" />
                    <span className="text-text-muted">
                      Prefix with &ldquo;&gt;&rdquo; to skip live search and see
                      only navigation + actions.
                    </span>
                  </CommandItem>
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
      </CommandDialog>

      {/* Confirm / prompt dialog for actions that need input or a
          destructive gate. Rendered outside CommandDialog so it stacks
          above the palette after the palette closes. */}
      <ActionDialog
        pending={pending}
        busy={actionBusy}
        onCancel={() => (actionBusy ? undefined : setPending(null))}
        onChange={(value) =>
          setPending((prev) => (prev ? { ...prev, input: value } : prev))
        }
        onConfirm={() => {
          if (!pending) return;
          void executeAction(pending.action, pending.input);
        }}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Confirm / prompt dialog for pending actions.
// ---------------------------------------------------------------------------

function ActionDialog({
  pending,
  busy,
  onCancel,
  onChange,
  onConfirm,
}: {
  pending: PendingAction | null;
  busy: boolean;
  onCancel: () => void;
  onChange: (value: string) => void;
  onConfirm: () => void;
}) {
  const action = pending?.action;
  const needsInput = Boolean(action?.prompt);
  const inputValid = !needsInput || (pending?.input ?? "").trim().length > 0;
  const title = action?.prompt?.title ?? action?.confirm?.title ?? action?.label ?? "";
  const body = action?.prompt?.body ?? action?.confirm?.body ?? "";
  const destructive = action?.confirm?.destructive ?? false;

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(next) => {
        if (!next && !busy) onCancel();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{body}</DialogDescription>
        </DialogHeader>
        {action?.prompt && (
          <div className="mt-2 flex flex-col gap-2">
            <label
              htmlFor="palette-action-input"
              className="font-mono text-[11px] uppercase tracking-wider text-text-muted"
            >
              {action.prompt.label}
            </label>
            <Input
              id="palette-action-input"
              value={pending?.input ?? ""}
              placeholder={action.prompt.placeholder}
              onChange={(event) => onChange(event.target.value)}
              autoFocus
              disabled={busy}
              onKeyDown={(event) => {
                if (event.key === "Enter" && inputValid && !busy) {
                  event.preventDefault();
                  onConfirm();
                }
              }}
            />
          </div>
        )}
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            onClick={onCancel}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant={destructive ? "destructive" : "default"}
            onClick={onConfirm}
            disabled={busy || !inputValid}
          >
            {busy ? "Running…" : destructive ? "Confirm" : "Run"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
