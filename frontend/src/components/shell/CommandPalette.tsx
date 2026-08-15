import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";

import { Desktop } from "@phosphor-icons/react/dist/csr/Desktop";
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
import { SignOut } from "@phosphor-icons/react/dist/csr/SignOut";

import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { toast } from "@/components/ui/sonner";

import { ApiHttpError, authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { isAllowedRole, type AppRole } from "@platform/auth/roles";
import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";

import { useRecentlyViewed } from "@/hooks/useRecentlyViewed";
import { useSearchHistory } from "@/hooks/useSearchHistory";
import {
  parseEntityJump,
  resolveEntityJumpTargets,
  shortId,
  useRecentEntities,
  useRecordEntityVisit,
} from "@/lib/recentEntities";

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

/** One selectable (or disabled-informational) row in the flat palette list. */
interface PaletteRow {
  key: string;
  onSelect?: () => void;
  disabled?: boolean;
  render: () => React.ReactNode;
}

interface PaletteSection {
  heading: string;
  rows: PaletteRow[];
}

// ---------------------------------------------------------------------------
// Static platform routes exposed in Navigate. Detail routes with :params
// are intentionally omitted -- the Search group is how you land on a row.
// ---------------------------------------------------------------------------

const PLATFORM_ROUTES: readonly NavEntry[] = [
  { id: "nav.chat", label: "Chat", to: "/", icon: <ChatCircleDots size={14} />, section: "platform" },
  { id: "nav.dashboard", label: "Dashboard", to: "/dashboard", icon: <Gauge size={14} />, section: "platform" },
  { id: "nav.systems", label: "Systems", to: "/systems", icon: <Desktop size={14} />, section: "platform" },
  { id: "nav.radar", label: "Network Radar", to: "/radar", icon: <ChartBar size={14} />, section: "platform", minRole: "operator" },
  { id: "nav.viz", label: "Data Visualization", to: "/viz", icon: <ChartBar size={14} />, section: "platform" },
  { id: "nav.console", label: "Console", to: "/console", icon: <Crosshair size={14} />, section: "platform" },
  { id: "nav.tasks", label: "Tasks", to: "/tasks", icon: <ClipboardText size={14} />, section: "platform" },
  { id: "nav.docs", label: "Docs", to: "/docs", icon: <FileText size={14} />, section: "platform" },
  { id: "nav.search", label: "Search", to: "/search", icon: <MagnifyingGlass size={14} />, section: "platform" },
  { id: "nav.settings", label: "Settings", to: "/settings", icon: <ClipboardText size={14} />, section: "platform" },
  { id: "nav.sessions", label: "Sessions", to: "/settings/sessions", icon: <ClipboardText size={14} />, section: "platform" },
  { id: "nav.admin.users", label: "Users", to: "/admin/users", icon: <ClipboardText size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.api-keys", label: "API Keys", to: "/admin/api-keys", icon: <Key size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.audit", label: "Audit Logs", to: "/admin/audit", icon: <FileText size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.tools", label: "Tools Console", to: "/admin/tools", icon: <Wrench size={14} />, section: "admin", minRole: "operator" },
  { id: "nav.admin.workflows", label: "Workflow Inspector", to: "/admin/workflows", icon: <Compass size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.llm-log", label: "LLM Log", to: "/admin/llm-log", icon: <Files size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.config", label: "Platform Config", to: "/admin/config", icon: <Wrench size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.platform-ops", label: "Platform Ops", to: "/admin/platform-ops", icon: <Wrench size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.tags", label: "Tag Vocabulary", to: "/admin/tags", icon: <ClipboardText size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.health", label: "System Health", to: "/admin/health", icon: <ShieldWarning size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.oidc", label: "OIDC Providers", to: "/admin/auth/oidc-providers", icon: <Key size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.teams", label: "Teams", to: "/admin/teams", icon: <ClipboardText size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.saved-filters", label: "Saved Filters", to: "/admin/saved-filters", icon: <ClipboardText size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.task-queue", label: "Task Queue", to: "/admin/task-queue", icon: <ClipboardText size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.dead-letter", label: "Dead Letter Queue", to: "/admin/dead-letter", icon: <Skull size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.automation", label: "Automation Schedules", to: "/admin/automation", icon: <ArrowsCounterClockwise size={14} />, section: "admin" },
  { id: "nav.admin.scheduled-reports", label: "Scheduled Reports", to: "/admin/scheduled-reports", icon: <Calendar size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.cost", label: "Cost Intelligence", to: "/admin/cost", icon: <ChartBar size={14} />, section: "admin", minRole: "admin" },
  { id: "nav.admin.executive", label: "Executive Dashboard", to: "/admin/executive", icon: <ChartBar size={14} />, section: "admin", minRole: "admin" },
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
        icon: <ArrowSquareOut size={14} />,
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
    icon: <Crosshair size={14} />,
    run: ({ navigate }) => {
      navigate("/console?new=1");
    },
  },
  {
    id: "action.new-chat",
    label: "New chat session",
    description: "Create a session and jump into Chat",
    icon: <PlusCircle size={14} />,
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
    icon: <Calendar size={14} />,
    minRole: "admin",
    run: ({ navigate }) => {
      navigate("/admin/scheduled-reports");
    },
  },
  {
    id: "action.drain-queue",
    label: "Drain task queue",
    description: "Pause new submissions to the task queue",
    icon: <Pause size={14} />,
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
    icon: <ArrowsCounterClockwise size={14} />,
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
    icon: <Files size={14} />,
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
    icon: <Skull size={14} />,
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
    icon: <Wrench size={14} />,
    minRole: "admin",
    prompt: {
      title: "Reconcile task",
      body: "Runs one StateReconciler.reconcile() pass for the given task_id. Idempotent -- a consistent row returns healed=false.",
      label: "Task ID",
      placeholder: "e.g. 01HZ9M\u2026",
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
    id: "action.sign-out",
    label: "Sign out",
    description: "End the current session",
    icon: <SignOut size={14} />,
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
// Presentation primitives -- shared by every row renderer.
// ---------------------------------------------------------------------------

const ROW_STYLE_BASE: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  width: "100%",
  minHeight: 30,
  padding: "0 12px",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  letterSpacing: "0.02em",
  color: "var(--text-primary)",
  background: "transparent",
  border: 0,
  borderLeft: "2px solid transparent",
  cursor: "pointer",
  textAlign: "left",
};

function ShortcutLabel({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="font-mono uppercase"
      style={{
        marginLeft: "auto",
        fontSize: 9,
        letterSpacing: "0.1em",
        color: "var(--text-faint)",
        maxWidth: 220,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const navigate = useNavigate();
  const { items: recentItems } = useRecentlyViewed();
  const { items: searchHistory, addSearch, clearHistory } = useSearchHistory();
  const { items: recentEntities, clear: clearRecentEntitiesList } =
    useRecentEntities();
  // Record entity/detail-route visits once, at the always-mounted palette.
  // Mounting here avoids editing AppShell while still covering every route.
  useRecordEntityVisit();
  const role = useAuthStore((s) => s.role);

  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

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

  useEffect(() => {
    if (open) {
      // Focus the input once the dialog paints.
      const raf = window.requestAnimationFrame(() => inputRef.current?.focus());
      return () => window.cancelAnimationFrame(raf);
    }
    return undefined;
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
      // Local overrides for actions that use React-hook APIs (auth).
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
    [executeAction, navigate],
  );

  // ---------------------------------------------------------------------------
  // Selection helpers.
  // ---------------------------------------------------------------------------
  const closeAndNavigate = useCallback(
    (url: string) => {
      navigate(url);
      setOpen(false);
    },
    [navigate],
  );

  const selectSearchResult = useCallback(
    (result: SearchResult) => {
      addSearch(rawQuery.trim());
      closeAndNavigate(entityRoute(result));
    },
    [addSearch, closeAndNavigate, rawQuery],
  );

  // ---------------------------------------------------------------------------
  // Derived flags.
  // ---------------------------------------------------------------------------
  const isEmptyQuery = query === "";
  const searchList = searchResults.data?.results ?? [];
  const showSearchGroup = !isCommandMode && debouncedSearch.length >= 2;
  // Entity-jump: `#<id>` / `#<type> <id>` / bare id-looking token. Suppressed
  // in command mode (`>`), which is reserved for nav + actions only.
  const entityJump = useMemo(
    () => (isCommandMode ? null : parseEntityJump(rawQuery)),
    [isCommandMode, rawQuery],
  );
  const jumpTargets = useMemo(
    () => (entityJump ? resolveEntityJumpTargets(entityJump) : []),
    [entityJump],
  );
  const showJumpGroup = !isEmptyQuery && jumpTargets.length > 0;
  const placeholderText = isCommandMode
    ? "> Command\u2026"
    : "Navigate, search, or run an action\u2026";

  // ---------------------------------------------------------------------------
  // Row assembly. Each PaletteRow encapsulates a render function and (if
  // selectable) an onSelect. `sections` drives the grouped render; the flat
  // list of selectable rows drives keyboard navigation.
  // ---------------------------------------------------------------------------
  const sections = useMemo<PaletteSection[]>(() => {
    const out: PaletteSection[] = [];

    if (isEmptyQuery) {
      if (recentEntities.length > 0) {
        const rows: PaletteRow[] = recentEntities.map((entity) => ({
          key: `recent-entity:${entity.path}`,
          onSelect: () => closeAndNavigate(entity.path),
          render: () => (
            <>
              <MonoBadge tone="info">{entity.type}</MonoBadge>
              <span
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {entity.title}
              </span>
              <ShortcutLabel>{shortId(entity.id)}</ShortcutLabel>
            </>
          ),
        }));
        rows.push({
          key: "recent-entity:clear",
          onSelect: () => clearRecentEntitiesList(),
          render: () => (
            <>
              <X size={14} style={{ color: "var(--text-faint)" }} />
              <span style={{ color: "var(--text-muted)" }}>
                Clear recent entities
              </span>
            </>
          ),
        });
        out.push({ heading: "Recent", rows });
      }

      if (recentItems.length > 0) {
        out.push({
          heading: "Recently viewed",
          rows: recentItems.map((item) => ({
            key: `recent:${item.path}`,
            onSelect: () => closeAndNavigate(item.path),
            render: () => (
              <>
                <ClockCounterClockwise
                  size={14}
                  style={{ color: "var(--text-faint)" }}
                />
                <span>{item.label}</span>
              </>
            ),
          })),
        });
      }

      if (searchHistory.length > 0) {
        const rows: PaletteRow[] = searchHistory.map((item) => ({
          key: `history:${item.query}`,
          onSelect: () => setQuery(item.query),
          render: () => (
            <>
              <MagnifyingGlass
                size={14}
                style={{ color: "var(--text-faint)" }}
              />
              <span>{item.query}</span>
            </>
          ),
        }));
        rows.push({
          key: "clear-history",
          onSelect: () => clearHistory(),
          render: () => (
            <>
              <X size={14} style={{ color: "var(--text-faint)" }} />
              <span style={{ color: "var(--text-muted)" }}>
                Clear search history
              </span>
            </>
          ),
        });
        out.push({ heading: "Recent searches", rows });
      }

      if (
        recentEntities.length > 0 ||
        recentItems.length > 0 ||
        searchHistory.length > 0
      ) {
        out.push({
          heading: "Tips",
          rows: [
            {
              key: "tip:command",
              disabled: true,
              render: () => (
                <>
                  <Lightning
                    size={14}
                    style={{ color: "var(--text-faint)" }}
                  />
                  <span style={{ color: "var(--text-muted)" }}>
                    Prefix with &ldquo;&gt;&rdquo; to skip live search and see
                    only navigation + actions.
                  </span>
                </>
              ),
            },
          ],
        });
      }
    } else {
      if (showJumpGroup && entityJump) {
        out.push({
          heading: "Jump to",
          rows: jumpTargets.map((target) => ({
            key: `jump:${target.type}:${entityJump.id}`,
            onSelect: () => closeAndNavigate(target.build(entityJump.id)),
            render: () => (
              <>
                <ArrowSquareOut size={14} />
                <span>
                  Open {target.label} {shortId(entityJump.id)}
                </span>
                <ShortcutLabel>{target.build(entityJump.id)}</ShortcutLabel>
              </>
            ),
          })),
        });
      }

      if (filteredRoutes.length > 0) {
        out.push({
          heading: "Navigate",
          rows: filteredRoutes.slice(0, 12).map((entry) => ({
            key: `nav:${entry.id}`,
            onSelect: () => closeAndNavigate(entry.to),
            render: () => (
              <>
                {entry.icon}
                <span>{entry.label}</span>
                <ShortcutLabel>{entry.to}</ShortcutLabel>
              </>
            ),
          })),
        });
      }

      if (showSearchGroup) {
        const rows: PaletteRow[] = [];
        if (searchResults.isFetching && searchList.length === 0) {
          rows.push({
            key: "search:loading",
            disabled: true,
            render: () => (
              <>
                <MagnifyingGlass
                  size={14}
                  style={{ color: "var(--text-faint)" }}
                />
                <span style={{ color: "var(--text-muted)" }}>Searching\u2026</span>
              </>
            ),
          });
        } else if (!searchResults.isFetching && searchList.length === 0) {
          rows.push({
            key: "search:open",
            onSelect: () =>
              closeAndNavigate(
                `/search?q=${encodeURIComponent(rawQuery.trim())}`,
              ),
            render: () => (
              <>
                <MagnifyingGlass
                  size={14}
                  style={{ color: "var(--text-faint)" }}
                />
                <span>
                  Open full search for &ldquo;{rawQuery.trim()}&rdquo;
                </span>
              </>
            ),
          });
        }
        for (const result of searchList) {
          rows.push({
            key: `search:${result.entity_type}:${result.entity_id}:${result.module_id ?? "-"}`,
            onSelect: () => selectSearchResult(result),
            render: () => (
              <>
                <MonoBadge
                  tone={
                    entityTypeSeverity(result.entity_type) === "neutral"
                      ? "muted"
                      : entityTypeSeverity(result.entity_type)
                  }
                >
                  {entityTypeLabel(result.entity_type)}
                </MonoBadge>
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {result.title || result.entity_id}
                </span>
                {result.snippet && (
                  <span
                    style={{
                      marginLeft: 8,
                      color: "var(--text-muted)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {result.snippet}
                  </span>
                )}
              </>
            ),
          });
        }
        if (searchList.length > 0) {
          rows.push({
            key: "search:more",
            onSelect: () =>
              closeAndNavigate(
                `/search?q=${encodeURIComponent(rawQuery.trim())}`,
              ),
            render: () => (
              <>
                <MagnifyingGlass
                  size={14}
                  style={{ color: "var(--text-faint)" }}
                />
                <span style={{ color: "var(--text-muted)" }}>
                  See all results\u2026
                </span>
              </>
            ),
          });
        }
        out.push({ heading: "Search", rows });
      }

      if (filteredActions.length > 0) {
        out.push({
          heading: "Actions",
          rows: filteredActions.map((action) => ({
            key: `action:${action.id}`,
            onSelect: () => invokeAction(action),
            render: () => (
              <>
                {action.icon}
                <span>{action.label}</span>
                {action.confirm?.destructive ? (
                  <ShortcutLabel>destructive</ShortcutLabel>
                ) : action.minRole ? (
                  <ShortcutLabel>{action.minRole}</ShortcutLabel>
                ) : null}
              </>
            ),
          })),
        });
      }
    }

    return out;
  }, [
    clearHistory,
    clearRecentEntitiesList,
    closeAndNavigate,
    entityJump,
    filteredActions,
    filteredRoutes,
    invokeAction,
    isEmptyQuery,
    jumpTargets,
    rawQuery,
    recentEntities,
    recentItems,
    searchHistory,
    searchList,
    searchResults.isFetching,
    selectSearchResult,
    showJumpGroup,
    showSearchGroup,
  ]);

  const selectableRows = useMemo(
    () =>
      sections.flatMap((s) => s.rows).filter((row) => !row.disabled && row.onSelect),
    [sections],
  );

  const totalRowCount = selectableRows.length;

  const isEmptyResults =
    !isEmptyQuery &&
    filteredRoutes.length === 0 &&
    filteredActions.length === 0 &&
    !showJumpGroup &&
    (!showSearchGroup ||
      (searchList.length === 0 && !searchResults.isFetching));

  const isCompletelyEmpty =
    isEmptyQuery &&
    recentEntities.length === 0 &&
    recentItems.length === 0 &&
    searchHistory.length === 0;

  // Keep selected row valid across query changes.
  useEffect(() => {
    if (totalRowCount === 0) {
      setSelectedKey(null);
      return;
    }
    if (!selectedKey || !selectableRows.some((r) => r.key === selectedKey)) {
      setSelectedKey(selectableRows[0]!.key);
    }
  }, [selectableRows, selectedKey, totalRowCount]);

  // Scroll the highlighted row into view.
  useEffect(() => {
    if (!selectedKey || !listRef.current) return;
    const el = listRef.current.querySelector(
      `[data-row-key="${CSS.escape(selectedKey)}"]`,
    ) as HTMLElement | null;
    el?.scrollIntoView({ block: "nearest" });
  }, [selectedKey]);

  const move = useCallback(
    (delta: 1 | -1) => {
      if (selectableRows.length === 0) return;
      const idx = Math.max(
        0,
        selectableRows.findIndex((r) => r.key === selectedKey),
      );
      const next =
        (idx + delta + selectableRows.length) % selectableRows.length;
      setSelectedKey(selectableRows[next]!.key);
    },
    [selectableRows, selectedKey],
  );

  const submit = useCallback(() => {
    const row = selectableRows.find((r) => r.key === selectedKey);
    row?.onSelect?.();
  }, [selectableRows, selectedKey]);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        move(1);
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        move(-1);
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        submit();
      }
    },
    [move, submit],
  );

  return (
    <>
      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Command palette"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setOpen(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 100,
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "center",
            padding: "12vh 16px 16px",
            background:
              "color-mix(in srgb, var(--surface-page) 82%, transparent)",
            backdropFilter: "blur(2px)",
          }}
        >
          <div
            style={{ width: "100%", maxWidth: 640 }}
            onMouseDown={(event) => event.stopPropagation()}
            onKeyDown={onKeyDown}
          >
            <WindowPanel
              title="command"
              tone="accent"
              flush
              status={
                isCompletelyEmpty
                  ? "type to search / \u203a command mode / # id jump"
                  : `${totalRowCount} match${totalRowCount === 1 ? "" : "es"}`
              }
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "8px 10px",
                  borderBottom: "1px solid var(--border-faint)",
                  background: "var(--surface-sunk)",
                }}
              >
                <MagnifyingGlass
                  size={14}
                  style={{ color: "var(--text-faint)", flex: "0 0 auto" }}
                />
                <input
                  ref={inputRef}
                  type="text"
                  placeholder={placeholderText}
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  aria-label="Command palette search"
                  style={{
                    flex: 1,
                    height: 26,
                    padding: 0,
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    letterSpacing: "0.02em",
                    color: "var(--text-primary)",
                    background: "transparent",
                    border: 0,
                    outline: "none",
                  }}
                />
                <button
                  type="button"
                  aria-label="Close command palette"
                  onClick={() => setOpen(false)}
                  className="font-mono uppercase"
                  style={{
                    height: 22,
                    padding: "0 8px",
                    fontSize: 9,
                    letterSpacing: "0.1em",
                    color: "var(--text-faint)",
                    background: "transparent",
                    border: "1px solid var(--border-soft)",
                    borderRadius: 3,
                    cursor: "pointer",
                  }}
                >
                  ESC
                </button>
              </div>

              <div
                ref={listRef}
                role="listbox"
                aria-label="Command palette results"
                style={{
                  maxHeight: "60vh",
                  overflowY: "auto",
                  padding: "6px 0",
                }}
              >
                {isEmptyResults ? (
                  <EmptyMessage>
                    {isCommandMode
                      ? "No matching commands"
                      : `No matches for "${rawQuery}"`}
                  </EmptyMessage>
                ) : isCompletelyEmpty ? (
                  <EmptyMessage>
                    Type to search, prefix with &ldquo;&gt;&rdquo; for command
                    mode or &ldquo;#&rdquo; to jump to an id.
                  </EmptyMessage>
                ) : (
                  sections.map((section) => (
                    <section key={section.heading} style={{ paddingBottom: 4 }}>
                      <div
                        className="font-mono uppercase"
                        style={{
                          padding: "8px 12px 4px",
                          fontSize: 9,
                          letterSpacing: "0.14em",
                          color: "var(--text-faint)",
                        }}
                      >
                        {section.heading}
                      </div>
                      {section.rows.map((row) => {
                        const active = row.key === selectedKey;
                        const disabled = row.disabled;
                        return (
                          <button
                            type="button"
                            role="option"
                            aria-selected={active}
                            key={row.key}
                            data-row-key={row.key}
                            disabled={disabled}
                            onMouseEnter={() => {
                              if (!disabled) setSelectedKey(row.key);
                            }}
                            onClick={() => {
                              if (!disabled) row.onSelect?.();
                            }}
                            style={{
                              ...ROW_STYLE_BASE,
                              cursor: disabled ? "default" : "pointer",
                              background: active
                                ? "var(--surface-hover)"
                                : "transparent",
                              borderLeft: active
                                ? "2px solid var(--accent)"
                                : "2px solid transparent",
                            }}
                          >
                            {row.render()}
                          </button>
                        );
                      })}
                    </section>
                  ))
                )}
              </div>
            </WindowPanel>
          </div>
        </div>
      )}

      {/* Confirm / prompt dialog for actions that need input or a
          destructive gate. Rendered outside the palette so it stacks
          above after the palette closes. */}
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
// Empty-state message inside the results scroller.
// ---------------------------------------------------------------------------

function EmptyMessage({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        padding: "24px 16px",
        textAlign: "center",
        fontSize: 10.5,
        color: "var(--text-muted)",
        letterSpacing: "0.02em",
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Confirm / prompt dialog for pending actions.
// ---------------------------------------------------------------------------

const ACTION_BUTTON_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 12px",
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 30,
  fontSize: 11,
  padding: "0 10px",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  fontFamily: "var(--font-mono)",
  width: "100%",
};

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
  const title =
    action?.prompt?.title ?? action?.confirm?.title ?? action?.label ?? "";
  const body = action?.prompt?.body ?? action?.confirm?.body ?? "";
  const destructive = action?.confirm?.destructive ?? false;

  useEffect(() => {
    if (!pending) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onCancel();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pending, busy, onCancel]);

  if (!pending || !action) return null;

  const confirmColor = destructive ? "var(--status-warn)" : "var(--accent)";

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 110,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        padding: "18vh 16px 16px",
        background:
          "color-mix(in srgb, var(--surface-page) 82%, transparent)",
        backdropFilter: "blur(2px)",
      }}
    >
      <div
        style={{ width: "100%", maxWidth: 480 }}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <WindowPanel
          title={destructive ? "confirm \u00b7 destructive" : "confirm"}
          tone={destructive ? "warn" : "accent"}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div
              className="font-mono uppercase"
              style={{
                fontSize: 12,
                letterSpacing: "0.06em",
                color: "var(--text-primary)",
              }}
            >
              {title}
            </div>
            <div
              className="font-mono"
              style={{
                fontSize: 11,
                lineHeight: 1.55,
                color: "var(--text-muted)",
                letterSpacing: "0.02em",
              }}
            >
              {body}
            </div>

            {action.prompt && (
              <div
                style={{ display: "flex", flexDirection: "column", gap: 6 }}
              >
                <label
                  htmlFor="palette-action-input"
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9.5,
                    letterSpacing: "0.14em",
                    color: "var(--text-faint)",
                  }}
                >
                  {action.prompt.label}
                </label>
                <input
                  id="palette-action-input"
                  type="text"
                  value={pending.input}
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
                  style={INPUT_STYLE}
                />
              </div>
            )}

            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: 8,
                paddingTop: 4,
              }}
            >
              <button
                type="button"
                onClick={onCancel}
                disabled={busy}
                style={ACTION_BUTTON_STYLE}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={onConfirm}
                disabled={busy || !inputValid}
                style={{
                  ...ACTION_BUTTON_STYLE,
                  color: confirmColor,
                  border: `1px solid ${confirmColor}`,
                  background: `color-mix(in srgb, ${confirmColor} 10%, transparent)`,
                  opacity: busy || !inputValid ? 0.6 : 1,
                }}
              >
                {busy ? "Running\u2026" : destructive ? "Confirm" : "Run"}
              </button>
            </div>
          </div>
        </WindowPanel>
      </div>
    </div>
  );
}
