import { lazy, Suspense, type ComponentType, type ReactElement } from "react";
import { createBrowserRouter, Navigate, Outlet, useParams, type RouteObject } from "react-router";

import { AppErrorBoundary } from "@app/ErrorBoundary";
import { ProtectedRoute } from "@app/auth/ProtectedRoute";
import { AppShell } from "@app/layout/AppShell";
import { PageFrame } from "@app/layout/PageFrame";
import type { AppRole } from "@platform/auth/roles";
import { AppStateScreen } from "@platform/ui/AppStateScreen";
import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";
import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

// Route-level code-splitting: every page component below is loaded on demand
// via React.lazy so the initial shell bundle only ships the framework, the
// AppShell chrome, and the routing table. Each `import(...)` becomes its own
// Vite chunk. All pages here are NAMED exports, so we re-map to a default
// export shape (React.lazy requires `{ default: ComponentType }`). Suspense
// boundaries are already in place inside `RoutedPage` (below) for every
// protected route, and are added inline around the public login/error pages
// and the catch-all NotFoundPage.
const DocsPage = lazy(() =>
  import("@app/screens/DocsPage").then((m) => ({ default: m.DocsPage })),
);
const ForbiddenPage = lazy(() =>
  import("@app/screens/ForbiddenPage").then((m) => ({ default: m.ForbiddenPage })),
);
const LoginPage = lazy(() =>
  import("@app/screens/LoginPage").then((m) => ({ default: m.LoginPage })),
);
const NotFoundPage = lazy(() =>
  import("@app/screens/NotFoundPage").then((m) => ({ default: m.NotFoundPage })),
);
const OidcCallbackPage = lazy(() =>
  import("@app/screens/OidcCallbackPage").then((m) => ({ default: m.OidcCallbackPage })),
);
const ServerErrorPage = lazy(() =>
  import("@app/screens/ServerErrorPage").then((m) => ({ default: m.ServerErrorPage })),
);
const ApiKeysPage = lazy(() =>
  import("@platform/features/admin/ApiKeysPage").then((m) => ({ default: m.ApiKeysPage })),
);
const AuditLogsPage = lazy(() =>
  import("@platform/features/admin/AuditLogsPage").then((m) => ({ default: m.AuditLogsPage })),
);
const LLMLogPage = lazy(() =>
  import("@platform/features/admin/LLMLogPage").then((m) => ({ default: m.LLMLogPage })),
);
const ToolsConsolePage = lazy(() =>
  import("@platform/features/admin/ToolsConsolePage").then((m) => ({ default: m.ToolsConsolePage })),
);
const WorkflowInspectorPage = lazy(() =>
  import("@platform/features/admin/WorkflowInspectorPage").then((m) => ({ default: m.WorkflowInspectorPage })),
);
const OidcProvidersPage = lazy(() =>
  import("@platform/features/admin/OidcProvidersPage").then((m) => ({ default: m.OidcProvidersPage })),
);
const PlatformConfigPage = lazy(() =>
  import("@platform/features/admin/PlatformConfigPage").then((m) => ({ default: m.PlatformConfigPage })),
);
const PlatformInfraPage = lazy(() =>
  import("@platform/features/admin/PlatformInfraPage").then((m) => ({ default: m.PlatformInfraPage })),
);
const PlatformOpsPage = lazy(() =>
  import("@platform/features/admin/PlatformOpsPage").then((m) => ({ default: m.PlatformOpsPage })),
);
const MlOpsPage = lazy(() =>
  import("@platform/features/admin/MlOpsPage").then((m) => ({ default: m.MlOpsPage })),
);
const TagVocabularyPage = lazy(() =>
  import("@platform/features/admin/TagVocabularyPage").then((m) => ({ default: m.TagVocabularyPage })),
);
const SystemHealthPage = lazy(() =>
  import("@platform/features/admin/SystemHealthPage").then((m) => ({ default: m.SystemHealthPage })),
);
const TeamDetailPage = lazy(() =>
  import("@platform/features/admin/TeamDetailPage").then((m) => ({ default: m.TeamDetailPage })),
);
const TeamsPage = lazy(() =>
  import("@platform/features/admin/TeamsPage").then((m) => ({ default: m.TeamsPage })),
);
const UsersPage = lazy(() =>
  import("@platform/features/admin/UsersPage").then((m) => ({ default: m.UsersPage })),
);
const SavedFiltersPage = lazy(() =>
  import("@platform/features/admin/SavedFiltersPage").then((m) => ({ default: m.SavedFiltersPage })),
);
const TaskQueueAdminPage = lazy(() =>
  import("@platform/features/admin/TaskQueueAdminPage").then((m) => ({ default: m.TaskQueueAdminPage })),
);
const DeadLetterPage = lazy(() =>
  import("@platform/features/admin/DeadLetterPage").then((m) => ({ default: m.DeadLetterPage })),
);
const AutomationPage = lazy(() =>
  import("@platform/features/admin/AutomationPage").then((m) => ({ default: m.AutomationPage })),
);
const ScheduledReportsPage = lazy(() =>
  import("@platform/features/admin/ScheduledReportsPage").then((m) => ({ default: m.ScheduledReportsPage })),
);
const CostPage = lazy(() =>
  import("@platform/features/admin/CostPage").then((m) => ({ default: m.CostPage })),
);
const ExecutivePage = lazy(() =>
  import("@platform/features/admin/ExecutivePage").then((m) => ({ default: m.ExecutivePage })),
);
const WarRoomPage = lazy(() =>
  import("@platform/features/ops/WarRoomPage").then((m) => ({ default: m.WarRoomPage })),
);
const DashboardPage = lazy(() =>
  import("@platform/features/dashboard/DashboardPage").then((m) => ({ default: m.DashboardPage })),
);
const ScanCenterPage = lazy(() =>
  import("@platform/features/scans/ScanCenterPage").then((m) => ({ default: m.ScanCenterPage })),
);
const SystemDetailPage = lazy(() =>
  import("@platform/features/systems/SystemDetailPage").then((m) => ({ default: m.SystemDetailPage })),
);
const SystemsPage = lazy(() =>
  import("@platform/features/systems/SystemsPage").then((m) => ({ default: m.SystemsPage })),
);
const TasksPage = lazy(() =>
  import("@platform/features/tasks/TasksPage").then((m) => ({ default: m.TasksPage })),
);
const SessionsPage = lazy(() =>
  import("@platform/features/sessions/SessionsPage").then((m) => ({ default: m.SessionsPage })),
);
const ChatPage = lazy(() =>
  import("@platform/features/chat/ChatPage").then((m) => ({ default: m.ChatPage })),
);
const SettingsPage = lazy(() =>
  import("@platform/features/settings/SettingsPage").then((m) => ({ default: m.SettingsPage })),
);
const RadarPage = lazy(() =>
  import("@platform/features/radar/RadarPage").then((m) => ({ default: m.RadarPage })),
);
const TopologyPage = lazy(() =>
  import("@platform/features/topology/TopologyPage").then((m) => ({ default: m.TopologyPage })),
);
const VizPage = lazy(() =>
  import("@platform/features/viz/VizPage").then((m) => ({ default: m.VizPage })),
);
const SearchPage = lazy(() =>
  import("@platform/features/search/SearchPage").then((m) => ({ default: m.SearchPage })),
);
import { House } from "@phosphor-icons/react/dist/csr/House";
import { HardDrives } from "@phosphor-icons/react/dist/csr/HardDrives";
import { Broadcast } from "@phosphor-icons/react/dist/csr/Broadcast";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";
import { ChartLine } from "@phosphor-icons/react/dist/csr/ChartLine";
import { Terminal } from "@phosphor-icons/react/dist/csr/Terminal";
import { ListChecks } from "@phosphor-icons/react/dist/csr/ListChecks";
import { ChatCircleText } from "@phosphor-icons/react/dist/csr/ChatCircleText";
import { BookOpen } from "@phosphor-icons/react/dist/csr/BookOpen";
import { Users as UsersIcon } from "@phosphor-icons/react/dist/csr/Users";
import { Key } from "@phosphor-icons/react/dist/csr/Key";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { Wrench } from "@phosphor-icons/react/dist/csr/Wrench";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";
import { Robot } from "@phosphor-icons/react/dist/csr/Robot";
import { GearSix } from "@phosphor-icons/react/dist/csr/GearSix";
import { Tag } from "@phosphor-icons/react/dist/csr/Tag";
import { Heartbeat } from "@phosphor-icons/react/dist/csr/Heartbeat";
import { UsersThree } from "@phosphor-icons/react/dist/csr/UsersThree";
import { BookmarkSimple } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { Queue } from "@phosphor-icons/react/dist/csr/Queue";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";
import { Calendar } from "@phosphor-icons/react/dist/csr/Calendar";
import { CurrencyDollar } from "@phosphor-icons/react/dist/csr/CurrencyDollar";
import { Briefcase } from "@phosphor-icons/react/dist/csr/Briefcase";
import { Monitor } from "@phosphor-icons/react/dist/csr/Monitor";
import { PlugsConnected } from "@phosphor-icons/react/dist/csr/PlugsConnected";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { Pulse } from "@phosphor-icons/react/dist/csr/Pulse";
import { Brain } from "@phosphor-icons/react/dist/csr/Brain";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

// C2: CrashNow is a DEV-only test crash component. In production builds we
// never reference the module so Vite tree-shakes it out of the bundle.
const CrashNow: ComponentType | null = import.meta.env.DEV
  ? lazy(() =>
      import("@/testing/CrashButton").then((m) => ({ default: m.CrashNow })),
    )
  : null;

const moduleSpecs = loadModuleFrontendSpecs();

function RoutedPage({
  page: Page,
  title,
  icon,
}: {
  page: ComponentType;
  title: string;
  icon?: ReactElement;
}) {
  return (
    <PageFrame title={title} icon={icon}>
      <Suspense
        fallback={(
          <AppStateScreen
            title={`Loading ${title}`}
            message="Waiting for the module page to finish loading."
            tone="neutral"
          />
        )}
      >
        <Page />
      </Suspense>
    </PageFrame>
  );
}

function ProtectedLayout() {
  return (
    <ProtectedRoute>
      <AppShell moduleSpecs={moduleSpecs}>
        <Outlet />
      </AppShell>
    </ProtectedRoute>
  );
}

/**
 * Suspense wrapper for the handful of public / direct-render route
 * elements (login, oidc callback, 403, 500, and the catch-all 404).
 * Protected routes already receive a Suspense boundary inside
 * `RoutedPage`; this keeps the fallback consistent for the public ones
 * without any layout shift or new dependency.
 */
function LazyBoundary({
  title,
  children,
}: {
  title: string;
  children: ReactElement;
}) {
  return (
    <Suspense
      fallback={(
        <AppStateScreen
          title={`Loading ${title}`}
          message="Fetching the page module."
          tone="neutral"
        />
      )}
    >
      {children}
    </Suspense>
  );
}

/**
 * Wrap a feature route element in a per-feature AppErrorBoundary (D-23).
 *
 * The router-root boundary remains in place to catch shell errors; this
 * inner boundary catches render errors inside individual pages so the
 * shell does not unmount when a feature crashes (T-176a-02-01).
 */
function withFeatureBoundary(element: ReactElement): ReactElement {
  return <AppErrorBoundary>{element}</AppErrorBoundary>;
}

/**
 * Title-keyed icon map for platform-owned routes. Modules supply their
 * own icons via `RouteContribution.icon` (or inherit from the module's
 * first nav contribution); this map only covers the in-platform routes
 * registered statically below.
 */
const PLATFORM_PAGE_ICONS: Record<string, ReactElement> = {
  Overview: <House />,
  Systems: <HardDrives />,
  "System Detail": <HardDrives />,
  "Network Radar": <Broadcast />,
  Topology: <TreeStructure />,
  "Data Visualization": <ChartLine />,
  Console: <Terminal />,
  Tasks: <ListChecks />,
  "Task Detail": <ListChecks />,
  Chat: <ChatCircleText />,
  Docs: <BookOpen />,
  Settings: <GearSix />,
  Sessions: <Monitor />,
  Users: <UsersIcon />,
  "API Keys": <Key />,
  "Audit Logs": <ClipboardText />,
  "Tools Console": <Wrench />,
  "Workflow Inspector": <GitBranch />,
  "LLM Log": <Robot />,
  "Platform Config": <GearSix />,
  "Platform Ops": <Wrench />,
  "ML Ops": <Brain />,
  "Platform Infra": <PlugsConnected />,
  "Tag Vocabulary": <Tag />,
  "System Health": <Heartbeat />,
  "OIDC Providers": <Key />,
  Teams: <UsersThree />,
  "Team Detail": <UsersThree />,
  "Saved Filters": <BookmarkSimple />,
  "Task Queue": <Queue />,
  "Dead Letter Queue": <Skull />,
  "Automation Schedules": <Robot />,
  "Scheduled Reports": <Calendar />,
  "Cost Intelligence": <CurrencyDollar />,
  "Executive Dashboard": <Briefcase />,
  "War Room": <Pulse />,
  "Not Found": <Warning />,
  Search: <MagnifyingGlass />,
};

function protectPage(
  title: string,
  Page: ComponentType,
  requiredRole?: AppRole,
  icon?: ReactElement,
) {
  const resolvedIcon = icon ?? PLATFORM_PAGE_ICONS[title];
  return withFeatureBoundary(
    <ProtectedRoute requiredRole={requiredRole}>
      <RoutedPage page={Page} title={title} icon={resolvedIcon} />
    </ProtectedRoute>,
  );
}

function normalizeModulePath(pathname: string): string {
  return pathname.replace(/^\/+/, "").replace(/\/+$/, "");
}

function buildModuleRouteObjects(specs: ModuleFrontendSpec[]): RouteObject[] {
  return specs.flatMap((spec) => {
    // Inherit the module's primary nav icon when an individual route
    // didn't supply its own -- keeps all `/vr/*` detail pages on the
    // Briefcase icon, all `/forensics/*` on Detective, etc.
    const fallbackIcon = spec.nav?.find((n) => n.icon)?.icon ?? undefined;
    return (spec.routes ?? []).map((route) => {
      const IconComponent = route.icon ?? fallbackIcon;
      const icon = IconComponent ? <IconComponent /> : undefined;
      return {
        id: route.id,
        path: normalizeModulePath(route.path),
        // Each contributed module route also gets its own feature-level boundary.
        element: protectPage(route.title, route.page, route.minRole, icon),
        handle: route.breadcrumb ? { breadcrumb: route.breadcrumb } : undefined,
      };
    });
  });
}

// Test-only crash route (preflight FE-H / D-23). Gated behind Vite DEV so
// production bundles never register it. Lazy-loaded via Suspense so
// CrashButton is NEVER imported in prod (C2).
const testOnlyRoutes: RouteObject[] = import.meta.env.DEV && CrashNow
  ? [
      {
        path: "__test__/crash",
        element: withFeatureBoundary(
          <PageFrame title="Crash Test">
            <Suspense fallback={null}>
              <CrashNow />
            </Suspense>
          </PageFrame>,
        ),
      },
    ]
  : [];

/**
 * C-M7: preserve the sub-path when redirecting legacy /scans/* URLs to
 * /console. A bare `<Navigate to="/console" replace />` dropped everything
 * after `/scans/`, so bookmarks like `/scans/abc-run-id` lost their run id.
 */
function ScansRedirect() {
  const params = useParams();
  const rest = params["*"] ?? "";
  return <Navigate to={`/console${rest ? `/${rest}` : ""}`} replace />;
}

export const routeObjects: RouteObject[] = [
  {
    path: "/login",
    element: <LazyBoundary title="Sign In"><LoginPage /></LazyBoundary>,
  },
  {
    // OIDC callback -- public, no ProtectedRoute (T-140-08)
    path: "/auth/callback",
    element: <LazyBoundary title="Sign In"><OidcCallbackPage /></LazyBoundary>,
  },
  {
    // 403 page -- public (redirected here from ProtectedRoute on role failure)
    path: "/403",
    element: <LazyBoundary title="Forbidden"><ForbiddenPage /></LazyBoundary>,
  },
  {
    // 500 page -- public direct navigation
    path: "/500",
    element: <LazyBoundary title="Server Error"><ServerErrorPage /></LazyBoundary>,
  },
  {
    path: "/",
    element: (
      <AppErrorBoundary>
        <ProtectedLayout />
      </AppErrorBoundary>
    ),
    children: [
      {
        // Chat is the primary surface: the operator lands on the
        // platform assistant, which routes natural-language requests
        // through platform.handle() across every module.
        index: true,
        element: protectPage("Home", ChatPage),
        handle: { breadcrumb: "Home" },
      },
      {
        path: "dashboard",
        element: protectPage("Overview", DashboardPage),
        handle: { breadcrumb: "Dashboard" },
      },
      {
        path: "systems",
        element: protectPage("Systems", SystemsPage),
        handle: { breadcrumb: "Systems" },
      },
      {
        path: "systems/:systemId",
        element: protectPage("System Detail", SystemDetailPage),
        handle: { breadcrumb: "System Detail" },
      },
      {
        path: "radar",
        element: protectPage("Network Radar", RadarPage, "operator"),
        handle: { breadcrumb: "Radar" },
      },
      {
        path: "topology",
        element: protectPage("Topology", TopologyPage, "operator"),
        handle: { breadcrumb: "Topology" },
      },
      {
        path: "viz",
        element: protectPage("Data Visualization", VizPage),
        handle: { breadcrumb: "Data Visualization" },
      },
      // D-01 rename: Scans → Console.
      // /console is the live route; /scans* redirects preserved for old bookmarks (D-14).
      {
        path: "console",
        element: protectPage("Console", ScanCenterPage),
        handle: { breadcrumb: "Console" },
      },
      {
        path: "console/:runId",
        element: protectPage("Console", ScanCenterPage),
        handle: { breadcrumb: "Console Detail" },
      },
      {
        path: "scans",
        element: <Navigate to="/console" replace />,
      },
      {
        path: "scans/*",
        element: <ScansRedirect />,
      },
      {
        path: "tasks",
        element: protectPage("Tasks", TasksPage),
        handle: { breadcrumb: "Tasks" },
      },
      // Chat is now the index/home surface; keep /chat as a redirect
      // so existing links and the prior nav entry still resolve.
      {
        path: "chat",
        element: <Navigate to="/" replace />,
      },
      {
        path: "tasks/:taskId",
        // Detail view reuses TasksPage which consumes the ?task= search param; :taskId navigation
        // lands on the list page with the selected row (minimal scaffold per plan Task 1 Step 4).
        element: protectPage("Task Detail", TasksPage),
        handle: { breadcrumb: "Task Detail" },
      },
      // D-03: Docs tab.
      {
        path: "docs",
        element: protectPage("Docs", DocsPage),
        handle: { breadcrumb: "Docs" },
      },
      {
        path: "admin/users",
        element: protectPage("Users", UsersPage, "admin"),
        handle: { breadcrumb: "Users" },
      },
      {
        path: "admin/api-keys",
        element: protectPage("API Keys", ApiKeysPage, "admin"),
        handle: { breadcrumb: "API Keys" },
      },
      {
        path: "admin/audit",
        element: protectPage("Audit Logs", AuditLogsPage, "admin"),
        handle: { breadcrumb: "Audit Logs" },
      },
      {
        path: "admin/tools",
        element: protectPage("Tools Console", ToolsConsolePage, "operator"),
        handle: { breadcrumb: "Tools Console" },
      },
      {
        path: "admin/workflows",
        element: protectPage("Workflow Inspector", WorkflowInspectorPage, "admin"),
        handle: { breadcrumb: "Workflow Inspector" },
      },
      {
        path: "admin/llm-log",
        element: protectPage("LLM Log", LLMLogPage, "admin"),
        handle: { breadcrumb: "LLM Log" },
      },
      {
        path: "admin/config",
        element: protectPage("Platform Config", PlatformConfigPage, "admin"),
        handle: { breadcrumb: "Platform Config" },
      },
      {
        path: "admin/platform-ops",
        element: protectPage("Platform Ops", PlatformOpsPage, "admin"),
        handle: { breadcrumb: "Platform Ops" },
      },
      {
        path: "admin/ml-ops",
        element: protectPage("ML Ops", MlOpsPage, "admin"),
        handle: { breadcrumb: "ML Ops" },
      },
      {
        path: "admin/platform-infra",
        element: protectPage("Platform Infra", PlatformInfraPage, "admin"),
        handle: { breadcrumb: "Platform Infra" },
      },
      {
        path: "admin/tags",
        element: protectPage("Tag Vocabulary", TagVocabularyPage, "admin"),
        handle: { breadcrumb: "Tag Vocabulary" },
      },
      {
        path: "admin/health",
        element: protectPage("System Health", SystemHealthPage, "admin"),
        handle: { breadcrumb: "System Health" },
      },
      {
        path: "admin/auth/oidc-providers",
        element: protectPage("OIDC Providers", OidcProvidersPage, "admin"),
        handle: { breadcrumb: "OIDC Providers" },
      },
      {
        path: "admin/teams",
        element: protectPage("Teams", TeamsPage, "admin"),
        handle: { breadcrumb: "Teams" },
      },
      {
        path: "admin/teams/:id",
        element: protectPage("Team Detail", TeamDetailPage, "admin"),
        handle: { breadcrumb: "Team Detail" },
      },
      {
        path: "admin/saved-filters",
        element: protectPage("Saved Filters", SavedFiltersPage, "admin"),
        handle: { breadcrumb: "Saved Filters" },
      },
      {
        path: "admin/task-queue",
        element: protectPage("Task Queue", TaskQueueAdminPage, "admin"),
        handle: { breadcrumb: "Task Queue" },
      },
      {
        path: "admin/dead-letter",
        element: protectPage("Dead Letter Queue", DeadLetterPage, "admin"),
        handle: { breadcrumb: "Dead Letter" },
      },
      {
        path: "admin/automation",
        element: protectPage("Automation Schedules", AutomationPage),
        handle: { breadcrumb: "Automation" },
      },
      {
        path: "admin/scheduled-reports",
        element: protectPage("Scheduled Reports", ScheduledReportsPage, "admin"),
        handle: { breadcrumb: "Scheduled Reports" },
      },
      {
        path: "admin/cost",
        element: protectPage("Cost Intelligence", CostPage, "admin"),
        handle: { breadcrumb: "Cost" },
      },
      {
        path: "admin/executive",
        element: protectPage("Executive Dashboard", ExecutivePage, "admin"),
        handle: { breadcrumb: "Executive" },
      },
      {
        path: "ops",
        element: protectPage("War Room", WarRoomPage),
        handle: { breadcrumb: "War Room" },
      },
      {
        path: "settings",
        element: protectPage("Settings", SettingsPage),
        handle: { breadcrumb: "Settings" },
      },
      {
        path: "settings/sessions",
        element: protectPage("Sessions", SessionsPage),
        handle: { breadcrumb: "Sessions" },
      },
      {
        path: "findings",
        element: <Navigate to="/vulnerability/findings" replace />,
      },
      {
        path: "search",
        element: protectPage("Search", SearchPage),
        handle: { breadcrumb: "Search" },
      },
      ...testOnlyRoutes,
      ...buildModuleRouteObjects(moduleSpecs),
      {
        path: "*",
        element: (
          <PageFrame title="Not Found">
            <LazyBoundary title="Not Found">
              <NotFoundPage />
            </LazyBoundary>
          </PageFrame>
        ),
      },
    ],
  },
  {
    path: "*",
    element: <Navigate to="/" replace />,
  },
];

export const appRouter = createBrowserRouter(routeObjects);
