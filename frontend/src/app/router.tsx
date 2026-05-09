import { lazy, Suspense, type ComponentType, type ReactElement } from "react";
import { createBrowserRouter, Navigate, Outlet, useParams, type RouteObject } from "react-router";

import { AppErrorBoundary } from "@app/ErrorBoundary";
import { ProtectedRoute } from "@app/auth/ProtectedRoute";
import { AppShell } from "@app/layout/AppShell";
import { PageFrame } from "@app/layout/PageFrame";
import { DocsPage } from "@app/screens/DocsPage";
import { ForbiddenPage } from "@app/screens/ForbiddenPage";
import { LoginPage } from "@app/screens/LoginPage";
import { NotFoundPage } from "@app/screens/NotFoundPage";
import { OidcCallbackPage } from "@app/screens/OidcCallbackPage";
import { ServerErrorPage } from "@app/screens/ServerErrorPage";
import type { AppRole } from "@platform/auth/roles";
import { ApiKeysPage } from "@platform/features/admin/ApiKeysPage";
import { AuditLogsPage } from "@platform/features/admin/AuditLogsPage";
import { LLMLogPage } from "@platform/features/admin/LLMLogPage";
import { ToolsConsolePage } from "@platform/features/admin/ToolsConsolePage";
import { WorkflowInspectorPage } from "@platform/features/admin/WorkflowInspectorPage";
import { OidcProvidersPage } from "@platform/features/admin/OidcProvidersPage";
import { PlatformConfigPage } from "@platform/features/admin/PlatformConfigPage";
import { TagVocabularyPage } from "@platform/features/admin/TagVocabularyPage";
import { SystemHealthPage } from "@platform/features/admin/SystemHealthPage";
import { TeamDetailPage } from "@platform/features/admin/TeamDetailPage";
import { TeamsPage } from "@platform/features/admin/TeamsPage";
import { UsersPage } from "@platform/features/admin/UsersPage";
import { SavedFiltersPage } from "@platform/features/admin/SavedFiltersPage";
import { TaskQueueAdminPage } from "@platform/features/admin/TaskQueueAdminPage";
import { DeadLetterPage } from "@platform/features/admin/DeadLetterPage";
import { AutomationPage } from "@platform/features/admin/AutomationPage";
import { ScheduledReportsPage } from "@platform/features/admin/ScheduledReportsPage";
import { CostPage } from "@platform/features/admin/CostPage";
import { ExecutivePage } from "@platform/features/admin/ExecutivePage";
import { DashboardPage } from "@platform/features/dashboard/DashboardPage";
import { ScanCenterPage } from "@platform/features/scans/ScanCenterPage";
import { SystemDetailPage } from "@platform/features/systems/SystemDetailPage";
import { SystemsPage } from "@platform/features/systems/SystemsPage";
import { TasksPage } from "@platform/features/tasks/TasksPage";
import { AppStateScreen } from "@platform/ui/AppStateScreen";
import { loadModuleFrontendSpecs } from "@platform/extension-registry/loadModuleSpecs";
import type { ModuleFrontendSpec } from "@platform/extension-registry/types";
import { SessionsPage } from "@platform/features/sessions/SessionsPage";
import { ChatPage } from "@platform/features/chat/ChatPage";
import { SettingsPage } from "@platform/features/settings/SettingsPage";
import { RadarPage } from "@platform/features/radar/RadarPage";
import { VizPage } from "@platform/features/viz/VizPage";

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
}: {
  page: ComponentType;
  title: string;
}) {
  return (
    <PageFrame title={title}>
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
 * Wrap a feature route element in a per-feature AppErrorBoundary (D-23).
 *
 * The router-root boundary remains in place to catch shell errors; this
 * inner boundary catches render errors inside individual pages so the
 * shell does not unmount when a feature crashes (T-176a-02-01).
 */
function withFeatureBoundary(element: ReactElement): ReactElement {
  return <AppErrorBoundary>{element}</AppErrorBoundary>;
}

function protectPage(title: string, Page: ComponentType, requiredRole?: AppRole) {
  return withFeatureBoundary(
    <ProtectedRoute requiredRole={requiredRole}>
      <RoutedPage page={Page} title={title} />
    </ProtectedRoute>,
  );
}

function normalizeModulePath(pathname: string): string {
  return pathname.replace(/^\/+/, "").replace(/\/+$/, "");
}

function buildModuleRouteObjects(specs: ModuleFrontendSpec[]): RouteObject[] {
  return specs.flatMap((spec) =>
    (spec.routes ?? []).map((route) => ({
      id: route.id,
      path: normalizeModulePath(route.path),
      // Each contributed module route also gets its own feature-level boundary.
      element: protectPage(route.title, route.page, route.minRole),
      handle: route.breadcrumb ? { breadcrumb: route.breadcrumb } : undefined,
    })),
  );
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
    element: <LoginPage />,
  },
  {
    // OIDC callback — public, no ProtectedRoute (T-140-08)
    path: "/auth/callback",
    element: <OidcCallbackPage />,
  },
  {
    // 403 page — public (redirected here from ProtectedRoute on role failure)
    path: "/403",
    element: <ForbiddenPage />,
  },
  {
    // 500 page — public direct navigation
    path: "/500",
    element: <ServerErrorPage />,
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
        index: true,
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
      // 176c: natural-language chat with the platform.
      {
        path: "chat",
        element: protectPage("Chat", ChatPage),
        handle: { breadcrumb: "Chat" },
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
      // D-09: SbD NFR workspace redirects. Deprecated document endpoints
      // were removed in v2.2; /assessments is the live workspace.
      {
        path: "sbd_nfr/documents",
        element: <Navigate to="/assessments" replace />,
      },
      {
        path: "sbd_nfr/documents/*",
        element: <Navigate to="/assessments" replace />,
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
      ...testOnlyRoutes,
      ...buildModuleRouteObjects(moduleSpecs),
      {
        path: "*",
        element: (
          <PageFrame title="Not Found">
            <NotFoundPage />
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
