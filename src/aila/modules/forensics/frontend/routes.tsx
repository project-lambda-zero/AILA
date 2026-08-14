import { lazy } from "react";

// Route-level code-splitting: each screen becomes its own Vite chunk so
// the shell entry bundle stays lean. Every page below is a NAMED export,
// re-mapped to the default shape React.lazy requires. Suspense boundaries
// are supplied by the shell's `RoutedPage` in frontend/src/app/router.tsx,
// which wraps every module route element flowed through
// `buildModuleRouteObjects` -> `protectPage`.
const InvestigationDetailPage = lazy(() =>
  import("./screens/InvestigationDetailPage").then((m) => ({
    default: m.InvestigationDetailPage,
  })),
);
const ProjectDashboardPage = lazy(() =>
  import("./screens/ProjectDashboardPage").then((m) => ({
    default: m.ProjectDashboardPage,
  })),
);
const ProjectDetailsPage = lazy(() =>
  import("./screens/ProjectDetailsPage").then((m) => ({
    default: m.ProjectDetailsPage,
  })),
);
const ProjectsPage = lazy(() =>
  import("./screens/ProjectsPage").then((m) => ({ default: m.ProjectsPage })),
);
const NewProjectPage = lazy(() =>
  import("./screens/NewProjectPage").then((m) => ({
    default: m.NewProjectPage,
  })),
);
const ReasoningReplayPage = lazy(() =>
  import("./screens/ReasoningReplayPage").then((m) => ({
    default: m.ReasoningReplayPage,
  })),
);

export const routes = [
  {
    id: "forensics.projects",
    path: "/forensics",
    page: ProjectsPage,
    title: "Forensics Projects",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Forensics",
  },
  {
    id: "forensics.new-project",
    path: "/forensics/projects/new",
    page: NewProjectPage,
    title: "New Forensics Project",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "New Project",
  },
  {
    id: "forensics.project-dashboard",
    path: "/forensics/projects/:projectId",
    page: ProjectDashboardPage,
    title: "Project Dashboard",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Project",
  },
  {
    id: "forensics.project-details",
    path: "/forensics/projects/:projectId/details",
    page: ProjectDetailsPage,
    title: "Project Details",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Details",
  },
  {
    id: "forensics.investigation-detail",
    path: "/forensics/projects/:projectId/investigations/:investigationId",
    page: InvestigationDetailPage,
    title: "Investigation Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Investigation",
  },
  {
    id: "forensics.reasoning-replay",
    path: "/forensics/projects/:projectId/investigations/:investigationId/reasoning-replay",
    page: ReasoningReplayPage,
    title: "Reasoning Replay",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Reasoning Replay",
  },
];
