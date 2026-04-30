import { InvestigationDetailPage } from "./screens/InvestigationDetailPage";
import { ProjectDashboardPage } from "./screens/ProjectDashboardPage";
import { ProjectDetailsPage } from "./screens/ProjectDetailsPage";
import { ProjectsPage } from "./screens/ProjectsPage";
import { NewProjectPage } from "./screens/NewProjectPage";

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
];
