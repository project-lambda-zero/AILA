import { InvestigationDetailPage } from "./screens/InvestigationDetailPage";
import { InvestigationsListPage } from "./screens/InvestigationsListPage";
import { ProjectDetailPage } from "./screens/ProjectDetailPage";
import { ProjectsPage } from "./screens/ProjectsPage";
import { TargetDetailPage } from "./screens/TargetDetailPage";
import { TargetsPage } from "./screens/TargetsPage";
import { WorkspacesPage } from "./screens/WorkspacesPage";

export const routes = [
  {
    id: "vr.projects",
    path: "/vr",
    page: ProjectsPage,
    title: "Vuln Research Projects",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Vuln Research",
  },
  {
    id: "vr.project-detail",
    path: "/vr/projects/:projectId",
    page: ProjectDetailPage,
    title: "VR Project Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Project",
  },
  {
    id: "vr.investigations",
    path: "/vr/investigations",
    page: InvestigationsListPage,
    title: "Investigations",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Investigations",
  },
  {
    id: "vr.investigation-detail",
    path: "/vr/investigations/:investigationId",
    page: InvestigationDetailPage,
    title: "Investigation Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Investigation",
  },
  {
    id: "vr.workspaces",
    path: "/vr/workspaces",
    page: WorkspacesPage,
    title: "Workspaces",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Workspaces",
  },
  {
    id: "vr.targets",
    path: "/vr/targets",
    page: TargetsPage,
    title: "Targets",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Targets",
  },
  {
    id: "vr.target-detail",
    path: "/vr/targets/:targetId",
    page: TargetDetailPage,
    title: "Target Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Target",
  },
];
