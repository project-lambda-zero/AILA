import { ProjectDetailPage } from "./screens/ProjectDetailPage";
import { ProjectsPage } from "./screens/ProjectsPage";

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
];
