import { InvestigationDetailPage } from "./screens/InvestigationDetailPage";
import { InvestigationsListPage } from "./screens/InvestigationsListPage";
import { ProjectDetailPage } from "./screens/ProjectDetailPage";
import { ProjectsPage } from "./screens/ProjectsPage";
import { TargetDetailPage } from "./screens/TargetDetailPage";
import { TargetsPage } from "./screens/TargetsPage";
import { WorkspacesPage } from "./screens/WorkspacesPage";
import { DisclosureDetailPage } from "./screens/DisclosureDetailPage";
import { BranchTreePage } from "./screens/BranchTreePage";
import { DisclosuresPage } from "./screens/DisclosuresPage";
import { FuzzCampaignDetailPage } from "./screens/FuzzCampaignDetailPage";
import { FuzzCampaignsPage } from "./screens/FuzzCampaignsPage";
import { FuzzCrashDetailPage } from "./screens/FuzzCrashDetailPage";
import { PatternDetailPage } from "./screens/PatternDetailPage";
import { PatternsPage } from "./screens/PatternsPage";
import { McpServersPage } from "./screens/McpServersPage";

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
  {
    id: "vr.patterns",
    path: "/vr/patterns",
    page: PatternsPage,
    title: "Patterns",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Patterns",
  },
  {
    id: "vr.pattern-detail",
    path: "/vr/patterns/:patternId",
    page: PatternDetailPage,
    title: "Pattern Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Pattern",
  },
  {
    id: "vr.disclosures",
    path: "/vr/disclosures",
    page: DisclosuresPage,
    title: "Disclosures",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Disclosures",
  },
  {
    id: "vr.disclosure-detail",
    path: "/vr/disclosures/:submissionId",
    page: DisclosureDetailPage,
    title: "Disclosure Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Disclosure",
  },
  {
    id: "vr.fuzz-campaigns",
    path: "/vr/fuzz/campaigns",
    page: FuzzCampaignsPage,
    title: "Fuzz Campaigns",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "Fuzz Campaigns",
  },
  {
    id: "vr.fuzz-campaign-detail",
    path: "/vr/fuzz/campaigns/:campaignId",
    page: FuzzCampaignDetailPage,
    title: "Fuzz Campaign",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Fuzz Campaign",
  },
  {
    id: "vr.fuzz-crash-detail",
    path: "/vr/fuzz/crashes/:crashId",
    page: FuzzCrashDetailPage,
    title: "Fuzz Crash",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Fuzz Crash",
  },
  {
    id: "vr.branch-tree",
    path: "/vr/investigations/:investigationId/tree",
    page: BranchTreePage,
    title: "Branch Tree",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Branch Tree",
  },
  {
    id: "vr.mcp-servers",
    path: "/vr/mcp/servers",
    page: McpServersPage,
    title: "MCP Servers",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "MCP Servers",
  },
];
