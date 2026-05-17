import { lazy } from "react";

import { InvestigationDetailPage } from "./screens/InvestigationDetailPage";
import { InvestigationsListPage } from "./screens/InvestigationsListPage";
import { ProjectDetailPage } from "./screens/ProjectDetailPage";
import { ProjectsPage } from "./screens/ProjectsPage";
import { TargetDetailPage } from "./screens/TargetDetailPage";
import { TargetsPage } from "./screens/TargetsPage";
import { WorkspacesPage } from "./screens/WorkspacesPage";
import { DisclosureDetailPage } from "./screens/DisclosureDetailPage";
import { DisclosuresPage } from "./screens/DisclosuresPage";
import { FuzzCampaignDetailPage } from "./screens/FuzzCampaignDetailPage";
import { FuzzCampaignsPage } from "./screens/FuzzCampaignsPage";
import { FuzzCrashDetailPage } from "./screens/FuzzCrashDetailPage";
import { PatternDetailPage } from "./screens/PatternDetailPage";
import { PatternsPage } from "./screens/PatternsPage";
import { McpServersPage } from "./screens/McpServersPage";
import { McpCallLogPage } from "./screens/McpCallLogPage";
import { FindingDetailPage } from "./screens/FindingDetailPage";
import { NdayPage } from "./screens/NdayPage";

// Heavy pages — ReactFlow / Monaco-style editor / wizard / branch tree
// bundles add weight that users who never visit them shouldn't pay for
// on the projects list. Lazy-loaded per 08_FRONTEND_UX.md §4.4.
const EvidenceGraphPage = lazy(() =>
  import("./screens/EvidenceGraphPage").then((m) => ({ default: m.EvidenceGraphPage })),
);
const ExploitEditorPage = lazy(() =>
  import("./screens/ExploitEditorPage").then((m) => ({ default: m.ExploitEditorPage })),
);
const NewProjectWizard = lazy(() =>
  import("./screens/NewProjectWizard").then((m) => ({ default: m.NewProjectWizard })),
);
const BranchTreePage = lazy(() =>
  import("./screens/BranchTreePage").then((m) => ({ default: m.BranchTreePage })),
);

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
    id: "vr.project-new",
    path: "/vr/projects/new",
    page: NewProjectWizard,
    title: "New VR Project",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "New",
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
    id: "vr.evidence-graph",
    path: "/vr/investigations/:investigationId/graph",
    page: EvidenceGraphPage,
    title: "Evidence Graph",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Evidence Graph",
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
  {
    id: "vr.nday",
    path: "/vr/projects/:projectId/ndays/:cveId",
    page: NdayPage,
    title: "N-day Reproduction",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "N-day",
  },
  {
    id: "vr.finding-detail",
    path: "/vr/projects/:projectId/findings/:findingId",
    page: FindingDetailPage,
    title: "Finding Detail",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Finding",
  },
  {
    id: "vr.exploit-editor",
    path: "/vr/projects/:projectId/findings/:findingId/exploit",
    page: ExploitEditorPage,
    title: "Exploit Editor",
    nav: false,
    slot: "page.full" as const,
    breadcrumb: "Exploit",
  },
  {
    id: "vr.mcp-calls",
    path: "/vr/mcp/calls",
    page: McpCallLogPage,
    title: "MCP Call Log",
    nav: true,
    slot: "page.full" as const,
    breadcrumb: "MCP Call Log",
  },
];
