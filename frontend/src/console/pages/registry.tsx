import { lazy, Suspense } from "react";
import type { JSX } from "react";

import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { PAGE_CONFIGS } from "./configs";
import DataPage from "./DataPage";

export type PageRender = (p: ModulePageProps) => JSX.Element;
export interface PageEntry {
  title: string;
  render: PageRender;
}

// Every bespoke page is code-split: the registry is the shell's only eager
// dependency on them, so opening a window downloads just that page's chunk.
// Detail bodies used inside DataPage render props are lazy too; the shared
// Suspense fallback below covers both the page and its drill-down bodies.
const DocsPage = lazy(() => import("./DocsPage"));
const XRayPage = lazy(() => import("./XRayPage"));
const MalwareXRayPage = lazy(() => import("./MalwareXRayPage"));
const MalwareHealthPanel = lazy(() => import("./MalwareHealthPanel"));
const UploadForm = lazy(() => import("./UploadForm"));
const NdayProjectForm = lazy(() => import("./NdayProjectForm"));
const CveReproduceDetail = lazy(() => import("./NdayProjectForm").then((m) => ({ default: m.CveReproduceDetail })));
const VrPatternsPage = lazy(() => import("./VrPatternsPage"));
const ForensicsProjectPage = lazy(() => import("./forensics/ForensicsProjectPage"));
const VulnerabilityPage = lazy(() => import("./VulnerabilityPage"));
const AdminDashboardPage = lazy(() => import("./AdminDashboardPage"));
const OpsWarRoom = lazy(() => import("./OpsWarRoom"));
const SystemsRegistryPage = lazy(() => import("./SystemsRegistryPage"));
const CostReportingPage = lazy(() => import("./cost/CostReportingPage"));
const AdminFindingStatesPage = lazy(() => import("./AdminFindingStatesPage"));
const AdminPlatformCorpusPage = lazy(() => import("./AdminPlatformCorpusPage"));
const KnowledgePage = lazy(() => import("./KnowledgePage"));
const SandboxPage = lazy(() => import("./SandboxPage"));
const OnboardingWizard = lazy(() => import("../wizards/OnboardingWizard"));
const WidgetLayoutPage = lazy(() => import("./WidgetLayoutPage"));
const PersonaModelRoutingPage = lazy(() => import("./PersonaModelRoutingPage"));
const AutomationWizard = lazy(() => import("./AutomationWizard"));
const AutomationActionDetail = lazy(() => import("./automation/AutomationActionDetail").then((m) => ({ default: m.AutomationActionDetail })));
const ScheduledReportWizard = lazy(() => import("./ScheduledReportWizard"));
const ScheduledReportDetail = lazy(() => import("./scheduledReport/ScheduledReportDetail").then((m) => ({ default: m.ScheduledReportDetail })));
const McpInstanceToolsDetail = lazy(() => import("./McpInstanceToolsDetail").then((m) => ({ default: m.McpInstanceToolsDetail })));
const WorkflowTransitionsDetail = lazy(() => import("./WorkflowTransitionsDetail").then((m) => ({ default: m.WorkflowTransitionsDetail })));
const TeamCrossDetail = lazy(() => import("./TeamCrossDetail").then((m) => ({ default: m.TeamCrossDetail })));
const WorkspaceTargets = lazy(() => import("./WorkspaceTargets"));
const VRTargetDetail = lazy(() => import("./VRTargetDetail"));
const FuzzCampaignDetail = lazy(() => import("./FuzzCampaignDetail"));
const MalwareTargetDetail = lazy(() => import("./MalwareTargetDetail"));
const LifecyclePage = lazy(() => import("./admin/LifecyclePage"));
const EvalBenchmarksPage = lazy(() => import("./admin/EvalBenchmarksPage"));
const PromptAliasesPage = lazy(() => import("./admin/PromptAliasesPage"));
const ReconcilePage = lazy(() => import("./admin/ReconcilePage"));
const AuditSealsPage = lazy(() => import("./admin/AuditSealsPage"));
const GlobalSearchPage = lazy(() => import("./admin/GlobalSearchPage"));
const CrossTeamHeatmapPage = lazy(() => import("./admin/CrossTeamHeatmapPage"));

/** Shared lazy fallback: the console's standard centered loading note
 * (matches the DataPage empty/loading note style). */
function PageLoading(): JSX.Element {
  return <div style={css("flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;")}>loading&#8230;</div>;
}

// Bespoke pages: the rich per-investigation X-Rays (VR + malware), the guided
// target-upload wizards, the forensics project-detail window, and the designed
// Vulnerability sub-views. Everything else is a declarative DataPage.
const BESPOKE = {
  "platform:docs": { title: "docs", render: (p) => <DocsPage {...p} /> },
  xray: { title: "x-ray", render: (p) => <XRayPage {...p} /> },
  // Registry alias so `onOpenPage("vr", "xray", ...)` (row-activate from the
  // investigations/targets pages) resolves the same X-Ray renderer that the
  // left-rail bound-investigation open uses (bare "xray").
  "vr:xray": { title: "vr \u00b7 x-ray", render: (p) => <XRayPage {...p} /> },
  "malware:xray": { title: "malware \u00b7 x-ray", render: (p) => <MalwareXRayPage {...p} /> },
  "malware:health": { title: "malware \u00b7 health", render: (p) => <MalwareHealthPanel {...p} /> },
  "vr:new-target": { title: "vr \u00b7 upload target", render: (p) => <UploadForm module="vr" {...p} /> },
  // The n-day CVE reproduction surface: opened from the CVE registry ("+ new"
  // for a blank start, or a row's "reproduce" button prefilled with its cve).
  "vr:new-project": { title: "vr \u00b7 new n-day project", render: (p) => <NdayProjectForm {...p} /> },
  // CVE registry is the single CVE/reproduction surface: "+ new" opens a blank
  // reproduction, and a row's detail body carries a "reproduce" control that
  // opens the create flow prefilled with that cve_id.
  "vr:cves": {
    title: PAGE_CONFIGS["vr:cves"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["vr:cves"]}
        configKey="vr:cves"
        {...p}
        onNewClick={() => p.onOpenPage?.("vr", "new-project", "new n-day project")}
        detailBody={(row) => (
          <CveReproduceDetail
            row={row}
            onReproduce={() =>
              p.onOpenPage?.(
                "vr",
                "new-project",
                `reproduce ${String(row.cve_id ?? "")}`.trim(),
                String(row.cve_id ?? ""),
              )
            }
          />
        )}
      />
    ),
  },
  // Patterns get a bespoke wrapper: the declarative DataPage (list + detail +
  // edit + promote/archive review actions + kind/status/scope filters) plus a
  // "preview applicable" toolbar control that simulates the retrieval gate.
  "vr:patterns": { title: PAGE_CONFIGS["vr:patterns"].title, render: (p) => <VrPatternsPage {...p} /> },
  "malware:new-target": { title: "malware \u00b7 upload target", render: (p) => <UploadForm module="malware" {...p} /> },
  "forensics:project": { title: "forensics \u00b7 project", render: (p) => <ForensicsProjectPage {...p} /> },
  "vulnerability:scan": { title: "vulnerability \u00b7 launch scan", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:findings": { title: "vulnerability \u00b7 findings", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:cves": { title: "vulnerability \u00b7 cve intelligence", render: (p) => <VulnerabilityPage {...p} section="cves" /> },
  "vulnerability:radar": { title: "vulnerability \u00b7 network radar", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:topology": { title: "vulnerability \u00b7 network topology", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:viz": { title: "vulnerability \u00b7 data visualization", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:reports": { title: "vulnerability \u00b7 reports", render: (p) => <VulnerabilityPage {...p} /> },
  "admin:dashboard": { title: "admin \u00b7 dashboard", render: (p) => <AdminDashboardPage {...p} /> },
  "admin:ops-war-room": { title: "admin \u00b7 ops war room", render: (p) => <OpsWarRoom {...p} /> },
  // God-tier operator consoles (#212): ML-Ops lifecycle, eval benchmarks and
  // runs, prompt alias deploy/rollback with version diff, task reconcile,
  // audit seal viewer + export, global search, and the cross-team heatmap.
  "admin:lifecycle": { title: "admin \u00b7 lifecycle", render: (p) => <LifecyclePage {...p} /> },
  "admin:eval-benchmarks": { title: "admin \u00b7 eval benchmarks", render: (p) => <EvalBenchmarksPage {...p} /> },
  "admin:prompt-aliases": { title: "admin \u00b7 prompt aliases", render: (p) => <PromptAliasesPage {...p} /> },
  "admin:reconcile": { title: "admin \u00b7 reconcile", render: (p) => <ReconcilePage {...p} /> },
  "admin:audit-seals": { title: "admin \u00b7 audit seals", render: (p) => <AuditSealsPage {...p} /> },
  "admin:global-search": { title: "admin \u00b7 global search", render: (p) => <GlobalSearchPage {...p} /> },
  "admin:cross-team-heatmap": { title: "admin \u00b7 cross-team heatmap", render: (p) => <CrossTeamHeatmapPage {...p} /> },
  // Platform-owned SSH host registry (system-registry-platform.md req 11):
  // the only systems surface, re-homed off the vulnerability module.
  "admin:systems": { title: "admin \u00b7 systems", render: (p) => <SystemsRegistryPage {...p} /> },
  // Cost & reporting: the former cost / cost-roi / executive views merged into
  // one page with overview / detail / configs segments (req 47).
  "admin:cost": { title: "admin \u00b7 cost", render: (p) => <CostReportingPage {...p} /> },
  "admin:finding-states": { title: "admin \u00b7 finding states", render: (p) => <AdminFindingStatesPage {...p} /> },
  "admin:platform-corpus": {
    title: "admin \u00b7 platform corpus",
    render: (p) => <AdminPlatformCorpusPage {...p} />,
  },
  "admin:knowledge": { title: "admin \u00b7 knowledge", render: (p) => <KnowledgePage {...p} /> },
  "admin:sandbox": { title: "admin \u00b7 sandbox", render: (p) => <SandboxPage {...p} /> },
  // First-run platform onboarding (#246): auto-opened for god-tier admins
  // until onboarding_completed is set; re-openable from settings and here.
  "admin:onboarding": { title: "admin \u00b7 onboarding", render: (p) => <OnboardingWizard {...p} /> },
  "admin:widget-layout": { title: "admin \u00b7 widget layout", render: (p) => <WidgetLayoutPage {...p} /> },
  "admin:persona-routing": {
    title: "admin \u00b7 persona model routing",
    render: (p) => <PersonaModelRoutingPage {...p} />,
  },
  // Automation schedule creation is a stepped wizard rather than a raw
  // typed form: "+ new" on the automation list opens this window, and the
  // action catalog's "schedule this action" button opens it with step 1
  // pre-filled by threading the action_id through the shell's prefill slot.
  "admin:new-automation": {
    title: "admin \u00b7 new automation schedule",
    render: (p) => <AutomationWizard {...p} />,
  },
  "admin:automation": {
    title: PAGE_CONFIGS["admin:automation"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["admin:automation"]}
        configKey="admin:automation"
        {...p}
        onNewClick={() => p.onOpenPage?.("admin", "new-automation", "new automation schedule")}
      />
    ),
  },
  // Scheduled-report creation is a bespoke wizard (kind catalog + typed
  // options + recipient chips + cron preset picker) instead of a raw typed
  // form: "+ new" on the scheduled-reports list opens it, and the detail
  // body owns triggering + task polling (the generic list-level trigger
  // action was removed so there is a single trigger path).
  "admin:new-scheduled-report": {
    title: "admin \u00b7 new scheduled report",
    render: (p) => <ScheduledReportWizard {...p} />,
  },
  "admin:scheduled-reports": {
    title: PAGE_CONFIGS["admin:scheduled-reports"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["admin:scheduled-reports"]}
        configKey="admin:scheduled-reports"
        {...p}
        onNewClick={() => p.onOpenPage?.("admin", "new-scheduled-report", "new scheduled report")}
        detailBody={(row) => <ScheduledReportDetail key={String(row.id ?? "")} row={row} />}
      />
    ),
  },
  // The mcp-instances page gets a bespoke detail body so a row click
  // renders the live tools schema + drift chip from
  // GET /platform/mcp/instances/{id}/tools alongside the row's fields.
  "admin:mcp-instances": {
    title: PAGE_CONFIGS["admin:mcp-instances"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["admin:mcp-instances"]}
        configKey="admin:mcp-instances"
        {...p}
        detailBody={(row) => <McpInstanceToolsDetail row={row} />}
      />
    ),
  },
  "admin:automation-actions": {
    title: PAGE_CONFIGS["admin:automation-actions"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["admin:automation-actions"]}
        configKey="admin:automation-actions"
        {...p}
        detailBody={(row) => (
          <AutomationActionDetail
            row={row}
            onSchedule={(actionId) =>
              p.onOpenPage?.(
                "admin",
                "new-automation",
                `schedule ${actionId}`.trim(),
                actionId,
              )
            }
          />
        )}
      />
    ),
  },
  // Workflows: the read-only cursor list (columns + run/definition/state/date
  // filters from configs.ts) plus a bespoke detail body that drills a row into
  // its full transition history via GET /admin/workflows/runs/{run_id}/
  // transitions -- an ordered timeline with repeat-retry runs collapsed. The
  // detail replaces the generic field grid, so the component owns the header.
  "admin:workflows": {
    title: PAGE_CONFIGS["admin:workflows"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["admin:workflows"]}
        configKey="admin:workflows"
        {...p}
        detailBody={(row) => <WorkflowTransitionsDetail row={row} />}
      />
    ),
  },
  // Teams cross-view: a god-tier cross-tenant table (columns + text/count
  // filters from configs.ts) plus a bespoke detail body that drills a row into
  // that team's detail + member roster via GET /admin/teams/{team_id}, so the
  // operator moves from counts to one team's members without leaving the panel.
  "admin:teams-cross-view": {
    title: PAGE_CONFIGS["admin:teams-cross-view"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["admin:teams-cross-view"]}
        configKey="admin:teams-cross-view"
        {...p}
        detailBody={(row) => <TeamCrossDetail row={row} />}
      />
    ),
  },
  // Workspace-first drill (req 4 / vr-navigation-ia): a workspace row's detail
  // panel lists that workspace's targets; expanding a target reveals its
  // investigations, each opening the X-Ray -- Workspace -> Target ->
  // Investigation, without hopping out to the top-level targets list.
  "vr:workspaces": {
    title: PAGE_CONFIGS["vr:workspaces"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["vr:workspaces"]}
        configKey="vr:workspaces"
        {...p}
        detailBody={(row) => (
          <WorkspaceTargets
            workspaceId={String(row.id ?? "")}
            targetsEndpoint="/vr/targets"
            investigationsEndpoint="/vr/investigations"
            onOpenXray={(inv) => p.onOpenPage?.("vr", "xray", "x-ray", inv.id)}
          />
        )}
      />
    ),
  },
  // Targets create is a multipart upload wizard, not a typed field form: the
  // "+ new" button opens the module's upload window instead.
  "vr:targets": {
    title: PAGE_CONFIGS["vr:targets"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["vr:targets"]}
        configKey="vr:targets"
        {...p}
        onNewClick={() => p.onOpenPage?.("vr", "new-target", "upload target")}
        detailBody={(row) => (
          <VRTargetDetail
            row={row}
            onOpenXray={(inv) => p.onOpenPage?.("vr", "xray", "x-ray", inv.id)}
          />
        )}
      />
    ),
  },
  // Fuzz campaigns own the merged detail: proposals for the campaign's target
  // + crashes for the campaign itself, in one collapsible drill-down.
  "vr:fuzz-campaigns": {
    title: PAGE_CONFIGS["vr:fuzz-campaigns"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["vr:fuzz-campaigns"]}
        configKey="vr:fuzz-campaigns"
        {...p}
        detailBody={(row) => (
          <FuzzCampaignDetail
            campaignId={String(row.id ?? "")}
            targetId={String(row.target_id ?? "")}
            campaignStatus={String(row.status ?? "")}
          />
        )}
      />
    ),
  },
  // Row-activate: clicking an investigation raises its X-Ray window directly
  // (same drill-down the targets page offers, one less hop).
  "vr:investigations": {
    title: PAGE_CONFIGS["vr:investigations"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["vr:investigations"]}
        configKey="vr:investigations"
        {...p}
        onRowActivate={(row) => p.onOpenPage?.("vr", "xray", "x-ray", String(row.id ?? ""))}
      />
    ),
  },
  "malware:targets": {
    title: PAGE_CONFIGS["malware:targets"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["malware:targets"]}
        configKey="malware:targets"
        {...p}
        onNewClick={() => p.onOpenPage?.("malware", "new-target", "upload target")}
        detailBody={(row) => (
          <MalwareTargetDetail
            row={row}
            onOpenXray={(inv) => p.onOpenPage?.("malware", "xray", "x-ray", inv.id)}
          />
        )}
      />
    ),
  },
  "malware:investigations": {
    title: PAGE_CONFIGS["malware:investigations"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["malware:investigations"]}
        configKey="malware:investigations"
        {...p}
        onRowActivate={(row) => p.onOpenPage?.("malware", "xray", "x-ray", String(row.id ?? ""))}
      />
    ),
  },
  // Forensics sub-resources are project-scoped: a project row opens the tabbed
  // detail window rather than an in-row detail panel.
  "forensics:projects": {
    title: PAGE_CONFIGS["forensics:projects"].title,
    render: (p) => (
      <DataPage
        config={PAGE_CONFIGS["forensics:projects"]}
        configKey="forensics:projects"
        {...p}
        onRowActivate={(row) => p.onOpenPage?.("forensics", "project", String(row.name ?? row.id ?? ""), String(row.id ?? ""))}
      />
    ),
  },
} satisfies Record<string, PageEntry>;

const DATA: Record<string, PageEntry> = Object.fromEntries(
  Object.entries(PAGE_CONFIGS).map(([key, config]): [string, PageEntry] => [
    key,
    { title: config.title, render: (p: ModulePageProps) => <DataPage config={config} configKey={key} {...p} /> },
  ]),
);

/** One Suspense boundary per rendered page: bespoke pages and their lazy
 * detail bodies share the single fallback. */
function suspenseEntry(entry: PageEntry): PageEntry {
  return {
    title: entry.title,
    render: (p: ModulePageProps) => (
      <Suspense fallback={<PageLoading />}>
        {entry.render(p)}
      </Suspense>
    ),
  };
}

export const PAGE_REGISTRY: Record<string, PageEntry> = Object.fromEntries(
  [...Object.entries(DATA), ...Object.entries(BESPOKE)].map(([key, entry]): [string, PageEntry] => [
    key,
    suspenseEntry(entry),
  ]),
);

export function resolvePage(key: string): PageEntry | null {
  return PAGE_REGISTRY[key] ?? null;
}
