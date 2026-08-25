import type { JSX } from "react";

import type { ModulePageProps } from "../contract";
import AdminDashboardPage from "./AdminDashboardPage";
import AdminFindingStatesPage from "./AdminFindingStatesPage";
import AdminPlatformCorpusPage from "./AdminPlatformCorpusPage";
import AutomationWizard, { AutomationActionDetail } from "./AutomationWizard";
import { PAGE_CONFIGS } from "./configs";
import CostReportingPage from "./cost/CostReportingPage";
import DataPage from "./DataPage";
import ForensicsProjectPage from "./forensics/ForensicsProjectPage";
import FuzzCampaignDetail from "./FuzzCampaignDetail";
import KnowledgePage from "./KnowledgePage";
import MalwareHealthPanel from "./MalwareHealthPanel";
import MalwareXRayPage from "./MalwareXRayPage";
import { McpInstanceToolsDetail } from "./McpInstanceToolsDetail";
import NdayProjectForm, { CveReproduceDetail } from "./NdayProjectForm";
import PersonaModelRoutingPage from "./PersonaModelRoutingPage";
import SandboxPage from "./SandboxPage";
import TargetInvestigations from "./TargetInvestigations";
import UploadForm from "./UploadForm";
import VulnerabilityPage from "./VulnerabilityPage";
import XRayPage from "./XRayPage";

export type PageRender = (p: ModulePageProps) => JSX.Element;
export interface PageEntry {
  title: string;
  render: PageRender;
}

// Bespoke pages: the rich per-investigation X-Rays (VR + malware), the guided
// target-upload wizards, the forensics project-detail window, and the designed
// Vulnerability sub-views. Everything else is a declarative DataPage.
const BESPOKE: Record<string, PageEntry> = {
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
  "malware:new-target": { title: "malware \u00b7 upload target", render: (p) => <UploadForm module="malware" {...p} /> },
  "forensics:project": { title: "forensics \u00b7 project", render: (p) => <ForensicsProjectPage {...p} /> },
  "vulnerability:scan": { title: "vulnerability \u00b7 launch scan", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:findings": { title: "vulnerability \u00b7 findings", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:systems": { title: "vulnerability \u00b7 systems", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:radar": { title: "vulnerability \u00b7 network radar", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:viz": { title: "vulnerability \u00b7 data visualization", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:reports": { title: "vulnerability \u00b7 reports", render: (p) => <VulnerabilityPage {...p} /> },
  "admin:dashboard": { title: "admin \u00b7 dashboard", render: (p) => <AdminDashboardPage {...p} /> },
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
          <TargetInvestigations
            targetId={String(row.id ?? "")}
            endpoint="/vr/investigations"
            onOpenXray={(inv) => p.onOpenPage?.("vr", "xray", `vr \u00b7 x-ray`, inv.id)}
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
        onRowActivate={(row) => p.onOpenPage?.("vr", "xray", `vr \u00b7 x-ray`, String(row.id ?? ""))}
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
          <TargetInvestigations
            targetId={String(row.id ?? "")}
            endpoint="/malware/investigations"
            onOpenXray={(inv) => p.onOpenPage?.("malware", "xray", `malware \u00b7 x-ray`, inv.id)}
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
        onRowActivate={(row) => p.onOpenPage?.("malware", "xray", `malware \u00b7 x-ray`, String(row.id ?? ""))}
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
};

const DATA: Record<string, PageEntry> = Object.fromEntries(
  Object.entries(PAGE_CONFIGS).map(([key, config]): [string, PageEntry] => [
    key,
    { title: config.title, render: (p: ModulePageProps) => <DataPage config={config} configKey={key} {...p} /> },
  ]),
);

export const PAGE_REGISTRY: Record<string, PageEntry> = { ...DATA, ...BESPOKE };

export function resolvePage(key: string): PageEntry | null {
  return PAGE_REGISTRY[key] ?? null;
}
