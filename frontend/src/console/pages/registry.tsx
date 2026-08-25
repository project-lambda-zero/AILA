import type { JSX } from "react";

import type { ModulePageProps } from "../contract";
import AdminDashboardPage from "./AdminDashboardPage";
import AdminPlatformCorpusPage from "./AdminPlatformCorpusPage";
import { PAGE_CONFIGS } from "./configs";
import DataPage from "./DataPage";
import ForensicsProjectPage from "./forensics/ForensicsProjectPage";
import KnowledgePage from "./KnowledgePage";
import MalwareHealthPanel from "./MalwareHealthPanel";
import MalwareXRayPage from "./MalwareXRayPage";
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
  "malware:new-target": { title: "malware \u00b7 upload target", render: (p) => <UploadForm module="malware" {...p} /> },
  "forensics:project": { title: "forensics \u00b7 project", render: (p) => <ForensicsProjectPage {...p} /> },
  "vulnerability:scan": { title: "vulnerability \u00b7 launch scan", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:findings": { title: "vulnerability \u00b7 findings", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:systems": { title: "vulnerability \u00b7 systems", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:radar": { title: "vulnerability \u00b7 network radar", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:viz": { title: "vulnerability \u00b7 data visualization", render: (p) => <VulnerabilityPage {...p} /> },
  "vulnerability:reports": { title: "vulnerability \u00b7 reports", render: (p) => <VulnerabilityPage {...p} /> },
  "admin:dashboard": { title: "admin \u00b7 dashboard", render: (p) => <AdminDashboardPage {...p} /> },
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
