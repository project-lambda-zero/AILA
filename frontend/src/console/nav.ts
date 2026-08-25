/** Module / page / admin navigation model -- mirrors the design page's MODULES,
 * PAGES and ADMIN constants exactly. */

export interface PageDef {
  id: string;
  label: string;
  href: string | null;
  /** Optional workflow group label. When set, LeftRail renders a small group
   * separator before the first page of each contiguous group. Generic across
   * modules -- a flat (group-less) page list renders exactly as before. */
  group?: string;
}

export interface ModuleDef {
  id: string;
  label: string;
  noun: string;
  pages: PageDef[];
}

const page = (label: string, href: string | null = null): PageDef => ({
  id: label.replace(/\s+/g, "-"),
  label,
  href,
});

/** Build a run of href-less pages under one workflow group label. LeftRail
 * renders a separator before each group's first page. Keeps grouped nav blocks
 * readable and is reusable by any module that wants a grouped rail. */
const grouped = (group: string, ...labels: string[]): PageDef[] =>
  labels.map((label) => ({ id: label.replace(/\s+/g, "-"), label, href: null, group }));

export const MODULES: ModuleDef[] = [
  {
    id: "vr",
    label: "vulnerability research",
    noun: "investigations",
    pages: [
      // workflow -- workspace-first backbone (req 4 / vr-navigation-ia): a
      // workspace contains targets, a target binds investigations, so the
      // rail leads with Workspaces, then Targets, then Investigations.
      page("workspaces"),
      page("targets"),
      page("investigations"),
      page("cves"),
      // artifacts
      page("findings"),
      page("patterns"),
      page("disclosures"),
      page("fuzz campaigns"),
    ],
  },
  {
    id: "vulnerability",
    label: "vulnerability mgmt",
    noun: "advisories",
    pages: [
      // workflow
      page("launch scan", "Vulnerability.dc.html#scan"),
      page("systems"),
      // artifacts
      page("findings", "Vulnerability.dc.html#findings"),
      page("reports"),
      // utility
      page("network radar", "Vulnerability.dc.html#radar"),
      page("data visualization", "Vulnerability.dc.html#viz"),
    ],
  },
  {
    id: "forensics",
    label: "dfir",
    noun: "cases",
    // Every sub-resource (evidence, artifacts, leads, timeline, ...) is
    // project-scoped: the rail lists projects; opening one raises the tabbed
    // project-detail window that owns those views.
    pages: [page("projects")],
  },
  {
    id: "malware",
    label: "malware analysis",
    noun: "investigations",
    // Workflow-first rail (req 18 / malware-navigation-ia): the pages read as
    // the reverse-engineering job -- pick a workspace, upload a target, run an
    // investigation, then review evidence and durable knowledge. The server
    // enforces the analyze spine (a target needs a workspace, an investigation
    // needs a target), so the nav reads in dependency order. Health is module
    // infra and sits at the tail. Investigations is a single entry whose row
    // activation opens the X-Ray cockpit (registry.tsx bespoke override).
    pages: [
      ...grouped("analyze", "workspaces", "targets", "investigations"),
      ...grouped("evidence", "observations"),
      ...grouped("knowledge", "findings", "patterns", "families", "playbooks"),
      ...grouped("module admin", "health"),
    ],
  },
];

/** Collapsible ADMIN SETTINGS categories -- verbatim from the mock adminCats. */
export const ADMIN_CATS: { cat: string; items: string[] }[] = [
  { cat: "access", items: ["users", "teams", "teams cross-view", "api keys", "oidc providers"] },
  { cat: "operations", items: ["task queue", "queue depth", "dead letter", "health", "automation", "automation actions", "workflows", "scheduled reports", "mcp instances", "mcp servers", "mcp call log", "eval calibrators", "calibration proposals"] },
  { cat: "platform", items: ["dashboard", "systems", "sessions", "specialist agents", "persona routing", "platform corpus", "knowledge", "sandbox", "widget layout"] },
  { cat: "cost & reporting", items: ["cost"] },
  { cat: "data & config", items: ["config", "tools", "finding states"] },
  { cat: "audit", items: ["audit logs", "llm log"] },
];
