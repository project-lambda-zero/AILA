/** Module / page / admin navigation model -- mirrors the design page's MODULES,
 * PAGES and ADMIN constants exactly. */

export interface PageDef {
  id: string;
  label: string;
  href: string | null;
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

export const MODULES: ModuleDef[] = [
  {
    id: "vr",
    label: "vulnerability research",
    noun: "investigations",
    pages: [
      page("workspaces"),
      page("targets"),
      page("vuln research"),
      page("cves"),
      page("investigations"),
      page("patterns"),
      page("findings"),
      page("disclosures"),
      page("disclosure tracks"),
      page("fuzz campaigns"),
      page("fuzz proposals"),
      page("crashes"),
      page("mcp servers"),
      page("mcp call log"),
    ],
  },
  {
    id: "vulnerability",
    label: "vulnerability mgmt",
    noun: "advisories",
    pages: [
      page("launch scan", "Vulnerability.dc.html#scan"),
      page("findings", "Vulnerability.dc.html#findings"),
      page("systems"),
      page("network radar", "Vulnerability.dc.html#radar"),
      page("data visualization", "Vulnerability.dc.html#viz"),
      page("reports"),
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
    noun: "reports",
    pages: [
      page("malware analysis"),
      page("health"),
      page("workspaces"),
      page("targets"),
      page("projects"),
      page("investigations"),
      page("observations"),
      page("patterns"),
      page("findings"),
      page("families"),
      page("playbooks"),
      page("mcp servers"),
      page("mcp call log"),
    ],
  },
];

/** Collapsible ADMIN SETTINGS categories -- verbatim from the mock adminCats. */
export const ADMIN_CATS: { cat: string; items: string[] }[] = [
  { cat: "access", items: ["users", "teams", "teams cross-view", "api keys", "oidc providers"] },
  { cat: "operations", items: ["task queue", "queue depth", "dead letter", "health", "automation", "automation actions", "workflows", "scheduled reports", "mcp instances", "eval calibrators"] },
  { cat: "platform", items: ["dashboard", "systems", "sessions", "specialist agents", "persona routing", "platform corpus", "knowledge", "sandbox", "widget layout"] },
  { cat: "cost & reporting", items: ["cost", "cost roi"] },
  { cat: "data & config", items: ["config", "tools", "finding states"] },
  { cat: "audit", items: ["audit logs", "llm log"] },
];
