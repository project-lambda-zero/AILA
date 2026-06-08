import type { Icon } from "@phosphor-icons/react/lib";
import { Bug as BugIcon } from "@phosphor-icons/react/dist/csr/Bug";
import { BookOpen as BookOpenIcon } from "@phosphor-icons/react/dist/csr/BookOpen";
import { ChatCircleDots as ChatCircleDotsIcon } from "@phosphor-icons/react/dist/csr/ChatCircleDots";
import { ClipboardText as ClipboardTextIcon } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { Desktop as DesktopIcon } from "@phosphor-icons/react/dist/csr/Desktop";
import { GearSix as GearSixIcon } from "@phosphor-icons/react/dist/csr/GearSix";
import { GitBranch as GitBranchIcon } from "@phosphor-icons/react/dist/csr/GitBranch";
import { Heartbeat as HeartbeatIcon } from "@phosphor-icons/react/dist/csr/Heartbeat";
import { House as HouseIcon } from "@phosphor-icons/react/dist/csr/House";
import { Key as KeyIcon } from "@phosphor-icons/react/dist/csr/Key";
import { ListChecks as ListChecksIcon } from "@phosphor-icons/react/dist/csr/ListChecks";
import { Robot as RobotIcon } from "@phosphor-icons/react/dist/csr/Robot";
import { ShieldCheck as ShieldCheckIcon } from "@phosphor-icons/react/dist/csr/ShieldCheck";
import { Users as UsersIcon } from "@phosphor-icons/react/dist/csr/Users";
import { Tag as TagIcon } from "@phosphor-icons/react/dist/csr/Tag";
import { UsersThree as UsersThreeIcon } from "@phosphor-icons/react/dist/csr/UsersThree";
import { Wrench as WrenchIcon } from "@phosphor-icons/react/dist/csr/Wrench";
import { BookmarkSimple as BookmarkSimpleIcon } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { Queue as QueueIcon } from "@phosphor-icons/react/dist/csr/Queue";
import { Skull as SkullIcon } from "@phosphor-icons/react/dist/csr/Skull";
import { ArrowsClockwise as ArrowsClockwiseIcon } from "@phosphor-icons/react/dist/csr/ArrowsClockwise";
import { Calendar as CalendarIcon } from "@phosphor-icons/react/dist/csr/Calendar";
import { CurrencyDollar as CurrencyDollarIcon } from "@phosphor-icons/react/dist/csr/CurrencyDollar";
import { Briefcase as BriefcaseIcon } from "@phosphor-icons/react/dist/csr/Briefcase";

import type { AppRole } from "@platform/auth/roles";
import type { ModuleFrontendSpec, NavContribution } from "@platform/extension-registry/types";

export type NavSection = "platform" | "modules" | "admin" | "settings" | "hidden";

export interface SidebarItem extends NavContribution {
  blockedMessage?: string;
  icon?: Icon;
  section?: NavSection;
}

export interface SidebarGroup {
  kind: "group";
  id: string;
  label: string;
  order: number;
  items: SidebarItem[];
}

export interface SidebarLeaf {
  kind: "item";
  order: number;
  item: SidebarItem;
}

export type SidebarEntry = SidebarGroup | SidebarLeaf;

export interface ModuleSubgroup {
  moduleId: string;
  label: string;
  items: SidebarItem[];
}

export interface SidebarSection {
  id: NavSection;
  label: string;
  items: SidebarItem[];
  /** Module sections may have items grouped by module */
  subgroups?: ModuleSubgroup[];
}

const platformSidebarItems: SidebarItem[] = [
  // Top (Platform) section — D-06
  {
    id: "platform.overview",
    slot: "sidebar.main",
    label: "Dashboard",
    to: "/",
    order: 10,
    description: "Platform health and shell state",
    icon: HouseIcon,
    section: "platform",
  },
  {
    id: "platform.systems",
    slot: "sidebar.main",
    label: "Systems",
    to: "/systems",
    order: 20,
    description: "Registered SSH targets",
    icon: DesktopIcon,
    section: "platform",
  },
  // NOTE: Findings, Reports, Scan Console, Radar, and Visualization are
  // contributed by the vulnerability module's nav.ts and render under
  // the Vulnerability subgroup of the Modules section.
  {
    id: "platform.tasks",
    slot: "sidebar.main",
    label: "Tasks",
    to: "/tasks",
    order: 36,
    description: "Background task queue — all modules",
    icon: ListChecksIcon,
    section: "platform",
  },
  // 176c: natural-language chat with the AILA platform.
  {
    id: "platform.chat",
    slot: "sidebar.main",
    label: "Chat",
    to: "/chat",
    order: 37,
    description: "Ask the platform questions — streaming responses",
    icon: ChatCircleDotsIcon,
    section: "platform",
  },
  // Admin section — D-06, D-14
  {
    id: "platform.admin.users",
    slot: "sidebar.main",
    label: "Users",
    to: "/admin/users",
    order: 80,
    description: "User management",
    icon: UsersIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "User management requires admin role.",
  },
  {
    id: "platform.api-keys",
    slot: "sidebar.main",
    label: "API Keys",
    to: "/admin/api-keys",
    order: 85,
    description: "Admin-only key management",
    icon: KeyIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "API key management requires admin role.",
  },
  {
    id: "platform.audit-logs",
    slot: "sidebar.main",
    label: "Audit Logs",
    to: "/admin/audit",
    order: 90,
    description: "Admin-only audit trail",
    icon: ClipboardTextIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Audit logs require admin role.",
  },
  // Part 9: Admin Tools Console — operator-level live tool invocation.
  {
    id: "platform.admin.tools",
    slot: "sidebar.main",
    label: "Tools",
    to: "/admin/tools",
    order: 91,
    description: "Live invocation console for registered platform tools",
    icon: WrenchIcon,
    section: "admin",
    minRole: "operator",
    blockedMessage: "Tools console requires operator role.",
  },
  // Plan 183-11: Admin Workflow Inspector — DurableStateMachine run browser.
  {
    id: "platform.admin.workflows",
    slot: "sidebar.main",
    label: "Workflows",
    to: "/admin/workflows",
    order: 93,
    description: "Live browser for DurableStateMachine runs and transition history",
    icon: GitBranchIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Workflow Inspector requires admin role.",
  },
  // Plan 176e: admin-only LLM interaction log (model, prompt/response previews,
  // tokens, cost, duration, run link).
  {
    id: "platform.llm-log",
    slot: "sidebar.main",
    label: "LLM Log",
    to: "/admin/llm-log",
    order: 92,
    description: "Admin-only per-call LLM interaction log",
    icon: RobotIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "LLM log requires admin role.",
  },
  {
    id: "platform.admin.config",
    slot: "sidebar.main",
    label: "Config",
    to: "/admin/config",
    order: 95,
    description: "Platform configuration",
    icon: ShieldCheckIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Config management requires admin role.",
  },
  {
    id: "platform.admin.health",
    slot: "sidebar.main",
    label: "Health",
    to: "/admin/health",
    order: 97,
    description: "System component health status",
    icon: HeartbeatIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "System health requires admin role.",
  },
  {
    id: "platform.admin.tags",
    slot: "sidebar.main",
    label: "Tag Vocabulary",
    to: "/admin/tags",
    order: 86,
    description: "Admin-managed tag keys for system categorization",
    icon: TagIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Tag vocabulary management requires admin role.",
  },
  // v6.0: Saved filter administration — surface user/team filter configurations.
  {
    id: "platform.admin.saved-filters",
    slot: "sidebar.main",
    label: "Saved Filters",
    to: "/admin/saved-filters",
    order: 87,
    description: "Manage user-saved filter configurations and team-shared filters",
    icon: BookmarkSimpleIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Saved filter administration requires admin role.",
  },
  // v6.0: Task queue admin — drain/requeue/dead-letter controls.
  {
    id: "platform.admin.task-queue",
    slot: "sidebar.main",
    label: "Task Queue",
    to: "/admin/task-queue",
    order: 88,
    description: "Drain queue, requeue failures, and inspect dead-lettered tasks",
    icon: QueueIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Task queue administration requires admin role.",
  },
  // Phase 177 — multi-team admin console
  {
    id: "platform.admin.teams",
    slot: "sidebar.main",
    label: "Teams",
    to: "/admin/teams",
    order: 96,
    description: "Multi-team management and cross-team view",
    icon: UsersThreeIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Team management requires admin role.",
  },
  // v6.0: Dead letter queue — exhausted-retry inspection and requeue.
  {
    id: "platform.admin.dead-letter",
    slot: "sidebar.main",
    label: "Dead Letter",
    to: "/admin/dead-letter",
    order: 89,
    description: "Inspect and requeue tasks that exhausted their retry budget",
    icon: SkullIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Dead letter queue requires admin role.",
  },
  // v6.0: Automation schedules — cron-driven actions registered by modules.
  {
    id: "platform.admin.automation",
    slot: "sidebar.main",
    label: "Automation",
    to: "/admin/automation",
    order: 99,
    description: "Cron-driven automation schedules registered by platform modules",
    icon: ArrowsClockwiseIcon,
    section: "admin",
  },
  // v6.0: Scheduled reports — emailed report runs on a cron.
  {
    id: "platform.admin.scheduled-reports",
    slot: "sidebar.main",
    label: "Scheduled Reports",
    to: "/admin/scheduled-reports",
    order: 81,
    description: "Emailed reports configured with cron expressions",
    icon: CalendarIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Scheduled reports require admin role.",
  },
  // v6.0: Cost intelligence — LLM spend, ROI, model breakdown.
  {
    id: "platform.admin.cost",
    slot: "sidebar.main",
    label: "Cost",
    to: "/admin/cost",
    order: 82,
    description: "LLM cost trends, per-model spend, and ROI vs human-equivalent",
    icon: CurrencyDollarIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Cost intelligence requires admin role.",
  },
  // v6.0: Executive dashboard — fleet posture and downloadable artifacts.
  {
    id: "platform.admin.executive",
    slot: "sidebar.main",
    label: "Executive",
    to: "/admin/executive",
    order: 83,
    description: "Fleet-wide risk posture, executive PDF, and evidence packages",
    icon: BriefcaseIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "Executive dashboard requires admin role.",
  },
  // Phase 177 — OIDC providers (Microsoft, Google, generic)
  {
    id: "platform.admin.oidc",
    slot: "sidebar.main",
    label: "OIDC Providers",
    to: "/admin/auth/oidc-providers",
    order: 94,
    description: "Configure Microsoft, Google, and generic OIDC providers",
    icon: ShieldCheckIcon,
    section: "admin",
    minRole: "admin",
    blockedMessage: "OIDC provider management requires admin role.",
  },
  // Docs — operator-facing usage guide (D-03, D-33)
  {
    id: "platform.docs",
    slot: "sidebar.main",
    label: "Docs",
    to: "/docs",
    order: 98,
    description: "Operator guide: what each sidebar item does, how to scan, where to set the API key",
    icon: BookOpenIcon,
    section: "settings",
  },
  // Settings — bottom section
  {
    id: "platform.settings",
    slot: "sidebar.main",
    label: "Settings",
    to: "/settings",
    order: 100,
    description: "User and application settings",
    icon: GearSixIcon,
    section: "settings",
  },
];

export function blockedReasonForRole(requiredRole?: AppRole): string {
  if (!requiredRole) {
    return "This navigation item is unavailable.";
  }
  return `This navigation item requires ${requiredRole} role or higher.`;
}

function splitPathSegments(pathname: string): string[] {
  return pathname.replace(/^\/+/, "").replace(/\/+$/, "").split("/").filter(Boolean);
}

function titleCaseSegment(segment: string): string {
  return segment
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function deriveGroup(item: SidebarItem): { id: string; label: string } | null {
  const segments = splitPathSegments(item.to);
  if (segments.length < 2) {
    return null;
  }

  const [firstSegment] = segments;
  return {
    id: `sidebar-group.${firstSegment}`,
    label: firstSegment === "admin" ? "Admin" : titleCaseSegment(firstSegment),
  };
}

export function isSidebarPathActive(currentPath: string, itemPath: string): boolean {
  if (itemPath === "/") {
    return currentPath === "/";
  }
  return currentPath === itemPath || currentPath.startsWith(`${itemPath}/`);
}

/**
 * Returns sidebar items grouped by section for the new AppSidebar.
 * Sections: platform, modules (from moduleSpecs), admin, settings.
 * Hidden section items are excluded from rendering.
 */
export function getSidebarSections(moduleSpecs: ModuleFrontendSpec[]): SidebarSection[] {
  const moduleItems: SidebarItem[] = moduleSpecs
    .flatMap((spec) => spec.nav ?? [])
    .filter((item) => item.slot === "sidebar.main")
    .map((item) => ({
      ...item,
      section: "modules" as NavSection,
      // NavContribution.icon (optional) is now plumbed through to
      // SidebarItem.icon so module-contributed nav rows render the
      // module's chosen icon. Before this change, only platformSidebarItems
      // got icons; spec.nav items always rendered iconless.
      // Cast is safe — NavContribution.icon is typed as a generic
      // ComponentType, SidebarItem.icon expects Phosphor's Icon (a
      // narrower ForwardRef type). Every Phosphor icon satisfies both.
      icon: (item.icon ?? undefined) as Icon | undefined,
    }))
    .sort((a, b) => a.order - b.order);

  const platformItems = platformSidebarItems
    .filter((item) => item.section === "platform")
    .sort((a, b) => a.order - b.order);

  const adminItems = platformSidebarItems
    .filter((item) => item.section === "admin")
    .sort((a, b) => a.order - b.order);

  const settingsItems = platformSidebarItems
    .filter((item) => item.section === "settings")
    .sort((a, b) => a.order - b.order);

  const sections: SidebarSection[] = [
    { id: "platform", label: "Platform", items: platformItems },
  ];

  if (moduleItems.length > 0) {
    // Group module items by their parent moduleSpec for visual subgroups
    const subgroupMap = new Map<string, ModuleSubgroup>();
    for (const spec of moduleSpecs) {
      const specItems = (spec.nav ?? [])
        .filter((item) => item.slot === "sidebar.main")
        .map((item) => ({
          ...item,
          section: "modules" as NavSection,
          icon: (item.icon ?? undefined) as Icon | undefined,
        }))
        .sort((a, b) => a.order - b.order);
      if (specItems.length > 0) {
        subgroupMap.set(spec.moduleId, {
          moduleId: spec.moduleId,
          label: titleCaseSegment(spec.moduleId),
          items: specItems,
        });
      }
    }
    const subgroups = [...subgroupMap.values()];

    sections.push({
      id: "modules",
      label: "Modules",
      items: moduleItems,
      subgroups: subgroups.length > 0 ? subgroups : undefined,
    });
  }

  if (adminItems.length > 0) {
    sections.push({ id: "admin", label: "Admin", items: adminItems });
  }

  if (settingsItems.length > 0) {
    sections.push({ id: "settings", label: "Settings", items: settingsItems });
  }

  return sections;
}

/**
 * Legacy entry builder — retained for any code that still calls buildSidebarEntries.
 * New AppSidebar uses getSidebarSections instead.
 */
export function buildSidebarEntries(moduleSpecs: ModuleFrontendSpec[]): SidebarEntry[] {
  const navAsSidebarItems: SidebarItem[] = moduleSpecs
    .flatMap((spec) => spec.nav ?? [])
    .map((item) => ({
      ...item,
      icon: (item.icon ?? undefined) as Icon | undefined,
    }));
  const sortedItems: SidebarItem[] = [
    ...platformSidebarItems.filter((item) => item.section !== "hidden"),
    ...navAsSidebarItems,
  ]
    .filter((item) => item.slot === "sidebar.main")
    .sort((left, right) => left.order - right.order);

  const groupedItems = new Map<string, SidebarItem[]>();
  for (const item of sortedItems) {
    const group = deriveGroup(item);
    if (!group) {
      continue;
    }
    const items = groupedItems.get(group.id) ?? [];
    items.push(item);
    groupedItems.set(group.id, items);
  }

  const entries: SidebarEntry[] = [];
  const emittedGroups = new Set<string>();

  for (const item of sortedItems) {
    const group = deriveGroup(item);
    if (!group) {
      entries.push({ kind: "item", order: item.order, item });
      continue;
    }

    const groupItems = groupedItems.get(group.id) ?? [];
    if (groupItems.length < 2) {
      entries.push({ kind: "item", order: item.order, item });
      continue;
    }

    if (emittedGroups.has(group.id)) {
      continue;
    }

    emittedGroups.add(group.id);
    entries.push({
      kind: "group",
      id: group.id,
      label: group.label,
      order: Math.min(...groupItems.map((groupItem) => groupItem.order)),
      items: groupItems,
    });
  }

  return entries.sort((left, right) => left.order - right.order);
}

export type { Icon };
