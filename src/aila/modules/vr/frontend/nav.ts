import { Briefcase } from "@phosphor-icons/react/dist/csr/Briefcase";
import { Bug } from "@phosphor-icons/react/dist/csr/Bug";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { Crosshair } from "@phosphor-icons/react/dist/csr/Crosshair";
import { EnvelopeSimple } from "@phosphor-icons/react/dist/csr/EnvelopeSimple";
import { Folders } from "@phosphor-icons/react/dist/csr/Folders";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { Pulse } from "@phosphor-icons/react/dist/csr/Pulse";
import { Plugs } from "@phosphor-icons/react/dist/csr/Plugs";
import { Receipt } from "@phosphor-icons/react/dist/csr/Receipt";

import type { NavContribution } from "@platform/extension-registry/types";

export const nav: NavContribution[] = [
  {
    id: "vr.projects",
    slot: "sidebar.main" as const,
    label: "Vuln Research",
    to: "/vr",
    order: 70,
    description: "N-day vulnerability research projects",
    icon: Briefcase,
  },
  {
    id: "vr.investigations",
    slot: "sidebar.main" as const,
    label: "Investigations",
    to: "/vr/investigations",
    order: 71,
    description: "Hypothesis-driven investigations across targets",
    icon: MagnifyingGlass,
  },
  {
    id: "vr.workspaces",
    slot: "sidebar.main" as const,
    label: "Workspaces",
    to: "/vr/workspaces",
    order: 69,
    description: "Thematic workspaces grouping related VR targets",
    icon: Folders,
  },
  {
    id: "vr.targets",
    slot: "sidebar.main" as const,
    label: "Targets",
    to: "/vr/targets",
    order: 69.5,
    description: "Persistent VR targets across workspaces",
    icon: Crosshair,
  },
  {
    id: "vr.patterns",
    slot: "sidebar.main" as const,
    label: "Patterns",
    to: "/vr/patterns",
    order: 72,
    description: "Reusable patterns extracted from successful investigations",
    icon: Pulse,
  },
  {
    id: "vr.disclosures",
    slot: "sidebar.main" as const,
    label: "Disclosures",
    to: "/vr/disclosures",
    order: 73,
    description: "Multi-track disclosure submission lifecycle",
    icon: EnvelopeSimple,
  },
  {
    id: "vr.fuzz-campaigns",
    slot: "sidebar.main" as const,
    label: "Fuzz Campaigns",
    to: "/vr/fuzz/campaigns",
    order: 74,
    description: "Fuzzing campaigns + crash triage",
    icon: Bug,
  },
  {
    id: "vr.mcp-servers",
    slot: "sidebar.main" as const,
    label: "MCP Servers",
    to: "/vr/mcp/servers",
    order: 75,
    description: "Configure + monitor delegated MCP workstations",
    icon: Plugs,
  },
  {
    id: "vr.audit-log",
    slot: "sidebar.main" as const,
    label: "Audit Log",
    to: "/vr/audit",
    order: 76.5,
    description: "Who-did-what-when audit trail for VR engagements",
    icon: ClipboardText,
  },
  {
    id: "vr.mcp-calls",
    slot: "sidebar.main" as const,
    label: "MCP Call Log",
    to: "/vr/mcp/calls",
    order: 76,
    description: "Live audit trail of every MCP call AILA forwarded",
    icon: Receipt,
  },
];
