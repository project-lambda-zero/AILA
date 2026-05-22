import { Detective } from "@phosphor-icons/react";

import type { NavContribution } from "@platform/extension-registry/types";

export const nav: NavContribution[] = [
  {
    id: "forensics.projects",
    slot: "sidebar.main" as const,
    label: "Forensics",
    to: "/forensics",
    order: 60,
    description: "Forensic investigation projects",
    icon: Detective,
  },
];
