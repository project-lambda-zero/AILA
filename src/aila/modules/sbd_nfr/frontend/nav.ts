import { Code, ListChecks, ShieldStar } from "@phosphor-icons/react";

import type { AppRole } from "@platform/auth/roles";
import type { NavContribution } from "@platform/extension-registry/types";

export const nav: NavContribution[] = [
  {
    id: "sbd_nfr.schema_editor",
    slot: "sidebar.main",
    label: "Schema Editor",
    to: "/admin/schema-editor",
    order: 59,
    description: "Admin: questionnaire schema management",
    minRole: "admin" as AppRole,
    icon: Code,
  },
  {
    id: "sbd_nfr.workspace",
    slot: "sidebar.main",
    label: "SbD NFR",
    to: "/sbd-nfr",
    order: 60,
    description: "Excel replacement workflow",
    icon: ShieldStar,
  },
  {
    id: "sbd_nfr.assessments",
    slot: "sidebar.main",
    label: "Assessments",
    to: "/assessments",
    order: 61,
    description: "SbD NFR assessment wizard",
    icon: ListChecks,
  },
];
