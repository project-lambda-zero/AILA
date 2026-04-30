import React from "react";

import type { AppRole } from "@platform/auth/roles";
import type { RouteContribution } from "@platform/extension-registry/types";

import { SbdNfrWorkspacePage } from "./screens/SbdNfrWorkspacePage";

// Phase 156: Schema editor (admin only)
const SchemaEditorScreen = React.lazy(
  () => import("./screens/SchemaEditorScreen").then((m) => ({ default: m.default })),
);

// v2.2 Wizard screens (lazy-loaded — implementations arrive in Plans 02-04)
const AssessmentsListPage = React.lazy(
  () => import("./screens/AssessmentsListPage").then((m) => ({ default: m.AssessmentsListPage })),
);
const WizardShareGatePage = React.lazy(
  () =>
    import("./screens/WizardShareGatePage").then((m) => ({ default: m.WizardShareGatePage })),
);
const WizardPage = React.lazy(
  () => import("./screens/WizardPage").then((m) => ({ default: m.WizardPage })),
);
const WizardResultsPage = React.lazy(
  () =>
    import("./screens/WizardResultsPage").then((m) => ({ default: m.WizardResultsPage })),
);

// Phase 145: Architect review, report preview, comparison, template management
const ArchitectReviewPage = React.lazy(
  () =>
    import("./screens/ArchitectReviewPage").then((m) => ({ default: m.ArchitectReviewPage })),
);
const ReportPreviewPage = React.lazy(
  () =>
    import("./screens/ReportPreviewPage").then((m) => ({ default: m.ReportPreviewPage })),
);
const SessionComparisonPage = React.lazy(
  () =>
    import("./screens/SessionComparisonPage").then((m) => ({ default: m.SessionComparisonPage })),
);
const TemplateManagementPage = React.lazy(
  () =>
    import("./screens/TemplateManagementPage").then((m) => ({
      default: m.TemplateManagementPage,
    })),
);

// CRITICAL: /assessments/shared MUST appear before /assessments/:sessionId/...
// to prevent React Router 7 matching the literal string "shared" as a sessionId
// (per Pitfall 1 in RESEARCH.md — static segments before dynamic segments).
export const routes: RouteContribution[] = [
  {
    id: "sbd_nfr.workspace",
    path: "/sbd-nfr",
    page: SbdNfrWorkspacePage,
    title: "SbD NFR",
    nav: true,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.assessments",
    path: "/assessments",
    page: AssessmentsListPage,
    title: "Assessments",
    nav: true,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.wizard.shared",
    path: "/assessments/shared",
    page: WizardShareGatePage,
    title: "NFR Assessment",
    nav: false,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.wizard",
    path: "/assessments/:sessionId/wizard/:sectionKey",
    page: WizardPage,
    title: "NFR Wizard",
    nav: false,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.wizard.results",
    path: "/assessments/:sessionId/results",
    page: WizardResultsPage,
    title: "Assessment Results",
    nav: false,
    slot: "page.full",
  },
  // Phase 145 routes
  {
    id: "sbd_nfr.review",
    path: "/assessments/:sessionId/review",
    page: ArchitectReviewPage,
    title: "Architect Review",
    nav: false,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.report",
    path: "/assessments/:sessionId/report",
    page: ReportPreviewPage,
    title: "Assessment Report",
    nav: false,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.compare",
    path: "/assessments/compare",
    page: SessionComparisonPage,
    title: "Compare Assessments",
    nav: false,
    slot: "page.full",
  },
  {
    id: "sbd_nfr.templates",
    path: "/assessments/templates",
    page: TemplateManagementPage,
    title: "Assessment Templates",
    nav: false,
    slot: "page.full",
  },
  // Phase 156: Schema editor — admin only
  {
    id: "sbd_nfr.schema_editor",
    path: "/admin/schema-editor",
    page: SchemaEditorScreen,
    title: "Schema Editor",
    nav: false,
    slot: "page.full" as const,
    minRole: "admin" as AppRole,
  },
];
