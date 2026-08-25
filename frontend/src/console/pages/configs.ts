import { createElement } from "react";

import { css } from "../css";
import { AuditEventDetail } from "./AuditEventDetail";
import { SeverityBadge, StatusBadge, WorkflowStateBadge } from "./badges";
import { humanizeCron } from "./cronPreview";
import type { PageAction, PageColumn, PageConfig } from "./DataPage";
import { LlmLogViewer } from "./LlmLogViewer";

/** Build a workflow-transition PageAction for a findings DataPage. Each POST
 * hits /findings/{id}/transition with the module id and target state; the
 * `whenField: "workflow_state"` gate hides the button on rows whose current
 * state cannot legally reach the target. Notes are collected in a small pre-
 * flight modal so operators can record why the state changed. */
function transitionAction(moduleId: string, target: string, sources: string[]): PageAction {
  return {
    label: "\u2192 " + target,
    method: "POST",
    endpoint: "/findings/{id}/transition",
    body: { module_id: moduleId, target_state: target },
    whenField: "workflow_state",
    whenStatus: sources,
    fields: [
      { name: "notes", label: "notes", type: "textarea", placeholder: "optional context recorded on the workflow record" },
    ],
  };
}

const mwTransition = (target: string, sources: string[]): PageAction =>
  transitionAction("malware", target, sources);

const vrTransition = (target: string, sources: string[]): PageAction =>
  transitionAction("vr", target, sources);

/** Column shorthand: field + auto-labelled from the field name. */
// Auto-assign a shared semantic renderer (badges.tsx) for fields whose names
// carry status/severity/timestamp/cost semantics, so every table reads state
// the same way without per-page wiring. Explicit `render` on a column still
// wins in DataPage.
const KIND_FIELDS: Record<string, "status" | "severity" | "time" | "cost"> = {
  status: "status",
  analysis_state: "status",
  disclosure_status: "status",
  latest_disclosure_status: "status",
  connectivity_status: "status",
  last_scan_status: "status",
  run_status: "status",
  severity_rating: "severity",
  cvss_score: "severity",
  cost_actual_usd: "cost",
  cost_budget_usd: "cost",
  bounty_awarded_usd: "cost",
  created_at: "time",
  updated_at: "time",
  started_at: "time",
  completed_at: "time",
  last_run_at: "time",
  last_login_at: "time",
  last_probed_at: "time",
  called_at: "time",
  last_seen_at: "time",
};

const c = (field: string, label?: string): PageColumn => ({
  field,
  label: label ?? field.replace(/_/g, " "),
  kind: KIND_FIELDS[field],
});

/** Actions on the auth surface that read as medium severity even when they
 * succeed -- minting, revoking, or issuing a credential is a security-relevant
 * event worth surfacing above routine activity. */
const AUDIT_MEDIUM_ACTIONS: Record<string, true> = {
  create_api_key: true,
  revoke_api_key: true,
  token_issue: true,
  token_refresh: true,
};

/** Audit severity is a read-time projection of (action, status), NOT a stored
 * column: a failed event is high, an auth-surface action is medium, everything
 * else is low. Named `severity` so the chip reads through the same tone map as
 * every other severity chip on the console (badges.tsx SEVERITY_TONE). */
function auditSeverity(row: Record<string, unknown>): "high" | "medium" | "low" {
  if (String(row["status"] ?? "").toLowerCase() === "failed") return "high";
  if (AUDIT_MEDIUM_ACTIONS[String(row["action"] ?? "")]) return "medium";
  return "low";
}

/** One DataPage config per left-rail item, keyed `${moduleId}:${pageId}`.
 * Endpoints + fields are the real backend contract (mapped from the routers).
 * The registry turns each of these into a live data window. */
export const PAGE_CONFIGS = {
  // ---- VR (prefix /vr) --------------------------------------------------
  "vr:workspaces": {
    title: "vr \u00b7 workspaces",
    endpoint: "/vr/workspaces",
    columns: [c("name"), c("slug"), c("status"), c("target_count", "targets"), c("active_investigation_count", "active"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "vr:targets": {
    title: "vr \u00b7 targets",
    endpoint: "/vr/targets",
    columns: [c("display_name", "name"), c("kind"), c("status"), c("analysis_state", "analysis"), c("primary_language", "lang"), c("workspace_name", "workspace"), c("created_at", "created")],
    filters: [{ name: "display_name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "vr:investigations": {
    title: "vr \u00b7 investigations",
    endpoint: "/vr/investigations",
    blurb: "click a row to raise its x-ray; the targets page drills down per target",
    // Server-side pagination + filters: /vr/investigations paginates by
    // offset/limit (meta.total) and accepts ?q=&status=&kind= (api_router
    // list_investigations). The filters below are marked server:true so they
    // narrow the full catalogue and the page count reflects the filtered
    // total, not just the loaded page.
    pagination: true,
    paginationParams: "offset",
    filters: [
      { name: "q", label: "search title", type: "text", server: true },
      { name: "status", label: "status", type: "select", server: true, options: [
        { value: "running", label: "running" },
        { value: "paused", label: "paused" },
        { value: "stalled", label: "stalled" },
        { value: "completed", label: "completed" },
        { value: "failed", label: "failed" },
        { value: "abandoned", label: "abandoned" },
        { value: "created", label: "created" },
      ] },
      { name: "kind", label: "kind", type: "select", server: true, options: [
        { value: "discovery", label: "discovery" },
        { value: "variant_hunt", label: "variant hunt" },
        { value: "triage", label: "triage" },
        { value: "n_day", label: "n-day" },
        { value: "audit", label: "audit" },
        { value: "masvs_audit", label: "masvs audit" },
        { value: "apk_static_audit", label: "apk static audit" },
      ] },
      // targets label uses `display_name` because VRTargetSummary has no
      // `name` field. `has_outcomes` offers only the `true` option since an
      // empty select reads as any. Polarity and verifier verdict are
      // enumerable sets, so they are `select`, not free text.
      { name: "target_id", label: "target", type: "select", server: true, optionsFrom: "/vr/targets", optionsValueField: "id", optionsLabelField: "display_name" },
      { name: "workspace_id", label: "workspace", type: "select", server: true, optionsFrom: "/vr/workspaces", optionsValueField: "id", optionsLabelField: "name" },
      // No project_id filter: VRInvestigationRecord.project_id is never set on
      // any creation path (main create, variant-hunt children, and fuzz child
      // copies all leave it NULL), and VRInvestigationSummary carries no
      // project_id field -- so the filter could only ever return zero rows and
      // the column could never confirm a match. The n-day project surface is
      // the CVE-reproduction page instead (req 4 / vr-navigation-ia AC4).
      { name: "has_outcomes", label: "outcomes", type: "select", server: true, options: [{ value: "true", label: "with outcomes" }] },
      { name: "primary_outcome_polarity", label: "verdict polarity", type: "select", server: true, options: [
        { value: "finding", label: "finding" },
        { value: "no_finding", label: "no finding" },
        { value: "inconclusive", label: "inconclusive" },
      ] },
      { name: "verifier_verdict", label: "verdict", type: "select", server: true, options: [
        { value: "confirmed", label: "confirmed" },
        { value: "refuted", label: "refuted" },
        { value: "inconclusive", label: "inconclusive" },
      ] },
    ],
    // Result-first columns. `kind` is the operator's classification of the
    // investigation (discovery / variant_hunt / triage / n_day / audit);
    // `strategy_family` is the reasoning playbook the engine runs, which the
    // server derives from `kind` by default -- so it duplicates `kind` on
    // almost every row and is dropped here (still visible in the x-ray when
    // overridden). `verdict` is the polarity of the primary outcome, `outcome`
    // its type, `findings` the concrete finding records produced, `outcomes`
    // the count of typed reasoning outcomes.
    columns: [
      c("title"),
      c("kind"),
      c("status"),
      {
        field: "primary_outcome_polarity",
        label: "verdict",
        render: (v) => {
          if (v === null || v === undefined || v === "") return "\u2014";
          const s = String(v);
          const tone = s === "finding" ? "ok" : s === "inconclusive" ? "warn" : "muted";
          return createElement(StatusBadge, { value: s.replace(/_/g, " "), tone });
        },
      },
      {
        field: "primary_outcome_kind",
        label: "outcome",
        render: (v) => (v === null || v === undefined || v === "" ? "\u2014" : String(v).replace(/_/g, " ")),
      },
      {
        field: "linked_finding_ids",
        label: "findings",
        render: (v) => {
          const n = Array.isArray(v) ? v.length : 0;
          return createElement(
            "span",
            { style: css(`font-family:var(--font-mono);font-variant-numeric:tabular-nums;color:${n > 0 ? "var(--accent)" : "var(--text-faint)"};`) },
            String(n),
          );
        },
      },
      c("outcome_count", "outcomes"),
      c("cost_actual_usd", "cost $"),
    ],
  },
  "vr:patterns": {
    title: "vr \u00b7 patterns",
    endpoint: "/vr/patterns",
    // /vr/patterns paginates by offset/limit (meta.total) and filters by
    // kind/status/scope; the filters below are server-side so they narrow the
    // full catalog and the page count reflects the filtered total.
    pagination: true,
    paginationParams: "offset",
    columns: [c("kind"), c("summary"), c("confidence"), c("status"), c("scope"), c("trust_tier", "trust"), c("times_retrieved", "reused")],
    // Review transitions go through the existing PATCH contract (there is no
    // dedicated review endpoint by design): promote draft -> active, and
    // archive active -> archived. Each is gated on the row's lifecycle status
    // so the button only shows on rows it can legally move.
    actions: [
      { label: "promote to active", method: "PATCH", endpoint: "/vr/patterns/{id}", body: { status: "active" }, whenField: "status", whenStatus: ["draft"] },
      { label: "archive", method: "PATCH", endpoint: "/vr/patterns/{id}", body: { status: "archived" }, whenField: "status", whenStatus: ["active"], confirm: "archive this pattern? archived patterns are no longer returned by applicable-pattern retrieval." },
    ],
    filters: [
      { name: "kind", label: "kind", type: "select", server: true, options: [
        { value: "exploitation_technique", label: "exploitation technique" },
        { value: "fuzzing_strategy", label: "fuzzing strategy" },
        { value: "search_heuristic", label: "search heuristic" },
        { value: "tool_recipe", label: "tool recipe" },
        { value: "triage_rule", label: "triage rule" },
      ] },
      { name: "status", label: "status", type: "select", server: true, options: [
        { value: "draft", label: "draft" },
        { value: "active", label: "active" },
        { value: "archived", label: "archived" },
      ] },
      { name: "scope", label: "scope", type: "select", server: true, options: [
        { value: "local", label: "local" },
        { value: "workspace", label: "workspace" },
        { value: "team", label: "team" },
        { value: "global", label: "global" },
      ] },
    ],
  },
  "vr:findings": {
    title: "vr \u00b7 findings",
    endpoint: "/vr/findings",
    // /vr/findings paginates by offset/limit with meta{total,offset,limit}
    // (api_router.py:1665+), so offset-mode pagination reads the true total.
    pagination: true,
    paginationParams: "offset",
    columns: [
      c("crash_type", "crash"),
      c("vulnerable_function", "function"),
      {
        field: "workflow_state",
        label: "state",
        render: (v) => createElement(WorkflowStateBadge, { value: v ?? "new" }),
      },
      c("disclosure_status", "disclosure"),
      c("assigned_cve_id", "cve"),
      c("cvss_score", "cvss"),
      c("cwe_id", "cwe"),
      c("evidence_count", "evidence"),
    ],
    filters: [{ name: "crash_type", label: "crash type", type: "text" }, { name: "workflow_state", label: "state", type: "select" }],
    // Enrich a finding in place: writers leave triage/classification fields
    // NULL for stub and direct-dispatch findings, so the operator fills them
    // through the pre-flight modal (fields prefill from the row where present).
    // PATCH /vr/findings/{id} is the project-agnostic edit endpoint so null-
    // project stubs are editable; the response re-derives the list row.
    actions: [
      {
        label: "edit",
        method: "PATCH",
        endpoint: "/vr/findings/{id}",
        fields: [
          { name: "crash_type", label: "crash type", type: "text", fromRow: "crash_type", placeholder: "e.g. overflow_heap, uaf, oob_write" },
          { name: "vulnerable_function", label: "vulnerable function", type: "text", fromRow: "vulnerable_function" },
          { name: "cvss_score", label: "cvss score", type: "number", fromRow: "cvss_score", placeholder: "0.0 - 10.0" },
          { name: "cvss_vector", label: "cvss vector", type: "text", fromRow: "cvss_vector" },
          { name: "cwe_id", label: "cwe id", type: "text", fromRow: "cwe_id", placeholder: "e.g. CWE-416" },
          { name: "assigned_cve_id", label: "cve id", type: "text", fromRow: "assigned_cve_id", placeholder: "e.g. CVE-2025-1234" },
          { name: "evidence_refs", label: "evidence refs", type: "tags", placeholder: "message / outcome ids or source citations" },
        ],
      },
      // Workflow transitions. Each row calls POST /findings/{id}/transition
      // with module_id="vr" and the target state; whenStatus gates the button
      // by the row's current workflow_state so only legal edges appear. The
      // graph mirrors module.py workflow_definitions() (base triage +
      // vr.false_positive / vr.accepted_risk) -- keep in lockstep.
      vrTransition("investigating", ["new", "mitigated", "vr.false_positive", "vr.accepted_risk"]),
      vrTransition("mitigated", ["investigating"]),
      vrTransition("verified", ["mitigated"]),
      vrTransition("closed", ["verified"]),
      vrTransition("vr.false_positive", ["investigating"]),
      vrTransition("vr.accepted_risk", ["investigating"]),
    ],
  },
  "vr:disclosures": {
    title: "vr \u00b7 disclosures",
    endpoint: "/vr/disclosures",
    // /vr/disclosures paginates by offset/limit with meta{total,offset,limit}
    // (api_router.py:7440+), so offset-mode reads the true total and the list
    // is reachable past the default 50-row page.
    pagination: true,
    paginationParams: "offset",
    // Each row embeds its resolved channel (VRDisclosureSubmissionSummary.
    // track_info), so the track name shows as a column and the full track
    // detail (program_url, accepted_poc_tiers, embargo_default_days, ...)
    // renders in the click-open detail panel via StructuredValue -- there is
    // no separate disclosure-tracks page.
    columns: [
      c("finding_id", "finding"),
      {
        field: "track_info",
        label: "track",
        render: (v) => {
          const info = v as { display_name?: unknown } | null;
          const name = info && typeof info === "object" ? info.display_name : null;
          return name != null && name !== "" ? String(name) : "\u2014";
        },
      },
      c("kind"),
      c("status"),
      c("poc_tier", "poc"),
      c("severity_rating", "severity"),
      c("bounty_awarded_usd", "bounty $"),
      c("created_at", "created"),
    ],
    filters: [{ name: "kind", label: "kind", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "vr:fuzz-campaigns": {
    title: "vr \u00b7 fuzz campaigns",
    endpoint: "/vr/fuzz/campaigns",
    columns: [c("name"), c("engine_id", "engine"), c("status"), c("coverage_pct", "coverage %"), c("crashes_found", "crashes"), c("total_execs", "execs"), c("execs_per_sec", "exec/s")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }],
    actions: [
      {
        label: "launch",
        method: "POST",
        endpoint: "/vr/fuzz/campaigns/{id}/launch",
        whenStatus: ["created", "draft", "stopped", "failed"],
        confirm: "Launch this fuzz campaign on its analysis system?",
      },
      {
        label: "stop",
        method: "PATCH",
        endpoint: "/vr/fuzz/campaigns/{id}",
        body: { status: "stopped" },
        whenStatus: ["running", "active", "launching"],
        confirm: "Stop this fuzz campaign?",
      },
    ],
  },
  // ---- Malware (prefix /malware) ---------------------------------------
  "malware:workspaces": {
    title: "malware \u00b7 workspaces",
    endpoint: "/malware/workspaces",
    columns: [c("name"), c("slug"), c("status"), c("target_count", "targets"), c("active_investigation_count", "active"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "malware:targets": {
    title: "malware \u00b7 targets",
    endpoint: "/malware/targets",
    columns: [c("display_name", "name"), c("kind"), c("primary_language", "lang"), c("status"), c("analysis_state", "analysis"), c("uploaded_filename", "file"), c("created_at", "created")],
    filters: [{ name: "display_name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "malware:investigations": {
    title: "malware \u00b7 investigations",
    endpoint: "/malware/investigations",
    columns: [c("title"), c("kind"), c("status"), c("strategy_family", "strategy"), c("branch_count", "branches"), c("message_count", "turns"), c("outcome_count", "outcomes"), c("cost_actual_usd", "cost $")],
    filters: [{ name: "title", label: "title", type: "text" }, { name: "status", label: "status", type: "select" }],
  },
  "malware:observations": {
    title: "malware \u00b7 observations",
    endpoint: "/malware/observations",
    scopeFrom: { endpoint: "/malware/targets", param: "target_id" },
    blurb: "scoped to the first target; pick another target in the header scope selector",
    columns: [c("kind"), c("polarity"), c("source"), c("target_id", "target"), c("investigation_id", "investigation"), c("created_at", "created")],
    filters: [{ name: "kind", label: "kind", type: "text" }, { name: "polarity", label: "polarity", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "malware:patterns": {
    title: "malware \u00b7 patterns",
    endpoint: "/malware/patterns",
    columns: [c("kind"), c("summary"), c("confidence"), c("status"), c("scope"), c("trust_tier", "trust"), c("times_retrieved", "reused")],
    filters: [{ name: "kind", label: "kind", type: "text" }, { name: "status", label: "status", type: "select" }],
  },
  "malware:findings": {
    title: "malware \u00b7 findings",
    endpoint: "/malware/findings",
    columns: [
      c("kind"),
      c("confidence"),
      {
        field: "workflow_state",
        label: "state",
        render: (v) => createElement(WorkflowStateBadge, { value: v ?? "new" }),
      },
      c("target_id", "target"),
      c("investigation_id", "investigation"),
      c("operator_notes", "notes"),
      c("created_at", "created"),
    ],
    filters: [{ name: "kind", label: "kind", type: "text" }, { name: "workflow_state", label: "state", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
    // Workflow transitions. Each row calls POST /findings/{id}/transition with
    // module_id="malware" and the target state; whenStatus gates the button by
    // the row's current workflow_state so only legal edges appear. The graph
    // mirrors the backend contract in module.py workflow_definitions() -- keep
    // in lockstep. Notes are optional operator context, sent verbatim.
    actions: [
      mwTransition("investigating", ["new", "mitigated", "malware.benign_confirmed", "malware.quarantined"]),
      mwTransition("mitigated", ["investigating"]),
      mwTransition("verified", ["mitigated"]),
      mwTransition("closed", ["verified"]),
      mwTransition("malware.benign_confirmed", ["investigating"]),
      mwTransition("malware.quarantined", ["investigating"]),
    ],
  },
  "malware:families": {
    title: "malware \u00b7 families",
    endpoint: "/malware/families",
    scopeFrom: { endpoint: "/malware/workspaces", param: "workspace_id" },
    blurb: "scoped to the first workspace; pick another workspace in the header scope selector",
    columns: [c("name"), c("actor_cluster", "actor"), c("status"), c("sample_count", "samples"), c("playbook_count", "playbooks"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "malware:playbooks": {
    title: "malware \u00b7 playbooks",
    endpoint: "/malware/playbooks",
    scopeFrom: { endpoint: "/malware/workspaces", param: "workspace_id" },
    blurb: "scoped to the first workspace; pick another workspace in the header scope selector",
    columns: [c("name"), c("description"), c("status"), c("run_count", "runs"), c("last_run_at", "last run"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "last_run_at", label: "last run", type: "date-range" }],
    actions: [
      {
        label: "run",
        method: "POST",
        endpoint: "/malware/playbooks/{id}/run",
        whenStatus: ["active", "draft", "published"],
        confirm: "Run this playbook now?",
      },
    ],
  },

  // ---- Forensics (prefix /forensics) -----------------------------------
  "forensics:projects": {
    title: "forensics \u00b7 projects",
    endpoint: "/forensics/projects",
    itemsKey: "items",
    columns: [c("name"), c("project_kind", "kind"), c("status"), c("system_name", "system"), c("evidence_count", "evidence"), c("artifact_count", "artifacts"), c("lead_count", "leads"), c("investigation_count", "investigations")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }],
    actions: [
      {
        label: "check readiness",
        method: "POST",
        endpoint: "/forensics/projects/{id}/readiness-check",
        confirm: "Check analyzer readiness for this project? This may enqueue a full-analysis run.",
      },
    ],
  },

  // ---- Admin: access ----------------------------------------------------
  "admin:users": {
    title: "admin \u00b7 users",
    endpoint: "/users",
    columns: [c("username"), c("email"), c("role"), c("team_id", "team"), c("is_active", "active"), c("last_login_at", "last login"), c("created_at", "created")],
    filters: [{ name: "username", label: "username", type: "text" }, { name: "role", label: "role", type: "select" }, { name: "last_login_at", label: "last login", type: "date-range" }],
    actions: [
      {
        label: "deactivate",
        method: "PATCH",
        endpoint: "/users/{id}",
        body: { is_active: false },
        whenStatus: ["true", "active", "1"],
        confirm: "Deactivate this user account?",
      },
      {
        label: "activate",
        method: "PATCH",
        endpoint: "/users/{id}",
        body: { is_active: true },
        whenStatus: ["false", "inactive", "0"],
      },
    ],
  },
  "admin:teams": {
    title: "admin \u00b7 teams",
    endpoint: "/admin/teams",
    columns: [c("name"), c("description"), c("member_count", "members"), c("created_at", "created"), c("updated_at", "updated")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "admin:api-keys": {
    title: "admin \u00b7 api keys",
    endpoint: "/auth/keys",
    itemsKey: "keys",
    idField: "key_id",
    columns: [c("key_prefix", "prefix"), c("role"), c("label"), c("created_by", "by"), c("created_at", "created"), c("revoked_at", "revoked")],
    filters: [
      { name: "role", label: "role", type: "multi-select" },
      {
        name: "revoked_at",
        label: "status",
        type: "segmented",
        options: [
          { value: "active", label: "active" },
          { value: "revoked", label: "revoked" },
        ],
        deriveValue: (r) => (r.revoked_at ? "revoked" : "active"),
      },
      {
        name: "label",
        label: "search",
        type: "text",
        deriveValue: (r) => `${r.label ?? ""} ${r.key_prefix ?? ""}`,
      },
      { name: "created_at", label: "created", type: "date-range" },
    ],
    pageActions: [
      {
        label: "mint key",
        method: "POST",
        endpoint: "/auth/keys",
        body: { role: "reader" },
        fields: [
          {
            name: "role",
            label: "role",
            type: "select",
            options: [
              { value: "reader", label: "reader" },
              { value: "operator", label: "operator" },
              { value: "admin", label: "admin" },
            ],
          },
          { name: "label", label: "label", type: "text", placeholder: "human-readable name" },
          {
            name: "team_id",
            label: "team id (god-tier only)",
            type: "text",
            placeholder: "blank = your own team",
            godTierOnly: true,
          },
        ],
        reveal: {
          title: "api key created",
          note: "copy the raw key now -- it is never shown again",
          fields: ["raw_key", "key_prefix", "role", "label"],
        },
      },
    ],
    actions: [
      {
        label: "revoke",
        method: "DELETE",
        endpoint: "/auth/keys/{id}",
        destructive: true,
        confirm: "Revoke this API key? This cannot be undone.",
      },
    ],
  },
  "admin:oidc-providers": {
    title: "admin \u00b7 oidc providers",
    endpoint: "/auth/oidc/providers",
    columns: [c("provider_name", "name"), c("provider_type", "type"), c("display_name", "display"), c("issuer_url", "issuer"), c("client_id", "client"), c("is_enabled", "enabled")],
    filters: [{ name: "display_name", label: "display name", type: "text" }],
  },
  // ---- Admin: operations ------------------------------------------------
  "admin:task-queue": {
    title: "admin \u00b7 task queue",
    endpoint: "/tasks",
    itemsKey: "tasks",
    idField: "task_id",
    columns: [c("task_id", "task"), c("track"), c("status"), c("fn_path", "fn"), c("created_at", "created"), c("started_at", "started"), c("completed_at", "completed")],
    filters: [{ name: "track", label: "track", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
    actions: [
      {
        label: "cancel",
        method: "POST",
        endpoint: "/tasks/{id}/cancel",
        whenStatus: ["queued", "running", "waiting"],
        destructive: true,
        confirm: "Cancel this task?",
      },
      {
        label: "resume",
        method: "POST",
        endpoint: "/tasks/{id}/resume",
        whenStatus: ["failed", "cancelled", "canceled"],
      },
    ],
    bulkActions: [
      {
        label: "cancel selected",
        method: "POST",
        endpoint: "/tasks/{id}/cancel",
        destructive: true,
        confirm: "Cancel the selected tasks?",
      },
    ],
    pageActions: [
      {
        label: "requeue failed",
        method: "POST",
        endpoint: "/tasks/requeue-failed",
        confirm: "Requeue all failed tasks?",
      },
      {
        label: "drain",
        method: "POST",
        endpoint: "/tasks/drain",
        destructive: true,
        confirm: "Drain the queue? This rejects queued tasks.",
      },
    ],
  },
  "admin:dead-letter": {
    title: "admin \u00b7 dead letter",
    endpoint: "/admin/tasks/dead-letter",
    idField: "task_id",
    columns: [c("task_id", "task"), c("track"), c("fn_path", "fn"), c("exception_class", "exception"), c("error"), c("attempts"), c("dead_lettered_at", "when")],
    filters: [{ name: "track", label: "track", type: "text" }],
    actions: [
      {
        label: "requeue",
        method: "POST",
        endpoint: "/admin/tasks/dead-letter/{id}/requeue",
        confirm: "Requeue this dead-lettered task?",
      },
    ],
  },
  "admin:health": {
    title: "admin \u00b7 health",
    endpoint: "/health/comprehensive",
    itemsKey: "subsystems",
    blurb: "per-subsystem comprehensive health",
    columns: [],
    // subsystems is a real multi-row list (SubsystemHealth per probe); both
    // controls narrow auto-derived columns the table actually renders --
    // name (text substring) and status (row-derived select over the live
    // SubsystemStatus enum). Client-side, so no backend coupling.
    filters: [
      { name: "name", label: "subsystem", type: "text" },
      { name: "status", label: "status", type: "select" },
    ],
  },
  "admin:automation": {
    title: "admin \u00b7 automation",
    endpoint: "/automation/schedules",
    blurb: "an automation schedule is a registered action the platform runs on a cron against a target system",
    columns: [
      c("action_id", "action"),
      c("target_name", "target"),
      c("cron_expression", "cron"),
      {
        // display-only humanized cron column derived from cron_expression
        // (distinct `field` so the React key + auto-derived filter options
        // don't collide with the raw cron column above).
        field: "cron_human",
        label: "schedule",
        render: (_value, row) => {
          const raw = typeof row["cron_expression"] === "string" ? String(row["cron_expression"]) : "";
          return raw ? humanizeCron(raw) : "\u2014";
        },
      },
      c("enabled"),
      c("last_run_at", "last run"),
      c("last_run_result", "result"),
    ],
    filters: [
      {
        name: "action_id",
        label: "action",
        type: "select",
        optionsFrom: "/automation/actions",
        optionsValueField: "action_id",
        optionsLabelField: "action_id",
      },
      {
        name: "enabled",
        label: "enabled",
        type: "select",
        options: [
          { value: "true", label: "yes" },
          { value: "false", label: "no" },
        ],
      },
      { name: "target_name", label: "target name", type: "text" },
      { name: "last_run_at", label: "last run", type: "date-range" },
    ],
  },
  "admin:workflows": {
    title: "admin \u00b7 workflows",
    endpoint: "/admin/workflows/runs",
    columns: [c("run_id", "run"), c("current_state", "state"), c("definition_id", "definition"), c("retries_in_state", "retries"), c("version"), c("updated_at", "updated")],
    filters: [
      { name: "run_id", label: "run", type: "text" },
      { name: "definition_id", label: "definition", type: "text", server: true },
      { name: "current_state", label: "state", type: "select", server: true },
      { name: "updated_at", label: "updated", type: "date-range" },
    ],
  },
  "admin:scheduled-reports": {
    title: "admin \u00b7 scheduled reports",
    endpoint: "/scheduled-reports",
    columns: [c("name"), c("report_type", "type"), c("cron_expression", "cron"), c("is_active", "active"), c("last_run_at", "last run"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "is_active", label: "is active", type: "select" }, { name: "last_run_at", label: "last run", type: "date-range" }],
    actions: [
      {
        label: "trigger now",
        method: "POST",
        endpoint: "/scheduled-reports/{id}/trigger",
        confirm: "Trigger this report now?",
      },
    ],
  },
  // ---- Admin: data & config --------------------------------------------
  "admin:config": {
    title: "admin \u00b7 config",
    endpoint: "/config",
    itemsKey: "items",
    // The registry holds 273 rows across namespaces; the backend list
    // endpoint accepts ONLY page/page_size (no namespace/type filter params,
    // verified in api/routers/config.py), so filters are client-side and the
    // full dataset is pulled once via fetchAllPages. Pagination then slices
    // the FILTERED set client-side so totals stay truthful.
    fetchAllPages: true,
    pagination: true,
    filters: [
      { name: "namespace", label: "namespace", type: "text" },
      { name: "value_type", label: "type", type: "select", options: [
        { value: "str", label: "str" },
        { value: "int", label: "int" },
        { value: "float", label: "float" },
        { value: "bool", label: "bool" },
      ] },
    ],
    // Each config PUT records an audit event with run_id="{namespace}/{key}"
    // (config.py:169-214); the detail panel shows that trail.
    detailEvents: { endpoint: "/audit/events?run_id={namespace}/{key}" },
    columns: [c("namespace"), c("key"), c("value_type", "type"), c("effective_value", "value"), c("effective_source", "source"), c("overridden_by_env", "env override"), c("updated_at", "updated")],
  },
  "admin:tools": {
    title: "admin \u00b7 tools",
    endpoint: "/tools",
    columns: [c("tool_key", "key"), c("name"), c("description"), c("module_id", "module")],
    filters: [{ name: "name", label: "name", type: "text" }],
  },
  // ---- Admin: audit -----------------------------------------------------
  "admin:audit-logs": {
    title: "admin \u00b7 audit logs",
    endpoint: "/audit/events",
    itemsKey: "items",
    // /audit/events honors page/page_size and returns total/pages in a
    // PaginatedResponse envelope (schemas/common.py:24), so server-side
    // pagination works exactly.
    pagination: true,
    // Derived `severity` is a read-time projection of (action, status), never a
    // stored column (auditSeverity). The five backend filters ride the req 28
    // primitive server-side so they compose with pagination + true total: the
    // multi-selects post repeated params (OR within a field), `search` maps to
    // the target ILIKE, and the `created_at` range posts created_at_since /
    // created_at_until -- all consumed by GET /audit/events.
    columns: [
      c("created_at", "when"),
      c("stage"),
      c("action"),
      c("status"),
      { field: "severity", label: "severity", render: (_v, row) => createElement(SeverityBadge, { value: auditSeverity(row) }) },
      c("target"),
      c("user_id", "user"),
      c("run_id", "run"),
    ],
    filters: [
      { name: "stage", label: "stage", type: "multi-select", server: true },
      { name: "action", label: "action", type: "multi-select", server: true },
      { name: "status", label: "status", type: "multi-select", server: true },
      { name: "user_id", label: "user", type: "multi-select", server: true },
      { name: "search", label: "target", type: "text", server: true },
      { name: "created_at", label: "when", type: "date-range", server: true },
    ],
    detailRenderers: {
      details: (v, row) => createElement(AuditEventDetail, { value: v, row }),
    },
  },
  "admin:llm-log": {
    title: "admin \u00b7 llm log",
    endpoint: "/admin/llm-log",
    itemsKey: "items",
    // Row previews were dropped from the table: they leaked opaque JSON
    // fragments and the same information is available in-context via the
    // rowViewer floater. The viewer fetches the full stored transcript
    // (paired audit seal when present, row preview when disabled) via
    // GET /admin/llm-log/{id}/content and renders it as a two-pane chat
    // transcript, so the list stays scannable while the detail carries
    // the full body. Filters ride the req 28 primitive server-side and
    // compose with pagination + true meta.total.
    pagination: true,
    columns: [
      c("timestamp", "when"),
      c("model"),
      c("task_type", "task"),
      c("user_id", "user"),
      c("run_id", "run"),
      c("input_tokens", "in"),
      c("output_tokens", "out"),
      c("cost_usd", "cost $"),
      c("duration_ms", "ms"),
      c("status"),
    ],
    filters: [
      { name: "model", label: "model", type: "multi-select", server: true },
      { name: "task_type", label: "task", type: "multi-select", server: true },
      { name: "status", label: "status", type: "multi-select", server: true },
      { name: "user_id", label: "user", type: "text", server: true },
      { name: "team_id", label: "team", type: "text", server: true },
      { name: "search", label: "search", type: "text", server: true },
      { name: "timestamp", label: "when", type: "date-range", server: true },
      { name: "cost_usd", label: "cost $", type: "numeric-range", server: true },
    ],
    rowViewer: {
      actionLabel: "view content",
      title: (row) => {
        const id = row["id"];
        const model = row["model"];
        const idStr = typeof id === "string" || typeof id === "number" ? String(id) : "?";
        const modelStr = typeof model === "string" && model !== "" ? model : "llm call";
        return `llm log \u00b7 ${modelStr} \u00b7 ${idStr}`;
      },
      render: (row) => createElement(LlmLogViewer, { row }),
    },
  },
  // ---- Admin: platform (added -- previously unlisted features) ----------
  // admin:systems is intentionally not a DataPage config: it is served by
  // the bespoke SystemsRegistryPage (registry.tsx) which owns the rich
  // registry surface (create/edit/tags/heartbeat + role filter + probe).
  "admin:sessions": {
    title: "admin \u00b7 sessions",
    endpoint: "/sessions",
    itemsKey: "items",
    columns: [c("session_id", "session"), c("user_id", "user"), c("title"), c("message_count", "messages"), c("last_message_at", "last msg"), c("created_at", "created")],
    filters: [{ name: "title", label: "title", type: "text" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  "admin:mcp-instances": {
    title: "admin \u00b7 mcp instances",
    endpoint: "/platform/mcp/instances",
    // Server-side pagination + filters: the platform router accepts
    // module_scope / transport / approval_state / enabled (comma-OR),
    // `search` (ILIKE on name+endpoint) and offset/limit with meta.total.
    // Row detail (registered in registry.tsx) opens the live tools schema
    // from GET /platform/mcp/instances/{id}/tools so drift is visible without
    // hitting the bridge by hand.
    pagination: true,
    paginationParams: "offset",
    columns: [c("name"), c("transport"), c("endpoint"), c("enabled"), c("module_scope", "module"), c("approval_state", "approval"), c("created_at", "created")],
    filters: [
      { name: "search", label: "search", type: "text", server: true },
      { name: "module_scope", label: "module", type: "select", server: true, options: [
        { value: "vr", label: "vr" },
        { value: "malware", label: "malware" },
      ] },
      { name: "transport", label: "transport", type: "select", server: true, options: [
        { value: "http", label: "http" },
        { value: "stdio", label: "stdio" },
      ] },
      { name: "approval_state", label: "approval", type: "select", server: true, options: [
        { value: "pending", label: "pending" },
        { value: "approved", label: "approved" },
        { value: "revoked", label: "revoked" },
      ] },
      { name: "enabled", label: "enabled", type: "select", server: true, options: [
        { value: "true", label: "true" },
        { value: "false", label: "false" },
      ] },
    ],
    actions: [
      {
        label: "approve",
        method: "POST",
        endpoint: "/platform/mcp/instances/{id}/approve",
        // Approve is legal for any row not already approved. `whenField`
        // reads approval_state (not status/is_active) via the shared gate.
        whenField: "approval_state",
        whenStatus: ["pending", "revoked"],
        confirm: "Approve this MCP instance? Its current tool schema hash is pinned.",
      },
      {
        label: "revoke",
        method: "POST",
        endpoint: "/platform/mcp/instances/{id}/revoke",
        whenField: "approval_state",
        whenStatus: ["approved"],
        destructive: true,
        // McpInstanceRevokeRequest.reason: Field(min_length=1); the modal
        // enforces the same rule client-side via `required`.
        fields: [
          { name: "reason", label: "reason", type: "textarea", required: true, placeholder: "why this instance is being revoked (recorded on the approval-change record)" },
        ],
      },
    ],
  },
  "admin:mcp-servers": {
    title: "admin \u00b7 mcp servers",
    endpoint: "/platform/mcp/servers",
    // Row id is the composite `<module_scope>:<server_id>`; the platform
    // route uses it verbatim for the PATCH URL. `idField: "id"` matches the
    // envelope shape.
    idField: "id",
    columns: [
      c("module_scope", "module"),
      c("server_id", "server"),
      c("base_url", "url"),
      c("status"),
      c("latency_ms", "latency"),
      c("tool_count", "tools"),
      c("last_probed_at", "probed"),
      c("error"),
    ],
    // `GET /platform/mcp/servers` accepts only `module_scope` as a query param
    // (comma-OR), so that filter narrows server-side. It has no `status` param,
    // so `status` filters the fetched (unpaginated) rows client-side against the
    // "reachable"/"unreachable" probe projection -- a server:true here would be
    // dropped by FastAPI and narrow nothing.
    filters: [
      { name: "module_scope", label: "module", type: "select", server: true, options: [
        { value: "vr", label: "vr" },
        { value: "malware", label: "malware" },
      ] },
      { name: "status", label: "status", type: "select", options: [
        { value: "reachable", label: "reachable" },
        { value: "unreachable", label: "unreachable" },
      ] },
    ],
    actions: [
      {
        // PATCH /platform/mcp/servers/{id} writes the new base_url to the
        // ConfigRegistry key the descriptor declares and re-probes the one
        // server; the returned row shape matches the list projection so the
        // table refresh reflects the new state.
        label: "edit url",
        method: "PATCH",
        endpoint: "/platform/mcp/servers/{id}",
        fields: [
          { name: "base_url", label: "base url", type: "text", required: true, fromRow: "base_url", placeholder: "https://host:port" },
        ],
        confirm: "Update this MCP server base URL and re-probe?",
      },
    ],
  },
  "admin:mcp-call-log": {
    title: "admin \u00b7 mcp call log",
    endpoint: "/platform/mcp/calls",
    // Server-paginated by offset/limit (meta.total). Every filter is
    // server:true so the backend narrows the consolidated call-log table.
    pagination: true,
    paginationParams: "offset",
    columns: [
      c("module_scope", "module"),
      c("server_id", "server"),
      c("action"),
      c("status"),
      c("http_status", "http"),
      c("latency_ms", "latency"),
      c("error_excerpt", "error"),
      c("called_at", "called"),
    ],
    filters: [
      { name: "module_scope", label: "module", type: "select", server: true, options: [
        { value: "vr", label: "vr" },
        { value: "malware", label: "malware" },
      ] },
      { name: "server_id", label: "server", type: "text", server: true },
      { name: "status", label: "status", type: "select", server: true, options: [
        { value: "ok", label: "ok" },
        { value: "http_error", label: "http_error" },
        { value: "transport_error", label: "transport_error" },
        { value: "timeout", label: "timeout" },
      ] },
      { name: "called_at", label: "called", type: "date-range", server: true },
    ],
  },
  "admin:specialist-agents": {
    title: "admin \u00b7 specialist agents",
    endpoint: "/agents/specialists",
    blurb: "per-module specialist roster \u00b7 pick a module to list, or seed its built-in defaults",
    columns: [c("name"), c("module_id", "module"), c("capability"), c("strategy_family", "strategy"), c("enabled"), c("created_at", "created")],
    filters: [
      // `module_id` is required by the backend list handler; seed with vr so
      // the first fetch is well-formed, and let the operator switch modules
      // from the same page without reloading the shell.
      { name: "module_id", label: "module", type: "select", server: true, defaultValue: "vr", options: [
        { value: "vr", label: "vr" },
        { value: "malware", label: "malware" },
        { value: "forensics", label: "forensics" },
      ] },
      { name: "name", label: "name", type: "text" },
      { name: "created_at", label: "created", type: "date-range" },
    ],
    // Seed endpoints are per-module and idempotent; a filter-substituted
    // pageAction is not expressible (PageAction only templates `{id}`/`{scope}`
    // from the selected row), so expose one fixed seed button per module.
    pageActions: [
      { label: "seed vr", method: "POST", endpoint: "/agents/specialists/vr/seed" },
      { label: "seed malware", method: "POST", endpoint: "/agents/specialists/malware/seed" },
      { label: "seed forensics", method: "POST", endpoint: "/agents/specialists/forensics/seed" },
    ],
  },
  // ---- VR: additional (previously unmapped) ----------------------------
  "vr:cves": {
    title: "vr \u00b7 cves",
    endpoint: "/vr/cves",
    blurb: "known-cve registry \u00b7 open a row to reproduce it as an n-day project, or + new for a blank reproduction",
    columns: [c("cve_id", "cve"), c("title"), c("source"), c("cvss_score", "cvss"), c("published_at", "published")],
    filters: [
      { name: "cve_id", label: "cve", type: "text" },
      { name: "title", label: "title", type: "text" },
      { name: "source", label: "source", type: "select" },
    ],
  },

  // ---- Vulnerability: reports (DataPage; scan/findings/radar/viz are bespoke) --
  "vulnerability:reports": {
    title: "vulnerability \u00b7 reports",
    endpoint: "/vulnerability/reports/list",
    columns: [c("title"), c("target"), c("status"), c("finding_count", "findings"), c("created_at", "created")],
    filters: [{ name: "title", label: "title", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },

  // Forensics sub-resources (evidence / artifacts / leads / timeline / ...)
  // are project-scoped and live as tabs inside the forensics:project detail
  // window, not as flat rail pages.

  // ---- Admin: eval & lifecycle (previously unlisted) -------------------
  "admin:automation-actions": {
    title: "admin \u00b7 automation actions",
    endpoint: "/automation/actions",
    blurb: "the live AutomationRegistry -- every registered action a module exposes for scheduling",
    idField: "action_id",
    columns: [c("action_id", "action"), c("description"), c("module_id", "module")],
    filters: [
      { name: "module_id", label: "module", type: "select" },
      { name: "action_id", label: "action id", type: "text" },
    ],
  },
  "admin:eval-calibrators": {
    title: "admin \u00b7 eval calibrators",
    endpoint: "/admin/eval/calibrators",
    blurb: "a calibrator maps raw model confidence to an empirical accept rate for a task_type; training fits isotonic + temperature from that task's accept/reject history and keeps the lower ECE; promoting flips a candidate to active behind an ECE-beats-baseline + quorum gate. benchmark registration + run scoring live at /admin/eval/benchmarks and /admin/eval/runs.",
    columns: [
      c("task_type", "task type"),
      c("method"),
      c("status"),
      c("ece_before"),
      c("ece_after"),
      {
        field: "ece_after",
        label: "\u0394 ece",
        render: (_v, row) => {
          const b = Number(row.ece_before);
          const a = Number(row.ece_after);
          if (Number.isNaN(b) || Number.isNaN(a)) return "\u2014";
          return (b - a).toFixed(4);
        },
      },
      c("sample_count", "samples"),
      c("actor"),
      c("created_at", "created"),
    ],
    filters: [
      { name: "task_type", label: "task type", type: "select" },
      { name: "status", label: "status", type: "select" },
      { name: "method", label: "method", type: "text" },
    ],
    groupBy: "task_type",
    selectCreatedRow: true,
    actions: [
      {
        label: "promote",
        method: "POST",
        endpoint: "/admin/eval/calibrators/{id}/promote",
        whenField: "status",
        whenStatus: ["candidate"],
        fields: [
          { name: "approver_ids", label: "approver ids", type: "tags", required: true, placeholder: "space/comma separated approver ids" },
        ],
      },
    ],
  },
  "admin:calibration-proposals": {
    title: "admin \u00b7 calibration proposals",
    endpoint: "/admin/eval/calibration-proposals",
    blurb: "a proposal maps a raw confidence threshold to a promoted one per outcome_kind; promoting writes into live config platform.calibration_threshold_{outcome_kind} behind a quorum gate.",
    columns: [
      c("outcome_kind", "outcome kind"),
      c("before_threshold", "before"),
      c("after_threshold", "after"),
      c("approve_count", "approves"),
      c("reject_count", "rejects"),
      c("status"),
      c("actor"),
      c("created_at", "created"),
    ],
    filters: [
      { name: "outcome_kind", label: "outcome kind", type: "select" },
      { name: "status", label: "status", type: "select" },
    ],
    actions: [
      {
        label: "promote",
        method: "POST",
        endpoint: "/admin/eval/calibration-proposals/{id}/promote",
        whenField: "status",
        whenStatus: ["active"],
        fields: [
          { name: "approver_ids", label: "approver ids", type: "tags", required: true, placeholder: "space/comma separated approver ids" },
        ],
      },
    ],
  },

  // ---- Final coverage: stats / reference endpoints ---------------------
  "admin:teams-cross-view": {
    title: "admin \u00b7 teams cross-view",
    endpoint: "/admin/teams/cross-view",
    // CrossTeamStatsRow has no `id`; key rows on team_id so selection and the
    // detail drill (registry.tsx -> TeamCrossDetail, GET /admin/teams/{id})
    // resolve. Columns bind 1:1 to the projection fields. The endpoint is
    // unpaginated and takes no filter params, so the req 28 filters run
    // client-side over the fetched set (server: unset).
    idField: "team_id",
    empty: "no teams \u2014 create one from admin \u00b7 teams",
    columns: [c("team_name", "team"), c("systems_count", "systems"), c("runs_count", "runs"), c("members_count", "members"), c("team_id", "id")],
    filters: [
      { name: "team_name", label: "team", type: "text" },
      { name: "systems_count", label: "systems", type: "numeric-range" },
      { name: "runs_count", label: "runs", type: "numeric-range" },
      { name: "members_count", label: "members", type: "numeric-range" },
    ],
  },
  "admin:queue-depth": {
    title: "admin \u00b7 queue depth",
    endpoint: "/tasks/queue-depth",
    blurb: "task counts by status",
    columns: [],
    // No filters by design: /tasks/queue-depth returns a single dict[str,int]
    // aggregate, which toRows renders as exactly ONE row (status keys become
    // columns). A filter narrows nothing on a one-row aggregate, so any control
    // would be decorative -- forbidden by the structural-honesty constraint in
    // specs/table-filtering-global.md. Not a list config in that spec's sense.
  },
  // admin:finding-states is a bespoke read-only overview (see
  // AdminFindingStatesPage) since the endpoint returns a state machine, not a
  // list of rows a DataPage can render honestly.
  // admin:widget-layout is a bespoke editor page (see WidgetLayoutPage); it
  // reads/writes /widgets/layout as a single JSON blob, not a table of rows.
} satisfies Record<string, PageConfig>;

/** DELETE wiring per page (a delete button with confirm is legitimate human
 * UI). Create/update are handled by dedicated typed forms + wizards, NOT here.
 * `{id}` / `{scope}` are filled from the selected row + active scope. */
const DELETES: Record<string, { delete: string; idField?: string }> = {
  "vr:workspaces": { delete: "/vr/workspaces/{id}" },
  // vr:targets delete lives in the bespoke VRTargetDetail action toolbar
  // (with kind/state-aware siblings), so no generic header delete here.
  "vr:investigations": { delete: "/vr/investigations/{id}" },
  "vr:patterns": { delete: "/vr/patterns/{id}" },
  "vr:disclosures": { delete: "/vr/disclosures/{id}" },
  "vr:fuzz-campaigns": { delete: "/vr/fuzz/campaigns/{id}" },
  "malware:workspaces": { delete: "/malware/workspaces/{id}" },
  // malware:targets delete lives in the bespoke MalwareTargetDetail action
  // toolbar (soft-archive + state-aware siblings), so no generic header
  // delete here -- mirrors vr:targets above.
  "malware:investigations": { delete: "/malware/investigations/{id}" },
  "malware:patterns": { delete: "/malware/patterns/{id}" },
  "malware:findings": { delete: "/malware/findings/{id}" },
  "malware:families": { delete: "/malware/families/{id}" },
  "malware:playbooks": { delete: "/malware/playbooks/{id}" },
  "admin:teams": { delete: "/admin/teams/{id}" },
  "admin:oidc-providers": { delete: "/auth/oidc/providers/{id}" },
  "admin:automation": { delete: "/automation/schedules/{id}" },
  "admin:scheduled-reports": { delete: "/scheduled-reports/{id}" },
  "admin:mcp-instances": { delete: "/platform/mcp/instances/{id}" },
};

for (const [key, m] of Object.entries(DELETES)) {
  const target = (PAGE_CONFIGS as Record<string, PageConfig>)[key];
  if (target) Object.assign(target, m);
}
// Typed create/edit forms live in formSpecs.ts (CREATE_FORMS/EDIT_FORMS),
// keyed the same way as PAGE_CONFIGS. DataPage resolves them by configKey
// (passed by the registry) or, when absent, by identity/title/endpoint match.



