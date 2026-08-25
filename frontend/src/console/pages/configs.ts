import { createElement } from "react";

import { css } from "../css";
import { AuditEventDetail } from "./AuditEventDetail";
import { SeverityBadge, StatusBadge } from "./badges";
import type { PageColumn, PageConfig } from "./DataPage";
import { LlmChatTranscript, llmPreviewLine } from "./LlmLogEntry";

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
  "vr:vuln-research": {
    title: "vr \u00b7 research projects",
    endpoint: "/vr/projects",
    columns: [c("name"), c("cve_id", "cve"), c("status"), c("finding_count", "findings"), c("latest_disclosure_status", "disclosure"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
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
    columns: [c("kind"), c("summary"), c("confidence"), c("status"), c("scope"), c("trust_tier", "trust"), c("times_retrieved", "reused")],
    filters: [{ name: "kind", label: "kind", type: "text" }, { name: "status", label: "status", type: "select" }],
  },
  "vr:findings": {
    title: "vr \u00b7 findings",
    endpoint: "/vr/findings",
    // /vr/findings paginates by offset/limit with meta{total,offset,limit}
    // (api_router.py:1665+), so offset-mode pagination reads the true total.
    pagination: true,
    paginationParams: "offset",
    columns: [c("crash_type", "crash"), c("vulnerable_function", "function"), c("disclosure_status", "disclosure"), c("assigned_cve_id", "cve"), c("cvss_score", "cvss"), c("cwe_id", "cwe"), c("evidence_count", "evidence")],
    filters: [{ name: "crash_type", label: "crash type", type: "text" }],
  },
  "vr:disclosures": {
    title: "vr \u00b7 disclosures",
    endpoint: "/vr/disclosures",
    columns: [c("finding_id", "finding"), c("kind"), c("status"), c("poc_tier", "poc"), c("severity_rating", "severity"), c("bounty_awarded_usd", "bounty $"), c("created_at", "created")],
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
  "vr:mcp-servers": {
    title: "vr \u00b7 mcp servers",
    endpoint: "/vr/mcp/servers",
    columns: [c("name"), c("base_url", "url"), c("status"), c("latency_ms", "latency"), c("tool_count", "tools"), c("last_probed_at", "probed")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "last_probed_at", label: "probed", type: "date-range" }],
  },
  "vr:mcp-call-log": {
    title: "vr \u00b7 mcp call log",
    endpoint: "/vr/mcp/calls",
    columns: [c("server_id", "server"), c("action"), c("status"), c("http_status", "http"), c("latency_ms", "latency"), c("error_excerpt", "error"), c("called_at", "called")],
    filters: [{ name: "action", label: "action", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "called_at", label: "called", type: "date-range" }],
  },
  // ---- Malware (prefix /malware) ---------------------------------------
  "malware:malware-analysis": {
    title: "malware \u00b7 analysis",
    endpoint: "/malware/investigations",
    columns: [c("title"), c("kind"), c("status"), c("strategy_family", "strategy"), c("branch_count", "branches"), c("outcome_count", "outcomes"), c("cost_actual_usd", "cost $"), c("created_at", "created")],
    filters: [{ name: "title", label: "title", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
  },
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
    columns: [c("kind"), c("confidence"), c("target_id", "target"), c("investigation_id", "investigation"), c("operator_notes", "notes"), c("created_at", "created")],
    filters: [{ name: "kind", label: "kind", type: "text" }, { name: "kind", label: "kind", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
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
  "malware:mcp-servers": {
    title: "malware \u00b7 mcp servers",
    endpoint: "/malware/mcp/servers",
    columns: [c("name"), c("base_url", "url"), c("status"), c("latency_ms", "latency"), c("tool_count", "tools")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "status", label: "status", type: "select" }],
    actions: [
      {
        label: "re-probe",
        method: "POST",
        endpoint: "/malware/mcp/servers/{id}/probe",
      },
    ],
  },
  "malware:mcp-call-log": {
    title: "malware \u00b7 mcp call log",
    endpoint: "/malware/mcp/call-log",
    columns: [c("called_at", "when"), c("server_id", "server"), c("action"), c("status"), c("http_status", "http"), c("latency_ms", "latency"), c("error_excerpt", "error")],
    filters: [{ name: "action", label: "action", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "called_at", label: "when", type: "date-range" }],
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
  },
  "admin:automation": {
    title: "admin \u00b7 automation",
    endpoint: "/automation/schedules",
    columns: [c("action_id", "action"), c("target_name", "target"), c("cron_expression", "cron"), c("enabled"), c("last_run_at", "last run"), c("last_run_result", "result")],
    filters: [{ name: "target_name", label: "target name", type: "text" }, { name: "last_run_at", label: "last run", type: "date-range" }],
  },
  "admin:workflows": {
    title: "admin \u00b7 workflows",
    endpoint: "/admin/workflows/runs",
    columns: [c("run_id", "run"), c("current_state", "state"), c("definition_id", "definition"), c("retries_in_state", "retries"), c("version"), c("updated_at", "updated")],
    filters: [{ name: "definition_id", label: "definition", type: "text" }, { name: "updated_at", label: "updated", type: "date-range" }],
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
  // ---- Admin: cost & reporting -----------------------------------------
  "admin:cost": {
    title: "admin \u00b7 cost",
    endpoint: "/cost/history",
    itemsKey: "months",
    blurb: "monthly LLM cost history",
    columns: [c("year_month", "month"), c("total_cost_usd", "cost $"), c("total_tokens", "tokens")],
    filters: [{ name: "year_month", label: "year month", type: "text" }],
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
    // Prompt + response previews arrive as opaque 200-char strings that
    // are sometimes JSON (chat-messages array or a `{summary: ...}`
    // response). Renderers turn either shape into a single readable line
    // so the table doesn't leak raw JSON; the full transcript view lives
    // in LlmLogEntry.tsx (`LlmChatTranscript`) for the detail panel.
    columns: [
      c("timestamp", "when"),
      c("model"),
      c("task_type", "task"),
      {
        field: "prompt_preview",
        label: "prompt",
        render: (v) => llmPreviewLine(v, "prompt") ?? "\u2014",
      },
      {
        field: "response_preview",
        label: "response",
        render: (v) => llmPreviewLine(v, "response") ?? "\u2014",
      },
      c("input_tokens", "in"),
      c("output_tokens", "out"),
      c("cost_usd", "cost $"),
      c("duration_ms", "ms"),
      c("status"),
    ],
    filters: [{ name: "model", label: "model", type: "text" }, { name: "status", label: "status", type: "select" }, { name: "timestamp", label: "when", type: "date-range" }],
    detailRenderers: {
      prompt_preview: (v) => createElement(LlmChatTranscript, { value: v }),
      response_preview: (v) => createElement(LlmChatTranscript, { value: v }),
    },
  },
  // ---- Admin: platform (added -- previously unlisted features) ----------
  "admin:systems": {
    title: "admin \u00b7 systems",
    endpoint: "/systems",
    itemsKey: "items",
    columns: [c("name"), c("host"), c("distro"), c("connectivity_status", "conn"), c("last_scan_at", "last scan"), c("last_scan_status", "scan status"), c("top_severity", "top sev")],
    filters: [{ name: "name", label: "name", type: "text" }],
  },
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
    columns: [c("name"), c("transport"), c("endpoint"), c("enabled"), c("module_scope", "module"), c("approval_state", "approval"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "transport", label: "transport", type: "select" }, { name: "created_at", label: "created", type: "date-range" }],
    actions: [
      {
        label: "approve",
        method: "POST",
        endpoint: "/platform/mcp/instances/{id}/approve",
        whenStatus: ["pending", "pending_approval"],
      },
      {
        label: "revoke",
        method: "POST",
        endpoint: "/platform/mcp/instances/{id}/revoke",
        whenStatus: ["approved"],
        destructive: true,
        confirm: "Revoke this MCP instance? Its tools become unavailable.",
      },
    ],
  },
  "admin:specialist-agents": {
    title: "admin \u00b7 specialist agents",
    endpoint: "/agents/specialists?module_id=vr",
    blurb: "vr module specialists",
    columns: [c("name"), c("module_id", "module"), c("capability"), c("strategy_family", "strategy"), c("enabled"), c("created_at", "created")],
    filters: [{ name: "name", label: "name", type: "text" }, { name: "created_at", label: "created", type: "date-range" }],
  },
  // ---- VR: additional (previously unmapped) ----------------------------
  "vr:cves": {
    title: "vr \u00b7 cves",
    endpoint: "/vr/cves",
    columns: [],
  },
  "vr:fuzz-proposals": {
    title: "vr \u00b7 fuzz proposals",
    endpoint: "/vr/fuzz/proposals",
    columns: [],
    detailLinks: {
      target_id: { module: "vr", section: "targets", label: "target" },
      source_investigation_id: { module: "vr", section: "investigations", label: "investigation" },
    },
    actions: [
      {
        label: "accept",
        method: "POST",
        endpoint: "/vr/fuzz/proposals/{id}/accept",
        whenStatus: ["pending", "submitted"],
        confirm: "Accept this proposal? It will write the harness, build, and create a campaign.",
      },
      {
        label: "reject",
        method: "POST",
        endpoint: "/vr/fuzz/proposals/{id}/reject",
        whenStatus: ["pending", "submitted"],
        destructive: true,
        confirm: "Reject this proposal?",
      },
    ],
  },
  "vr:crashes": {
    title: "vr \u00b7 fuzz crashes",
    endpoint: "/vr/fuzz/crashes",
    columns: [],
    detailLinks: {
      campaign_id: { module: "vr", section: "fuzz-campaigns", label: "campaign" },
      target_id: { module: "vr", section: "targets", label: "target" },
      source_investigation_id: { module: "vr", section: "investigations", label: "investigation" },
    },
  },

  // ---- Malware: additional ---------------------------------------------
  "malware:projects": {
    title: "malware \u00b7 projects",
    endpoint: "/malware/projects",
    columns: [],
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
    columns: [],
  },
  "admin:eval-calibrators": {
    title: "admin \u00b7 eval calibrators",
    endpoint: "/admin/eval/calibrators",
    columns: [],
  },

  // ---- Final coverage: stats / reference endpoints ---------------------
  "vr:disclosure-tracks": {
    title: "vr \u00b7 disclosure tracks",
    endpoint: "/vr/disclosure-tracks",
    columns: [],
  },
  "admin:teams-cross-view": {
    title: "admin \u00b7 teams cross-view",
    endpoint: "/admin/teams/cross-view",
    columns: [],
  },
  "admin:cost-roi": {
    title: "admin \u00b7 cost roi",
    endpoint: "/cost/roi",
    columns: [],
  },
  "admin:queue-depth": {
    title: "admin \u00b7 queue depth",
    endpoint: "/tasks/queue-depth",
    blurb: "task counts by status",
    columns: [],
  },
  "admin:finding-states": {
    title: "admin \u00b7 finding states",
    endpoint: "/findings/workflow/states",
    blurb: "finding workflow state machine",
    columns: [],
  },
  "admin:widget-layout": {
    title: "admin \u00b7 widget layout",
    endpoint: "/widgets/layout",
    columns: [],
  },
} satisfies Record<string, PageConfig>;

/** DELETE wiring per page (a delete button with confirm is legitimate human
 * UI). Create/update are handled by dedicated typed forms + wizards, NOT here.
 * `{id}` / `{scope}` are filled from the selected row + active scope. */
const DELETES: Record<string, { delete: string; idField?: string }> = {
  "vr:workspaces": { delete: "/vr/workspaces/{id}" },
  "vr:targets": { delete: "/vr/targets/{id}" },
  "vr:vuln-research": { delete: "/vr/projects/{id}" },
  "vr:investigations": { delete: "/vr/investigations/{id}" },
  "vr:patterns": { delete: "/vr/patterns/{id}" },
  "vr:disclosures": { delete: "/vr/disclosures/{id}" },
  "vr:fuzz-campaigns": { delete: "/vr/fuzz/campaigns/{id}" },
  "malware:workspaces": { delete: "/malware/workspaces/{id}" },
  "malware:targets": { delete: "/malware/targets/{id}" },
  "malware:investigations": { delete: "/malware/investigations/{id}" },
  "malware:patterns": { delete: "/malware/patterns/{id}" },
  "malware:findings": { delete: "/malware/findings/{id}" },
  "malware:families": { delete: "/malware/families/{id}" },
  "malware:playbooks": { delete: "/malware/playbooks/{id}" },
  "malware:projects": { delete: "/malware/projects/{id}" },
  "admin:teams": { delete: "/admin/teams/{id}" },
  "admin:oidc-providers": { delete: "/auth/oidc/providers/{id}" },
  "admin:automation": { delete: "/automation/schedules/{id}" },
  "admin:scheduled-reports": { delete: "/scheduled-reports/{id}" },
  "admin:systems": { delete: "/systems/{id}" },
  "admin:mcp-instances": { delete: "/platform/mcp/instances/{id}" },
};

for (const [key, m] of Object.entries(DELETES)) {
  const target = (PAGE_CONFIGS as Record<string, PageConfig>)[key];
  if (target) Object.assign(target, m);
}
// Typed create/edit forms live in formSpecs.ts (CREATE_FORMS/EDIT_FORMS),
// keyed the same way as PAGE_CONFIGS. DataPage resolves them by configKey
// (passed by the registry) or, when absent, by identity/title/endpoint match.



