import { createElement } from "react";

import type { PageColumn, PageConfig } from "./DataPage";
import { LlmChatTranscript, llmPreviewLine } from "./LlmLogEntry";

/** Column shorthand: field + auto-labelled from the field name. */
const c = (field: string, label?: string): PageColumn => ({
  field,
  label: label ?? field.replace(/_/g, " "),
});

/** One DataPage config per left-rail item, keyed `${moduleId}:${pageId}`.
 * Endpoints + fields are the real backend contract (mapped from the routers).
 * The registry turns each of these into a live data window. */
export const PAGE_CONFIGS: Record<string, PageConfig> = {
  // ---- VR (prefix /vr) --------------------------------------------------
  "vr:workspaces": {
    title: "vr \u00b7 workspaces",
    endpoint: "/vr/workspaces",
    columns: [c("name"), c("slug"), c("status"), c("target_count", "targets"), c("active_investigation_count", "active"), c("created_at", "created")],
  },
  "vr:targets": {
    title: "vr \u00b7 targets",
    endpoint: "/vr/targets",
    columns: [c("display_name", "name"), c("kind"), c("status"), c("analysis_state", "analysis"), c("primary_language", "lang"), c("workspace_name", "workspace"), c("created_at", "created")],
  },
  "vr:vuln-research": {
    title: "vr \u00b7 research projects",
    endpoint: "/vr/projects",
    columns: [c("name"), c("cve_id", "cve"), c("status"), c("finding_count", "findings"), c("latest_disclosure_status", "disclosure"), c("created_at", "created")],
  },
  "vr:investigations": {
    title: "vr \u00b7 investigations",
    endpoint: "/vr/investigations",
    blurb: "open one from the left rail to raise its x-ray",
    columns: [c("title"), c("kind"), c("status"), c("strategy_family", "strategy"), c("branch_count", "branches"), c("message_count", "turns"), c("outcome_count", "outcomes"), c("cost_actual_usd", "cost $")],
  },
  "vr:patterns": {
    title: "vr \u00b7 patterns",
    endpoint: "/vr/patterns",
    columns: [c("kind"), c("summary"), c("confidence"), c("status"), c("scope"), c("trust_tier", "trust"), c("times_retrieved", "reused")],
  },
  "vr:findings": {
    title: "vr \u00b7 findings",
    endpoint: "/vr/findings",
    columns: [c("crash_type", "crash"), c("vulnerable_function", "function"), c("disclosure_status", "disclosure"), c("assigned_cve_id", "cve"), c("cvss_score", "cvss"), c("cwe_id", "cwe"), c("evidence_count", "evidence")],
  },
  "vr:disclosures": {
    title: "vr \u00b7 disclosures",
    endpoint: "/vr/disclosures",
    columns: [c("finding_id", "finding"), c("kind"), c("status"), c("poc_tier", "poc"), c("severity_rating", "severity"), c("bounty_awarded_usd", "bounty $"), c("created_at", "created")],
  },
  "vr:fuzz-campaigns": {
    title: "vr \u00b7 fuzz campaigns",
    endpoint: "/vr/fuzz/campaigns",
    columns: [c("name"), c("engine_id", "engine"), c("status"), c("coverage_pct", "coverage %"), c("crashes_found", "crashes"), c("total_execs", "execs"), c("execs_per_sec", "exec/s")],
  },
  "vr:mcp-servers": {
    title: "vr \u00b7 mcp servers",
    endpoint: "/vr/mcp/servers",
    columns: [c("name"), c("base_url", "url"), c("status"), c("latency_ms", "latency"), c("tool_count", "tools"), c("last_probed_at", "probed")],
  },
  "vr:mcp-call-log": {
    title: "vr \u00b7 mcp call log",
    endpoint: "/vr/mcp/calls",
    columns: [c("server_id", "server"), c("action"), c("status"), c("http_status", "http"), c("latency_ms", "latency"), c("error_excerpt", "error"), c("called_at", "called")],
  },
  "vr:audit-log": {
    title: "vr \u00b7 audit log",
    endpoint: "/vr/mcp/calls",
    blurb: "operator-facing audit trail of every mcp bridge forward()",
    columns: [c("called_at", "when"), c("server_id", "server"), c("action"), c("status"), c("http_status", "http"), c("latency_ms", "latency"), c("error_excerpt", "error")],
  },

  // ---- Malware (prefix /malware) ---------------------------------------
  "malware:malware-analysis": {
    title: "malware \u00b7 analysis",
    endpoint: "/malware/investigations",
    columns: [c("title"), c("kind"), c("status"), c("strategy_family", "strategy"), c("branch_count", "branches"), c("outcome_count", "outcomes"), c("cost_actual_usd", "cost $"), c("created_at", "created")],
  },
  "malware:workspaces": {
    title: "malware \u00b7 workspaces",
    endpoint: "/malware/workspaces",
    columns: [c("name"), c("slug"), c("status"), c("target_count", "targets"), c("active_investigation_count", "active"), c("created_at", "created")],
  },
  "malware:targets": {
    title: "malware \u00b7 targets",
    endpoint: "/malware/targets",
    columns: [c("display_name", "name"), c("kind"), c("primary_language", "lang"), c("status"), c("analysis_state", "analysis"), c("uploaded_filename", "file"), c("created_at", "created")],
  },
  "malware:investigations": {
    title: "malware \u00b7 investigations",
    endpoint: "/malware/investigations",
    columns: [c("title"), c("kind"), c("status"), c("strategy_family", "strategy"), c("branch_count", "branches"), c("message_count", "turns"), c("outcome_count", "outcomes"), c("cost_actual_usd", "cost $")],
  },
  "malware:observations": {
    title: "malware \u00b7 observations",
    endpoint: "/malware/observations",
    scopeFrom: { endpoint: "/malware/targets", param: "target_id" },
    blurb: "scoped to the first target",
    columns: [c("kind"), c("polarity"), c("source"), c("target_id", "target"), c("investigation_id", "investigation"), c("created_at", "created")],
  },
  "malware:patterns": {
    title: "malware \u00b7 patterns",
    endpoint: "/malware/patterns",
    columns: [c("kind"), c("summary"), c("confidence"), c("status"), c("scope"), c("trust_tier", "trust"), c("times_retrieved", "reused")],
  },
  "malware:findings": {
    title: "malware \u00b7 findings",
    endpoint: "/malware/findings",
    columns: [c("kind"), c("confidence"), c("target_id", "target"), c("investigation_id", "investigation"), c("operator_notes", "notes"), c("created_at", "created")],
  },
  "malware:families": {
    title: "malware \u00b7 families",
    endpoint: "/malware/families",
    scopeFrom: { endpoint: "/malware/workspaces", param: "workspace_id" },
    blurb: "scoped to the first workspace",
    columns: [c("name"), c("actor_cluster", "actor"), c("status"), c("sample_count", "samples"), c("playbook_count", "playbooks"), c("created_at", "created")],
  },
  "malware:playbooks": {
    title: "malware \u00b7 playbooks",
    endpoint: "/malware/playbooks",
    scopeFrom: { endpoint: "/malware/workspaces", param: "workspace_id" },
    blurb: "scoped to the first workspace",
    columns: [c("name"), c("description"), c("status"), c("run_count", "runs"), c("last_run_at", "last run"), c("created_at", "created")],
  },
  "malware:mcp-servers": {
    title: "malware \u00b7 mcp servers",
    endpoint: "/malware/mcp/servers",
    columns: [c("name"), c("base_url", "url"), c("status"), c("latency_ms", "latency"), c("tool_count", "tools")],
  },
  "malware:mcp-call-log": {
    title: "malware \u00b7 mcp call log",
    endpoint: "/malware/mcp/call-log",
    columns: [c("called_at", "when"), c("server_id", "server"), c("action"), c("status"), c("http_status", "http"), c("latency_ms", "latency"), c("error_excerpt", "error")],
  },

  // ---- Forensics (prefix /forensics) -----------------------------------
  "forensics:projects": {
    title: "forensics \u00b7 projects",
    endpoint: "/forensics/projects",
    itemsKey: "items",
    columns: [c("name"), c("project_kind", "kind"), c("status"), c("system_name", "system"), c("evidence_count", "evidence"), c("artifact_count", "artifacts"), c("lead_count", "leads"), c("investigation_count", "investigations")],
  },

  // ---- Admin: access ----------------------------------------------------
  "admin:users": {
    title: "admin \u00b7 users",
    endpoint: "/users",
    columns: [c("username"), c("email"), c("role"), c("team_id", "team"), c("is_active", "active"), c("last_login_at", "last login"), c("created_at", "created")],
  },
  "admin:teams": {
    title: "admin \u00b7 teams",
    endpoint: "/admin/teams",
    columns: [c("name"), c("description"), c("member_count", "members"), c("created_at", "created"), c("updated_at", "updated")],
  },
  "admin:api-keys": {
    title: "admin \u00b7 api keys",
    endpoint: "/auth/keys",
    itemsKey: "keys",
    columns: [c("key_prefix", "prefix"), c("role"), c("label"), c("created_by", "by"), c("created_at", "created"), c("revoked_at", "revoked")],
  },
  "admin:oidc-providers": {
    title: "admin \u00b7 oidc providers",
    endpoint: "/auth/oidc/providers",
    columns: [c("provider_name", "name"), c("provider_type", "type"), c("display_name", "display"), c("issuer_url", "issuer"), c("client_id", "client"), c("is_enabled", "enabled")],
  },
  // ---- Admin: operations ------------------------------------------------
  "admin:task-queue": {
    title: "admin \u00b7 task queue",
    endpoint: "/tasks",
    itemsKey: "tasks",
    columns: [c("task_id", "task"), c("track"), c("status"), c("fn_path", "fn"), c("created_at", "created"), c("started_at", "started"), c("completed_at", "completed")],
  },
  "admin:dead-letter": {
    title: "admin \u00b7 dead letter",
    endpoint: "/admin/tasks/dead-letter",
    columns: [c("task_id", "task"), c("track"), c("fn_path", "fn"), c("exception_class", "exception"), c("error"), c("attempts"), c("dead_lettered_at", "when")],
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
  },
  "admin:workflows": {
    title: "admin \u00b7 workflows",
    endpoint: "/admin/workflows/runs",
    columns: [c("run_id", "run"), c("current_state", "state"), c("definition_id", "definition"), c("retries_in_state", "retries"), c("version"), c("updated_at", "updated")],
  },
  "admin:scheduled-reports": {
    title: "admin \u00b7 scheduled reports",
    endpoint: "/scheduled-reports",
    columns: [c("name"), c("report_type", "type"), c("cron_expression", "cron"), c("is_active", "active"), c("last_run_at", "last run"), c("created_at", "created")],
  },
  // ---- Admin: cost & reporting -----------------------------------------
  "admin:cost": {
    title: "admin \u00b7 cost",
    endpoint: "/cost/history",
    itemsKey: "months",
    blurb: "monthly LLM cost history",
    columns: [c("year_month", "month"), c("total_cost_usd", "cost $"), c("total_tokens", "tokens")],
  },
  "admin:executive": {
    title: "admin \u00b7 executive",
    endpoint: "/executive/health",
    blurb: "fleet finding + severity summary",
    columns: [],
  },
  // ---- Admin: data & config --------------------------------------------
  "admin:tag-vocabulary": {
    title: "admin \u00b7 tag vocabulary",
    endpoint: "/tags/vocabulary",
    columns: [c("tag_key", "tag"), c("description"), c("is_system_default", "system"), c("created_at", "created")],
  },
  "admin:saved-filters": {
    title: "admin \u00b7 saved filters",
    endpoint: "/saved-filters",
    columns: [c("name"), c("entity_type", "entity"), c("is_pinned", "pinned"), c("shared_with_team", "shared"), c("created_at", "created")],
  },
  "admin:config": {
    title: "admin \u00b7 config",
    endpoint: "/config",
    itemsKey: "items",
    columns: [c("namespace"), c("key"), c("value_type", "type"), c("effective_value", "value"), c("effective_source", "source"), c("overridden_by_env", "env override"), c("updated_at", "updated")],
  },
  "admin:tools": {
    title: "admin \u00b7 tools",
    endpoint: "/tools",
    columns: [c("tool_key", "key"), c("name"), c("description"), c("module_id", "module")],
  },
  // ---- Admin: audit -----------------------------------------------------
  "admin:audit-logs": {
    title: "admin \u00b7 audit logs",
    endpoint: "/audit/events",
    itemsKey: "items",
    columns: [c("created_at", "when"), c("stage"), c("action"), c("status"), c("target"), c("user_id", "user"), c("run_id", "run")],
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
    detailRenderers: {
      prompt_preview: (v) => createElement(LlmChatTranscript, { value: v }),
      response_preview: (v) => createElement(LlmChatTranscript, { value: v }),
    },
  },
  // ---- Admin: platform (added -- previously unlisted features) ----------
  "admin:dashboard": {
    title: "admin \u00b7 dashboard",
    endpoint: "/dashboard",
    blurb: "fleet risk + stats snapshot",
    columns: [],
  },
  "admin:systems": {
    title: "admin \u00b7 systems",
    endpoint: "/systems",
    itemsKey: "items",
    columns: [c("name"), c("host"), c("distro"), c("connectivity_status", "conn"), c("last_scan_at", "last scan"), c("last_scan_status", "scan status"), c("top_severity", "top sev")],
  },
  "admin:topology": {
    title: "admin \u00b7 topology",
    endpoint: "/topology",
    itemsKey: "nodes",
    blurb: "fleet nodes",
    columns: [],
  },
  "admin:sessions": {
    title: "admin \u00b7 sessions",
    endpoint: "/sessions",
    itemsKey: "items",
    columns: [c("session_id", "session"), c("user_id", "user"), c("title"), c("message_count", "messages"), c("last_message_at", "last msg"), c("created_at", "created")],
  },
  "admin:notifications": {
    title: "admin \u00b7 notifications",
    endpoint: "/notifications",
    columns: [c("title"), c("category"), c("source_module", "module"), c("is_read", "read"), c("created_at", "created")],
  },
  "admin:mcp-instances": {
    title: "admin \u00b7 mcp instances",
    endpoint: "/platform/mcp/instances",
    columns: [c("name"), c("transport"), c("endpoint"), c("enabled"), c("module_scope", "module"), c("approval_state", "approval"), c("created_at", "created")],
  },
  "admin:specialist-agents": {
    title: "admin \u00b7 specialist agents",
    endpoint: "/agents/specialists?module_id=vr",
    blurb: "vr module specialists",
    columns: [c("name"), c("module_id", "module"), c("capability"), c("strategy_family", "strategy"), c("enabled"), c("created_at", "created")],
  },
  "admin:platform-corpus": {
    title: "admin \u00b7 platform corpus",
    endpoint: "/platform/eval/corpus/stats",
    blurb: "eval corpus stats",
    columns: [],
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
  },
  "vr:crashes": {
    title: "vr \u00b7 fuzz crashes",
    endpoint: "/vr/fuzz/crashes",
    columns: [],
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
  "malware:health": {
    title: "malware \u00b7 health",
    endpoint: "/malware/health",
    blurb: "module health snapshot",
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
  "admin:topology-subnets": {
    title: "admin \u00b7 topology subnets",
    endpoint: "/topology/subnets",
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
};

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
  "admin:api-keys": { delete: "/auth/keys/{id}", idField: "key_id" },
  "admin:oidc-providers": { delete: "/auth/oidc/providers/{id}" },
  "admin:automation": { delete: "/automation/schedules/{id}" },
  "admin:scheduled-reports": { delete: "/scheduled-reports/{id}" },
  "admin:tag-vocabulary": { delete: "/tags/vocabulary/{id}", idField: "tag_key" },
  "admin:saved-filters": { delete: "/saved-filters/{id}" },
  "admin:systems": { delete: "/systems/{id}" },
  "admin:notifications": { delete: "/notifications/{id}" },
  "admin:mcp-instances": { delete: "/platform/mcp/instances/{id}" },
};

for (const [key, m] of Object.entries(DELETES)) {
  if (PAGE_CONFIGS[key]) Object.assign(PAGE_CONFIGS[key], m);
}
// Typed create/edit forms live in formSpecs.ts (CREATE_FORMS/EDIT_FORMS),
// keyed the same way as PAGE_CONFIGS. DataPage resolves them by configKey
// (passed by the registry) or, when absent, by identity/title/endpoint match.



