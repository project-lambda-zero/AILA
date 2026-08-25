/**
 * Per-resource FormSpec catalog for typed create/edit forms.
 *
 * Every entry is keyed the same way as PAGE_CONFIGS (`${moduleId}:${pageId}`)
 * so DataPage can look up the matching create/edit form directly. Field
 * names, types, and enum values are copied verbatim from the Pydantic
 * Create/Patch models -- deviate and the server 400s (ConfigDict extra=forbid).
 *
 * Sources:
 *   src/aila/modules/vr/contracts/{workspace,pattern,disclosure,fuzz}.py
 *   src/aila/modules/malware/contracts/{workspace,pattern,family,playbook,observation}.py
 *   src/aila/modules/forensics/contracts/project.py
 *   src/aila/api/schemas/{users,systems,automation,config,endpoints}.py
 *   src/aila/api/routers/{admin_teams,oidc,mcp_instances}.py
 */
import type { FieldSpec, FormSpec } from "./FieldForm";

// ---- enum option tables (copied from src/aila/**/enums) --------------------

const opt = (value: string, label?: string) => ({ value, label: label ?? value.replace(/_/g, " ") });

const VR_WORKSPACE_THEMES: { value: string; label: string }[] = [
  opt("browser_engines", "browser engines"),
  opt("linux_kernel", "linux kernel"),
  opt("container_runtimes", "container runtimes"),
  opt("industrial_scada", "industrial scada"),
  opt("mobile_baseband", "mobile baseband"),
  opt("custom"),
];
const MALWARE_WORKSPACE_THEMES: { value: string; label: string }[] = [
  opt("families"),
  opt("campaigns"),
  opt("incidents"),
  opt("custom"),
];
const WORKSPACE_STATUS: { value: string; label: string }[] = [opt("active"), opt("archived")];

const PATTERN_CONFIDENCE: { value: string; label: string }[] = [
  opt("exact"),
  opt("strong"),
  opt("medium"),
  opt("caveated"),
  opt("unknown"),
];
const PATTERN_SCOPE: { value: string; label: string }[] = [
  opt("local"),
  opt("workspace"),
  opt("team"),
  opt("global"),
];
const PATTERN_STATUS: { value: string; label: string }[] = [
  opt("draft"),
  opt("active"),
  opt("archived"),
];
const PATTERN_TRUST_TIER: { value: string; label: string }[] = [
  opt("verified"),
  opt("unreviewed"),
  opt("negative"),
];

const VR_PATTERN_KIND: { value: string; label: string }[] = [
  opt("exploitation_technique", "exploitation technique"),
  opt("fuzzing_strategy", "fuzzing strategy"),
  opt("search_heuristic", "search heuristic"),
  opt("tool_recipe", "tool recipe"),
  opt("triage_rule", "triage rule"),
];
const MALWARE_PATTERN_KIND: { value: string; label: string }[] = [
  opt("yara_template", "yara template"),
  opt("unpacker_recipe", "unpacker recipe"),
  opt("config_extractor_template", "config extractor template"),
  opt("family_fingerprint", "family fingerprint"),
  opt("config_extraction_heuristic", "config extraction heuristic"),
  opt("triage_rule", "triage rule"),
];

const ARTIFACT_TIER: { value: string; label: string }[] = [
  opt("working_poc", "working poc"),
  opt("sanitized_poc", "sanitized poc"),
  opt("no_poc", "no poc"),
];
const DISCLOSURE_STATUS: { value: string; label: string }[] = [
  opt("drafted"),
  opt("submitted"),
  opt("acknowledged"),
  opt("triaging"),
  opt("accepted"),
  opt("rejected"),
  opt("patched"),
  opt("published"),
  opt("closed"),
  opt("withdrawn"),
];

const FUZZ_ENGINE: { value: string; label: string }[] = [
  opt("afl++"),
  opt("afl++_qemu"),
  opt("libfuzzer"),
  opt("honggfuzz"),
  opt("fuzzilli_v8"),
  opt("v8_d8_sbx"),
  opt("jazzer"),
  opt("cargo-fuzz"),
  opt("go-fuzz"),
  opt("atheris"),
];
const FUZZ_STRATEGY: { value: string; label: string }[] = [
  opt("mutational"),
  opt("coverage_guided", "coverage guided"),
  opt("differential"),
  opt("generative"),
  opt("grammar"),
];
const CAMPAIGN_STATUS: { value: string; label: string }[] = [
  opt("created"),
  opt("running"),
  opt("paused"),
  opt("completed"),
  opt("failed"),
  opt("aborted"),
];

const FAMILY_STATUS: { value: string; label: string }[] = [
  opt("draft"),
  opt("active"),
  opt("archived"),
];
const PLAYBOOK_STATUS: { value: string; label: string }[] = [
  opt("draft"),
  opt("proposed"),
  opt("active"),
  opt("archived"),
];

const OBSERVATION_KIND: { value: string; label: string }[] = [
  opt("function_named", "function named"),
  opt("function_summarized", "function summarized"),
  opt("library_function", "library function"),
  opt("wrapper_function", "wrapper function"),
  opt("crypto_algorithm", "crypto algorithm"),
  opt("section_note", "section note"),
  opt("packer_detected", "packer detected"),
  opt("unpack_result", "unpack result"),
  opt("capability_detected", "capability detected"),
  opt("ttp_mapped", "ttp mapped"),
  opt("string_finding", "string finding"),
  opt("c2_url", "c2 url"),
  opt("c2_ip", "c2 ip"),
  opt("encryption_key", "encryption key"),
  opt("campaign_id", "campaign id"),
  opt("config_field", "config field"),
  opt("ioc_hash", "ioc hash"),
  opt("ioc_domain", "ioc domain"),
  opt("ioc_file_path", "ioc file path"),
  opt("ioc_registry_key", "ioc registry key"),
  opt("ioc_mutex", "ioc mutex"),
  opt("family_hint", "family hint"),
  opt("family_verdict", "family verdict"),
  opt("yara_rule_fragment", "yara rule fragment"),
];
const OBSERVATION_POLARITY: { value: string; label: string }[] = [
  opt("positive"),
  opt("negative"),
];
const OBSERVATION_SOURCE: { value: string; label: string }[] = [
  opt("agent"),
  opt("mcp_direct", "mcp direct"),
  opt("operator"),
  opt("playbook"),
];

const FORENSICS_ANALYZER_OS: { value: string; label: string }[] = [
  opt("linux"),
  opt("windows"),
];
const FORENSICS_PROJECT_KIND: { value: string; label: string }[] = [
  opt("disk_evidence", "disk evidence"),
  opt("raw_directory", "raw directory"),
];

const USER_ROLES: { value: string; label: string }[] = [
  opt("admin"),
  opt("operator"),
  opt("reader"),
];
const OIDC_PROVIDER_TYPES: { value: string; label: string }[] = [
  opt("microsoft"),
  opt("google"),
  opt("generic"),
];

// ---- shared field constructors --------------------------------------------

const workspaceRef = (endpoint: string, required = true): FieldSpec => ({
  name: "workspace_id",
  label: "workspace",
  type: "select",
  required,
  optionsFrom: endpoint,
  optionsValueField: "id",
  optionsLabelField: "name",
});

// ============================================================================
// CREATE FORMS
// ============================================================================

export const CREATE_FORMS = {
  // -- VR ---------------------------------------------------------------
  "vr:workspaces": {
    title: "vr \u00b7 new workspace",
    endpoint: "/vr/workspaces",
    method: "POST",
    fields: [
      { name: "name", label: "name", type: "text", required: true, placeholder: "Browser engines" },
      {
        name: "slug",
        label: "slug (url-safe)",
        type: "text",
        required: true,
        placeholder: "browser-engines",
        help: "lowercase alphanumeric + hyphen/underscore",
      },
      { name: "description", label: "description", type: "textarea" },
      { name: "theme", label: "theme", type: "select", options: VR_WORKSPACE_THEMES },
    ],
  },
  "vr:patterns": {
    title: "vr \u00b7 new pattern",
    endpoint: "/vr/patterns",
    method: "POST",
    fields: [
      workspaceRef("/vr/workspaces"),
      {
        name: "investigation_id",
        label: "source investigation (optional)",
        type: "text",
        help: "investigation id if extracted from an investigation",
      },
      { name: "kind", label: "kind", type: "select", required: true, options: VR_PATTERN_KIND },
      { name: "summary", label: "one-line summary", type: "text", required: true },
      { name: "body", label: "body", type: "textarea", required: true },
      { name: "applicability", label: "applicability (target_kinds/languages/bug_classes as lists)", type: "keyval" },
      { name: "confidence", label: "confidence", type: "select", options: PATTERN_CONFIDENCE },
      { name: "evidence_refs", label: "evidence refs", type: "tags" },
      { name: "scope", label: "scope", type: "select", options: PATTERN_SCOPE },
      // trust_tier is stamped at write time (RFC-08) and the store overrides
      // any payload value, so an operator control here would be dead. The
      // detail view surfaces trust_tier read-only instead.
    ],
  },
  "vr:disclosures": {
    title: "vr \u00b7 new disclosure",
    endpoint: "/vr/disclosures",
    method: "POST",
    fields: [
      {
        name: "finding_id",
        label: "anchor: finding (choose ONE)",
        type: "select",
        optionsFrom: "/vr/findings",
        optionsValueField: "id",
        optionsLabelField: "vulnerable_function",
        help: "leave blank to anchor on an investigation instead",
      },
      {
        name: "investigation_id",
        label: "anchor: investigation (choose ONE)",
        type: "select",
        optionsFrom: "/vr/investigations",
        optionsValueField: "id",
        optionsLabelField: "title",
        help: "leave blank to anchor on a finding instead",
      },
      {
        name: "track_id",
        label: "track",
        type: "select",
        required: true,
        optionsFrom: "/vr/disclosure-tracks",
        optionsValueField: "track_id",
        optionsLabelField: "display_name",
      },
      workspaceRef("/vr/workspaces"),
      { name: "poc_tier", label: "poc tier", type: "select", options: ARTIFACT_TIER },
      { name: "severity_rating", label: "severity", type: "text", placeholder: "critical / 9.8 high" },
      { name: "embargo_days_override", label: "embargo override (days)", type: "number", min: 0, max: 730 },
      { name: "notes", label: "notes", type: "textarea" },
    ],
  },
  "vr:fuzz-campaigns": {
    title: "vr \u00b7 new fuzz campaign",
    endpoint: "/vr/fuzz/campaigns",
    method: "POST",
    fields: [
      {
        name: "target_id",
        label: "target",
        type: "select",
        required: true,
        optionsFrom: "/vr/targets",
        optionsValueField: "id",
        optionsLabelField: "display_name",
      },
      workspaceRef("/vr/workspaces"),
      { name: "name", label: "name", type: "text", required: true },
      { name: "engine_id", label: "engine", type: "select", required: true, options: FUZZ_ENGINE },
      { name: "strategy_id", label: "strategy", type: "select", required: true, options: FUZZ_STRATEGY },
      { name: "engine_config", label: "engine config", type: "keyval" },
      { name: "strategy_config", label: "strategy config", type: "keyval" },
      { name: "duration_hours", label: "duration (hours)", type: "number", min: 1, max: 720 },
      {
        name: "analysis_system_id",
        label: "analysis workstation",
        type: "select",
        optionsFrom: "/systems",
        optionsValueField: "id",
        optionsLabelField: "name",
      },
      { name: "notes", label: "notes", type: "textarea" },
    ],
  },

  // -- Malware ----------------------------------------------------------
  "malware:workspaces": {
    title: "malware \u00b7 new workspace",
    endpoint: "/malware/workspaces",
    method: "POST",
    fields: [
      { name: "name", label: "name", type: "text", required: true },
      {
        name: "slug",
        label: "slug (url-safe)",
        type: "text",
        required: true,
        help: "lowercase alphanumeric + hyphen/underscore",
      },
      { name: "description", label: "description", type: "textarea" },
      { name: "theme", label: "theme", type: "select", options: MALWARE_WORKSPACE_THEMES },
    ],
  },
  "malware:patterns": {
    title: "malware \u00b7 new pattern",
    endpoint: "/malware/patterns",
    method: "POST",
    fields: [
      workspaceRef("/malware/workspaces"),
      { name: "investigation_id", label: "source investigation (optional)", type: "text" },
      { name: "kind", label: "kind", type: "select", required: true, options: MALWARE_PATTERN_KIND },
      { name: "summary", label: "one-line summary", type: "text", required: true },
      { name: "body", label: "body", type: "textarea", required: true },
      { name: "applicability", label: "applicability (target_kinds/families/capabilities as lists)", type: "keyval" },
      { name: "confidence", label: "confidence", type: "select", options: PATTERN_CONFIDENCE },
      { name: "evidence_refs", label: "evidence refs", type: "tags" },
      { name: "scope", label: "scope", type: "select", options: PATTERN_SCOPE },
      { name: "trust_tier", label: "trust tier", type: "select", options: PATTERN_TRUST_TIER },
    ],
  },
  "malware:families": {
    title: "malware \u00b7 new family",
    endpoint: "/malware/families",
    method: "POST",
    fields: [
      workspaceRef("/malware/workspaces"),
      { name: "name", label: "family name", type: "text", required: true },
      { name: "aliases", label: "aliases", type: "tags" },
      { name: "description", label: "description", type: "textarea" },
      { name: "actor_cluster", label: "actor cluster", type: "text" },
      { name: "references", label: "references", type: "tags" },
      { name: "status", label: "status", type: "select", options: FAMILY_STATUS },
    ],
  },
  "malware:playbooks": {
    title: "malware \u00b7 new playbook",
    endpoint: "/malware/playbooks",
    method: "POST",
    fields: [
      workspaceRef("/malware/workspaces"),
      { name: "name", label: "name", type: "text", required: true },
      { name: "description", label: "description", type: "textarea" },
      { name: "steps", label: "steps", type: "steps", required: true, help: "at least one step" },
      { name: "status", label: "status", type: "select", options: PLAYBOOK_STATUS },
      {
        name: "family_ids",
        label: "attached families (ids)",
        type: "tags",
        help: "family ids from the families catalog",
      },
    ],
  },
  "malware:observations": {
    title: "malware \u00b7 new observation",
    endpoint: "/malware/observations",
    method: "POST",
    fields: [
      {
        name: "target_id",
        label: "target",
        type: "select",
        required: true,
        optionsFrom: "/malware/targets",
        optionsValueField: "id",
        optionsLabelField: "display_name",
      },
      { name: "kind", label: "kind", type: "select", required: true, options: OBSERVATION_KIND },
      { name: "polarity", label: "polarity", type: "select", options: OBSERVATION_POLARITY },
      {
        name: "source",
        label: "source",
        type: "select",
        options: OBSERVATION_SOURCE,
        help: "operator-created rows should choose 'operator'",
      },
      { name: "payload", label: "payload (kind-specific)", type: "keyval" },
      { name: "evidence_refs", label: "evidence refs", type: "tags" },
      { name: "supersedes_id", label: "supersedes (id)", type: "text" },
    ],
  },

  // -- Forensics --------------------------------------------------------
  "forensics:projects": {
    title: "forensics \u00b7 new project",
    endpoint: "/forensics/projects",
    method: "POST",
    fields: [
      { name: "name", label: "project name", type: "text", required: true },
      { name: "description", label: "description", type: "textarea" },
      {
        name: "system_id",
        label: "analyzer machine",
        type: "select",
        required: true,
        optionsFrom: "/systems",
        optionsValueField: "id",
        optionsLabelField: "name",
      },
      {
        name: "evidence_directory",
        label: "evidence directory (absolute path on analyzer)",
        type: "text",
        required: true,
        placeholder: "/var/evidence/case-2026-a",
      },
      { name: "analyzer_os", label: "analyzer os", type: "select", options: FORENSICS_ANALYZER_OS },
      {
        name: "project_kind",
        label: "evidence kind",
        type: "select",
        options: FORENSICS_PROJECT_KIND,
        help: "raw_directory skips disk-image parsing + pre/full-analysis",
      },
    ],
  },

  // -- Admin ------------------------------------------------------------
  "admin:users": {
    title: "admin \u00b7 new user",
    endpoint: "/users",
    method: "POST",
    fields: [
      { name: "username", label: "username", type: "text", required: true, placeholder: "3-64 chars" },
      { name: "password", label: "password", type: "password", required: true, help: "min 8 chars (NIST 800-63B)" },
      { name: "email", label: "email", type: "text" },
      { name: "role", label: "role", type: "select", options: USER_ROLES },
      { name: "group_id", label: "group id", type: "text" },
      {
        name: "team_id",
        label: "team",
        type: "select",
        optionsFrom: "/admin/teams",
        optionsValueField: "id",
        optionsLabelField: "name",
      },
    ],
  },
  "admin:teams": {
    title: "admin \u00b7 new team",
    endpoint: "/admin/teams",
    method: "POST",
    fields: [
      { name: "name", label: "team name", type: "text", required: true },
      { name: "description", label: "description", type: "textarea" },
    ],
  },
  "admin:oidc-providers": {
    title: "admin \u00b7 new oidc provider",
    endpoint: "/auth/oidc/providers",
    method: "POST",
    fields: [
      { name: "provider_name", label: "provider name", type: "text", required: true, placeholder: "1-64 chars" },
      { name: "provider_type", label: "provider type", type: "select", required: true, options: OIDC_PROVIDER_TYPES },
      { name: "display_name", label: "display name", type: "text" },
      { name: "tenant_id", label: "tenant id", type: "text", help: "required for microsoft" },
      { name: "issuer_url", label: "issuer url", type: "text", help: "required for generic" },
      { name: "client_id", label: "client id", type: "text", required: true },
      { name: "client_secret", label: "client secret", type: "password", required: true, help: "never returned by the server" },
      { name: "scopes", label: "scopes", type: "tags" },
      { name: "is_enabled", label: "enabled", type: "checkbox" },
      { name: "default_team_id", label: "default team id", type: "text" },
    ],
  },
  // NOTE: `admin:automation` CREATE lives in the bespoke AutomationWizard
  // (registered as `admin:new-automation`), not as a FieldForm spec. The
  // wizard drives the same POST /automation/schedules with a stepped UX
  // over the live action catalog + system fleet + cron preset picker.
  "admin:scheduled-reports": {
    title: "admin \u00b7 new scheduled report",
    endpoint: "/scheduled-reports",
    method: "POST",
    fields: [
      { name: "name", label: "report name", type: "text", required: true },
      { name: "report_type", label: "report type", type: "text", required: true, placeholder: "e.g. fleet_health" },
      { name: "cron_expression", label: "cron expression", type: "text", required: true },
      {
        name: "recipient_emails_json",
        label: "recipients",
        type: "json-array-tags",
        placeholder: "one email per chip",
      },
      {
        name: "config_json",
        label: "report options",
        type: "json-object-keyval",
        help: "per-report-type options",
      },
      { name: "is_active", label: "active", type: "checkbox" },
    ],
  },
  "admin:systems": {
    title: "admin \u00b7 new system",
    endpoint: "/systems",
    method: "POST",
    fields: [
      { name: "name", label: "system name", type: "text", required: true },
      { name: "host", label: "host / ip", type: "text", required: true },
      { name: "username", label: "ssh username", type: "text", placeholder: "root" },
      { name: "port", label: "ssh port", type: "number", min: 1, max: 65535, step: 1 },
      { name: "distro", label: "distro", type: "text" },
      { name: "description", label: "description", type: "textarea" },
      { name: "private_key", label: "ssh private key (pem)", type: "textarea", help: "encrypted at rest" },
      { name: "password", label: "ssh password", type: "password" },
      { name: "private_key_passphrase", label: "key passphrase", type: "password" },
    ],
  },
  "admin:mcp-instances": {
    title: "admin \u00b7 new mcp instance",
    endpoint: "/platform/mcp/instances",
    method: "POST",
    fields: [
      { name: "name", label: "instance name", type: "text", required: true },
      { name: "transport", label: "transport", type: "select", options: [opt("http"), opt("stdio")] },
      { name: "endpoint", label: "endpoint", type: "text", required: true, placeholder: "https://..." },
      { name: "capability_tags", label: "capability tags", type: "tags" },
      { name: "enabled", label: "enabled", type: "checkbox" },
      { name: "module_scope", label: "module scope", type: "text" },
      { name: "team_id", label: "team id", type: "text" },
      { name: "instance_id", label: "explicit instance id", type: "text" },
    ],
  },
  "admin:eval-calibrators": {
    title: "admin \u00b7 train calibrator",
    endpoint: "/admin/eval/calibrators/train",
    method: "POST",
    fields: [
      { name: "task_type", label: "task type", type: "text", required: true, placeholder: "e.g. vr.finding_accept", help: "fits isotonic + temperature calibrators from this task_type's accept/reject history; persists a candidate (inert until promoted)" },
    ],
  },
} satisfies Record<string, FormSpec>;

// ============================================================================
// EDIT FORMS  (PATCH / PUT -- omit untouched fields to preserve server state)
// ============================================================================

export const EDIT_FORMS = {
  // -- VR ---------------------------------------------------------------
  "vr:workspaces": {
    title: "vr \u00b7 edit workspace",
    endpoint: "/vr/workspaces/{id}",
    method: "PATCH",
    fields: [
      { name: "name", label: "name", type: "text" },
      { name: "description", label: "description", type: "textarea" },
      { name: "theme", label: "theme", type: "select", options: VR_WORKSPACE_THEMES },
      { name: "status", label: "status", type: "select", options: WORKSPACE_STATUS },
    ],
  },
  "vr:patterns": {
    title: "vr \u00b7 edit pattern",
    endpoint: "/vr/patterns/{id}",
    method: "PATCH",
    fields: [
      { name: "summary", label: "summary", type: "text" },
      { name: "body", label: "body", type: "textarea" },
      { name: "applicability", label: "applicability", type: "keyval" },
      { name: "confidence", label: "confidence", type: "select", options: PATTERN_CONFIDENCE },
      { name: "status", label: "status", type: "select", options: PATTERN_STATUS },
      { name: "scope", label: "scope", type: "select", options: PATTERN_SCOPE, help: "scope demotion rejected by server" },
      { name: "superseded_by", label: "superseded by (id)", type: "text" },
    ],
  },
  "vr:disclosures": {
    title: "vr \u00b7 edit disclosure",
    endpoint: "/vr/disclosures/{id}",
    method: "PATCH",
    fields: [
      { name: "status", label: "status", type: "select", options: DISCLOSURE_STATUS },
      { name: "poc_tier", label: "poc tier", type: "select", options: ARTIFACT_TIER },
      { name: "severity_rating", label: "severity", type: "text" },
      { name: "embargo_days_override", label: "embargo (days)", type: "number", min: 0, max: 730 },
      { name: "vendor_reference", label: "vendor reference", type: "text" },
      { name: "bounty_awarded_usd", label: "bounty awarded (usd)", type: "number", min: 0 },
      { name: "notes", label: "notes", type: "textarea" },
    ],
  },
  "vr:fuzz-campaigns": {
    title: "vr \u00b7 edit fuzz campaign",
    endpoint: "/vr/fuzz/campaigns/{id}",
    method: "PATCH",
    fields: [
      { name: "status", label: "status", type: "select", options: CAMPAIGN_STATUS },
      { name: "notes", label: "notes", type: "textarea" },
      { name: "duration_hours", label: "duration (hours)", type: "number", min: 1, max: 720 },
    ],
  },

  // -- Malware ----------------------------------------------------------
  "malware:workspaces": {
    title: "malware \u00b7 edit workspace",
    endpoint: "/malware/workspaces/{id}",
    method: "PATCH",
    fields: [
      { name: "name", label: "name", type: "text" },
      { name: "description", label: "description", type: "textarea" },
      { name: "theme", label: "theme", type: "select", options: MALWARE_WORKSPACE_THEMES },
      { name: "status", label: "status", type: "select", options: WORKSPACE_STATUS },
    ],
  },
  "malware:patterns": {
    title: "malware \u00b7 edit pattern",
    endpoint: "/malware/patterns/{id}",
    method: "PATCH",
    fields: [
      { name: "summary", label: "summary", type: "text" },
      { name: "body", label: "body", type: "textarea" },
      { name: "applicability", label: "applicability", type: "keyval" },
      { name: "confidence", label: "confidence", type: "select", options: PATTERN_CONFIDENCE },
      { name: "status", label: "status", type: "select", options: PATTERN_STATUS },
      { name: "scope", label: "scope", type: "select", options: PATTERN_SCOPE },
      { name: "superseded_by", label: "superseded by (id)", type: "text" },
    ],
  },
  "malware:families": {
    title: "malware \u00b7 edit family",
    endpoint: "/malware/families/{id}",
    method: "PATCH",
    fields: [
      { name: "name", label: "family name", type: "text" },
      { name: "aliases", label: "aliases", type: "tags" },
      { name: "description", label: "description", type: "textarea" },
      { name: "actor_cluster", label: "actor cluster", type: "text" },
      { name: "references", label: "references", type: "tags" },
      { name: "status", label: "status", type: "select", options: FAMILY_STATUS },
    ],
  },
  "malware:playbooks": {
    title: "malware \u00b7 edit playbook",
    endpoint: "/malware/playbooks/{id}",
    method: "PATCH",
    fields: [
      { name: "name", label: "name", type: "text" },
      { name: "description", label: "description", type: "textarea" },
      { name: "steps", label: "steps", type: "steps" },
      { name: "status", label: "status", type: "select", options: PLAYBOOK_STATUS },
      { name: "family_ids", label: "attached families (ids)", type: "tags" },
    ],
  },

  // -- Admin ------------------------------------------------------------
  "admin:users": {
    title: "admin \u00b7 edit user",
    endpoint: "/users/{id}",
    method: "PATCH",
    fields: [
      { name: "email", label: "email", type: "text" },
      { name: "role", label: "role", type: "select", options: USER_ROLES },
      { name: "group_id", label: "group id", type: "text" },
      {
        name: "team_id",
        label: "team",
        type: "select",
        optionsFrom: "/admin/teams",
        optionsValueField: "id",
        optionsLabelField: "name",
      },
      { name: "is_active", label: "active (false = soft-delete)", type: "checkbox" },
    ],
  },
  "admin:teams": {
    title: "admin \u00b7 edit team",
    endpoint: "/admin/teams/{id}",
    method: "PUT",
    fields: [
      { name: "name", label: "team name", type: "text" },
      { name: "description", label: "description", type: "textarea" },
    ],
  },
  "admin:oidc-providers": {
    title: "admin \u00b7 edit oidc provider",
    endpoint: "/auth/oidc/providers/{id}",
    method: "PUT",
    fields: [
      { name: "provider_name", label: "provider name", type: "text" },
      { name: "provider_type", label: "provider type", type: "select", options: OIDC_PROVIDER_TYPES },
      { name: "display_name", label: "display name", type: "text" },
      { name: "tenant_id", label: "tenant id", type: "text" },
      { name: "issuer_url", label: "issuer url", type: "text" },
      { name: "client_id", label: "client id", type: "text" },
      { name: "client_secret", label: "client secret", type: "password", help: "leave blank to keep current" },
      { name: "scopes", label: "scopes", type: "tags" },
      { name: "is_enabled", label: "enabled", type: "checkbox" },
      { name: "default_team_id", label: "default team id", type: "text" },
    ],
  },
  "admin:automation": {
    title: "admin \u00b7 edit automation schedule",
    endpoint: "/automation/schedules/{id}",
    method: "PATCH",
    fields: [
      { name: "cron_expression", label: "cron expression", type: "text" },
      { name: "action_kwargs", label: "action arguments", type: "keyval" },
      { name: "enabled", label: "enabled", type: "checkbox" },
    ],
  },
  "admin:scheduled-reports": {
    title: "admin \u00b7 edit scheduled report",
    endpoint: "/scheduled-reports/{id}",
    method: "PATCH",
    fields: [
      { name: "name", label: "report name", type: "text" },
      { name: "cron_expression", label: "cron expression", type: "text" },
      { name: "recipient_emails_json", label: "recipients", type: "json-array-tags" },
      { name: "config_json", label: "report options", type: "json-object-keyval" },
      { name: "is_active", label: "active", type: "checkbox" },
    ],
  },
  "admin:systems": {
    title: "admin \u00b7 edit system",
    endpoint: "/systems/{id}",
    method: "PUT",
    fields: [
      { name: "name", label: "system name", type: "text" },
      { name: "host", label: "host / ip", type: "text" },
      { name: "username", label: "ssh username", type: "text" },
      { name: "port", label: "ssh port", type: "number", min: 1, max: 65535, step: 1 },
      { name: "distro", label: "distro", type: "text" },
      { name: "description", label: "description", type: "textarea" },
      { name: "private_key", label: "ssh private key (pem)", type: "textarea", help: "leave blank to keep; explicit null clears" },
      { name: "password", label: "ssh password", type: "password" },
      { name: "private_key_passphrase", label: "key passphrase", type: "password" },
    ],
  },
  "admin:mcp-instances": {
    title: "admin \u00b7 edit mcp instance",
    endpoint: "/platform/mcp/instances/{id}",
    method: "PATCH",
    fields: [
      { name: "endpoint", label: "endpoint", type: "text" },
      { name: "enabled", label: "enabled", type: "checkbox" },
      { name: "capability_tags", label: "capability tags", type: "tags" },
      { name: "team_id", label: "team id", type: "text" },
    ],
  },
  // Config is edit-only: namespace + key are the composite path key. FieldForm
  // substitutes both {namespace} and {key} directly from the selected row.
  // The value widget derives from the row's value_type (text/number/checkbox)
  // via typeFrom; the backend casts by the schema type, so there is no
  // free-form type select. The row detail already surfaces the effective
  // value + env override; this form edits the stored DB value.
  "admin:config": {
    title: "admin \u00b7 edit config value",
    endpoint: "/config/{namespace}/{key}",
    method: "PUT",
    fields: [
      {
        name: "value",
        label: "value",
        type: "text",
        typeFrom: "value_type",
        required: true,
        help: "stored value; an env override (AILA_*) wins at runtime when set",
      },
    ],
  },
} satisfies Record<string, FormSpec>;
