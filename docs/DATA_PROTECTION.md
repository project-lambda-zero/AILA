# Data Protection and Redaction

How AILA prevents sensitive data from leaking into LLM prompts, API responses, audit logs, and reports. Three systems work together: **data posture mode**, **classification and redaction**, and **input/output sanitization**.

---

## Data Posture Mode

A global switch that controls how aggressively the platform handles sensitive data in LLM interactions. Configurable at runtime via ConfigRegistry or environment variable.

| Mode | Behavior |
|---|---|
| `transparent` | Skip classification entirely. All prompts marked PUBLIC. No redaction. Used in lab/development environments where the LLM is local and trusted. |
| `standard` | Full classification. RESTRICTED prompts are handled per task_type config: either blocked (`fail`) or redacted (`redact`). Default mode. |
| `paranoid` | Full classification. RESTRICTED prompts are always redacted, never blocked. Used when you want the scan to complete but with sensitive tokens replaced. |

### Configuration

```bash
# Environment variable (highest priority)
AILA_PLATFORM_DATA_POSTURE_MODE=transparent

# Or via Config page / API
PUT /config/platform/data_posture_mode
{"value": "standard"}
```

Resolution chain: env var `AILA_PLATFORM_DATA_POSTURE_MODE` -> ConfigRegistry DB row -> default `"standard"`.

### Where it's read

`platform/llm/config.py:resolve_posture()` is called by the classify pipeline step before every LLM call. The posture mode is stamped on the pipeline context (`ctx["posture_mode"]`) and persisted in the audit seal.

---

## Classification and Redaction

The `classify` step is the first pre-call step in the LLM pipeline. It scans every message for sensitive patterns and classifies the prompt.

### Pipeline position

```
classify -> [API call] -> validate -> gate -> verify -> seal
   ^
   |
   This step. Runs BEFORE the LLM call.
```

### Classification levels

| Level | Meaning | Example patterns |
|---|---|---|
| `PUBLIC` | No sensitive data detected | CVE IDs, package names |
| `INTERNAL` | Contains infrastructure identifiers | Public IPs, FQDNs |
| `RESTRICTED` | Contains secrets or private network data | RFC1918 IPs, SSH keys, credentials, passwords |

### Built-in patterns

| Pattern | Detects | Level | Redaction tag |
|---|---|---|---|
| `rfc1918_ip` | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` | RESTRICTED | `[REDACTED-IP]` |
| `public_ip` | Any IPv4 address | INTERNAL | `[REDACTED-IP]` |
| `fqdn` | Fully qualified domain names (3+ labels) | INTERNAL | `[REDACTED-HOST]` |
| `ssh_key` | `-----BEGIN * PRIVATE KEY-----` | RESTRICTED | `[REDACTED-KEY]` |
| `credential` | `password=`, `api_key=`, `token=`, `secret=` | RESTRICTED | `[REDACTED-CRED]` |
| `cve_id` | `CVE-2024-1234` | PUBLIC | *(not redacted)* |

False positive guards:
- FQDN matches that end in file extensions (`.py`, `.json`, `.tar.gz`) are excluded
- Version-like strings (`v1.2.3`) are excluded from FQDN matching
- Public IP matches that are actually RFC1918 addresses are deduplicated

### What happens when RESTRICTED is detected

Depends on posture mode and per-task-type config:

```
RESTRICTED detected
  |
  +-- posture == transparent?
  |     -> skip (already returned before classification runs)
  |
  +-- posture == paranoid?
  |     -> redact all RESTRICTED tokens, continue with LLM call
  |
  +-- posture == standard?
        |
        +-- behavior == "fail" (default)?
        |     -> raise ClassificationBlockedError, LLM call never happens
        |
        +-- behavior == "redact"?
              -> redact all RESTRICTED tokens, continue with LLM call
```

### Per-task-type behavior config

Each module's task types can be configured independently:

```bash
# Allow redacted send for vulnerability scoring (instead of blocking)
AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_RESTRICTED_BEHAVIOR_SCORING=redact

# Block forensics freeflow (sensitive evidence must not reach external LLM)
AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_RESTRICTED_BEHAVIOR_FORENSICS_FREEFLOW=fail
```

Or via Config page:
```
PUT /config/platform/llm_pipeline_classify_restricted_behavior_scoring
{"value": "redact"}
```

### Redaction in practice

When redaction is active, RESTRICTED-level tokens are replaced **in the message list itself** before the LLM call:

```
Before: "Check SSH access to 192.168.1.50 with password=hunter2"
After:  "Check SSH access to [REDACTED-IP] with [REDACTED-CRED]"
```

The LLM sees only redacted content. The pipeline context records:
- `ctx["redacted"] = True`
- `ctx["redacted_count"] = 2`

This is logged in the audit seal but the original unredacted prompt is **not persisted anywhere**.

### Custom patterns

Modules can register additional patterns at startup:

```python
from aila.platform.llm.classify import register_pattern, ClassificationLevel

register_pattern(
    name="internal_hostname",
    regex=r"\b(?:prod|staging|dev)-[a-z]+-\d+\b",
    level=ClassificationLevel.INTERNAL,
    redact_tag="[REDACTED-HOST]",
)
```

---

## Input Sanitization

Separate from classification. Strips **prompt injection patterns** from untrusted text (CVE descriptions, user queries) before it enters an LLM prompt.

This is a utility function called at agent call sites, not a pipeline step. It runs **before** the pipeline.

### Built-in injection patterns

| Pattern | Detects |
|---|---|
| `system_override` | "ignore all previous instructions", "you are now" |
| `system_tag` | `system:`, `<<SYS>>`, `[INST]` |
| `role_injection` | Lines starting with `assistant:`, `user:`, `human:` |
| `delimiter_injection` | Lines of `---` or `===` (section breaks that could split prompts) |
| `backtick_boundary` | ` ```system`, ` ```assistant` (code fence role injection) |

### Usage

```python
from aila.platform.llm import sanitize_input

clean_text = sanitize_input(untrusted_cve_description)
# Injection patterns stripped, safe to embed in prompt
```

### Custom patterns

```python
from aila.platform.llm import register_injection_pattern

register_injection_pattern(
    "custom_override",
    r"(?:disregard|forget)\s+(?:everything|all)",
)
```

---

## Output Sanitization

Strips XSS patterns and control characters from LLM response text **before database storage**.

Runs inside `AilaLLMClient._single_call()` after every LLM response, before the response is returned to callers.

### What it strips

| Category | Patterns |
|---|---|
| XSS | `<script>`, `<iframe>`, `<object>`, `<embed>`, `javascript:`, `onXxx=` event handlers |
| Control characters | `0x00-0x08`, `0x0B-0x0C`, `0x0E-0x1F` (preserves tab, newline, carriage return) |

### Usage

Automatic -- every LLM response is sanitized before returning. The sanitization count is logged but does not block the response.

---

## Audit Trail

Every LLM call produces an `AuditSealRecord` with:

| Field | Content |
|---|---|
| `seal_hash` | HMAC-SHA256 over prompt + response + model + timestamp |
| `classification_level` | PUBLIC, INTERNAL, or RESTRICTED |
| `posture_mode` | transparent, standard, or paranoid |
| `redacted` | Whether redaction was applied |
| `task_type` | Which module task type made the call |
| `model_id` | Which model was used |
| `token_usage` | prompt_tokens, completion_tokens, total_tokens |
| `estimated_cost_usd` | Per-call cost estimate |

No prompt content is stored in audit records. The seal proves the call happened and what classification was applied, without retaining the sensitive data.

---

## Exception Redaction

Workflow engine audit records redact exception messages by default. `safe_exc_message()` in `platform/workflows/log.py` truncates and sanitizes exception text before it reaches the `workflowauditrecord` table. This prevents stack traces containing credentials or internal paths from being persisted.

---

## Report Artifact Protection

- Report artifacts (CSV, JSON, PDF) are stored as **files on the filesystem**, not inline in the database. Only file paths are persisted in `ReportArtifactRecord`.
- The `report_store.py` rejects tilde (`~`) paths to prevent home-directory expansion in container environments.
- Sensitive fields (SSH credentials, API keys) are excluded from exported report payloads via `to_payload()` exclusion lists.

---

## Summary

| Layer | What it protects | When it runs |
|---|---|---|
| Data posture mode | Controls classification aggressiveness | Before every LLM call |
| Classification | Detects sensitive patterns in prompts | Pre-call pipeline step |
| Redaction | Replaces RESTRICTED tokens with tags | Pre-call, when configured |
| Input sanitization | Strips prompt injection from untrusted text | Before prompt assembly |
| Output sanitization | Strips XSS and control chars from responses | After every LLM response |
| Audit seals | Proves what happened without storing content | After every LLM call |
| Exception redaction | Sanitizes error messages in audit records | On workflow state failures |
| Report protection | Filesystem storage, path validation, field exclusion | At report persistence |

---

## Configuration Reference

| Variable | Default | Effect |
|---|---|---|
| `AILA_PLATFORM_DATA_POSTURE_MODE` | `standard` | Global posture: transparent / standard / paranoid |
| `AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_RESTRICTED_BEHAVIOR_{TASK_TYPE}` | `fail` | Per-task-type: fail (block) or redact (replace and continue) |

Both are configurable via environment variable, Config page (`/admin/config`), or `PUT /config/platform/{key}` API.
