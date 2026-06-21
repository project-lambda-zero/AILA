# LLM Integration Guide

This guide explains how to use the AILA LLM layer from a feature module. It covers the client API, model routing, structured output, evidence validators, the pipeline, sanitization, cost tracking, audit sealing, configuration, and error handling. Every section is self-contained with a working code example.

All imports use the public surface:

```python
from aila.platform.llm import AilaLLMClient, LLMResponse
```

No internal module paths are needed or supported -- always import from the package root.

---

## 1. Quick Start

Module authors receive the LLM client via `ModuleContext.runtime_model`. You do not instantiate it yourself -- the platform builds it at startup with the correct ConfigRegistry and SecretStore.

### Async (primary interface)

```python
from aila.platform.llm import AilaLLMClient, LLMResponse

async def score_finding(client: AilaLLMClient, cve_id: str) -> str:
    messages = [
        {"role": "system", "content": "You are a vulnerability scoring expert."},
        {"role": "user", "content": f"Score the severity of {cve_id}."},
    ]
    response: LLMResponse = await client.chat("scoring", messages)
    return response.content
```

The string `"scoring"` is the **task type** -- it determines which model, temperature, and token limit are used. You never know or care which model runs behind the call.

### Sync (legacy code paths)

For code that cannot be async (legacy CLI paths, synchronous helpers), use the sync wrappers. They call `asyncio.run()` internally and are safe from FastAPI's `asyncio.to_thread` context.

```python
response = client.chat_sync("scoring", messages)
print(response.content)
```

### Reading the response

Every call returns an `LLMResponse`:

```python
if response.disabled:
    # Kill switch is active -- LLM calls are blocked by operator
    print("LLM is disabled:", response.content)
else:
    print("Model used:", response.model)
    print("Content:", response.content)
    print("Tokens:", response.usage)
```

---

## 2. Client API Reference

`AilaLLMClient` exposes six methods -- three async and three sync wrappers.

### `chat(task_type, messages, *, tools=None, tool_executor=None, run_id=None) -> LLMResponse`

Plain text completion. Returns the model's text response.

```python
response = await client.chat("synthesis", [
    {"role": "user", "content": "Summarize these findings."},
])
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `task_type` | `str` | Routing key (e.g. `"scoring"`, `"synthesis"`) |
| `messages` | `list[dict[str, Any]]` | OpenAI-format message list |
| `tools` | `list[dict[str, Any]] \| None` | Optional tool definitions (OpenAI function-calling format) |
| `tool_executor` | `Callable[[str, dict[str, Any]], Awaitable[str]] \| None` | Async callable `(tool_name, arguments) -> result_string`. Required when tools is provided. |
| `run_id` | `str \| None` | Optional run identifier for cost tracking and budget enforcement |

**Raises:** `LLMError` on permanent API failures. `BudgetExceededError` if the run's token budget is exhausted.

### `chat_json(task_type, messages, schema, *, tools=None, tool_executor=None, run_id=None) -> LLMResponse`

JSON-constrained completion. Sends the schema via OpenAI strict mode (`json_schema`). The response `content` is a JSON string matching the schema.

```python
schema = {
    "type": "object",
    "properties": {
        "severity": {"type": "string"},
        "score": {"type": "number"},
    },
}
response = await client.chat_json("scoring", messages, schema)
data = json.loads(response.content)
```

Falls back to client-side JSON extraction if the model returns markdown-wrapped JSON. Raises `LLMError` if JSON is invalid after recovery attempts.

### `chat_structured(task_type, messages, model_class, *, tools=None, tool_executor=None, run_id=None) -> LLMResponse`

Pydantic-validated completion. Generates JSON schema from the model class, sends with strict mode, parses and validates the response. On parse failure, retries once with an explicit correction prompt.

```python
from pydantic import BaseModel
from aila.platform.llm import AilaLLMClient

class SeverityResult(BaseModel):
    severity: str
    score: float
    reasoning: str

response = await client.chat_structured("scoring", messages, SeverityResult)
data = json.loads(response.content)  # Guaranteed valid against SeverityResult
```

**Behavior details:**

1. Generates JSON schema from `model_class.model_json_schema()`
2. Injects `additionalProperties: false` and full `required` arrays for OpenAI strict mode
3. Sends via `chat_json()` with the generated schema
4. Parses the response with `model_class.model_validate()`
5. On parse failure: retries once with a correction prompt appended to messages
6. On second failure: raises `LLMError` (not retryable)
7. Usage from both attempts is merged (summed) in the returned `LLMResponse.usage`

### `chat_sync(task_type, messages, *, tools=None, tool_executor=None, run_id=None) -> LLMResponse`

Synchronous wrapper for `chat()`. Uses `asyncio.run()`.

### `chat_json_sync(task_type, messages, schema, *, tools=None, tool_executor=None, run_id=None) -> LLMResponse`

Synchronous wrapper for `chat_json()`. Uses `asyncio.run()`.

### `chat_structured_sync(task_type, messages, model_class, *, tools=None, tool_executor=None, run_id=None) -> LLMResponse`

Synchronous wrapper for `chat_structured()`. Uses `asyncio.run()`.

### `LLMResponse` fields

| Field | Type | Description |
|-------|------|-------------|
| `content` | `str` | Text content from the model. `"LLM disabled by operator"` when kill switch is active. |
| `model` | `str` | The model_id that was used (e.g. `"openai/gpt-4o-mini"`). Empty string when disabled. |
| `usage` | `dict[str, int]` | Token counts: `prompt_tokens`, `completion_tokens`, `total_tokens`. Empty dict when disabled. |
| `disabled` | `bool` | `True` if the kill switch was active. Check this before reading `content`. |
| `finish_reason` | `str` | API finish reason (e.g. `"stop"`, `"length"`, `"tool_calls"`). Empty string when disabled. |
| `classification` | `str \| None` | Data classification level from the pipeline classify step (`"PUBLIC"`, `"INTERNAL"`, `"RESTRICTED"`). |
| `confidence` | `str \| None` | Confidence level from the pipeline gate step (`"HIGH"`, `"MEDIUM"`, `"LOW"`, `"REJECT"`). |
| `seal_id` | `str \| None` | HMAC-SHA256 seal hash from the pipeline seal step. |
| `pipeline_metadata` | `dict \| None` | Additional pipeline step metadata (evidence validation results, gating details). |

`LLMResponse` is a frozen dataclass (`frozen=True, slots=True`). It is immutable after creation.

---

## 3. Task Types and Model Routing

Every LLM call requires a `task_type` string (e.g. `"scoring"`, `"synthesis"`, `"selection"`). The client uses it to resolve which model, temperature, max tokens, and tool step limit to use -- callers never know which model runs.

### Resolution order

For a call with `task_type="scoring"`:

1. Look up `llm_model_scoring` in ConfigRegistry
2. If not set, fall back to `llm_default_model`
3. If not set, fall back to `"openai/gpt-4o-mini"` (hardcoded safe default)

The same pattern applies to temperature, max tokens, and tool steps:

| Parameter | Task-specific key | Default key | In-process fallback | Shipped `.env.example` |
|-----------|-------------------|-------------|--------------------|------------------------|
| Model | `llm_model_{task_type}` | `llm_default_model` (env: `AILA_PLATFORM_LLM_DEFAULT_MODEL`) | `antigravity/claude-opus-4-6-thinking` | `gpt-4o` |
| Base URL | — | `llm_base_url` (env: `AILA_PLATFORM_LLM_BASE_URL`) | `https://openrouter.ai/api/v1` | `https://api.openai.com/v1` |
| Max tokens | `llm_max_tokens_{task_type}` | `llm_default_max_tokens` (env: `AILA_PLATFORM_LLM_DEFAULT_MAX_TOKENS`) | `4096` | `32000` |
| Temperature | `llm_temperature_{task_type}` | `llm_default_temperature` | `0.0` | — |
| Max tool steps | `llm_max_tool_steps_{task_type}` | — | `0` (disabled) | — |
| Per-call timeout | — | `AILA_LLM_TIMEOUT_SECONDS` env var | `180` | `300` |

Models that reject the `temperature` parameter (the o1/o3/o4/gpt-5 family,
Claude Opus 4.6/4.7, Claude Sonnet 4.7, high-thinking models, `hadi`) are
declared in `AILA_LLM_MODELS_REJECTING_TEMPERATURE`
(comma-separated substrings, matched lowercase against the routed `model_id`).
The resolved list is cached for the process lifetime and falls back, in
order, to the env var, the `platform.llm_models_rejecting_temperature`
config DB entry, and finally a hardcoded tuple of known offenders. When a
routed model matches, the client omits `temperature` from the request.

### Configuring at runtime

All routing is driven by ConfigRegistry, which can be changed at runtime via `PUT /config`:

```bash
# Route scoring tasks to Claude Haiku
curl -X PUT http://localhost:8000/config/platform/llm_model_scoring \
  -H "Content-Type: application/json" \
  -d '{"value": "anthropic/claude-haiku-4-5-20251001"}'

# Set a higher token limit for synthesis
curl -X PUT http://localhost:8000/config/platform/llm_max_tokens_synthesis \
  -H "Content-Type: application/json" \
  -d '{"value": 8192}'

# Change the default model for all task types
curl -X PUT http://localhost:8000/config/platform/llm_default_model \
  -H "Content-Type: application/json" \
  -d '{"value": "openai/gpt-4o"}'
```

Changes take effect immediately -- the client reads config on every call with zero caching.

### API key resolution

The API key is resolved in this order:

1. `SecretStore("provider", "openai_api_key")` -- encrypted at rest
2. `OPENAI_API_KEY` environment variable
3. If neither is set, `LLMError` is raised

### Tool calling

When `tools` and `tool_executor` are provided, the client runs an async tool loop: call -> tool_use -> execute -> tool_result -> call -> ... until the model stops calling tools or `max_tool_steps` is reached. The maximum number of loop iterations is controlled by `llm_max_tool_steps_{task_type}`. If set to `0` (the default), tool calling is disabled for that task type even if tools are passed.

---

## 4. Structured Output

### With Pydantic models (`chat_structured`)

The preferred approach for structured data. Define a Pydantic model and pass it:

```python
from pydantic import BaseModel
from aila.platform.llm import AilaLLMClient

class VulnAssessment(BaseModel):
    cve_id: str
    severity: str
    cvss_score: float
    exploitable: bool
    reasoning: str

response = await client.chat_structured("scoring", messages, VulnAssessment)

if response.disabled:
    # Handle kill switch
    return

import json
data = json.loads(response.content)
# data is guaranteed valid against VulnAssessment schema
```

**What happens internally:**

1. `model_class.model_json_schema()` generates the JSON schema
2. `additionalProperties: false` and full `required` lists are injected recursively (OpenAI strict mode requirement)
3. The schema is sent via `response_format` with `"strict": True`
4. The response is parsed with `model_class.model_validate()`
5. On parse failure, a correction prompt is appended and the call is retried once
6. If the retry also fails, `LLMError` is raised

**Truncation detection:** If `finish_reason` is `"length"` and JSON was expected, the client checks if the content is valid JSON. If not, it raises `LLMError` with `retryable=True` and a message suggesting you increase `max_tokens` for the task type.

### With raw JSON schema (`chat_json`)

For cases where you want a dict instead of a model instance:

```python
schema = {
    "type": "object",
    "properties": {
        "hosts": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
}
response = await client.chat_json("analysis", messages, schema)
data = json.loads(response.content)
```

---

## 5. Evidence Validators

Evidence validators cross-reference LLM-cited evidence against stored enrichment data. They catch hallucinated citations -- identifiers the model invented that have no backing data.

### The EvidenceValidator Protocol

```python
from aila.platform.llm import EvidenceValidator, ValidationResult

class EvidenceValidator(Protocol):
    async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult: ...
```

Any class that implements this method is a valid evidence validator. It is `runtime_checkable`, so you can use `isinstance()` checks.

### Creating a validator for your module

Suppose you are building a malware analysis module that references hash identifiers. You want to verify the model does not invent hashes:

```python
import re
from aila.platform.llm import EvidenceValidator, ValidationResult, CitationResult

class MalwareHashValidator:
    """Validates SHA-256 hash citations in LLM responses."""

    HASH_PATTERN = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

    def __init__(self, known_hashes: set[str]) -> None:
        self._known = known_hashes

    async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
        citations: list[CitationResult] = []
        hallucinated = 0

        for match in self.HASH_PATTERN.finditer(content):
            hash_id = match.group().lower()
            if hash_id in self._known:
                citations.append(CitationResult(
                    citation_id=hash_id,
                    citation_type="sha256_hash",
                    status="valid",
                ))
            else:
                citations.append(CitationResult(
                    citation_id=hash_id,
                    citation_type="sha256_hash",
                    status="hallucinated",
                    detail=f"Hash {hash_id[:16]}... not found in enrichment store",
                ))
                hallucinated += 1

        return ValidationResult(
            validator_name="malware_hash",
            citations=citations,
            hallucination_count=hallucinated,
            overall_pass=(hallucinated == 0),
        )
```

### Data types

**`CitationResult`** -- result of validating a single citation:

| Field | Type | Description |
|-------|------|-------------|
| `citation_id` | `str` | The cited identifier (e.g. `"CVE-2024-1234"`, a SHA-256 hash) |
| `citation_type` | `str` | Category string (e.g. `"cve_id"`, `"epss_score"`, `"sha256_hash"`) |
| `status` | `str` | One of `"valid"`, `"invalid"`, `"hallucinated"` |
| `detail` | `str` | Human-readable explanation (empty string if valid) |

**`ValidationResult`** -- output of a single validator's `validate()` call:

| Field | Type | Description |
|-------|------|-------------|
| `validator_name` | `str` | Name of the validator that produced this result |
| `citations` | `list[CitationResult]` | Individual citation results |
| `hallucination_count` | `int` | Number of hallucinated citations found |
| `overall_pass` | `bool` | `True` if no hallucinated citations were found |

**`EvidenceValidationReport`** -- aggregated report across all validators for one LLM response:

| Field | Type | Description |
|-------|------|-------------|
| `citations_found` | `int` | Total unique CVE IDs found (`cve_id` type only) |
| `citations_valid` | `int` | Count of citations with `status="valid"` |
| `citations_hallucinated` | `int` | Count of citations with `status="hallucinated"` |
| `hallucinated_ids` | `list[str]` | Deduplicated list of hallucinated citation IDs |
| `overall_pass` | `bool` | `True` if all validators passed |
| `results` | `list[ValidationResult]` | Individual validator results |

### Registering a validator

Validators are registered in `builder.py` via `make_validate_step()`:

```python
from aila.platform.llm import make_validate_step

validator = MalwareHashValidator(known_hashes=loaded_hashes)
validate_step = make_validate_step(validators=[validator], emitter=emitter)
runtime_model.pipeline.register("validate", validate_step)
```

The shipping implementation registers `VulnEvidenceValidator` which validates CVE IDs, EPSS scores, and KEV status against stored enrichment data.

---

## 6. Pipeline Overview

Every `client.chat()` call runs through a fixed 5-step pipeline. This is transparent to callers -- you do not interact with the pipeline directly.

### Step order

```
classify -> call -> validate -> gate -> verify -> seal
```

| Step | Phase | What it does |
|------|-------|-------------|
| **classify** | Pre-call | Scans messages for sensitive data (IPs, hostnames, credentials). Classifies as PUBLIC, INTERNAL, or RESTRICTED. |
| **call** | -- | The actual LLM API call. Not a registered step -- it is the core `_single_call` logic. |
| **validate** | Post-call | Runs registered EvidenceValidators against the response content. Reports hallucinated citations. |
| **gate** | Post-call | Extracts confidence score, maps to HIGH/MEDIUM/LOW/REJECT. May run consensus retries for LOW. Discards REJECT. |
| **verify** | Post-call | Runs registered VerificationRecord cross-model verification (Phase 174, LLM-SEC-01). |
| **seal** | Post-call | Computes HMAC-SHA256 seal over input+model+output+classification+confidence+validation. Stores to PostgreSQL (`llm_audit_seals`). |

### Per-task-type step toggling

Each step can be enabled or disabled per task type via ConfigRegistry:

```bash
# Disable classification for the "analysis" task type
curl -X PUT http://localhost:8000/config/platform/llm_pipeline_classify_analysis \
  -H "Content-Type: application/json" \
  -d '{"value": false}'
```

Missing config key means enabled (`True` by default).

### Fail mode

Each step has a fail mode that controls what happens when the step throws an error:

- **`closed`** (default for security-critical steps: classify, validate, gate, verify, seal, sanitize): Re-raise the error as `LLMError`. The LLM call fails.
- **`open`** (default for other steps): Log the error and continue the pipeline. The LLM call succeeds.

Operators that want fail-open on a security-critical step MUST opt in explicitly per `task_type`. Source: `src/aila/platform/llm/config.py:280-285` (Phase 156).

Configure via `llm_pipeline_{step}_fail_mode_{task_type}`:

```bash
# Make classification fail-closed for scoring tasks
curl -X PUT http://localhost:8000/config/platform/llm_pipeline_classify_fail_mode_scoring \
  -H "Content-Type: application/json" \
  -d '{"value": "closed"}'
```

**Exception:** `ClassificationBlockedError` and `ConfidenceRejectedError` always propagate regardless of fail mode. They represent intentional blocks, not unexpected failures.

### When no steps are registered

If no pipeline steps are registered, the pipeline is a transparent pass-through -- `call_fn` is invoked directly with zero overhead.

---

## 7. Input/Output Sanitization

### Input sanitization (`sanitize_input`)

Use `sanitize_input()` to strip prompt injection patterns from untrusted text **before** including it in LLM prompts. This is a manual call-site function, not automatic.

```python
from aila.platform.llm import sanitize_input

# Sanitize a CVE description from an external source before prompting
raw_description = fetch_cve_description(cve_id)
safe_description = sanitize_input(raw_description)

messages = [
    {"role": "system", "content": "Analyze this vulnerability."},
    {"role": "user", "content": f"CVE: {cve_id}\nDescription: {safe_description}"},
]
response = await client.chat("analysis", messages)
```

### Built-in injection patterns

Five patterns are registered at module load time:

| Pattern | What it catches |
|---------|----------------|
| `system_override` | "Ignore all previous instructions", "you are now" |
| `system_tag` | `system:`, `<<SYS>>`, `[INST]`, `[/INST]` |
| `role_injection` | Lines starting with `assistant:`, `user:`, `human:` |
| `delimiter_injection` | Lines of `---` or `===` used to break prompt structure |
| `backtick_boundary` | Triple-backtick blocks labeled `system`, `assistant`, `user`, `human` |

All patterns are case-insensitive. Matched text is removed (replaced with empty string).

### Extending the pattern set

Register additional patterns at module startup:

```python
from aila.platform.llm import register_injection_pattern

register_injection_pattern(
    name="base64_payload",
    regex=r"base64\s*:\s*[A-Za-z0-9+/=]{50,}",
)
```

### Output sanitization (`sanitize_output`)

Output sanitization is **automatic** -- it runs in the pipeline enrichment phase after every LLM call. It strips XSS patterns (`<script>`, `javascript:`, `onclick=`, `<iframe>`, `<object>`, `<embed>`) and control characters from the response content before callers or the database receive it.

```python
from aila.platform.llm import sanitize_output

cleaned, count = sanitize_output(raw_content)
# count = number of patterns stripped
```

You typically do not need to call `sanitize_output` manually -- the pipeline handles it.

---

## 8. Cost Tracking and Budget

Cost flows through three layers, all driven by the same `run_id` and
`team_id` arguments passed to `client.chat*()`.

### Layer 1: in-memory per-run tracker (`CostTracker`)

`CostTracker` accumulates `prompt_tokens` and `completion_tokens` per
`run_id` in `RunMemory` (a process-local thread-safe store). It is wired at
platform startup so module authors never instantiate it. After every
successful API call the client records usage on the tracker. The tracker is
also the budget gate — see below.

```python
response = await client.chat("scoring", messages, run_id="run-abc-123")
# Usage is recorded automatically
usage = client.cost_tracker.get_usage("run-abc-123")
print(f"Tokens used so far: {usage['total_tokens']}")
```

### Layer 2: durable `LLMCostRecord`

After every successful call the client also writes an `LLMCostRecord` row
(`src/aila/platform/llm/cost_record.py`) into Postgres via
`persist_cost_record()`:

| Column | Source |
|--------|--------|
| `run_id` | Caller-supplied `run_id`, or `"_no_run"` |
| `model_id` | The routed model identifier |
| `task_type` | The routing key |
| `team_id` | Caller-supplied `team_id` (RLS-scoped via `TeamScopedMixin`) |
| `prompt_tokens`, `completion_tokens` | From the upstream response |
| `cost_usd` | `calculate_cost_usd()` over operator-configured pricing; `0.0` + a one-time `pricing_missing:{model}` notification when pricing is not set |
| `duration_ms` | Wall clock for the upstream call |
| `prompt_preview` | First 200 chars of the last `user` message (or NULL) |
| `response_preview` | First 200 chars of the response content (or NULL) |
| `status` | `"ok"` |

Cost persistence is fire-and-forget: a Postgres failure is logged but never
aborts the LLM call. After commit, `check_monthly_budget()` runs for the
team if `team_id` and a registry are present (Plan 175 budget alerts).
`LLM_COST_TOTAL` Prometheus counter increments per call.

The admin LLM interaction log at `GET /llm-log` (admin-only) projects from
`LLMCostRecord` rows using `prompt_preview` and `response_preview` so the
full secrets-bearing prompt is never mirrored into a long-lived surface.

### Layer 3: in-flight budget ceiling

Set a token ceiling per task type to short-circuit before the next API call:

```bash
# Limit scoring tasks to 50,000 tokens per run
curl -X PUT http://localhost:8000/config/platform/llm_budget_max_total_tokens_scoring \
  -H "Content-Type: application/json" \
  -d '{"value": 50000}'
```

When a run's accumulated `total_tokens` reaches the ceiling, the next call
raises `BudgetExceededError` **before** any HTTP request is made. The check
runs ahead of the retry loop so a depleted budget never costs a single
retry.

```python
from aila.platform.llm import AilaLLMClient, BudgetExceededError

async def score_all_findings(client, findings, run_id):
    results = []
    for finding in findings:
        try:
            response = await client.chat("scoring", messages, run_id=run_id)
            results.append(response.content)
        except BudgetExceededError:
            # Preserve partial results; never re-raise without writing what you have
            break
    return results
```

Calls without a `run_id` (or with `run_id=None`) accumulate under the
`_no_run` sentinel and **bypass budget enforcement entirely** — the budget
check requires a real run id.

### Budget configuration

| Key | Default | Description |
|-----|---------|-------------|
| `llm_budget_max_total_tokens_{task_type}` | `0` (unlimited) | Maximum total tokens per run for this task type. `0` means no enforcement. |

### Known gap: VR investigation cost aggregation

`VRInvestigationRecord.cost_actual_usd` has **no writer** — it stays `0.0`
forever. The investigation summary instead reads a live value computed by
`_compute_live_investigation_cost()`
(`src/aila/modules/vr/api_router.py`), which sums
`LLMCostRecord.cost_usd` over rows whose `run_id` joins back to the
investigation's `TaskRecord` ids via
`TaskRecord.kwargs_json LIKE '%"<investigation_id>"%'`.

The join only works when `LLMCostRecord.run_id` matches the ARQ
`TaskRecord.id`. In VR-driven calls the value of `run_id` is the
workflow-engine `RunRecord.id` rather than the ARQ `TaskRecord.id`, so the
sum often comes back as `0.0` even when LLM spend is real. The budget
gauge is therefore decorative for some investigations until the join is
routed through `workflow_run_records` (planned follow-up). Use the
`/llm-log` admin surface or query `LLMCostRecord` directly when you need
the actual spend for an investigation.

### Idempotency cache (VR turn replay)

VR's vulnerability researcher loop wraps every LLM turn in a deterministic
cache (`src/aila/platform/llm/idempotency_cache.py`, table
`llm_idempotency_cache`, Alembic migration `061_llm_idempotency_cache`).
The caller derives the cache key via:

```python
request_key = make_request_key(
    self.investigation_id,
    self.branch_id,
    turn_number,
    prompt_hash,  # sha256 of the serialized messages
)
```

`make_request_key` concatenates the parts with a `\x00` separator and
returns `sha256().hexdigest()`. On HIT (`lookup_cached_response`) the
cached response replays without an upstream call, including its
`prompt_tokens`, `completion_tokens`, and `cost_usd` so dashboards can
report cost saved. On MISS, the response is persisted via
`store_response()` under the same key, scoped to the investigation, with a
7-day TTL. DB write failures are best-effort: the call still returned a
real response to the caller.

The cache is opt-in per caller — the general `client.chat*()` API does not
invoke it. Only the VR researcher turn pipeline currently uses it.

---


## 9. Audit Trail

The pipeline automatically logs audit events at each step. No module code is needed to enable auditing.

### What each step logs

| Step | Audit event | Key fields |
|------|-------------|------------|
| **classify** | `llm_classification` | classification level, pattern types triggered, model_id, redacted flag |
| **validate** | `llm_evidence_validation` | citations found, citations valid, citations hallucinated, hallucinated IDs, overall pass |
| **gate** | `llm_confidence_gating` | confidence score, confidence level (HIGH/MEDIUM/LOW/REJECT), flagged, consensus attempted |
| **seal** | `llm_audit_seal` | seal hash, content stored flag, run_id |

### Seal records

Every LLM call that reaches the seal step gets an HMAC-SHA256 seal stored in the `AuditSealRecord` table. The seal covers: input hash, output hash, model_id, timestamp, classification, confidence, and evidence validation pass status.

**Query seal records:**

```bash
# Get seals for a specific run
curl http://localhost:8000/audit/seals?run_id=run-abc-123

# Export seals for a date range (compliance)
curl "http://localhost:8000/audit/seals/export?since=2026-04-01&until=2026-04-07"
```

Seal endpoints require admin role -- compliance data is sensitive.

### Content storage opt-in

By default, prompt and response content are **not** stored in seal records. To opt in per task type:

```bash
curl -X PUT http://localhost:8000/config/platform/llm_seal_store_content_scoring \
  -H "Content-Type: application/json" \
  -d '{"value": true}'
```

### Config change audit

Changes to ConfigRegistry keys (including all `llm_*` keys) are logged via the platform's config change audit mechanism (SEC-03).

---

## 10. Configuration Reference

All LLM configuration lives in the `platform` namespace of ConfigRegistry. Change any key at runtime via `PUT /config/platform/{key}`.

### Routing

| Key | Default | Description |
|-----|---------|-------------|
| `llm_kill_switch` | `false` | When `true`, all `chat*()` methods return a disabled response immediately. No API calls made. |
| `llm_default_model` (env: `AILA_PLATFORM_LLM_DEFAULT_MODEL`) | `antigravity/claude-opus-4-6-thinking` (in-process); `.env.example` sets `gpt-4o` | Default model when no per-task override is set. |
| `llm_model_{task_type}` | *(unset)* | Per-task-type model override. Example: `llm_model_scoring`. |
| `llm_base_url` (env: `AILA_PLATFORM_LLM_BASE_URL`) | `https://openrouter.ai/api/v1` (in-process); `.env.example` sets `https://api.openai.com/v1` | API base URL. Change to point to a local endpoint or direct OpenAI. |
| `llm_default_max_tokens` (env: `AILA_PLATFORM_LLM_DEFAULT_MAX_TOKENS`) | `4096` (in-process); `.env.example` sets `32000` | Default max completion tokens. |
| `llm_max_tokens_{task_type}` | *(unset)* | Per-task-type max tokens override. |
| `llm_default_temperature` | `0.0` | Default sampling temperature (deterministic). |
| `llm_temperature_{task_type}` | *(unset)* | Per-task-type temperature override. |
| `llm_max_tool_steps_{task_type}` | `0` | Max tool-calling loop iterations per task type. `0` = tool calling disabled. |

### Pipeline Step Toggling

| Key | Default | Description |
|-----|---------|-------------|
| `llm_pipeline_{step}_{task_type}` | `true` | Enable/disable a pipeline step for a task type. Steps: `classify`, `validate`, `gate`, `seal`. |
| `llm_pipeline_{step}_fail_mode_{task_type}` | `open` | Fail mode for a pipeline step. `"open"` = log and continue. `"closed"` = raise `LLMError`. |

### Classification

| Key | Default | Description |
|-----|---------|-------------|
| `llm_pipeline_classify_restricted_behavior_{task_type}` | `fail` | RESTRICTED data behavior. `"fail"` = raise `ClassificationBlockedError`. `"redact"` = replace sensitive tokens with `[REDACTED-*]` tags and continue. |

### Confidence Gating

| Key | Default | Description |
|-----|---------|-------------|
| `llm_pipeline_gate_high_threshold_{task_type}` | `0.8` | Score >= this = HIGH (auto-accept). |
| `llm_pipeline_gate_medium_threshold_{task_type}` | `0.5` | Score >= this = MEDIUM (flagged). |
| `llm_pipeline_gate_reject_threshold_{task_type}` | `0.2` | Score < this = REJECT (discard). Between reject and medium = LOW (consensus retry). |
| `llm_pipeline_gate_consensus_strategy_{task_type}` | `same_model_high_temp` | Consensus strategy. Options: `"same_model_high_temp"`, `"cross_model"`. |
| `llm_pipeline_gate_consensus_model_{task_type}` | *(empty)* | Model to use for `cross_model` consensus strategy. |
| `llm_pipeline_gate_consensus_retries_{task_type}` | `3` | Number of consensus retry calls for LOW confidence. |

### Audit Sealing

| Key | Default | Description |
|-----|---------|-------------|
| `llm_seal_hmac_key` | *(empty)* | HMAC-SHA256 key (hex string). Empty = auto-generated on first use via `secrets.token_hex(32)` and stored in ConfigRegistry. |
| `llm_seal_retention_days` | `90` | Days to retain seal records. Expired records are pruned on each new seal write. |
| `llm_seal_store_content_{task_type}` | `false` | When `true`, stores prompt and response content alongside the seal record. |

### Budget

| Key | Default | Description |
|-----|---------|-------------|
| `llm_budget_max_total_tokens_{task_type}` | `0` | Max total tokens per run for a task type. `0` = unlimited (no enforcement). |

### Common operations

```bash
# Switch all tasks to GPT-4o
curl -X PUT http://localhost:8000/config/platform/llm_default_model \
  -H "Content-Type: application/json" \
  -d '{"value": "openai/gpt-4o"}'

# Enable the kill switch
curl -X PUT http://localhost:8000/config/platform/llm_kill_switch \
  -H "Content-Type: application/json" \
  -d '{"value": true}'

# Set scoring budget to 100k tokens
curl -X PUT http://localhost:8000/config/platform/llm_budget_max_total_tokens_scoring \
  -H "Content-Type: application/json" \
  -d '{"value": 100000}'

# Allow redacted send for restricted data in analysis
curl -X PUT http://localhost:8000/config/platform/llm_pipeline_classify_restricted_behavior_analysis \
  -H "Content-Type: application/json" \
  -d '{"value": "redact"}'
```

---

## 11. Kill Switch

The `llm_kill_switch` config key is an operator-level circuit breaker. When set to `true`:

- All `chat()`, `chat_json()`, `chat_structured()` (and their sync variants) return immediately
- No API calls are made
- The returned `LLMResponse` has `disabled=True` and `content="LLM disabled by operator"`
- No exceptions are raised -- the response is a normal `LLMResponse` with the `disabled` flag set

### Checking in caller code

```python
response = await client.chat("scoring", messages)

if response.disabled:
    # LLM is off -- use cached results, skip scoring, or return a default
    return fallback_score(finding)

# Normal path
return parse_score(response.content)
```

### Toggling the kill switch

```bash
# Enable kill switch (disable all LLM calls)
curl -X PUT http://localhost:8000/config/platform/llm_kill_switch \
  -H "Content-Type: application/json" \
  -d '{"value": true}'

# Disable kill switch (re-enable LLM calls)
curl -X PUT http://localhost:8000/config/platform/llm_kill_switch \
  -H "Content-Type: application/json" \
  -d '{"value": false}'
```

The change takes effect immediately -- no restart required.

### LLMDisabledError

`LLMDisabledError` exists in the error hierarchy but is **not raised as an exception** during normal operation. When the kill switch is active, the client returns a structured response with `disabled=True` instead of throwing. `LLMDisabledError` carries the message `"LLM disabled by operator"` and `retryable=False`.

---

## 12. Troubleshooting

### Error reference

| Error | Cause | Resolution |
|-------|-------|------------|
| `LLMError` | Permanent API failure (authentication error, invalid config, malformed request) or configuration issue (no API key set). `retryable` flag indicates if retry may help. | Check API key is set (`SecretStore` or `OPENAI_API_KEY` env var). Check `llm_base_url` is correct. If `retryable=True`, the failure was transient after max retries -- check network or rate limits. |
| `LLMDisabledError` | Kill switch is active (`llm_kill_switch=true`). Not raised as an exception in normal flow -- check `response.disabled` instead. | Disable the kill switch via `PUT /config/platform/llm_kill_switch` with `{"value": false}`. |
| `ClassificationBlockedError` | RESTRICTED data detected (private IPs, SSH keys, credentials in prompts) and the classify step is configured to fail (`llm_pipeline_classify_restricted_behavior_{task_type}=fail`, which is the default). | Either sanitize sensitive data before prompting, or set the restricted behavior to `"redact"` for that task type. Always propagates regardless of pipeline fail mode. |
| `ConfidenceRejectedError` | Response confidence score fell below the reject threshold (default `0.2`) even after consensus retries. The response was discarded. | Review the reject threshold (`llm_pipeline_gate_reject_threshold_{task_type}`). Consider lowering it or adjusting the consensus strategy. Always propagates regardless of pipeline fail mode. |
| `BudgetExceededError` | The run's accumulated token usage reached the configured ceiling (`llm_budget_max_total_tokens_{task_type}`). Raised **before** the next API call to prevent waste. | Catch this error and preserve partial results. Increase the budget ceiling or set to `0` (unlimited). |

### Common issues

**"No API key configured"** -- `LLMError` raised at call time. Set the key via SecretStore or `OPENAI_API_KEY` environment variable.

**Truncated JSON** -- `LLMError` with `retryable=True` when `finish_reason="length"` and JSON was expected. Increase `llm_max_tokens_{task_type}` or `llm_default_max_tokens`.

**Pipeline step failing silently** -- Default fail mode is `"open"` (log and continue). Check Python logs for warnings like `"Pipeline step 'classify' failed (fail-open)"`. Switch to `"closed"` if you want failures to surface as errors.

**Tool calling not working** -- Ensure `llm_max_tool_steps_{task_type}` is set to a value greater than `0`. Default is `0` (disabled).

**Response always has `classification=None`** -- The classify step may be disabled for that task type. Check `llm_pipeline_classify_{task_type}` in ConfigRegistry.

### Retry behavior

Transient errors (connection failures, timeouts, rate limits, and every
other provider exception that is not `LLMError(retryable=False)`) are
retried with exponential backoff capped per attempt. Defaults:

| Env var | Default | Effect |
|---------|---------|--------|
| `AILA_LLM_MAX_RETRIES` | `3` | Total attempts before raising `LLMError(retryable=True)` with the last cause. Exponential backoff 1s, 2s, 4s capped at 30s. |
| `AILA_LLM_RETRY_BASE_DELAY_S` | `1.0` | First-attempt backoff (seconds). |
| `AILA_LLM_RETRY_MAX_DELAY_S` | `30.0` | Per-attempt backoff cap (seconds). |

At the shipped defaults the client retries up to 3 times with
exponential backoff (1s, 2s, 4s capped at 30s), for a total in-task
retry budget of ~7 seconds. Sustained provider degradation is handled
by ARQ task-level retry with cursor preservation, not by the in-call
retry loop. The OpenAI SDK's built-in retry is disabled
(`max_retries=0`) so every retry passes through this layer for
observability.

Non-retryable errors — `ClassificationBlockedError`,
`ConfidenceRejectedError`, `BudgetExceededError`, and any `LLMError`
constructed with `retryable=False` — surface immediately on first
attempt, regardless of the retry cap.

---

## 13. Request idempotency cache (migration 061)

Every LLM call is request-keyed via the `llm_idempotency_cache` table.
The key is `sha256(investigation_id, branch_id, turn_number,
prompt_hash)` for VR; other callers supply equivalent keys. On a retry
the cache replays the cached response instead of paying for another
provider round-trip.

- **Insert path** — gateway writes the response after successful
  validation + verification + seal.
- **Replay path** — gateway returns the cached row when the request
  key matches.
- **Cleanup** — the worker imports `run_purge_expired_cron` from
  `aila.platform.llm.idempotency_cache` and runs it on the cron
  schedule; expired entries drop so cache size stays bounded.
- **Source of truth** — `src/aila/platform/llm/idempotency_cache.py`,
  migration `061_llm_idempotency_cache.py`.
