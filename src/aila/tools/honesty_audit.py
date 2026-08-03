"""honesty_audit -- AST-based structural honesty checker for Python code.

Detects thirty-six categories of structural dishonesty:

1. unused_parameter    -- function parameter accepted but never referenced in body.
2. misleading_name     -- function name implies intelligence but body only forwards.
3. docstring_mismatch  -- docstring claims caching/persistence but body has none.
4. import_boundary     -- module imports from another module's package.
5. dead_isinstance     -- isinstance check on a parameter that already has a type annotation.
6. redundant_conversion -- str(already_str), int(already_int), Path(already_path).
7. private_in_all      -- underscore-prefixed name exported in __all__.
8. bare_exception_wrap -- except Exception that raises a less-specific type (destroys info).
9. always_true_default -- parameter with Optional/None default that is ALWAYS overridden by callers.
10. god_object_dispatch -- single function with 4+ if/elif branches on a string action parameter.
11. todo_in_code        -- TODO/FIXME/HACK/XXX comment in production source.
12. silent_exception    -- except Exception with pass or bare default assignment (no logging).
13. production_assert   -- assert statement in production code (stripped under -O).
14. do_nothing_wrapper  -- function body is a single return of another call with no added logic.
15. dead_config_field   -- Pydantic/config field declared but never read anywhere in the codebase.
16. sync_in_async       -- sync session_scope() called inside async def without asyncio.to_thread.
17. api_imports_module_internals -- api/platform/storage code imports modules/ internals.
18. asyncio_in_module   -- asyncio.to_thread/run, ThreadPoolExecutor or concurrent.futures in modules/.
19. response_model_dict -- @router.* decorator specifies response_model=dict/Dict.
20. bare_dict_return_endpoint -- endpoint handler returns a raw dict literal or dict() call.
21. noqa_inline         -- inline # noqa comment in production source (use honesty_whitelist.py instead).
22. http_client_in_module -- module imports httpx/requests/urllib3/aiohttp directly (use platform services).
23. direct_db_in_module -- module imports sqlalchemy.create_engine/asyncpg/psycopg2 directly (use platform UoW).
24. tautological_docstring -- docstring restates function name with no additional information.
25. commented_out_code  -- commented-out Python statement (import/def/class/if/for/return/raise).
26. except_return_default -- except handler returns an empty default ([], {}, None, 0, "") hiding real failures.
27. nested_if_collapsible -- if body is a single if with no else; can be combined with `and`.
28. pointless_pass      -- pass as sole body of non-abstract, non-stub function.
29. f_string_no_interpolation -- f-string with no embedded expressions (plain string suffices).
30. single_use_variable -- variable assigned then immediately returned with no other reference.
31. placeholder_return  -- function body is only a docstring + return {} or return []; no real logic.
32. log_format_concat   -- logging call uses string concatenation/f-string instead of %-formatting.
33. broad_exception_catch -- except Exception without a justifying comment (catches everything indiscriminately).
34. hoisted_enum_redeclared -- a unified vr/malware module redeclares a StrEnum owned by platform.contracts.enums (RFC-01).
35. unnamed_derived_constraint -- a unified vr/malware table hard-codes a UQ name instead of deriving via TabledUq.
36. shadowed_platform_base -- a unified vr/malware table recreates a platform base's columns instead of subclassing it.
37. module_config_schema_base -- a module config schema subclasses bare BaseModel instead of ModuleConfigBase (loses extra=forbid).
38. service_copy_of_platform -- a vr/malware service file is a full copy of a platform service instead of a thin binding.
39. cost_read_stored_actual -- a vr/malware lifecycle api_router reads the dead cost_actual_usd column in a response instead of aggregating live cost.
40. lifecycle_handler_bypass_service -- a pause/resume/re-enqueue route handler writes investigation .status directly instead of calling the platform lifecycle service.
41. workflow_state_copy_of_platform -- a vr/malware investigation state file duplicates a platform workflow-state base instead of binding the factory.
42. agent_primitive_reimplementation -- a module agents/ file defines a platform-owned agent primitive (auto-steering injector / intent classifier) at top level instead of importing it.
43. agent_llm_chat_bypass -- a module agents/ file calls llm_client.chat/chat_json/chat_structured directly instead of routing through platform idempotent_llm_call (double-pays the model on retry).
44. private_platform_import -- a module imports a platform-private submodule symbol (tools._common, mcp.adapters._shared) that the public package already re-exports; import from the public path instead (RFC-05 concern f).
45. module_prefix_in_platform_tool_name -- a platform MCP bridge hard-codes a module-prefixed tool name literal (name = "vr.audit_mcp_bridge"); derive the name from a constructor module_id instead (RFC-05 concern b).
46. platform_owns_event_vocabulary -- an event class under platform/events/ carries module-domain vocabulary (scan/finding/investigation or a module id) in its class name or event_type; the platform owns only generic infrastructure events (RFC-05 concern c).
47. raw_sql_platform_tables -- a module file issues raw SQL against a platform-owned task table (taskrecord, workflow_state_cursor); route through a platform lifecycle / TaskQueue service instead (RFC-05 Phase 6).
48. platform_names_module -- a boundary-guarded file (api/, platform/, storage/) names a feature module: a .require("vulnerability") / .require_module("forensics") registry call, a ConfigRegistry-shape .get("vr", ...) read of a module namespace, or a runtime "aila.modules.<module>" string constant. Resolve domain data by capability via ModuleRegistry.first_with/all_with; the platform layer owns only the 'platform' config namespace (RFC-05 concerns a/g).
49. agent_env_read -- a module agents/ file reads config via os.environ / os.getenv (attribute access or `from os import environ/getenv`) instead of platform ConfigRegistry; the RFC-03 lift removed every direct env read from module agent runtimes and this rule locks the closure in.
50. static_node_mutation -- a WorkflowDefinition.states mapping is mutated (subscript / update / delete) after construction, reopening the frozen node set the dispatch hub relies on (RFC-13 #68).
51. ledger_write_bypass -- investigation_ledger writes bypass LedgerService; the service owns idempotency + the append-only rule (RFC-13 #68).
52. fail_open_recovery_path -- a safety / rate-limit / verify / recovery / finalizer function returns a permissive value (True / 0 / 0.0 / "" / [] / {} / bare return) from an ``except`` handler. The RFC-07 posture is fail-closed: return a conservative default and surface a signal (a bounded defer, mark-and-block, close-with-reason).
53. close_without_infra_classification -- a finalizer that closes an investigation as a negative (a close_investigation / close_no_finding / synthesize_no_finding / finalize_negative call) does not consult InfraDeathClassifier in the same function body. An infra-death branch must be tagged as such, not silently recorded as a clean negative that vanishes from the operator's re-run queue.
54. heal_without_journal -- a recovery function whose body mutates run state (set_enabled / flip_status / drop_lock / delete_cursor / re_enqueue) without also writing a checkpointed recovery event (LedgerService.append_general, record_signal, record_and_check, emit_recovery_event). Every heal must leave an audit trail so recovery is itself auditable.
55. ungated_self_improvement_write -- a call to ``pattern_store.create(...)`` (or any ``.create`` / ``.add`` / ``.insert`` on a pattern-store-shaped receiver) outside :class:`ExperienceWriter` and the store's own file bypasses the RFC-08 review-gated write path. Every experience must be signed by a reviewed :class:`QuorumOutcome`; route the write through ``ExperienceWriter.record(verdict=...)``.
56. self_labeled_reward -- an agent runtime file (``platform/agents/**`` or ``modules/*/agents/**``) passes or assigns a self-labelled promotion signal (``reward=``, ``self_score=``, ``agent_score=``, ``promotion_score=``, ``self_reward=``, or the same as an attribute assignment). An agent must not set its own promotion field; the RFC-08 gate reads only reviewer-produced, quorum-signed signals.
57. unversioned_config_promotion -- a function calls ``.set("<...>_threshold", ...)`` / ``.set("<...>_ceiling", ...)`` / other threshold-shaped key without also referencing :class:`CalibrationProposalRecord` / :class:`CalibrationProposer` in the same body. RFC-08's propose-and-gate contract is that a live threshold only ever moves behind a versioned, reversible proposal row.
58. inline_prompt_literal -- a module-level ``_*_PROMPT*`` constant is assigned a multi-line string literal (3+ newlines, 200+ chars). RFC-09 requires prompt text to be resolved through :class:`PromptRegistry` from a versioned ``.md`` file so cost / seal / audit rows carry the resolved ``prompt_content_hash`` + ``prompt_version``; an inline literal drops the attribution.
59. untagged_llm_call -- a function calls ``.chat(...)`` / ``.chat_json(...)`` / ``.chat_structured(...)`` without ``correlation_scope(prompt_content_hash=, prompt_version=)`` or :func:`idempotent_llm_call` in the enclosing body. The RFC-09 stamp is mandatory: the raw call reaches the model with NULL prompt attribution and breaks the (cost, prompt) join.
60. unaudited_alias_flip -- a function writes a :class:`PromptAliasRecord` row (constructor call, ``session.add`` of one, or raw ``UPDATE prompt_aliases``) without also emitting a matching :class:`PromptAliasChangeRecord` in the same body. Every alias flip must leave an audit trail; the canonical writer is ``PromptVersionStore.set_alias`` (pair-write in one transaction).
61. promotion_without_gate -- a function flips a lifecycle version to production (a ``LifecycleTransitionRecord(to_stage=LifecycleStage.PRODUCTION)`` construct, or a ``set_alias(..., "production", ...)`` call) without referencing the eval + quorum gate markers (``_passing_evaluate``, ``_distinct_approver_count``, ``EvalRunner``, ``agent_promotion_quorum``, ``AgentLifecycleController``). Every promotion must pass the gate; delegate to :meth:`AgentLifecycleController.promote`.
62. untransitioned_stage_change -- a function assigns a :class:`LifecycleStage` value (``.lifecycle_stage = ...`` attribute assignment, or ``stage=`` / ``to_stage=`` / ``lifecycle_stage=`` kwarg carrying a ``LifecycleStage.<X>`` member) without also constructing a :class:`LifecycleTransitionRecord` or calling ``._journal(...)`` in the same body. Every stage move must be journaled (RFC-10).
63. canary_below_min_sample -- a function whose name matches ``promote_from_canary`` / ``promote_canary`` / ``flip_canary`` has no min-sample gate marker (``min_sample`` / ``min_samples`` / ``min_canary_sample`` / ``sample_count`` / ``signal_count`` / ``agent_canary_min_sample``) in its body. RFC-10 requires canary promotion to verify a minimum observed-signal count before flipping so a candidate that never saw traffic cannot be promoted on an empty history.
64. second_embedding_path -- an embedding provider (``resolve_provider`` / ``get_embedding_provider`` / ``BGEProvider`` / ``MiniLMProvider`` / ``SentenceTransformer``) is constructed outside the canonical ``platform/services/embedding.py`` + ``platform/services/knowledge.py``. RFC-12 / #37 require ONE embedding path; a second provider writes incompatible vectors into the shared knowledge table.
65. vector_without_provenance -- a ``KnowledgeEntryRecord`` is constructed with an ``embedding=`` kwarg but no ``model_id=`` kwarg. RFC-12 / #37 require every stored vector to carry its model provenance so a model swap triggers a re-embed sweep instead of silent corpus invalidation.
66. retrieval_without_gate -- agent-runtime code (``platform/agents/**`` or ``modules/*/agents/**``) calls the raw ``.retrieve(`` instead of ``retrieve_routed``. RFC-12 / #43: only the routed path applies the relevance floor + sanitize/classify gate, so agent-reachable retrieval must go through it.
67. unsanitized_retrieved_content -- a ``retrieve_routed`` definition's body no longer references the sanitize/classify gate (``apply_gate`` / ``apply_gate_many``). RFC-12 / #43: the routed entry point must gate every hit so retrieved content cannot reach a prompt unsanitised.

Usage (CLI):
    python -m aila.tools.honesty_audit src/
    python -m aila.tools.honesty_audit src/ --whitelist honesty_whitelist.py

Exit code 0 = no findings (clean).
Exit code 1 = findings exist.

Whitelist:
    honesty_whitelist.py defines HONESTY_WHITELIST as a list of
    (filename_suffix, function_name, detail) tuples.  A finding is suppressed
    when the finding's file ends with filename_suffix AND function_name appears
    in the finding's message AND detail appears in the finding's message.

Design constraints (D-04):
    AST analysis only -- no runtime inspection.
    No external dependencies beyond stdlib (ast, sys, pathlib, dataclasses).
"""

from __future__ import annotations

import ast
import difflib
import logging
import re as _re
import sys
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

__all__ = ["Finding", "HonestyAuditor", "load_whitelist"]

# ---------------------------------------------------------------------------
# Keyword sets
# ---------------------------------------------------------------------------

_MISLEADING_NAME_KEYWORDS: frozenset[str] = frozenset(
    {"planner", "manager", "manage", "helper", "coordinator", "processor", "handler"}
)

_CACHE_DOC_CLAIM_PHRASES: tuple[str, ...] = (
    "caches the",
    "cached result",
    "caches results",
    "persists the result",
    "memoizes",
    "stores the result in memory",
    "stores result in cache",
)

_CACHE_IMPL_IDENTIFIERS: frozenset[str] = frozenset(
    {"cache", "_cache", "lru_cache", "functools", "memo", "_store", "persist"}
)

# Decorator names that indicate a stub body is intentional.
_STUB_DECORATORS: frozenset[str] = frozenset({"abstractmethod", "overload"})

# Type names that make isinstance checks redundant (rule 5).
_TYPED_BUILTINS: frozenset[str] = frozenset(
    {"str", "int", "float", "bool", "dict", "list", "tuple", "set", "bytes"}
)

# Redundant conversions where the annotation already guarantees the type (rule 6).
_IDENTITY_CONVERSIONS: dict[str, str] = {
    "str": "str", "int": "int", "float": "float", "bool": "bool",
    "Path": "Path",
}

# Action-dispatch keywords that indicate a God Object pattern (rule 10).
_ACTION_PARAM_NAMES: frozenset[str] = frozenset({"action", "operation", "command", "mode"})

# Comment markers that indicate unfinished promises (rule 11).
_TODO_PATTERN = _re.compile(r"#\s*(TODO|FIXME|HACK|XXX)\b", _re.IGNORECASE)

# Rule 21 -- noqa inline comments.
_NOQA_PATTERN = _re.compile(r"#\s*noqa\b")

# Rule 18 -- asyncio threading primitives banned from modules/.
# These identifiers flag usage of asyncio.to_thread, asyncio.run,
# ThreadPoolExecutor, and concurrent.futures imports inside module files.
_ASYNCIO_THREAD_ATTRS: frozenset[str] = frozenset({
    "to_thread", "run", "run_until_complete", "run_in_executor",
})
_THREAD_CLASS_NAMES: frozenset[str] = frozenset({"ThreadPoolExecutor"})

# Files that are self-exempt from Rule 21 (they ARE the audit/whitelist tools).
_NOQA_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "aila/tools/honesty_audit.py",
    "aila/tools/honesty_whitelist.py",
)

# Alembic paths are exempt from Rule 21.
# Both the auto-generated migration files (alembic/versions/) and the hand-written
# alembic/env.py legitimately use # noqa: F401 for side-effect imports that populate
# SQLModel.metadata -- they cannot use honesty_whitelist.py because the import must
# appear at the module level and ruff processes it independently.
_ALEMBIC_PATH_PATTERN = _re.compile(r"[/\\]alembic[/\\]")

# Rule 22 -- HTTP client libraries banned from modules/.
# Modules must use platform HTTP services (SSHService, IDA bridge, etc.),
# not construct their own httpx/requests/aiohttp clients.
_HTTP_CLIENT_MODULES: frozenset[str] = frozenset({
    "httpx", "requests", "urllib3", "aiohttp",
})

# Rule 23 -- Direct DB connection libraries banned from modules/.
# Modules use UnitOfWork from aila.platform.uow for all DB access.
# Direct engine/connection construction bypasses team scoping and audit.
_DIRECT_DB_MODULES: frozenset[str] = frozenset({
    "asyncpg", "psycopg2", "psycopg", "sqlite3",
})
_DIRECT_DB_CALLABLES: frozenset[str] = frozenset({
    "create_engine", "create_async_engine",
})

# Rule 25 -- Commented-out code detection.
# Matches lines that look like commented-out Python statements.
_COMMENTED_CODE_RE = _re.compile(
    r'^\s*#\s*'
    r'(import\s|from\s|def\s|class\s|if\s|elif\s|for\s|while\s'
    r'|return\s|raise\s|try:|except\s|with\s|async\s|await\s|yield\s'
    r'|assert\s|pass$|break$|continue$)',
)
# Lines containing these phrases are documentation examples, not dead code.
_COMMENTED_CODE_EXEMPTIONS: tuple[str, ...] = (
    "example", "e.g.", "usage:", "like:", "such as", "pattern:",
    "alternative:", "note:", "see:", "returns:", "yields:",
    "template", "scaffold", "optional", "placeholder", "disabled",
    "investigation", "documentation", "explanation", "describes",
)

# Rule 29 -- f-string without interpolation.
# Ruff F541 catches this too but may be disabled; this is the structural backup.

# Rule 32 -- Logging calls using string concatenation or f-strings.
# Correct: _log.info("x=%s", x).  Wrong: _log.info(f"x={x}") or _log.info("x=" + str(x)).
_LOG_METHODS: frozenset[str] = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical",
})

# Names that indicate logging is present (rule 12 -- silent exception check).
_LOGGING_IDENTIFIERS: frozenset[str] = frozenset({
    "logger", "logging", "log", "LOGGER", "LOG",
    "warn", "warning", "error", "info", "debug", "exception", "critical",
})

# ---------------------------------------------------------------------------
# Module-boundary detection helpers
# ---------------------------------------------------------------------------

_MODULE_PATH_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\]([a-z][a-z0-9_]*)[/\\]"
)


def _owning_module_id(filepath: str) -> str | None:
    """Return the aila module_id if *filepath* is inside aila/modules/{id}/, else None."""
    match = _MODULE_PATH_PATTERN.search(filepath.replace("\\", "/"))
    return match.group(1) if match else None


def _endpoint_route_path(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Return the route path from a ``@router.<verb>("...")`` decorator.

    Returns the first positional string argument of the first router verb
    decorator on *node*, or None when the function is not a route handler.
    """
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        if dec.func.attr not in {"get", "post", "put", "delete", "patch"}:
            continue
        if (
            dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.args[0].value
    return None


_BOUNDARY_GUARDED_PATTERN = _re.compile(r"[/\\]aila[/\\](api|platform|storage)[/\\]")


def _is_boundary_guarded_file(filepath: str) -> bool:
    """Return True if *filepath* is inside a boundary-guarded package."""
    return bool(_BOUNDARY_GUARDED_PATTERN.search(filepath.replace("\\", "/")))


_MODULE_FILE_PATTERN = _re.compile(r"[/\\]aila[/\\]modules[/\\]")

# Rule 37 -- module config schemas must subclass ModuleConfigBase.
_CONFIG_SCHEMA_PATH_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\][a-z][a-z0-9_]*[/\\]config_schema\.py$"
)


def _is_module_file(filepath: str) -> bool:
    """Return True if *filepath* is inside the aila/modules/ package."""
    return bool(_MODULE_FILE_PATTERN.search(filepath.replace("\\", "/")))


# Rule 45 -- module_prefix_in_platform_tool_name. Platform MCP bridge tool
# names must derive from a constructor module_id, not a hard-coded literal
# that names a module.
_BRIDGE_FILE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]platform[/\\]mcp[/\\]bridges[/\\]"
)
_MODULE_TOOL_PREFIX_RE = _re.compile(
    r"^(vr|vulnerability|forensics|malware|hello_world)\."
)


def _module_prefixed_name_literal(value: ast.expr | None) -> str | None:
    """Return the string when *value* is a module-prefixed name literal."""
    if (
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and _MODULE_TOOL_PREFIX_RE.match(value.value)
    ):
        return value.value
    return None


# Rule 46 -- platform_owns_event_vocabulary. Event classes under
# platform/events/ must not carry module-domain vocabulary; the platform
# owns only generic infrastructure events (system lifecycle, config
# change, assessment lifecycle, LLM accounting).
_EVENTS_FILE_PATTERN = _re.compile(r"[/\\]aila[/\\]platform[/\\]events[/\\]")
_EVENT_DOMAIN_TOKENS: frozenset[str] = frozenset({
    "scan", "finding", "investigation", "malware", "vulnerability", "forensics",
})


# Rule 47 -- raw_sql_platform_tables. Modules must not issue raw SQL against
# platform-owned task tables; route through a platform lifecycle / TaskQueue
# service. Matches a FROM|INTO|UPDATE|JOIN <table> clause shape inside any
# string constant so the call wrapper (text / sa_text / execute) is
# irrelevant, while SQL-ish prose without the clause shape is not flagged.
_RAW_SQL_PLATFORM_TABLE_RE = _re.compile(
    r"\b(from|into|update|join)\s+(taskrecord|workflow_state_cursor)\b",
    _re.IGNORECASE,
)

# Rule 48 -- platform_names_module. Feature module ids a boundary-guarded file
# must never name: not in a registry require(...) call, not as the namespace
# argument of a ConfigRegistry-shape .get(...) read, and not as a runtime
# "aila.modules.<module>" string constant. The platform resolves domain data by
# capability (ModuleRegistry.first_with/all_with) and owns only the 'platform'
# config namespace; every other namespace belongs to a specific module.
_DOMAIN_MODULE_IDS = frozenset(
    {"vulnerability", "forensics", "malware", "vr", "hello_world"}
)

# Rule 48 sub-check (c): match "aila.modules.<domain-module-id>" or
# "aila.modules.<id>.<subpath>" appearing as a runtime string constant.
# Bare "aila.modules" (used by the discovery bootstrap in
# platform/tasks/worker.py) is intentionally not matched because it names
# no specific module. Docstring constants are skipped separately.
_AILA_MODULES_PATH_LITERAL_RE = _re.compile(
    r"^aila\.modules\.(vulnerability|forensics|malware|vr|hello_world)(\.|$)"
)


def _collect_docstring_constant_ids(tree: ast.Module) -> frozenset[int]:
    """Return the ``id()`` of every ast.Constant that lives in docstring position.

    A docstring is the first statement of a Module / ClassDef / FunctionDef /
    AsyncFunctionDef body when that statement is ``ast.Expr(value=ast.Constant(str))``.
    Callers use the resulting id-set to skip docstring string constants during
    a walk without re-parsing.
    """
    docstring_ids: set[int] = set()
    for parent in ast.walk(tree):
        body = getattr(parent, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr):
            continue
        val = first.value
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            docstring_ids.add(id(val))
    return frozenset(docstring_ids)


def _event_type_string_literal(stmt: ast.stmt) -> str | None:
    """Return the string assigned to an ``event_type`` field, or None."""
    value: ast.expr | None = None
    if (
        isinstance(stmt, ast.AnnAssign)
        and isinstance(stmt.target, ast.Name)
        and stmt.target.id == "event_type"
    ):
        value = stmt.value
    elif isinstance(stmt, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "event_type" for t in stmt.targets
    ):
        value = stmt.value
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


# ---------------------------------------------------------------------------
# AST walk helpers
# ---------------------------------------------------------------------------

_NESTED_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _walk_returns_shallow(node: ast.AST):
    """Yield Return nodes from *node*'s subtree without recursing into nested function/class bodies.

    Unlike ``ast.walk``, this generator stops at any ``FunctionDef``,
    ``AsyncFunctionDef``, or ``ClassDef`` node -- so return statements inside
    nested helper functions are invisible to the caller.  This prevents false
    positives in Rule 20 (bare_dict_return_endpoint) where an outer endpoint
    delegates work to an inner ``async def _helper()`` that legitimately
    returns a plain dict for internal use only.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _NESTED_DEF_TYPES):
            continue
        if isinstance(child, ast.Return):
            yield child
        yield from _walk_returns_shallow(child)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """A single honesty violation found in a source file."""

    file: str
    line: int
    rule: str
    message: str


Whitelist = set[tuple[str, str, str]]


# ---------------------------------------------------------------------------
# Whitelist loading
# ---------------------------------------------------------------------------


def load_whitelist(path: Path) -> Whitelist:
    """Parse *path* and return the set of (filename_suffix, func_name, detail) triples.

    The file must define a top-level ``HONESTY_WHITELIST`` list literal of
    3-element string tuples.  Non-tuple entries are silently skipped.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    result: Whitelist = set()
    for node in ast.walk(tree):
        # Handle both plain assignment and annotated assignment:
        #   HONESTY_WHITELIST = [...]
        #   HONESTY_WHITELIST: list[...] = _validate([...])
        if isinstance(node, ast.Assign):
            targets = node.targets
            raw_value: ast.expr | None = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            raw_value = node.value
        else:
            continue
        for target in targets:
            if not (isinstance(target, ast.Name) and target.id == "HONESTY_WHITELIST"):
                continue
            value = raw_value
            # Unwrap _validate([...]) → the inner list literal.
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if not isinstance(value, ast.List):
                continue
            for elt in value.elts:
                if (
                    isinstance(elt, ast.Tuple)
                    and len(elt.elts) == 3
                    and all(isinstance(e, ast.Constant) for e in elt.elts)
                ):
                    triple = tuple(e.value for e in elt.elts)  # type: ignore[union-attr]
                    result.add(triple)  # type: ignore[arg-type]
    return result


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return the simple names of all decorators on *func*."""
    names: list[str] = []
    for dec in func.decorator_list:
        if isinstance(dec, ast.Name):
            names.append(dec.id)
        elif isinstance(dec, ast.Attribute):
            names.append(dec.attr)
    return names


def _is_stub_body(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when the function body is a bare ``...`` (Ellipsis) stub.

    Protocol / ABC abstract methods have ``...`` as their entire body.  They
    declare signatures but contain no executable code -- flagging unused params
    there is meaningless.
    """
    stmts = func.body
    if len(stmts) == 1:
        stmt = stmts[0]
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
            return True
    return False


def _has_stub_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function carries @abstractmethod or @overload."""
    return bool(_STUB_DECORATORS & set(_decorator_names(func)))


def _collect_body_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all ast.Name ids that appear anywhere in the function body."""
    names: set[str] = set()
    for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
        if isinstance(node, ast.Name):
            names.add(node.id)
    return names


def _collect_body_identifiers(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all Name ids AND Attribute attrs from the function body AND decorators."""
    ids: set[str] = set()
    # Include decorator names (e.g. @lru_cache, @functools.cache).
    for dec in func.decorator_list:
        for node in ast.walk(dec):
            if isinstance(node, ast.Name):
                ids.add(node.id)
            elif isinstance(node, ast.Attribute):
                ids.add(node.attr)
    for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
        if isinstance(node, ast.Name):
            ids.add(node.id)
        elif isinstance(node, ast.Attribute):
            ids.add(node.attr)
    return ids


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return parameter names that are subject to the unused-parameter check.

    Excluded:
      - self, cls  (conventional receiver names)
      - _          (intentional discard sentinel)
      - *args arguments (vararg)
      - **kwargs arguments (kwarg)
    """
    args = func.args
    excluded = {"self", "cls", "_"}
    result: list[str] = []
    # positional + keyword
    all_args = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    for arg in all_args:
        if arg.arg not in excluded and not arg.arg.startswith("_"):
            result.append(arg.arg)
    return result

_DEPENDENCY_DEFAULT_NAMES = {"Depends", "Security"}


def _decorator_identifiers(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return Name ids and Attribute attrs appearing in decorators."""
    ids: set[str] = set()
    for dec in func.decorator_list:
        for node in ast.walk(dec):
            if isinstance(node, ast.Name):
                ids.add(node.id)
            elif isinstance(node, ast.Attribute):
                ids.add(node.attr)
    return ids


def _parameter_arg_map(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
 ) -> dict[str, ast.arg]:
    """Return a mapping of parameter name to ast.arg node."""
    args = func.args
    all_args = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    return {arg.arg: arg for arg in all_args}


def _parameter_defaults(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
 ) -> dict[str, ast.expr]:
    """Return a mapping of parameter name to its default expression."""
    args = func.args
    pos_args = list(args.posonlyargs) + list(args.args)
    defaults: dict[str, ast.expr] = {}
    if args.defaults:
        start = len(pos_args) - len(args.defaults)
        for arg, default in zip(pos_args[start:], args.defaults, strict=True):
            defaults[arg.arg] = default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if default is not None:
            defaults[arg.arg] = default
    return defaults


def _is_dependency_default(node: ast.expr | None) -> bool:
    """Return True if a default expression is a FastAPI dependency marker."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _DEPENDENCY_DEFAULT_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in _DEPENDENCY_DEFAULT_NAMES
    return False


def _is_request_annotation(node: ast.expr | None) -> bool:
    """Return True if an annotation refers to Request."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id == "Request"
    if isinstance(node, ast.Attribute):
        return node.attr == "Request"
    return False


def _parameter_is_framework_used(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    param_name: str,
 ) -> bool:
    """Return True when a parameter is consumed declaratively by framework contracts."""
    defaults = _parameter_defaults(func)
    if _is_dependency_default(defaults.get(param_name)):
        return True

    decorator_ids = _decorator_identifiers(func)
    arg_map = _parameter_arg_map(func)
    arg_node = arg_map.get(param_name)
    if (
        param_name == "request"
        and _is_request_annotation(arg_node.annotation if arg_node else None)
        and ("limit" in decorator_ids or func.name.endswith("_handler"))
    ):
        return True

    if param_name == "ctx":
        return True

    return False

def _root_name(node: ast.expr) -> str | None:
    """Walk attribute chains and return the root Name id, or None."""
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_forward_call_body(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the body is a single pure-forward call statement.

    A forward call is: the single statement is a Return (or Expr) of an
    ast.Call where the callable is an ast.Attribute whose root receiver is
    ``self`` or the first positional argument.  This covers both
    ``self.run(x)`` and chained ``self.delegate.run(x)`` patterns.

    An optional leading docstring is allowed and does not count against the
    "single statement" limit.
    """
    stmts = func.body
    if not stmts:
        return False

    # Strip leading docstring if present.
    real_stmts = stmts
    if (
        len(stmts) >= 1
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        real_stmts = stmts[1:]

    if len(real_stmts) != 1:
        return False

    stmt = real_stmts[0]

    # Extract the expression -- could be Return or bare Expr.
    if isinstance(stmt, ast.Return) and stmt.value is not None:
        expr = stmt.value
    elif isinstance(stmt, ast.Expr):
        expr = stmt.value
    else:
        return False

    # Must be a simple Call.
    if not isinstance(expr, ast.Call):
        return False

    func_node = expr.func
    # Must be attribute access (self.x, self.delegate.x, first_arg.x, etc.).
    if not isinstance(func_node, ast.Attribute):
        return False

    root = _root_name(func_node.value)
    if root is None:
        return False

    # Allowed roots: self, or the first positional parameter name.
    allowed_roots = {"self"}
    all_params = list(func.args.posonlyargs) + list(func.args.args)
    if all_params:
        allowed_roots.add(all_params[0].arg)

    return root in allowed_roots


def _get_docstring(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return the docstring of *func* if it has one, else None."""
    if not func.body:
        return None
    first = func.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        val = first.value.value
        if isinstance(val, str):
            return val
    return None


def _docstring_claims_caching(docstring: str) -> bool:
    """Return True if the docstring claims THIS function caches/persists results.

    Only flags phrases like 'caches the result' or 'memoizes' -- not functions
    that merely interact with a cache ('reads from cache', 'updates cache entry').
    """
    low = docstring.lower()
    return any(phrase in low for phrase in _CACHE_DOC_CLAIM_PHRASES)


def _body_has_cache_impl(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the body contains any identifier associated with caching."""
    body_ids = _collect_body_identifiers(func)
    return bool(body_ids & _CACHE_IMPL_IDENTIFIERS)


# ---------------------------------------------------------------------------
# RFC-01 re-duplication guardrails (rules 34-36)
# ---------------------------------------------------------------------------

# The enums hoisted to aila.platform.contracts.enums. A module must import
# these rather than redeclare them. Module-owned enums (WorkspaceTheme,
# TargetKind, etc.) are deliberately absent from this set.
_HOISTED_ENUM_NAMES: frozenset[str] = frozenset({
    "WorkspaceStatus", "TargetStatus", "AnalysisState", "TargetTagSource",
    "BranchStatus", "PersonaVoice", "BranchOperation", "InvestigationStatus",
    "InvestigationPauseReason", "OutcomeConfidence", "OutcomeDispatchStatus",
    "SenderKind", "OperatorIntent", "PatternStatus", "PatternScope",
    "PatternConfidence", "HypothesisState", "StageState", "StageName",
})

# Modules whose investigation-engine tables RFC-01 unified onto the platform
# record bases. Other modules (forensics, vulnerability) keep independent
# table shapes and are outside the scope of the derived-name + subclass rules.
_RFC01_UNIFIED_MODULES: frozenset[str] = frozenset({"vr", "malware"})

# Unified table role (tablename with the module prefix removed) mapped to the
# platform base class the concrete must subclass.
_UNIFIED_ROLE_BASES: dict[str, str] = {
    "workspaces": "WorkspaceRecordBase",
    "targets": "TargetRecordBase",
    "target_tag_index": "TargetTagIndexBase",
    "investigations": "InvestigationRecordBase",
    "investigation_messages": "MessageRecordBase",
    "investigation_branches": "BranchRecordBase",
    "investigation_outcomes": "OutcomeRecordBase",
    "outcome_reviews": "OutcomeReviewRecordBase",
    "mcp_call_log": "McpCallLogRecordBase",
    "investigation_targets": "InvestigationTargetRecordBase",
    "patterns": "PatternRecordBase",
    "projects": "ProjectRecordBase",
}

# Platform base class mapped to the *_base.py file under platform/contracts/
# that defines it (two share target_base.py).
_BASE_FILE_BY_CLASS: dict[str, str] = {
    "WorkspaceRecordBase": "workspace_base.py",
    "TargetRecordBase": "target_base.py",
    "TargetTagIndexBase": "target_base.py",
    "InvestigationRecordBase": "investigation_base.py",
    "MessageRecordBase": "message_base.py",
    "BranchRecordBase": "branch_base.py",
    "OutcomeRecordBase": "outcome_base.py",
    "OutcomeReviewRecordBase": "outcome_review_base.py",
    "McpCallLogRecordBase": "mcp_call_log_base.py",
    "InvestigationTargetRecordBase": "investigation_target_base.py",
    "PatternRecordBase": "pattern_base.py",
    "ProjectRecordBase": "project_base.py",
}

# Cache of platform base field-name sets, keyed by (base_file_path, class_name).
_BASE_FIELD_CACHE: dict[tuple[str, str], frozenset[str]] = {}

_CONTRACTS_DIR_PATTERN = _re.compile(r"^(.*/aila)/modules/")

# Rule 38 -- module service files must not be full copies of a platform
# service. Scoped to the vr/malware copy set (forensics keeps an
# independent machine_readiness variant, outside the check).
_SERVICE_COPY_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\](?:vr|malware)[/\\]services[/\\][^/\\]+\.py$"
)
_PLATFORM_SERVICE_SUBDIRS: tuple[str, ...] = ("services", "mcp", "tasks")
_SERVICE_COPY_THRESHOLD: float = 0.75
_SERVICE_CORPUS_CACHE: dict[str, dict[str, str]] = {}


def _platform_service_corpus(filepath: str) -> dict[str, str]:
    """Return {relpath: normalized_source} for every platform service file.

    Reads platform/services, platform/mcp, and platform/tasks so a module
    service copied from any of them is caught. Each source is normalized via
    ast.unparse (comments and formatting removed); cached per aila root.
    """
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return {}
    aila_root = match.group(1)
    cached = _SERVICE_CORPUS_CACHE.get(aila_root)
    if cached is not None:
        return cached
    corpus: dict[str, str] = {}
    for subdir in _PLATFORM_SERVICE_SUBDIRS:
        base = Path(aila_root) / "platform" / subdir
        if not base.is_dir():
            continue
        for py in sorted(base.glob("*.py")):
            if py.name == "__init__.py":
                continue
            try:
                normalized = ast.unparse(ast.parse(py.read_text(encoding="utf-8")))
            except (OSError, SyntaxError, ValueError, RecursionError):
                continue
            corpus[f"{subdir}/{py.name}"] = normalized
    _SERVICE_CORPUS_CACHE[aila_root] = corpus
    return corpus


# Rule 41 -- module workflow-state files must not be full copies of a
# platform workflow-state base. Scoped to the vr/malware investigation
# engine states (setup/loop/emit), which RFC-02 Phase 4 extracted to
# platform/workflows/investigation_*_base.py.
_WORKFLOW_STATE_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\](?:vr|malware)[/\\]workflow[/\\]states[/\\]"
    r"investigation_(?:setup|loop|emit)\.py$"
)
_WORKFLOW_BASE_CORPUS_CACHE: dict[str, dict[str, str]] = {}

# Rule 42 -- module agents/ files must not re-implement a platform agent
# primitive. RFC-03 Phase 1 lifted the operator-intent classifier and the
# auto-steering injector to platform/agents/; Phase 7 lifted the per-turn
# loop (AgentTurnRunnerBase.run_turn) and the case-state codec / terminal
# resolver helpers (aila.platform.agents.turn_helpers). Modules import
# them; a def of a lifted primitive -- whether at module top level or as a
# method redefinition on a class body -- is a copy that drifted back in.
# Import re-exports are Import/ImportFrom statements, not FunctionDefs, so
# they never trip this. A thin subclass ``class VrRunner(AgentTurnRunnerBase):
# pass`` inherits the platform method without defining one, so it stays
# clean; only an actual ``async def run_turn`` in the class body fires.
_AGENTS_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\][^/\\]+[/\\]agents[/\\]"
)
_LIFTED_AGENT_PRIMITIVES: frozenset[str] = frozenset({
    # Phase 1 lifts.
    "maybe_post_auto_steering",
    "classify_intent",
    # Phase 7 turn-runner + turn-helpers lifts.
    "run_turn",
    "decode_case_state",
    "encode_case_state",
    "auto_resolve_live_on_terminal",
    "to_outcome_confidence",
})

# Rule 49 -- agent_env_read. Attribute names on the ``os`` module that
# reach the process environment. RFC-03's config-drift closure removed
# every direct env read from ``modules/*/agents/**``; modules resolve
# config through ``ConfigRegistry(module_id, key)`` so a DB override,
# a per-module schema default, and env can all take turns without a
# hand-coded fork per copy.
_OS_ENV_ATTRS: frozenset[str] = frozenset({"environ", "getenv"})

# Rule 50 -- static_node_mutation. Mutating a WorkflowDefinition.states map
# after construction reopens the node set the dispatch-hub / phase-graph
# substrates freeze so every transition target stays auditable (RFC-13 #68).
_STATES_MUTATOR_METHODS: frozenset[str] = frozenset({
    "update", "pop", "setdefault", "clear", "popitem",
    "__setitem__", "__delitem__",
})

# Rule 51 -- ledger_write_bypass. LedgerService is the sole writer of the
# investigation_ledger table (it owns idempotency + the append-only rule).
_LEDGER_RECORD_NAME = "InvestigationLedgerRecord"
_LEDGER_TABLE_NAME = "investigation_ledger"
_LEDGER_INSERT_CALLABLES: frozenset[str] = frozenset({"insert", "pg_insert"})
_LEDGER_SERVICE_PATH_SUFFIX = "platform/services/ledger.py"

# ---------------------------------------------------------------------------
# RFC-07 rule constants (rules 52-54).
#
# Every RFC-07 rule flips the codebase's failure posture from fail-open
# (silence + permissive default) to fail-closed (surface + conservative
# default). The constants below let a reviewer trace WHY a specific
# function or callsite triggers a rule -- rename any set here and both
# the rule and its tests move at once.
# ---------------------------------------------------------------------------

# Rule 52 -- fail_open_recovery_path. A function whose name signals a
# safety, rate-limit, verify, or recovery contract must not return a
# permissive default from an ``except`` handler; the conservative
# default (a bounded defer, a fail-closed block, a mark-and-block) is
# required. The name markers are matched case-insensitively as
# substrings of the function name so ``verify_response``,
# ``compute_investigation_defer``, ``check_rate_limit``,
# ``run_recovery_pass``, ``synthesize_no_finding_outcomes``, etc all
# match. The markers deliberately capture RFC-07's five documented
# fail-open sites (queue defer, verify gate, pipeline post-call,
# finalizer, SSE emit) plus the class of future paths any of the
# above would grow into.
_RECOVERY_FUNCTION_MARKERS: frozenset[str] = frozenset({
    "verify", "recover", "recovery", "safety",
    "rate_limit", "rate-limit", "ratelimit",
    "compute_defer", "compute_investigation_defer",
    "finalize", "finaliser", "finalizer",
    "heal", "reconcile", "reap", "sweep", "guard",
})

# Rule 52 -- permissive default sentinel set. A return of any of these
# from an ``except`` inside a recovery-marked function is a finding.
# Bare ``return`` (None) is included via the ``val is None`` branch of
# the check; bare ``True`` (permissive boolean) is caught by the
# constant check. Numeric zero (0, 0.0) is fail-open for a rate-limiter
# but not for a heal path returning ``count = 0`` -- the rule
# distinguishes on the function-name marker, not on the value.
_FAIL_OPEN_PERMISSIVE_CONSTANTS: tuple[object, ...] = (
    True, 0, 0.0, "",
)

# Rule 53 -- close_without_infra_classification. A finalizer that closes
# an investigation as a negative outcome without calling
# :class:`InfraDeathClassifier` is a finding. The rule fires on a call
# to a closer name marker inside a finalize-marked function body when
# no ``InfraDeathClassifier`` reference appears in the same function.
_INFRA_CLASSIFIER_NAME: str = "InfraDeathClassifier"
_INFRA_CLASSIFIER_METHODS: frozenset[str] = frozenset({
    "classify", "is_infra_death", "classify_close",
})
_FINALIZER_NAME_MARKERS: frozenset[str] = frozenset({
    "finalize", "finalise",
    "synthesize_no_finding", "synthesise_no_finding",
    "close_investigation", "close_no_finding",
})
_CLOSE_CALLABLE_MARKERS: frozenset[str] = frozenset({
    "close_investigation", "close_no_finding", "finalize_negative",
    "mark_no_finding", "resolve_no_finding", "synthesize_no_finding",
})

# Rule 54 -- heal_without_journal. A recovery function that mutates run
# state (a workflow_state_cursor row, a taskrecord row, an
# arq:in-progress lock) without also writing a recovery event is a
# finding. The journal is the LedgerService append_general call (see
# rule 51) or a ``record_and_check``-style checkpoint. The rule fires
# on a heal-marked function whose body contains a state-mutation
# marker but no journal-write marker.
_HEAL_FUNCTION_MARKERS: frozenset[str] = frozenset({
    "heal", "reconcile", "reroute", "reenqueue", "re_enqueue",
    "downgrade", "failover", "recover_state",
})
_STATE_MUTATION_MARKERS: frozenset[str] = frozenset({
    "set_enabled", "set_status", "flip_status",
    "update_status", "cancel_task", "drop_lock",
    "delete_cursor", "purge_cursor",
    "reenqueue", "re_enqueue",
})
# Journal-write markers: a call to any of these in the heal function's
# body clears the finding. Kept intentionally short because a heal
# path that does NOT record its action is the exact anti-pattern the
# rule locks in; a valid heal spends one line on the journal.
_JOURNAL_WRITE_MARKERS: frozenset[str] = frozenset({
    "append_general", "append_ledger", "record_recovery",
    "record_healed", "record_signal", "record_and_check",
    "emit_recovery_event", "log_recovery",
})
# Files exempt from rule 54 because they ARE the journal implementation
# (LedgerService itself) or the recovery-event emitter -- writing the
# journal without also calling the journal would be circular.
_JOURNAL_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "platform/services/ledger.py",
    "platform/services/resilience.py",
    "platform/events/domain_events.py",
    "platform/events/emitter.py",
    "platform/llm/drift.py",
    # The reconciler helper file owns the mutation primitives (delete
    # cursor, flip status, drop lock) that the actual reconcile
    # dispatch composes -- the helpers write the journal via their
    # callers, not themselves.
    "platform/tasks/state_reconciler.py",
    "platform/tasks/cursor_reaper.py",
    "platform/tasks/worker.py",
    "platform/tasks/queue.py",
    "platform/tasks/storage.py",
)

# ---------------------------------------------------------------------------
# RFC-08 / RFC-09 / RFC-10 rule constants (rules 55-63).
#
# Every rule below locks in a review-gated write path so agent turns +
# operator commands cannot short-circuit a promotion / audit / journal
# invariant by writing the underlying row directly. Renaming a marker
# set here moves both the rule and its tests at once.
# ---------------------------------------------------------------------------

# Rule 55 -- ungated_self_improvement_write. Method names on a
# PatternStore-shaped receiver that constitute a write; ``.create`` is
# the canonical entry point but ``.add`` / ``.insert`` / ``.bulk_create``
# / ``.record`` are all shapes a future subclass may expose. The
# receiver-name markers match any dotted-attribute tail (Name.id or
# Attribute.attr) that ends in a ``pattern_store``-family token so
# ``self.pattern_store.create(...)`` / ``self._pattern_store.create(...)``
# / ``store.create(...)`` (when ``store`` was bound from a
# ``pattern_store``-typed attribute) all trigger the check while a
# bare ``kb.create(...)`` on the KnowledgeService does not.
_PATTERN_STORE_WRITE_METHODS: frozenset[str] = frozenset({
    "create", "add", "insert", "bulk_create", "record",
})
_PATTERN_STORE_RECEIVER_TOKENS: tuple[str, ...] = (
    "pattern_store", "_pattern_store",
)
# Files that OWN a pattern-store write path and legitimately call
# ``.create(...)`` directly on the store instance: :class:`ExperienceWriter`
# (the only reviewed-verdict-gated writer) and the store implementation
# files themselves. Everything else must go through ExperienceWriter.
_PATTERN_STORE_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "platform/eval/experience_writer.py",
    "platform/services/pattern_store.py",
    "modules/vr/services/pattern_store.py",
    "modules/malware/services/pattern_store.py",
    "modules/forensics/services/pattern_store.py",
)

# Rule 56 -- self_labeled_reward. Kwarg / attribute names that carry a
# self-labelled promotion signal. An agent turn is the model output;
# the RFC-08 gate consumes only reviewer-produced signals, so an
# agent that sets its own ``reward=`` / ``self_score=`` field short-
# circuits the gate. Confidence / probability signals the LLM emits
# for its own reasoning are not in this set; the names below are the
# specific promotion-input shapes RFC-08 forbids.
_SELF_LABELED_REWARD_NAMES: frozenset[str] = frozenset({
    "reward",
    "self_reward",
    "self_score",
    "agent_score",
    "promotion_score",
    "promotion_reward",
    "self_labeled_reward",
    "self_labeled_score",
})
# Scope: any file under ``platform/agents/`` OR ``modules/*/agents/``.
# Test fixtures + eval-harness code that scores an agent for research
# purposes live outside these paths and are correctly out of scope.
_AGENT_RUNTIME_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\](?:platform[/\\]agents|modules[/\\][^/\\]+[/\\]agents)[/\\]"
)

# Rule 57 -- unversioned_config_promotion. Substring tokens marking a
# threshold-shaped ConfigRegistry key. A ``.set("<key>", value)`` call
# whose key literal contains any of these tokens must run inside a
# function body that also references CalibrationProposalRecord /
# CalibrationProposer -- RFC-08's contract is that a threshold only
# ever moves behind a versioned proposal row.
_THRESHOLD_KEY_TOKENS: tuple[str, ...] = (
    "threshold", "ceiling", "min_sample", "cutoff", "calibration",
)
_CALIBRATION_JOURNAL_MARKERS: frozenset[str] = frozenset({
    "CalibrationProposalRecord",
    "CalibrationProposer",
    "CalibrationProposal",
})
_CALIBRATION_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "platform/eval/calibration.py",
    "tools/honesty_audit.py",
)

# Rule 58 -- inline_prompt_literal. A module-level assign whose target
# name contains the ``PROMPT`` uppercase token (``_SYSTEM_PROMPT``,
# ``_EXTRACTOR_SYSTEM_PROMPT``, ``_PROMPT_TEMPLATE``, ...) whose value
# is a multi-line string constant fires. RFC-09 requires the prompt
# text to live in a versioned ``.md`` file resolved through
# :class:`PromptRegistry`; the length + newline floors below prevent
# short single-purpose messages (a JSON schema hint, an error preamble)
# from tripping the rule.
_INLINE_PROMPT_NAME_TOKEN: str = "PROMPT"
_INLINE_PROMPT_MIN_NEWLINES: int = 3
_INLINE_PROMPT_MIN_LENGTH: int = 200
_INLINE_PROMPT_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "tools/honesty_audit.py",
)

# Rule 59 -- untagged_llm_call. Method-name markers for the three LLM
# entry points and the identifier markers whose presence in the
# enclosing function's body proves the call is tagged. A file that
# defines / calls the raw entry point (the client itself, the
# idempotent wrapper, the routing agents whose calls carry no prompt
# version by design) is exempted.
_LLM_CHAT_METHODS: frozenset[str] = frozenset({
    "chat", "chat_json", "chat_structured",
})
_LLM_TAG_MARKERS: frozenset[str] = frozenset({
    "correlation_scope",
    "prompt_content_hash",
    "prompt_version",
    "idempotent_llm_call",
    "current_prompt_content_hash",
    "current_prompt_version",
})
_LLM_TAG_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    # The client owns the underlying transport, its sync-CLI wrappers
    # forward to the async .chat() method, and it also defines schema-
    # hint messages that are not prompts.
    "platform/llm/client.py",
    # The idempotent wrapper IS the tag stamp.
    "platform/agents/idempotent_llm.py",
    # Routing calls (task-type classifier + model router) have no
    # investigation-scoped prompt version -- they carry only the
    # routing prompt string built inline, not a per-investigation
    # prompt from the version store.
    "platform/routing/agent.py",
    "platform/routing/router.py",
    "platform/modules/platform.py",
    # CyberReasoningEngine.decide_next_turn is a platform delegate
    # wrapped by its callers (forensics/investigator.py,
    # vr/agents/vuln_researcher.py) in ``correlation_scope(...)`` --
    # the ContextVar carries the tag stamp through the delegate, and
    # the reasoning file itself has no visibility into the resolved
    # prompt version.
    "platform/services/reasoning.py",
    # This file self-references the markers in its own rule strings.
    "tools/honesty_audit.py",
)

# Rule 60 -- unaudited_alias_flip. PromptAliasRecord is the mutable
# pointer; PromptAliasChangeRecord is the append-only audit row. A
# function that inserts / updates one without the other has drifted
# from PromptVersionStore.set_alias() and reopens the alias table's
# audit gap RFC-09 closed. The version_store file itself owns the
# canonical pair-write; alembic migrations and this file's rule
# strings are also exempt.
_PROMPT_ALIAS_RECORD_NAME: str = "PromptAliasRecord"
_PROMPT_ALIAS_CHANGE_RECORD_NAME: str = "PromptAliasChangeRecord"
_PROMPT_ALIAS_TABLE_NAME: str = "prompt_aliases"
_ALIAS_FLIP_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "platform/prompts/version_store.py",
    "tools/honesty_audit.py",
)

# Rule 61 -- promotion_without_gate. Identifier markers whose presence
# in a function that flips a version to production clears the rule. A
# body that constructs ``LifecycleTransitionRecord(to_stage=...
# .PRODUCTION)`` or calls ``set_alias(<key>, "production", ...)``
# without any gate marker is promoting without the eval + quorum guard
# the RFC-10 controller enforces. ``EvalRunner`` alone counts as a
# gate because its ``auto_promote`` path only flips the alias after
# the run's ``verdict == 'pass'`` check.
_PROMOTE_GATE_MARKERS: frozenset[str] = frozenset({
    "_passing_evaluate",
    "_distinct_approver_count",
    "EvalRunner",
    "agent_promotion_quorum",
    "AgentLifecycleController",
})
_PRODUCTION_STAGE_LITERAL: str = "production"
_LIFECYCLE_STAGE_NAME: str = "LifecycleStage"
_LIFECYCLE_TRANSITION_RECORD_NAME: str = "LifecycleTransitionRecord"
_LIFECYCLE_JOURNAL_METHOD_NAME: str = "_journal"
_LIFECYCLE_STAGE_KWARGS: frozenset[str] = frozenset({
    "stage", "to_stage", "lifecycle_stage", "new_stage",
})
_LIFECYCLE_CONTROLLER_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "platform/lifecycle/controller.py",
    # EvalRunner.run(auto_promote=True) flips the alias behind the
    # run's own eval verdict; the check IS the gate on that path.
    "platform/eval/runner.py",
    "tools/honesty_audit.py",
)

# Rule 63 -- canary_below_min_sample. Function-name markers that
# identify a canary promotion path and the identifier / call markers
# whose presence in the body clears the rule. The check is looser
# than a config-key match: any identifier or method call whose name
# is one of the min-sample terms counts because it proves the code
# path reasons about a sample count before flipping.
_CANARY_PROMOTE_MARKERS: frozenset[str] = frozenset({
    "promote_from_canary", "promote_canary", "flip_canary",
})
_CANARY_MIN_SAMPLE_MARKERS: frozenset[str] = frozenset({
    "min_sample",
    "min_samples",
    "min_canary_sample",
    "canary_min_sample",
    "agent_canary_min_sample",
    "sample_count",
    "signal_count",
})


def _function_name_matches(name: str, markers: frozenset[str]) -> bool:
    """Return True when any marker appears as a substring of ``name`` (case-insensitive).

    Shared by rules 52-54 so the three name-marker checks agree on
    matching semantics; a rename in one marker set never accidentally
    changes matching for a sibling rule.
    """
    low = name.lower()
    return any(marker in low for marker in markers)


def _call_names_in_body(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return the simple call-callee name set (Name.id or Attribute.attr) for the function body.

    Rules 53 and 54 use this to check for the presence of a specific
    call inside a function's body (an ``InfraDeathClassifier.classify``
    for rule 53, a journal-write for rule 54). Walks the body only --
    decorators and default values do not count.
    """
    names: set[str] = set()
    for stmt in func.body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            callee = node.func
            if isinstance(callee, ast.Name):
                names.add(callee.id)
            elif isinstance(callee, ast.Attribute):
                names.add(callee.attr)
    return names


def _identifier_names_in_body(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Return every Name.id and Attribute.attr appearing in the function body.

    Rule 53 uses this to detect an ``InfraDeathClassifier`` reference
    anywhere in the finalizer body -- an instance passed via ``self``
    or bound at construction still counts as "the classifier was
    consulted" so a legitimate finalizer that owns a classifier field
    does not trip the rule.
    """
    ids: set[str] = set()
    for stmt in func.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name):
                ids.add(node.id)
            elif isinstance(node, ast.Attribute):
                ids.add(node.attr)
    return ids



def _line_parses_as_python_statement(line: str) -> bool:
    """Return True when the un-commented text of *line* is real code.

    Rule 25's second-pass filter: strip the leading whitespace + ``#``
    from the comment, then try to :func:`ast.parse` the remainder as
    a module. Prose that starts with a Python keyword (``# for the
    coroutine``, ``# from its call site.``) fails to parse and is
    NOT flagged; a real commented-out statement (``# import os``,
    ``# for x in xs:``, ``# return None``) parses cleanly and IS.

    Two extra guards remove common English shapes the parser would
    otherwise accept: a single Name / Constant expression (a bare
    word or number) never counts as "code" -- ``# note`` shouldn't
    fire -- and text ending with a sentence period without a
    trailing closing paren / colon / bracket is prose. Together the
    two guards eliminate the false positives the first-pass regex
    surfaces on doc comments.
    """
    stripped = line.lstrip()
    if not stripped.startswith("#"):
        return False
    inner = stripped[1:].lstrip()
    if not inner:
        return False
    # Prose sentences (end with a period, no closing structural punctuation)
    # are the dominant false-positive shape; skip them early.
    if (
        inner.endswith(".")
        and not inner.endswith(("..", ").", "]", "}"))
    ):
        return False
    try:
        parsed = ast.parse(inner)
    except SyntaxError:
        return False
    if not parsed.body:
        return False
    if len(parsed.body) != 1:
        return True
    stmt = parsed.body[0]
    # A bare Expression whose value is just a Name / Constant is a
    # single-word comment, not code. ``# for x in xs:`` parses as a
    # For with body -> the Constant guard does not fire.
    if isinstance(stmt, ast.Expr) and isinstance(
        stmt.value, (ast.Name, ast.Constant),
    ):
        return False
    return True


def _pattern_store_receiver_tail(node: ast.expr) -> str | None:
    """Return the receiver's terminal name when it names a pattern-store.

    Rule 55 uses this to detect a ``.create(...)`` call whose receiver's
    dotted-attribute tail is a pattern-store binding. ``.pattern_store``
    / ``._pattern_store`` on an object (``self.pattern_store.create``,
    ``services._pattern_store.create``) all match. A bare
    ``pattern_store.create(...)`` where ``pattern_store`` is a local
    variable also matches by Name.id. Returns the matched terminal name
    for the diagnostic message, or ``None`` when the receiver is not a
    pattern-store shape.
    """
    if isinstance(node, ast.Name):
        return node.id if node.id in _PATTERN_STORE_RECEIVER_TOKENS else None
    if isinstance(node, ast.Attribute):
        return node.attr if node.attr in _PATTERN_STORE_RECEIVER_TOKENS else None
    return None


def _string_constant_value(node: ast.expr | None) -> str | None:
    """Return the string value of a Constant node, else None.

    Rules 58 / 60 use this to inspect a string literal after Python's
    parser has folded any implicit concatenation. In Python 3.11+ a
    parenthesised ``("foo\n" "bar\n" "baz\n")`` is a single
    ast.Constant whose value is the concatenated string, so the check
    matches both triple-quoted and paren-concat prompt bodies without
    a special JoinedStr traversal.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _references_lifecycle_stage(node: ast.expr | None) -> bool:
    """Return True when *node* names a ``LifecycleStage.<X>`` member.

    Rule 62 uses this to distinguish a genuine stage assignment (``.
    lifecycle_stage = LifecycleStage.PRODUCTION`` or ``to_stage=Lifec
    ycleStage.PRODUCTION.value``) from an incidental attribute access
    (``record.to_stage``, a router response that reads the field back
    from a DB row). Matches ``LifecycleStage.PRODUCTION``,
    ``LifecycleStage.PRODUCTION.value``, and the imported-shortname
    ``PRODUCTION`` when the source has ``from aila.platform.lifecycle.
    models import LifecycleStage``.
    """
    if node is None:
        return False
    if isinstance(node, ast.Attribute):
        # ``LifecycleStage.PRODUCTION`` -- value is Name(LifecycleStage).
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == _LIFECYCLE_STAGE_NAME
        ):
            return True
        # ``LifecycleStage.PRODUCTION.value`` -- one level deeper.
        return _references_lifecycle_stage(node.value)
    return False


def _call_callee_simple_name(node: ast.Call) -> str | None:
    """Return the callee's simple name (Name.id or Attribute.attr).

    Rule 62 uses this to skip the ``LifecycleTransitionRecord(...)``
    constructor call and the ``._journal(...)`` method call when
    counting stage writes -- those two ARE the journal, so a kwarg
    ``to_stage=LifecycleStage.PRODUCTION`` on them is the row being
    written, not a bypass.
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _is_production_alias_flip(node: ast.Call) -> bool:
    """Return True when a call flips the production alias.

    Matches either ``<x>.set_alias(<key>, "production", ...)`` (second
    positional arg is the literal alias name) OR the same call with
    an ``alias="production"`` kwarg. Rule 61 treats either shape as a
    production write that must sit behind the eval + quorum gate.
    """
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "set_alias":
        return False
    # Second positional arg (alias)
    if len(node.args) >= 2:
        alias_arg = node.args[1]
        if (
            isinstance(alias_arg, ast.Constant)
            and alias_arg.value == _PRODUCTION_STAGE_LITERAL
        ):
            return True
    for kw in node.keywords:
        if (
            kw.arg == "alias"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value == _PRODUCTION_STAGE_LITERAL
        ):
            return True
    return False


def _is_production_transition_construct(node: ast.Call) -> bool:
    """Return True when a call builds a LifecycleTransitionRecord to production.

    Matches ``LifecycleTransitionRecord(..., to_stage=<PRODUCTION>, ...)``
    where the kwarg value is either ``LifecycleStage.PRODUCTION`` /
    ``LifecycleStage.PRODUCTION.value`` or the literal string
    ``"production"``. Rule 61 uses this alongside
    :func:`_is_production_alias_flip` to detect every shape of
    production write.
    """
    callee = _call_callee_simple_name(node)
    if callee != _LIFECYCLE_TRANSITION_RECORD_NAME:
        return False
    for kw in node.keywords:
        if kw.arg != "to_stage":
            continue
        if isinstance(kw.value, ast.Constant) and kw.value.value == _PRODUCTION_STAGE_LITERAL:
            return True
        if _references_lifecycle_stage(kw.value):
            # Only fire when the specific member is PRODUCTION.
            root = kw.value
            while isinstance(root, ast.Attribute) and root.attr == "value":
                root = root.value
            if (
                isinstance(root, ast.Attribute)
                and root.attr == _PRODUCTION_STAGE_LITERAL.upper()
            ):
                return True
    return False


def _build_parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    """Return ``{id(child): parent_node}`` for the entire tree.

    Rules 59 (untagged_llm_call) and 60 (unaudited_alias_flip) need
    to answer "what function contains this node?" without carrying a
    stack through every visitor call. The parent map is cheap on the
    parse of one file and lets both rules use
    :func:`_enclosing_function` uniformly.
    """
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _enclosing_function(
    node: ast.AST, parents: dict[int, ast.AST],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the innermost ``def`` / ``async def`` enclosing *node*.

    Walks up through the parent map until a function definition is
    found. Returns None when the node lives at module level (a
    module-level chat call, for example, would not have a function
    scope to check for tag markers -- treated as unscoped and
    intentionally not flagged by rule 59).
    """
    cur = parents.get(id(node))
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(id(cur))
    return None


def _workflow_base_corpus(filepath: str) -> dict[str, str]:
    """Return {relpath: normalized_source} for platform workflow-state bases.

    Reads platform/workflows/investigation_*_base.py so a module state
    file copied back from a platform base is caught. Normalized via
    ast.unparse; cached per aila root.
    """
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return {}
    aila_root = match.group(1)
    cached = _WORKFLOW_BASE_CORPUS_CACHE.get(aila_root)
    if cached is not None:
        return cached
    corpus: dict[str, str] = {}
    base = Path(aila_root) / "platform" / "workflows"
    if base.is_dir():
        for py in sorted(base.glob("investigation_*_base.py")):
            try:
                normalized = ast.unparse(
                    ast.parse(py.read_text(encoding="utf-8")),
                )
            except (OSError, SyntaxError, ValueError, RecursionError):
                continue
            corpus[f"workflows/{py.name}"] = normalized
    _WORKFLOW_BASE_CORPUS_CACHE[aila_root] = corpus
    return corpus


def _classdef_is_table(node: ast.ClassDef) -> bool:
    """Return True when a class is declared with the SQLModel table=True flag."""
    for kw in node.keywords:
        if kw.arg == "table" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _classdef_tablename(node: ast.ClassDef) -> str | None:
    """Return the literal __tablename__ string assigned in a class body, or None."""
    for stmt in node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        value = stmt.value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name) and target.id == "__tablename__":
                return value.value
    return None


def _classdef_base_names(node: ast.ClassDef) -> set[str]:
    """Return the simple names of a class's declared bases."""
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def _sqlmodel_field_names(node: ast.ClassDef) -> set[str]:
    """Return the annotated (non-dunder) field names declared directly on a class."""
    names: set[str] = set()
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            field = stmt.target.id
            if not field.startswith("__"):
                names.add(field)
    return names


def _unique_constraint_literal_names(node: ast.ClassDef):
    """Yield (literal_name, lineno) for each UniqueConstraint(name=<str>) in the class body."""
    for stmt in node.body:
        if not (isinstance(stmt, ast.Assign) and _assigns_table_args(stmt)):
            continue
        for call in ast.walk(stmt.value):
            if not isinstance(call, ast.Call):
                continue
            callee = call.func
            is_uq = (isinstance(callee, ast.Name) and callee.id == "UniqueConstraint") or (
                isinstance(callee, ast.Attribute) and callee.attr == "UniqueConstraint"
            )
            if not is_uq:
                continue
            for kw in call.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    yield kw.value.value, call.lineno


def _assigns_table_args(stmt: ast.Assign) -> bool:
    """Return True when an assignment targets __table_args__."""
    return any(isinstance(t, ast.Name) and t.id == "__table_args__" for t in stmt.targets)


def _strip_module_prefix(tablename: str, module_id: str) -> str:
    """Return the table role: the tablename with a leading '<module_id>_' removed."""
    prefix = f"{module_id}_"
    return tablename[len(prefix):] if tablename.startswith(prefix) else tablename


def _platform_contracts_dir(filepath: str) -> Path | None:
    """Resolve the platform/contracts directory from a module file path, or None."""
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return None
    return Path(match.group(1)) / "platform" / "contracts"


# Rule 44 -- private_platform_import. Cache of a platform package's public
# name set (its __init__.py __all__ members plus names bound by relative
# re-export imports), keyed by the __init__.py path.
_PLATFORM_PUBLIC_EXPORTS_CACHE: dict[str, frozenset[str]] = {}


def _aila_root_from_module(filepath: str) -> Path | None:
    """Resolve the aila package root from a module file path, or None."""
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return None
    return Path(match.group(1))


def _platform_public_exports(init_path: Path) -> frozenset[str]:
    """Return the public names published by a platform package.

    A name is public when the package's ``__init__.py`` lists it in ``__all__``
    or binds it via a relative re-export (``from ._x import Name``). Read via
    AST and cached. Any read/parse failure yields an empty set so the caller
    skips defensively rather than raising inside the gate.
    """
    key = str(init_path)
    cached = _PLATFORM_PUBLIC_EXPORTS_CACHE.get(key)
    if cached is not None:
        return cached
    names: set[str] = set()
    try:
        tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=key)
    except (OSError, SyntaxError):
        result = frozenset(names)
        _PLATFORM_PUBLIC_EXPORTS_CACHE[key] = result
        return result
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level and node.names:
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)
            continue
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
            continue
        value = node.value
        if isinstance(value, (ast.List, ast.Tuple)):
            for elt in value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    names.add(elt.value)
    result = frozenset(names)
    _PLATFORM_PUBLIC_EXPORTS_CACHE[key] = result
    return result


def _platform_base_field_names(base_file: Path, base_class: str) -> frozenset[str]:
    """Return the field-name set of a platform base class, read via AST and cached.

    Returns an empty set when the file or class cannot be resolved so the caller
    skips defensively rather than raising inside the gate.
    """
    cache_key = (str(base_file), base_class)
    cached = _BASE_FIELD_CACHE.get(cache_key)
    if cached is not None:
        return cached
    result: frozenset[str] = frozenset()
    try:
        tree = ast.parse(base_file.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        _BASE_FIELD_CACHE[cache_key] = result
        return result
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == base_class:
            result = frozenset(_sqlmodel_field_names(node))
            break
    _BASE_FIELD_CACHE[cache_key] = result
    return result


# ---------------------------------------------------------------------------
# Main auditor class
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# RFC-12 knowledge-base guardrails (rules 64-67).
#
# The knowledge base must have ONE embedding path, provenance on every
# stored vector, a relevance-floored + sanitize/classify gated retrieval on
# the agent surface, and the gate permanently wired into the routed retrieval
# entry point. Each rule self-exempts or scopes to the surface it locks in.
# ---------------------------------------------------------------------------

# Rule 64 -- second_embedding_path. An embedding provider constructed or
# selected outside the canonical embedding + knowledge service files means a
# second model can write vectors into the shared table, making cross-model
# cosine similarity meaningless (#37).
_EMBEDDING_PROVIDER_CALLEES: frozenset[str] = frozenset({
    "resolve_provider", "get_embedding_provider",
    "BGEProvider", "MiniLMProvider", "SentenceTransformer",
})
_EMBEDDING_PATH_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "platform/services/embedding.py",
    "platform/services/knowledge.py",
)

# Rule 65 -- vector_without_provenance. A KnowledgeEntryRecord constructed
# with an embedding but no model_id stores a vector that a later model swap
# silently invalidates with no detection or re-embed trigger (#37).
_KNOWLEDGE_RECORD_NAME: str = "KnowledgeEntryRecord"

# Rule 66 -- retrieval_without_gate. Agent-scope code must retrieve through
# retrieve_routed (which applies the relevance floor + sanitize/classify
# gate), not the raw hybrid retrieve which returns ungated, unfloored hits.
_RAW_RETRIEVE_METHOD: str = "retrieve"
_ROUTED_RETRIEVE_METHOD: str = "retrieve_routed"

# Rule 67 -- unsanitized_retrieved_content. The routed retrieval entry point
# must keep applying the gate; a retrieve_routed body that stops calling
# apply_gate would return raw content into a prompt (#43).
_KNOWLEDGE_GATE_CALLS: frozenset[str] = frozenset({"apply_gate", "apply_gate_many"})


class _HonestyVisitor(ast.NodeVisitor):
    """AST visitor that accumulates Finding objects."""

    def _emit(self, line: int, rule: str, message: str) -> None:
        finding = Finding(file=self.filename, line=line, rule=rule, message=message)
        if not self._is_whitelisted(finding):
            self.findings.append(finding)

    def _is_whitelisted(self, finding: Finding) -> bool:
        # Normalize to forward slashes for cross-platform suffix matching.
        normalized_file = finding.file.replace("\\", "/")
        for suffix, func_name, detail in self.whitelist:
            normalized_suffix = suffix.replace("\\", "/")
            if (
                normalized_file.endswith(normalized_suffix)
                and func_name in finding.message
                and detail in finding.message
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Visitor entry points
    # ------------------------------------------------------------------

    def __init__(self, filename: str, whitelist: Whitelist) -> None:
        self.filename = filename
        self.whitelist = whitelist
        self.findings: list[Finding] = []
        self._in_protocol_class: bool = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Detect Protocol classes -- skip their methods for unused_parameter
        is_protocol = any(
            (isinstance(b, ast.Name) and b.id == "Protocol")
            or (isinstance(b, ast.Attribute) and b.attr == "Protocol")
            for b in node.bases
        )
        old = self._in_protocol_class
        if is_protocol:
            self._in_protocol_class = True
        self.generic_visit(node)
        self._in_protocol_class = old

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

    def _check_function(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        self._check_unused_parameter(func)
        self._check_misleading_name(func)
        self._check_docstring_mismatch(func)
        self._check_dead_isinstance(func)
        self._check_god_object_dispatch(func)
        self._check_do_nothing_wrapper(func)

    def _check_unused_parameter(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: unused_parameter."""
        # Skip stubs -- Protocol/ABC abstract bodies.
        if _is_stub_body(func) or _has_stub_decorator(func):
            return
        # Skip Protocol class methods -- they define interfaces, not implementations.
        if self._in_protocol_class:
            return

        params = _param_names(func)
        if not params:
            return

        body_names = _collect_body_names(func)
        for param in params:
            if param in body_names:
                continue
            if _parameter_is_framework_used(func, param):
                continue
            self._emit(
                func.lineno,
                "unused_parameter",
                f"function '{func.name}' has unused parameter '{param}'",
            )

    def _check_misleading_name(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Rule: misleading_name."""
        name_lower = func.name.lower()
        if not any(kw in name_lower for kw in _MISLEADING_NAME_KEYWORDS):
            return

        if _is_forward_call_body(func):
            self._emit(
                func.lineno,
                "misleading_name",
                (
                    f"function '{func.name}' name implies intelligent logic "
                    f"but body only forwards the call"
                ),
            )

    def _check_docstring_mismatch(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: docstring_mismatch."""
        docstring = _get_docstring(func)
        if docstring is None:
            return
        if not _docstring_claims_caching(docstring):
            return
        if _body_has_cache_impl(func):
            return

        self._emit(
            func.lineno,
            "docstring_mismatch",
            (
                f"function '{func.name}' docstring claims caching/persistence "
                f"but body has no caching implementation"
            ),
        )

    def _check_dead_isinstance(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: dead_isinstance -- isinstance check on a typed parameter."""
        # Build a map of param_name → annotation_type_name
        typed_params: dict[str, str] = {}
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            if arg.annotation and isinstance(arg.annotation, ast.Name) and arg.annotation.id in _TYPED_BUILTINS:
                typed_params[arg.arg] = arg.annotation.id

        if not typed_params:
            return

        for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != "isinstance":
                continue
            if len(node.args) < 2:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in typed_params:
                self._emit(
                    node.lineno,
                    "dead_isinstance",
                    f"function '{func.name}' checks isinstance({first_arg.id}, ...) "
                    f"but '{first_arg.id}' is already annotated as '{typed_params[first_arg.id]}'",
                )

    def _check_god_object_dispatch(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: god_object_dispatch -- 4+ if/elif branches on an action string parameter."""
        # Check if any parameter has an action-like name
        action_params = set()
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            if arg.arg in _ACTION_PARAM_NAMES:
                action_params.add(arg.arg)

        if not action_params:
            return

        # Count if/elif branches that compare the action param
        branch_count = 0
        for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
            if isinstance(node, ast.Compare):
                # Check if left side is the action param
                if isinstance(node.left, ast.Name) and node.left.id in action_params:
                    branch_count += 1
                # Check normalized_action pattern
                for name_node in ast.walk(node):
                    if (
                        isinstance(name_node, ast.Name)
                        and "action" in name_node.id.lower()
                        and any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in node.comparators)
                    ):
                        branch_count += 1
                        break

        # CRUD tools (upsert/list/get/delete on one resource) are acceptable
        # at 3-5 branches. Flag only when branches exceed 6 -- indicating
        # multiple unrelated concerns in one tool, not standard CRUD.
        if branch_count >= 7:
            self._emit(
                func.lineno,
                "god_object_dispatch",
                f"function '{func.name}' has {branch_count} action-dispatch branches -- "
                f"consider splitting into separate single-concern tools",
            )

    def _check_private_in_all(self, tree: ast.Module) -> None:
        """Rule: private_in_all -- underscore-prefixed name in __all__."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name) or target.id != "__all__":
                    continue
                if not isinstance(node.value, (ast.List, ast.Tuple)):
                    continue
                for elt in node.value.elts:
                    if (
                        isinstance(elt, ast.Constant)
                        and isinstance(elt.value, str)
                        and elt.value.startswith("_")
                    ):
                        self._emit(
                            elt.lineno if hasattr(elt, "lineno") else node.lineno,
                            "private_in_all",
                            f"'__all__' exports private name '{elt.value}' \u2014 "
                            "underscore prefix contradicts public API declaration",
                        )

    def _check_bare_exception_wrap(self, tree: ast.Module) -> None:
        """Rule: bare_exception_wrap -- except Exception that raises a less-specific type."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            # Only flag broad 'except Exception' catches
            if node.type is None:
                continue
            if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
                continue
            # Check if the handler body raises RuntimeError (destroys type info)
            for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if (
                    isinstance(stmt, ast.Raise)
                    and stmt.exc is not None
                    and isinstance(stmt.exc, ast.Call)
                    and isinstance(stmt.exc.func, ast.Name)
                    and stmt.exc.func.id == "RuntimeError"
                ):
                    self._emit(
                        node.lineno,
                        "bare_exception_wrap",
                        "'except Exception' catches typed errors then raises "
                        "RuntimeError \u2014 original exception type is destroyed",
                    )
                    break

    def _check_todo_in_code(self, source: str) -> None:
        """Rule: todo_in_code -- TODO/FIXME/HACK/XXX in production source.

        Scans raw source lines for comment markers.  A TODO is a promise
        embedded in code that nobody tracks -- either do the work or file
        an issue and delete the comment.
        """
        for lineno, line in enumerate(source.splitlines(), start=1):
            match = _TODO_PATTERN.search(line)
            if match:
                tag = match.group(1).upper()
                self._emit(
                    lineno,
                    "todo_in_code",
                    f"'{tag}' comment found -- either resolve it or track it in an issue",
                )

    def _check_silent_exception(self, tree: ast.Module) -> None:
        """Rule: silent_exception -- except Exception with pass or bare assignment, no logging.

        Catches the pattern where an exception is swallowed silently:
        ``except Exception: pass`` or ``except Exception: x = {}``.
        If the handler body references any logging identifier, it is not silent.
        Finalizer methods (__del__) are excluded -- silent cleanup is standard there.
        """
        # Build a set of line ranges for __del__ methods -- silent cleanup is standard there.
        del_ranges: set[range] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__del__":
                del_ranges.add(range(node.lineno, node.end_lineno + 1 if node.end_lineno else node.lineno + 50))

        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                continue
            if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
                continue

            # Skip if inside a __del__ method
            if any(node.lineno in r for r in del_ranges):
                continue

            body = node.body
            if not body:
                continue

            body_ids: set[str] = set()
            for child in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(child, ast.Name):
                    body_ids.add(child.id)
                elif isinstance(child, ast.Attribute):
                    body_ids.add(child.attr)

            if body_ids & _LOGGING_IDENTIFIERS:
                continue  # has logging -- not silent

            # Check for raise -- if it re-raises, it's not silent
            has_raise = any(isinstance(s, ast.Raise) for s in body)
            if has_raise:
                continue

            # Check if the body is trivially silent: pass, or single assignment
            is_silent = False
            if len(body) == 1:
                stmt = body[0]
                if isinstance(stmt, ast.Pass):
                    is_silent = True
                elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, (ast.Dict, ast.List, ast.Constant)):
                    # bare default assignment like `x = {}` or `x = []` or `x = None`
                    is_silent = True

            if is_silent:
                self._emit(
                    node.lineno,
                    "silent_exception",
                    "'except Exception' silently swallows errors with no logging or re-raise",
                )

    def _check_production_assert(self, tree: ast.Module) -> None:
        """Rule: production_assert -- assert in non-test code.

        ``assert`` statements are stripped when Python runs with ``-O``.
        Production invariants must use explicit ``if not x: raise`` instead.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                self._emit(
                    node.lineno,
                    "production_assert",
                    "'assert' in production code -- stripped under python -O, use explicit raise",
                )

    def _check_do_nothing_wrapper(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: do_nothing_wrapper -- function body is a single return of a call.

        Flags functions whose entire body (excluding docstring) is
        ``return some_function(args)`` where the function adds no validation,
        transformation, or error handling.  These can be inlined at call sites.

        Excluded:
        - Dunder methods and framework contracts (forward, handle, run, _execute).
        - Private helpers (underscore prefix) -- internal delegation is fine.
        - Named accessors/factories under 4 statements (to_payload, create_*, get_*).
        - Property-style accessors (modules, tools, keys, etc.).
        """
        # Skip framework-contract and dunder method names
        if func.name in {
            "forward", "forward_trusted", "handle", "run", "_execute",
            "__init__", "__del__", "__enter__", "__exit__", "format",
        }:
            return

        # Skip private helpers -- internal delegation is a valid pattern
        if func.name.startswith("_"):
            return

        # Skip named accessors, factories, and serialization helpers
        _accessor_prefixes = ("get_", "create_", "build_", "to_", "from_", "is_", "has_")
        if any(func.name.startswith(p) for p in _accessor_prefixes):
            return

        # Skip property-style collection accessors and named domain helpers
        _collection_accessors = {
            "modules", "tools", "keys", "values", "items", "entries",
            "utc_now", "minimum_score", "all_tool_keys", "arrivals",
            "departures", "order_group", "criticality_rank",
        }
        if func.name in _collection_accessors:
            return

        if "property" in _decorator_identifiers(func):
            return

        stmts = func.body
        if not stmts:
            return

        # Strip leading docstring
        real_stmts = stmts
        if (
            len(stmts) >= 1
            and isinstance(stmts[0], ast.Expr)
            and isinstance(stmts[0].value, ast.Constant)
            and isinstance(stmts[0].value.value, str)
        ):
            real_stmts = stmts[1:]

        if len(real_stmts) != 1:
            return

        stmt = real_stmts[0]
        if not isinstance(stmt, ast.Return) or stmt.value is None:
            return
        if not isinstance(stmt.value, ast.Call):
            return

        # The return value is a single function call -- this is a do-nothing wrapper
        # Get the callee name for the message
        callee = stmt.value.func
        if isinstance(callee, ast.Attribute):
            callee_name = callee.attr
        elif isinstance(callee, ast.Name):
            callee_name = callee.id
        else:
            callee_name = "?"

        self._emit(
            func.lineno,
            "do_nothing_wrapper",
            f"function '{func.name}' body is just 'return {callee_name}(...)' -- "
            f"consider inlining at call sites",
        )

    def _check_sync_session_in_async(self, tree: ast.Module) -> None:
        """Rule: sync_in_async -- session_scope() called directly in async def.

        The correct pattern is to define a sync inner function that uses
        session_scope(), then pass it to asyncio.to_thread().  Calling
        session_scope() directly inside an async def body blocks the event loop.

        This check walks the tree for AsyncFunctionDef nodes and reports any
        call to session_scope() that appears at the async function body level
        (i.e., NOT inside a nested sync def).
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            # Collect line ranges of nested sync functions -- calls inside
            # those are fine (they run via asyncio.to_thread).
            sync_ranges: list[range] = []
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(child, ast.FunctionDef):
                    end = child.end_lineno if child.end_lineno else child.lineno + 50
                    sync_ranges.append(range(child.lineno, end + 1))

            # Now find session_scope() calls in the async body
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if not isinstance(child, ast.Call):
                    continue
                callee = child.func
                callee_name: str | None = None
                if isinstance(callee, ast.Name):
                    callee_name = callee.id
                elif isinstance(callee, ast.Attribute):
                    callee_name = callee.attr
                if callee_name != "session_scope":
                    continue
                # Check if this call is inside a nested sync def
                call_line = child.lineno
                inside_sync = any(call_line in r for r in sync_ranges)
                if not inside_sync:
                    self._emit(
                        child.lineno,
                        "sync_in_async",
                        f"sync 'session_scope()' called directly in async def "
                        f"'{node.name}' -- wrap in a sync helper and use "
                        f"asyncio.to_thread()",
                    )

    def _check_api_imports_modules(self, tree: ast.Module) -> None:
        """Rule: api_imports_module_internals -- guarded layers import module internals.

        Files under aila/api/, aila/platform/, and aila/storage/ must not import
        directly from aila.modules.*. Those layers must use module contracts,
        registry lookups, or injected adapters instead.
        """
        layer = "boundary-guarded"
        normalized = self.filename.replace("\\", "/")
        if "/aila/api/" in normalized:
            layer = "api/"
        elif "/aila/platform/" in normalized:
            layer = "platform/"
        elif "/aila/storage/" in normalized:
            layer = "storage/"
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("aila.modules."):
                        self._emit(
                            node.lineno,
                            "api_imports_module_internals",
                            f"{layer} file imports '{alias.name}' -- use module contracts, registry lookups, or injected adapters instead",
                        )
                continue

            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                if node.module.startswith("aila.modules."):
                    self._emit(
                        node.lineno,
                        "api_imports_module_internals",
                        f"{layer} file imports from '{node.module}' -- use module contracts, registry lookups, or injected adapters instead",
                    )

    def _check_platform_names_module(self, tree: ast.Module) -> None:
        """Rule 48: platform_names_module -- a boundary-guarded file names a
        specific feature module.

        Three sub-checks that all fire under the same rule name so a single
        whitelist entry handles them uniformly:

        (a) ``.require("<module>")`` / ``.require_module("<module>")`` welds
            the platform or API layer to one module by id. Resolve domain data
            by capability (ModuleRegistry.first_with / all_with) instead.
        (b) ``.get("<module>", ...)`` where the first arg is a domain module
            id catches the ConfigRegistry-shape read
            ``ConfigRegistry().get("vr", "audit_mcp_url")``. Boundary-guarded
            layers own only the ``"platform"`` config namespace; every other
            namespace belongs to a specific module. A dynamic ``self._module_id``
            argument (the RFC-05 pattern) is not a literal and never fires.
        (c) A runtime string constant matching ``aila.modules.<module>`` (or
            a longer dotted path under it) hard-codes a module path in a layer
            that is supposed to name no module. Docstring string constants are
            skipped so descriptive prose in a docstring never fires.

        All sub-checks skip dynamic (variable) arguments; only literal string
        constants that name a real module id in ``_DOMAIN_MODULE_IDS`` fire.
        """
        docstring_ids = _collect_docstring_constant_ids(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if not isinstance(func, ast.Attribute):
                    continue
                if func.attr in ("require", "require_module"):
                    if not node.args or not isinstance(node.args[0], ast.Constant):
                        continue
                    value = node.args[0].value
                    if not isinstance(value, str) or value not in _DOMAIN_MODULE_IDS:
                        continue
                    self._emit(
                        node.lineno,
                        "platform_names_module",
                        f"platform_names_module: .{func.attr}({value!r}) names a feature "
                        f"module -- resolve by capability via "
                        f"ModuleRegistry.first_with/all_with instead",
                    )
                    continue
                if func.attr == "get":
                    if not node.args or not isinstance(node.args[0], ast.Constant):
                        continue
                    value = node.args[0].value
                    if not isinstance(value, str) or value not in _DOMAIN_MODULE_IDS:
                        continue
                    self._emit(
                        node.lineno,
                        "platform_names_module",
                        f"platform_names_module: .get({value!r}, ...) reads a "
                        f"feature-module config namespace from a boundary-guarded "
                        f"layer -- platform/api/storage own only the 'platform' "
                        f"namespace; move the read into the owning module or "
                        f"pass the module_id through a constructor parameter",
                    )
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) in docstring_ids:
                    continue
                if _AILA_MODULES_PATH_LITERAL_RE.match(node.value):
                    self._emit(
                        node.lineno,
                        "platform_names_module",
                        f"platform_names_module: string constant {node.value!r} "
                        f"names an 'aila.modules.<module>' path at runtime -- "
                        f"boundary-guarded layers never hard-code a module path; "
                        f"derive the target through the ModuleRegistry instead",
                    )

    def _check_import_boundary(self, tree: ast.Module, module_id: str) -> None:
        """Rule: import_boundary.

        Emits a finding for any import of aila.modules.{other_id} in a file that
        belongs to aila.modules.{module_id}.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._check_boundary_name(alias.name, node.lineno, module_id)
                continue

            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                self._check_boundary_name(node.module, node.lineno, module_id)

    def _check_boundary_name(self, dotted: str, lineno: int, module_id: str) -> None:
        """Emit import_boundary if dotted refers to a different aila module."""
        # Only care about aila.modules.* imports.
        if not dotted.startswith("aila.modules."):
            return
        # aila.modules.{segment}...
        rest = dotted[len("aila.modules."):]
        # rest may be empty (bare "aila.modules" import -- not a violation) or
        # "{other_id}" or "{other_id}.something"
        if not rest:
            return
        other_id = rest.split(".")[0]
        if other_id == module_id:
            return
        self._emit(
            lineno,
            "import_boundary",
            f"import of 'aila.modules.{other_id}' violates module boundary "
            f"(file belongs to 'aila.modules.{module_id}')",
        )

    def _check_module_session_scope_import(self, tree: ast.Module) -> None:
        """Rule: module_imports_session_scope.

        Files under aila/modules/ must not import session_scope or
        async_session_scope from storage.database. Data access must go
        through Platform Services (SDA-05).

        Phase 165: rule added with whitelist for all existing violators.
        Phase 166: whitelist entries removed after migration.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                if "storage.database" in node.module:
                    for alias in (node.names or []):
                        if alias.name in ("session_scope", "async_session_scope"):
                            self._emit(
                                node.lineno,
                                "module_imports_session_scope",
                                f"module_imports_session_scope: module file imports "
                                f"'{alias.name}' from storage.database -- use "
                                f"Platform Services (SDA-05)",
                            )

    def _check_module_prefix_in_tool_name(self, tree: ast.Module) -> None:
        """Rule 45: module_prefix_in_platform_tool_name -- a platform MCP
        bridge hard-codes a module-prefixed tool name literal.

        Bridge tool names surface in agent prompts; a literal like
        ``vr.audit_mcp_bridge`` welds the platform bridge to one module.
        The name must be built from the constructor's ``module_id``
        (an f-string / attribute), not a string constant. Flags a
        class-level ``name = "<prefix>.…"`` / ``name: str = "<prefix>.…"``
        or a ``self.name = "<prefix>.…"`` assignment where the prefix is a
        known module id.
        """
        if not _BRIDGE_FILE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for stmt in cls.body:
                if isinstance(stmt, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "name" for t in stmt.targets
                ):
                    literal = _module_prefixed_name_literal(stmt.value)
                    if literal is not None:
                        self._emit_tool_name_finding(literal, stmt.lineno)
                elif (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id == "name"
                ):
                    literal = _module_prefixed_name_literal(stmt.value)
                    if literal is not None:
                        self._emit_tool_name_finding(literal, stmt.lineno)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if (
                    isinstance(tgt, ast.Attribute)
                    and tgt.attr == "name"
                    and isinstance(tgt.value, ast.Name)
                    and tgt.value.id == "self"
                ):
                    literal = _module_prefixed_name_literal(node.value)
                    if literal is not None:
                        self._emit_tool_name_finding(literal, node.lineno)

    def _check_platform_owns_event_vocabulary(self, tree: ast.Module) -> None:
        """Rule 46: platform_owns_event_vocabulary -- a platform event class
        carries module-domain vocabulary.

        The platform owns generic infrastructure events (system lifecycle,
        config change, assessment lifecycle, LLM accounting). An event
        class under platform/events/ whose name -- or whose ``event_type``
        literal -- contains a module-domain token (scan, finding,
        investigation, or a module id) belongs to a module, not the
        platform.
        """
        if not _EVENTS_FILE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            low_name = node.name.lower()
            name_hit = next((t for t in _EVENT_DOMAIN_TOKENS if t in low_name), None)
            if name_hit is not None:
                self._emit(
                    node.lineno,
                    "platform_owns_event_vocabulary",
                    f"platform_owns_event_vocabulary: event class {node.name!r} "
                    f"carries module-domain token {name_hit!r} -- domain events "
                    f"belong to the owning module, not the platform",
                )
                continue
            for stmt in node.body:
                literal = _event_type_string_literal(stmt)
                if literal is None:
                    continue
                low_lit = literal.lower()
                lit_hit = next((t for t in _EVENT_DOMAIN_TOKENS if t in low_lit), None)
                if lit_hit is not None:
                    self._emit(
                        stmt.lineno,
                        "platform_owns_event_vocabulary",
                        f"platform_owns_event_vocabulary: event_type {literal!r} "
                        f"on class {node.name!r} carries module-domain token "
                        f"{lit_hit!r} -- domain events belong to the owning module",
                    )

    def _emit_tool_name_finding(self, literal: str, lineno: int) -> None:
        """Emit a module_prefix_in_platform_tool_name finding."""
        self._emit(
            lineno,
            "module_prefix_in_platform_tool_name",
            f"module_prefix_in_platform_tool_name: tool name literal "
            f"{literal!r} hard-codes a module prefix -- derive the name "
            f"from a constructor module_id instead",
        )

    def _check_raw_sql_platform_tables(self, tree: ast.Module) -> None:
        """Rule 47: raw_sql_platform_tables -- module file issues raw SQL
        against a platform-owned task table.

        ``taskrecord`` and ``workflow_state_cursor`` are platform-owned. A
        module that writes raw SQL against them (a DELETE / SELECT / UPDATE
        string literal with a ``FROM|INTO|UPDATE|JOIN <table>`` clause)
        bypasses the platform's ownership of the task lifecycle. Route
        through a platform service instead
        (investigation_lifecycle.purge_investigation_cursors, TaskQueue).
        The match is on the clause shape inside any string constant, so the
        call wrapper (text / sa_text / session.execute) is irrelevant and
        SQL-ish prose without the clause shape is left alone.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            match = _RAW_SQL_PLATFORM_TABLE_RE.search(node.value)
            if match is not None:
                self._emit(
                    node.lineno,
                    "raw_sql_platform_tables",
                    f"raw_sql_platform_tables: raw SQL against platform table "
                    f"{match.group(2)!r} -- route through a platform lifecycle "
                    f"/ TaskQueue service, never raw SQL from a module",
                )

    def _check_private_platform_import(self, tree: ast.Module) -> None:
        """Rule 44: private_platform_import -- module reaches into a platform
        private submodule for a publicly re-exported symbol.

        A module file importing ``from aila.platform.<pkg>._<priv> import Name``
        where ``Name`` is already published by ``aila.platform.<pkg>`` (its
        ``__init__`` re-exports it or lists it in ``__all__``) is a finding: it
        pins the module to an implementation path the platform is free to move.
        Import from the public package instead. A private symbol with no public
        counterpart is left alone -- the fence has no gate there.
        """
        aila_root = _aila_root_from_module(self.filename)
        if aila_root is None:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.module is None:
                continue
            mod = node.module
            if not mod.startswith("aila.platform."):
                continue
            segs = mod.split(".")
            priv_idx = next(
                (i for i in range(2, len(segs)) if segs[i].startswith("_")),
                None,
            )
            if priv_idx is None:
                continue
            public_segs = segs[:priv_idx]
            init_path = aila_root.joinpath(
                "platform", *public_segs[2:], "__init__.py",
            )
            public_names = _platform_public_exports(init_path)
            if not public_names:
                continue
            public_pkg = ".".join(public_segs)
            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.name in public_names:
                    self._emit(
                        node.lineno,
                        "private_platform_import",
                        f"private_platform_import: 'from {mod} import "
                        f"{alias.name}' -- {alias.name} is publicly re-exported "
                        f"from {public_pkg}; import from there",
                    )

    def _check_asyncio_in_module(self, tree: ast.Module) -> None:
        """Rule 18: asyncio_in_module -- threading primitives banned from modules/.

        Platform services own the threading boundary. Module code must never
        call asyncio.to_thread, asyncio.run, loop.run_until_complete,
        loop.run_in_executor, construct a ThreadPoolExecutor, or import from
        concurrent.futures. These are platform-layer responsibilities.
        """
        for node in ast.walk(tree):
            # concurrent.futures import -- flag the import itself
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("concurrent.futures") or alias.name == "concurrent":
                            self._emit(
                                node.lineno,
                                "asyncio_in_module",
                                f"asyncio_in_module: 'import {alias.name}' -- "
                                f"threading belongs to the platform layer, not modules",
                            )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if mod.startswith("concurrent.futures") or mod == "concurrent":
                        self._emit(
                            node.lineno,
                            "asyncio_in_module",
                            f"asyncio_in_module: 'from {mod} import ...' -- "
                            f"threading belongs to the platform layer, not modules",
                        )
                continue

            # asyncio.to_thread / asyncio.run / loop.run_until_complete / loop.run_in_executor
            if not isinstance(node, ast.Call):
                continue
            func_node = node.func
            if isinstance(func_node, ast.Attribute):
                attr = func_node.attr
                if attr in _ASYNCIO_THREAD_ATTRS:
                    # asyncio.to_thread and asyncio.run: object must be 'asyncio'
                    root = _root_name(func_node.value)
                    if attr in ("to_thread", "run"):
                        if root == "asyncio":
                            self._emit(
                                node.lineno,
                                "asyncio_in_module",
                                f"asyncio_in_module: 'asyncio.{attr}()' call -- "
                                f"threading belongs to the platform layer, not modules",
                            )
                    else:
                        # run_until_complete / run_in_executor -- any object (loop variable)
                        self._emit(
                            node.lineno,
                            "asyncio_in_module",
                            f"asyncio_in_module: '.{attr}()' call -- "
                            f"threading belongs to the platform layer, not modules",
                        )
            elif isinstance(func_node, ast.Name) and func_node.id in _THREAD_CLASS_NAMES:
                self._emit(
                    node.lineno,
                    "asyncio_in_module",
                    f"asyncio_in_module: '{func_node.id}()' construction \u2014 "
                    "threading belongs to the platform layer, not modules",
                )

    def _check_http_client_in_module(self, tree: ast.Module) -> None:
        """Rule 22: http_client_in_module -- direct HTTP client imports in modules/.

        Modules must not construct their own HTTP clients. HTTP transport
        is a platform concern -- use SSHService, IDABridgeTool, or platform
        HTTP helpers. Direct httpx/requests/urllib3/aiohttp imports bypass
        platform connection management and observability.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _HTTP_CLIENT_MODULES:
                        self._emit(
                            node.lineno,
                            "http_client_in_module",
                            f"http_client_in_module: 'import {alias.name}' -- "
                            f"HTTP clients belong to the platform layer, not modules",
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in _HTTP_CLIENT_MODULES:
                    self._emit(
                        node.lineno,
                        "http_client_in_module",
                        f"http_client_in_module: 'from {mod} import ...' -- "
                        f"HTTP clients belong to the platform layer, not modules",
                    )

    def _check_direct_db_in_module(self, tree: ast.Module) -> None:
        """Rule 23: direct_db_in_module -- direct DB driver imports in modules/.

        Modules access the database exclusively through ``UnitOfWork`` from
        ``aila.platform.uow``. Direct imports of connection-layer libraries
        (asyncpg, psycopg2, sqlite3) or engine-construction functions
        (create_engine, create_async_engine) bypass team scoping, audit
        trails, and connection-pool management.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _DIRECT_DB_MODULES:
                        self._emit(
                            node.lineno,
                            "direct_db_in_module",
                            f"direct_db_in_module: 'import {alias.name}' -- "
                            f"use UnitOfWork from aila.platform.uow instead",
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in _DIRECT_DB_MODULES:
                    self._emit(
                        node.lineno,
                        "direct_db_in_module",
                        f"direct_db_in_module: 'from {mod} import ...' -- "
                        f"use UnitOfWork from aila.platform.uow instead",
                    )
                # Also catch create_engine / create_async_engine from sqlalchemy
                if mod.startswith("sqlalchemy"):
                    for alias in (node.names or []):
                        if alias.name in _DIRECT_DB_CALLABLES:
                            self._emit(
                                node.lineno,
                                "direct_db_in_module",
                                f"direct_db_in_module: 'from {mod} import {alias.name}' -- "
                                f"use UnitOfWork from aila.platform.uow instead",
                            )

    # ------------------------------------------------------------------
    # Rules 24–33: AI slop detection
    # ------------------------------------------------------------------

    def _check_tautological_docstring(self, tree: ast.Module) -> None:
        """Rule 24: docstring that just restates the function/class name."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            doc = ast.get_docstring(node)
            if not doc or len(doc.split()) > 6:
                continue
            name_words = set(_re.findall(r'[a-z]+', node.name.lower()))
            doc_words = set(_re.findall(r'[a-z]+', doc.lower()))
            # Tautological if every name word appears in the docstring and
            # the docstring adds at most one filler word ("the", "a", etc.).
            filler = {"the", "a", "an", "of", "for", "to", "in", "on", "is", "and"}
            extra = doc_words - name_words - filler
            if name_words and not extra:
                self._emit(
                    node.lineno,
                    "tautological_docstring",
                    f"tautological_docstring: '{node.name}' docstring \"{doc}\" "
                    f"restates the name with no added information",
                )

    def _check_commented_out_code(self, source: str, filepath: str) -> None:
        """Rule 25: commented-out Python statements.

        The first-pass regex catches any comment whose text starts with
        a Python keyword (``for``, ``from``, ``except``, ``assert``,
        ...). English prose comments that use the same keyword as a
        preposition (``# for the append coroutine``, ``# from its call
        site.``, ``# except '.' and '-' to '_'``) trip that regex
        without being dead code, so the second pass tries to
        :func:`ast.parse` the un-commented text: only lines that parse
        cleanly as a real statement AND aren't a single bare name /
        constant AND aren't obviously prose (end with ``.`` /  ``,`` /
        no closing punctuation of a Python statement) count as dead
        code. This keeps the rule biting on ``# import os`` /
        ``# for x in xs:`` / ``# return None`` while letting doc
        comments through.
        """
        normalized = filepath.replace("\\", "/")
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return  # migrations legitimately have commented SQL/Python
        for suffix in _NOQA_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return  # audit tool itself has commented-out examples
        for lineno, line in enumerate(source.splitlines(), start=1):
            if not _COMMENTED_CODE_RE.match(line):
                continue
            lower = line.lower()
            if any(ex in lower for ex in _COMMENTED_CODE_EXEMPTIONS):
                continue
            if not _line_parses_as_python_statement(line):
                continue
            self._emit(
                lineno,
                "commented_out_code",
                "commented_out_code: line looks like commented-out Python -- "
                "delete dead code instead of commenting it out",
            )

    def _check_except_return_default(self, tree: ast.Module) -> None:
        """Rule 26: except handler that returns an empty default, hiding failures."""
        _empty_defaults = (type(None), int, float, str)  # None, 0, 0.0, ""
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
                continue
            val = node.body[0].value
            is_empty = False
            if val is None:
                is_empty = True
            elif isinstance(val, ast.Constant) and type(val.value) in _empty_defaults:
                if val.value in (None, 0, 0.0, ""):
                    is_empty = True
            elif isinstance(val, ast.Dict) and not val.keys:
                is_empty = True
            elif isinstance(val, (ast.List, ast.Tuple, ast.Set)) and not val.elts:
                is_empty = True
            if is_empty:
                self._emit(
                    node.lineno,
                    "except_return_default",
                    "except_return_default: except returns empty default -- "
                    "this silently hides failures; log or propagate instead",
                )

    def _check_nested_if_collapsible(self, tree: ast.Module) -> None:
        """Rule 27: if whose body is a single if (no else on either) -- combine with and."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            if node.orelse:
                continue
            if len(node.body) != 1:
                continue
            inner = node.body[0]
            if isinstance(inner, ast.If) and not inner.orelse:
                self._emit(
                    node.lineno,
                    "nested_if_collapsible",
                    "nested_if_collapsible: nested if with no else on either branch "
                    "-- combine with 'and' for readability",
                )

    def _check_pointless_pass(self, tree: ast.Module) -> None:
        """Rule 28: pass as sole body of non-abstract, non-decorator-stub function."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Strip docstring
            body = [s for s in node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                            and isinstance(s.value.value, str))]
            if len(body) != 1 or not isinstance(body[0], ast.Pass):
                continue
            dec_names = set()
            for d in node.decorator_list:
                if isinstance(d, ast.Attribute):
                    dec_names.add(d.attr)
                elif isinstance(d, ast.Name):
                    dec_names.add(d.id)
            exempt = {"abstractmethod", "overload", "platform_task"}
            if dec_names & exempt:
                continue
            self._emit(
                node.lineno,
                "pointless_pass",
                f"pointless_pass: '{node.name}()' body is only 'pass' "
                f"-- implement or mark @abstractmethod",
            )

    def _check_f_string_no_interpolation(self, tree: ast.Module) -> None:
        """Rule 29: f-string with no embedded expressions.

        Skips JoinedStr nodes that appear as format_spec inside a
        FormattedValue -- those are formatting directives (e.g. ``<6``
        in ``f"{'ID':<6}"``) and are not independent f-strings.
        """
        format_spec_ids: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FormattedValue) and isinstance(node.format_spec, ast.JoinedStr):
                format_spec_ids.add(id(node.format_spec))
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            if id(node) in format_spec_ids:
                continue
            if not any(isinstance(v, ast.FormattedValue) for v in node.values):
                self._emit(
                    node.lineno,
                    "f_string_no_interpolation",
                    "f_string_no_interpolation: f-string has no interpolated expressions "
                    "\u2014 use a plain string instead",
                )

    def _check_single_use_variable(self, tree: ast.Module) -> None:
        """Rule 30: variable assigned then immediately returned with no other use."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = node.body
            if len(body) < 2:
                continue
            last = body[-1]
            prev = body[-2]
            if not (isinstance(last, ast.Return) and isinstance(last.value, ast.Name)):
                continue
            if not (isinstance(prev, ast.Assign) and len(prev.targets) == 1
                    and isinstance(prev.targets[0], ast.Name)):
                continue
            name = last.value.id
            if prev.targets[0].id != name:
                continue
            # Count all references to this name in the entire function body
            refs = sum(1 for n in ast.walk(node)
                       if isinstance(n, ast.Name) and n.id == name)
            if refs == 2:  # one assign target, one return value
                self._emit(
                    prev.lineno,
                    "single_use_variable",
                    f"single_use_variable: '{name}' is assigned and immediately returned "
                    f"-- return the expression directly",
                )

    def _check_placeholder_return(self, tree: ast.Module) -> None:
        """Rule 31: function body is only docstring + return {} or return []."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = [s for s in node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                            and isinstance(s.value.value, str))]
            if len(body) != 1 or not isinstance(body[0], ast.Return):
                continue
            val = body[0].value
            if isinstance(val, ast.Dict) and not val.keys:
                self._emit(node.lineno, "placeholder_return",
                           f"placeholder_return: '{node.name}()' returns empty dict {{}} "
                           f"-- implement or raise NotImplementedError")
            elif isinstance(val, (ast.List, ast.Tuple)) and not val.elts:
                self._emit(node.lineno, "placeholder_return",
                           f"placeholder_return: '{node.name}()' returns empty collection "
                           f"-- implement or raise NotImplementedError")

    def _check_log_format_concat(self, tree: ast.Module) -> None:
        """Rule 32: logging call uses f-string or concatenation instead of %-formatting."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                self._emit(node.lineno, "log_format_concat",
                           f"log_format_concat: logging.{func.attr}(f'...') -- "
                           f"use %-formatting: .{func.attr}('x=%s', x)")
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                self._emit(node.lineno, "log_format_concat",
                           f"log_format_concat: logging.{func.attr}('...' + ...) -- "
                           f"use %-formatting: .{func.attr}('x=%s', x)")

    def _check_broad_exception_catch(self, tree: ast.Module) -> None:
        """Rule 33: except Exception without a justifying comment."""
        try:
            ast.unparse(tree)  # validate the AST round-trips before walking
        except (ValueError, TypeError):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                # bare except: -- even worse, but rule 12 covers this
                continue
            exc_name = ""
            if isinstance(node.type, ast.Name):
                exc_name = node.type.id
            elif isinstance(node.type, ast.Attribute):
                exc_name = node.type.attr
            if exc_name != "Exception":
                continue
            self._emit(
                node.lineno,
                "broad_exception_catch",
                "broad_exception_catch: 'except Exception' catches everything indiscriminately "
                "-- catch specific exception types",
            )

    def _check_response_model_dict(self, tree: ast.Module) -> None:
        """Rule 19: response_model_dict -- @router.* with response_model=dict/Dict.

        FastAPI endpoints must return a typed Pydantic schema, not a bare dict.
        Using response_model=dict bypasses response validation and schema
        generation, hiding what the endpoint actually returns.
        """
        _dict_names: frozenset[str] = frozenset({"dict", "Dict"})

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                # The decorator must be router.get / router.post / etc.
                dec_func = dec.func
                if not isinstance(dec_func, ast.Attribute):
                    continue
                if dec_func.attr not in {"get", "post", "put", "delete", "patch"}:
                    continue
                # Check keywords for response_model=dict / response_model=Dict
                for kw in dec.keywords:
                    if kw.arg != "response_model":
                        continue
                    val = kw.value
                    # response_model=dict or response_model=Dict
                    if isinstance(val, ast.Name) and val.id in _dict_names:
                        self._emit(
                            dec.lineno,
                            "response_model_dict",
                            f"response_model_dict: endpoint '{node.name}' uses "
                            f"response_model={val.id} -- use a typed Pydantic schema instead",
                        )
                    # response_model=typing.Dict
                    elif isinstance(val, ast.Attribute) and val.attr == "Dict":
                        self._emit(
                            dec.lineno,
                            "response_model_dict",
                            f"response_model_dict: endpoint '{node.name}' uses "
                            f"response_model=typing.Dict -- use a typed Pydantic schema instead",
                        )
                    # response_model=dict | None  (BinOp with left=dict)
                    elif isinstance(val, ast.BinOp):
                        left = val.left
                        if isinstance(left, ast.Name) and left.id in _dict_names:
                            self._emit(
                                dec.lineno,
                                "response_model_dict",
                                f"response_model_dict: endpoint '{node.name}' uses "
                                f"response_model={left.id} | ... -- use a typed Pydantic schema instead",
                            )

    def _check_bare_dict_return_endpoint(self, tree: ast.Module) -> None:
        """Rule 20: bare_dict_return_endpoint -- endpoint handler returns a raw dict.

        Functions decorated with @router.* must return a Pydantic model instance,
        not a plain dict literal or dict() call. Raw dict returns bypass response
        validation and OpenAPI schema generation.

        Also flags JSONResponse(content={...}) which is another form of the same
        anti-pattern: ad-hoc dict at the response boundary instead of a typed model.
        """
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Check if decorated with @router.*
            is_endpoint = False
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if dec.func.attr in {"get", "post", "put", "delete", "patch"}:
                        is_endpoint = True
                        break
                elif isinstance(dec, ast.Attribute) and dec.attr in {"get", "post", "put", "delete", "patch"}:
                    is_endpoint = True
                    break

            if not is_endpoint:
                continue

            # Walk the function body for Return nodes with dict values.
            # Use _walk_returns_shallow to avoid false positives from nested
            # helper functions (e.g. async def _query()) that return dicts
            # internally while the outer endpoint returns a typed Pydantic model.
            for child in _walk_returns_shallow(node):
                if not isinstance(child, ast.Return) or child.value is None:
                    continue
                ret_val = child.value

                # return {"key": val}  -- ast.Dict literal
                if isinstance(ret_val, ast.Dict):
                    self._emit(
                        child.lineno,
                        "bare_dict_return_endpoint",
                        f"bare_dict_return_endpoint: endpoint '{node.name}' returns a raw "
                        f"dict literal -- return a typed Pydantic model instead",
                    )
                    continue

                # return dict(...)  -- dict() constructor call
                if (
                    isinstance(ret_val, ast.Call)
                    and isinstance(ret_val.func, ast.Name)
                    and ret_val.func.id == "dict"
                ):
                    self._emit(
                        child.lineno,
                        "bare_dict_return_endpoint",
                        f"bare_dict_return_endpoint: endpoint '{node.name}' returns dict() -- "
                        f"return a typed Pydantic model instead",
                    )
                    continue

                # return JSONResponse(content={...})
                if isinstance(ret_val, ast.Call):
                    func_node = ret_val.func
                    callee_name = None
                    if isinstance(func_node, ast.Name):
                        callee_name = func_node.id
                    elif isinstance(func_node, ast.Attribute):
                        callee_name = func_node.attr
                    if callee_name == "JSONResponse":
                        for kw in ret_val.keywords:
                            if kw.arg == "content" and isinstance(kw.value, ast.Dict):
                                self._emit(
                                    child.lineno,
                                    "bare_dict_return_endpoint",
                                    f"bare_dict_return_endpoint: endpoint '{node.name}' returns "
                                    f"JSONResponse(content={{...}}) -- return a typed Pydantic model instead",
                                )
                                break

    def _check_noqa_inline(self, source: str, filepath: str) -> None:
        """Rule 21: noqa_inline -- inline # noqa comments in production source.

        All linter suppressions must go through honesty_whitelist.py with a
        documented justification. Inline # noqa is banned because it silently
        hides violations without requiring a reason.

        Self-exempt files: honesty_audit.py and honesty_whitelist.py themselves.
        Alembic migration files are also exempt (auto-generated code).
        """
        normalized = filepath.replace("\\", "/")

        # Self-exemption: audit tool and whitelist are allowed to reference noqa
        for suffix in _NOQA_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return

        # Alembic migrations are auto-generated -- exempt from this rule
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return

        for lineno, line in enumerate(source.splitlines(), start=1):
            if _NOQA_PATTERN.search(line):
                self._emit(
                    lineno,
                    "noqa_inline",
                    f"noqa_inline: inline '# noqa' comment on line {lineno} -- "
                    f"use honesty_whitelist.py with a documented justification instead",
                )

    def _check_hoisted_enum_redeclared(self, tree: ast.Module, module_id: str) -> None:
        """Rule 34: hoisted_enum_redeclared -- a unified module redeclares a platform enum.

        The enums in _HOISTED_ENUM_NAMES are owned by
        aila.platform.contracts.enums. A vr/malware contracts file must import
        them, never declare its own StrEnum of the same name. Scoped to the
        unified modules: forensics and vulnerability keep independent enums that
        happen to share a class name (e.g. their own InvestigationStatus).
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name not in _HOISTED_ENUM_NAMES:
                continue
            if "StrEnum" not in _classdef_base_names(node):
                continue
            self._emit(
                node.lineno,
                "hoisted_enum_redeclared",
                f"hoisted_enum_redeclared: enum '{node.name}' is owned by "
                f"platform.contracts.enums -- import it instead of redeclaring",
            )

    def _check_unnamed_derived_constraint(self, tree: ast.Module, module_id: str) -> None:
        """Rule 35: unnamed_derived_constraint -- a unified table hand-names a UQ.

        A vr/malware investigation-engine table must derive its unique-constraint
        name from the tablename via TabledUq, not hard-code a literal. Scoped to
        the unified tables so other modules keep their own constraint names.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not _classdef_is_table(node):
                continue
            tablename = _classdef_tablename(node)
            if tablename is None:
                continue
            if _strip_module_prefix(tablename, module_id) not in _UNIFIED_ROLE_BASES:
                continue
            derived_prefix = f"uq_{tablename}_"
            for literal, lineno in _unique_constraint_literal_names(node):
                if not literal.startswith(derived_prefix):
                    self._emit(
                        lineno,
                        "unnamed_derived_constraint",
                        f"unnamed_derived_constraint: table '{tablename}' hard-codes "
                        f"constraint name '{literal}' -- derive it via TabledUq "
                        f"({derived_prefix}...)",
                    )

    def _check_shadowed_platform_base(self, tree: ast.Module, module_id: str) -> None:
        """Rule 36: shadowed_platform_base -- a unified table recreates base columns.

        A vr/malware investigation-engine table whose role maps to a platform
        base must subclass that base, not redeclare its columns. Fires when the
        class does not subclass the base yet redeclares four or more of its
        fields. The base field set is read from platform/contracts via AST.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        contracts_dir = _platform_contracts_dir(self.filename)
        if contracts_dir is None:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not _classdef_is_table(node):
                continue
            tablename = _classdef_tablename(node)
            if tablename is None:
                continue
            base_class = _UNIFIED_ROLE_BASES.get(_strip_module_prefix(tablename, module_id))
            if base_class is None or base_class in _classdef_base_names(node):
                continue
            base_file = contracts_dir / _BASE_FILE_BY_CLASS[base_class]
            base_fields = _platform_base_field_names(base_file, base_class)
            if not base_fields:
                continue
            overlap = _sqlmodel_field_names(node) & base_fields
            if len(overlap) >= 4:
                self._emit(
                    node.lineno,
                    "shadowed_platform_base",
                    f"shadowed_platform_base: table '{tablename}' recreates "
                    f"{len(overlap)} columns of {base_class} -- subclass "
                    f"{base_class} instead",
                )

    def _check_config_schema_base(self, tree: ast.Module) -> None:
        """Rule 37: module_config_schema_base -- a module config schema must
        subclass ModuleConfigBase.

        A ``*ConfigSchema`` class in a ``modules/<name>/config_schema.py``
        file must subclass ``aila.platform.config_base.ModuleConfigBase``,
        which bakes in ``extra=forbid``. Subclassing bare ``BaseModel``
        lets an undeclared config key pass at construction instead of
        failing closed -- the gap vulnerability carried before RFC-04
        Phase 2.
        """
        if not _CONFIG_SCHEMA_PATH_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not node.name.endswith("ConfigSchema"):
                continue
            if "ModuleConfigBase" in _classdef_base_names(node):
                continue
            self._emit(
                node.lineno,
                "module_config_schema_base",
                f"module_config_schema_base: config schema '{node.name}' must "
                "subclass ModuleConfigBase (bakes in extra=forbid) instead of "
                "bare BaseModel",
            )

    def _check_service_copy_of_platform(self, tree: ast.Module) -> None:
        """Rule 38: service_copy_of_platform -- a vr/malware service duplicates
        a platform service.

        A file under modules/vr/services or modules/malware/services whose
        comment- and format-normalized body matches a platform service above
        the similarity threshold is the copy-and-rename pattern RFC-04 lifted
        out. After a service is lifted the module keeps only a thin binding, so
        a high-similarity match means a full copy slipped back in. Length
        asymmetry keeps thin bindings well under the threshold; only a
        same-size copy trips it. Scoped to the vr/malware copy set; forensics
        keeps an independent variant.
        """
        if not _SERVICE_COPY_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        try:
            own = ast.unparse(tree)
        except (ValueError, RecursionError):
            return
        if not own.strip():
            return
        best_name = ""
        best_ratio = 0.0
        own_len = len(own)
        for name, platform_src in _platform_service_corpus(self.filename).items():
            p_len = len(platform_src)
            if p_len == 0:
                continue
            # Length ceiling: the best achievable ratio is 2*min/(sum). Below
            # the threshold the pair cannot match, so skip the O(n*m) compare.
            # This prunes every thin binding (short) against a full platform
            # impl (long) in O(1).
            if 2 * min(own_len, p_len) / (own_len + p_len) < _SERVICE_COPY_THRESHOLD:
                continue
            matcher = difflib.SequenceMatcher(None, own, platform_src)
            if matcher.quick_ratio() < _SERVICE_COPY_THRESHOLD:
                continue
            ratio = matcher.ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_name = name
        if best_ratio >= _SERVICE_COPY_THRESHOLD:
            self._emit(
                1,
                "service_copy_of_platform",
                f"service_copy_of_platform: normalized body is {best_ratio:.0%} "
                f"similar to platform/{best_name}; lift the shared logic to the "
                "platform and keep a thin binding here",
            )

    def _check_workflow_state_copy_of_platform(self, tree: ast.Module) -> None:
        """Rule 41: workflow_state_copy_of_platform -- a vr/malware
        investigation state file duplicates a platform state base.

        RFC-02 Phase 4 extracted the setup/loop/emit turn engine to
        platform/workflows/investigation_*_base.py; each module keeps only
        a thin factory binding. A file whose normalized body matches a
        platform base above the similarity threshold is a copy that
        slipped back in. The length ceiling keeps thin bindings well under
        the threshold; only a same-size copy trips it.
        """
        if not _WORKFLOW_STATE_SCOPE_PATTERN.search(
            self.filename.replace("\\", "/"),
        ):
            return
        try:
            own = ast.unparse(tree)
        except (ValueError, RecursionError):
            return
        if not own.strip():
            return
        best_name = ""
        best_ratio = 0.0
        own_len = len(own)
        for name, base_src in _workflow_base_corpus(self.filename).items():
            b_len = len(base_src)
            if b_len == 0:
                continue
            if 2 * min(own_len, b_len) / (own_len + b_len) < _SERVICE_COPY_THRESHOLD:
                continue
            matcher = difflib.SequenceMatcher(None, own, base_src)
            if matcher.quick_ratio() < _SERVICE_COPY_THRESHOLD:
                continue
            ratio = matcher.ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_name = name
        if best_ratio >= _SERVICE_COPY_THRESHOLD:
            self._emit(
                1,
                "workflow_state_copy_of_platform",
                f"workflow_state_copy_of_platform: normalized body is "
                f"{best_ratio:.0%} similar to platform/{best_name}; bind the "
                "platform state factory instead of copying it",
            )

    def _check_agent_llm_chat_bypass(self, tree: ast.Module) -> None:
        """Rule 43: agent_llm_chat_bypass -- a module agents/ file calls the
        raw llm_client.chat() instead of the idempotent wrapper.

        RFC-03 Phase 2 routes the module agent LLM calls through
        platform.agents.idempotent_llm_call so a retried worker replays the
        cached response instead of paying the model API a second time. A
        direct ``<x>.llm_client.chat(...)`` / ``.chat_json(...)`` /
        ``.chat_structured(...)`` (or the same on ``self._llm``) in a module
        agents/ file is a bypass that reintroduces the double-pay.
        """
        if not _AGENTS_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        _methods = ("chat", "chat_json", "chat_structured")
        _receivers = ("llm_client", "_llm")
        # Pass 1: local names aliased to an llm client, e.g.
        # ``client = ServiceFactory().llm_client`` or ``c = services.llm_client``.
        # A later ``client.chat(...)`` reaches the model through a Name
        # receiver that the attribute check alone would miss.
        aliases: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            val = node.value
            if isinstance(val, ast.Attribute) and val.attr in _receivers:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        aliases.add(tgt.id)
        # Pass 2: flag chat* calls on an llm-client attribute OR an alias.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr in _methods):
                continue
            recv = fn.value
            is_bypass = (
                (isinstance(recv, ast.Attribute) and recv.attr in _receivers)
                or (isinstance(recv, ast.Name) and recv.id in aliases)
            )
            if is_bypass:
                self._emit(
                    node.lineno,
                    "agent_llm_chat_bypass",
                    "agent_llm_chat_bypass: route this LLM call through "
                    "platform.agents.idempotent_llm_call for retry safety",
                )

    def _check_agent_primitive_reimplementation(self, tree: ast.Module) -> None:
        """Rule 42: agent_primitive_reimplementation -- a module agents/ file
        defines a platform-owned agent primitive.

        RFC-03 lifted the per-turn loop (``run_turn``), the case-state
        codec (``decode_case_state`` / ``encode_case_state``), the
        terminal live-hypothesis resolver (``auto_resolve_live_on_terminal``),
        the outcome-confidence coercion (``to_outcome_confidence``), the
        auto-steering injector (``maybe_post_auto_steering``), and the
        operator-intent classifier (``classify_intent``) to
        ``aila.platform.agents``. Modules import them; a def of any of
        these names -- whether at module top level or as a method
        redefinition on a class body -- is a copy that drifts from the
        single platform implementation. Import re-exports are Import /
        ImportFrom statements, not FunctionDefs, so they never fire.
        A thin subclass that just inherits the platform method without
        overriding it stays clean; only an explicit ``async def run_turn``
        (etc.) inside the class body fires.
        """
        if not _AGENTS_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        def_types = (ast.FunctionDef, ast.AsyncFunctionDef)
        # Top-level defs (module body).
        for node in tree.body:
            if (
                isinstance(node, def_types)
                and node.name in _LIFTED_AGENT_PRIMITIVES
            ):
                self._emit(
                    node.lineno,
                    "agent_primitive_reimplementation",
                    f"agent_primitive_reimplementation: '{node.name}' is owned "
                    "by platform/agents/; import it instead of redefining it",
                )
        # Class-body method defs. A subclass that overrides a lifted
        # method (e.g. ``async def run_turn(self, ...)`` on a subclass of
        # ``AgentTurnRunnerBase``) is the exact regression Phase 7 forbids.
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            for stmt in node.body:
                if (
                    isinstance(stmt, def_types)
                    and stmt.name in _LIFTED_AGENT_PRIMITIVES
                ):
                    self._emit(
                        stmt.lineno,
                        "agent_primitive_reimplementation",
                        f"agent_primitive_reimplementation: '{stmt.name}' is "
                        f"owned by platform/agents/; do not override it in "
                        f"'{node.name}'",
                    )

    def _check_agent_env_read(self, tree: ast.Module) -> None:
        """Rule 49: agent_env_read -- a module agents/ file reads config
        via ``os.environ`` / ``os.getenv`` instead of ``ConfigRegistry``.

        RFC-03's config-drift closure removed every direct env read from
        ``modules/*/agents/**``: the old vr copies (``branch_manager.py``,
        ``claim_verifier.py``) reached ``os.environ`` for the branch cap
        and the auto-promote floor, silently bypassing the DB override
        and diverging from the malware copy. Modules now resolve config
        through ``ConfigRegistry(module_id, key)``, which lets env, the DB,
        and the per-module schema default each participate on one path.

        The check fires on three shapes:
          - ``os.environ`` / ``os.getenv`` attribute access on the ``os``
            module (covers ``os.environ["X"]``, ``os.environ.get("X")``,
            ``os.getenv("X")``);
          - ``from os import environ`` / ``from os import getenv``.
        """
        if not _AGENTS_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in _OS_ENV_ATTRS
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                self._emit(
                    node.lineno,
                    "agent_env_read",
                    f"agent_env_read: read config via ConfigRegistry(module_id, "
                    f"key) instead of os.{node.attr} (RFC-03 config-drift closure)",
                )
                continue
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if alias.name in _OS_ENV_ATTRS:
                        self._emit(
                            node.lineno,
                            "agent_env_read",
                            f"agent_env_read: read config via ConfigRegistry"
                            f"(module_id, key) instead of 'from os import "
                            f"{alias.name}' (RFC-03 config-drift closure)",
                        )

    def _check_static_node_mutation(self, tree: ast.Module) -> None:
        """Rule 50: static_node_mutation -- a WorkflowDefinition.states map is
        mutated after construction (RFC-13 #68).

        The dispatch-hub and phase-graph substrates freeze the node set at
        construction so every transition target is declared and the engine
        can validate it. Assigning into, deleting from, or calling a mutator
        on a ``.states`` attribute reopens that set at runtime -- the exact
        mint-a-node-on-the-fly escape the static-graph invariant forbids.
        Declare every state in the definition; never mutate ``.states`` after.

        A local ``states = {...}`` dict a builder assembles is a plain Name,
        not a ``.states`` attribute, so it never trips this.
        """
        for node in ast.walk(tree):
            hit_line: int | None = None
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if self._is_states_subscript(tgt):
                        hit_line = node.lineno
                        break
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                if self._is_states_subscript(node.target):
                    hit_line = node.lineno
            elif isinstance(node, ast.Delete):
                for tgt in node.targets:
                    if self._is_states_subscript(tgt):
                        hit_line = node.lineno
                        break
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _STATES_MUTATOR_METHODS
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "states"
            ):
                hit_line = node.lineno
            if hit_line is not None:
                self._emit(
                    hit_line,
                    "static_node_mutation",
                    "static_node_mutation: WorkflowDefinition.states is frozen "
                    "at construction; declare every state in the definition "
                    "rather than mutating .states afterwards (RFC-13 "
                    "static-graph invariant)",
                )

    @staticmethod
    def _is_states_subscript(target: ast.expr) -> bool:
        """Return True when *target* is a ``<expr>.states[...]`` subscript."""
        return (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "states"
        )

    def _check_fail_open_recovery_path(self, tree: ast.Module) -> None:
        """Rule 52: fail_open_recovery_path -- a recovery-marked function
        returns a permissive default from an ``except`` handler.

        The RFC-07 posture is fail-closed. A safety, rate-limit, verify,
        finalize, heal, or reconcile function whose ``except`` block
        returns True / 0 / 0.0 / "" / [] / {} / a bare ``return`` is
        silently deciding the call succeeded when it did not -- the
        rate-limiter passes zero defer under DB pressure, the verifier
        marks unverified as passing, the finalizer records a fault as a
        clean negative. Every one of those is an outage disguised as
        success. Return the conservative default (a bounded defer, a
        block, a close-with-reason) and log; do not return a permissive
        value from an ``except``.

        Scope: any Python source file. The rule fires ONLY when the
        enclosing function's name matches one of
        :data:`_RECOVERY_FUNCTION_MARKERS`; a helper whose name does not
        signal a recovery contract is out of scope. The rule matches
        the shape ``except ...: return <permissive>`` at any depth
        inside the function body -- an ``except`` inside a nested
        helper defined in the same function counts, but an ``except``
        inside a nested inner function (a ``def`` two levels down)
        does not because the inner function has its own name and
        recovery-marker check applies to IT.

        The audit tool itself is self-exempt: this file defines the
        marker strings and would otherwise flag its own docstrings.
        """
        normalized = self.filename.replace("\\", "/")
        if normalized.endswith("tools/honesty_audit.py"):
            return
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            if not _function_name_matches(
                node.name, _RECOVERY_FUNCTION_MARKERS,
            ):
                continue
            for handler in self._enclosed_except_handlers(node):
                # A handler that logs is already surfacing a signal, and a
                # handler that re-raises is not returning at all -- either
                # one clears the rule so a legitimate log-and-return-zero
                # sweep (see cursor_reaper.sweep_orphan_crashed_cursors)
                # is not flagged. The offending shape is the SILENT
                # permissive return.
                handler_ids = self._handler_identifiers(handler)
                if handler_ids & _LOGGING_IDENTIFIERS:
                    continue
                if self._handler_reraises(handler):
                    continue
                offending = self._find_permissive_return(handler)
                if offending is None:
                    continue
                self._emit(
                    offending.lineno,
                    "fail_open_recovery_path",
                    (
                        f"fail_open_recovery_path: function '{node.name}' "
                        f"returns a permissive default from an except handler "
                        "without logging or re-raising -- RFC-07 requires a "
                        "fail-closed conservative default (bounded defer, "
                        "mark-and-block, close-with-reason) and a surfaced "
                        "signal, not a silent success"
                    ),
                )

    @staticmethod
    def _handler_identifiers(handler: ast.ExceptHandler) -> set[str]:
        """Return every Name.id / Attribute.attr appearing in the handler body."""
        ids: set[str] = set()
        for stmt in handler.body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name):
                    ids.add(node.id)
                elif isinstance(node, ast.Attribute):
                    ids.add(node.attr)
        return ids

    @staticmethod
    def _handler_reraises(handler: ast.ExceptHandler) -> bool:
        """Return True when the handler body contains a raise statement."""
        for stmt in handler.body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Raise):
                    return True
        return False

    @staticmethod
    def _enclosed_except_handlers(
        func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[ast.ExceptHandler]:
        """Yield every ExceptHandler inside ``func`` NOT under a nested def.

        A nested ``def`` / ``async def`` / ``class`` inside the body
        introduces a fresh name; the outer rule's recovery-marker
        match should not leak into the nested scope. This mirrors the
        :func:`_walk_returns_shallow` boundary used by rule 20.
        """
        handlers: list[ast.ExceptHandler] = []
        for stmt in func.body:
            handlers.extend(_HonestyVisitor._walk_except_shallow(stmt))
        return handlers

    @staticmethod
    def _walk_except_shallow(node: ast.AST) -> list[ast.ExceptHandler]:
        """Return every ExceptHandler in *node*'s subtree, stopping at nested defs."""
        found: list[ast.ExceptHandler] = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _NESTED_DEF_TYPES):
                continue
            if isinstance(child, ast.ExceptHandler):
                found.append(child)
            found.extend(_HonestyVisitor._walk_except_shallow(child))
        return found

    @staticmethod
    def _find_permissive_return(
        handler: ast.ExceptHandler,
    ) -> ast.Return | None:
        """Return the offending ast.Return in ``handler``, or None.

        A ``return`` with no value (implicit None) or a return of any
        constant in :data:`_FAIL_OPEN_PERMISSIVE_CONSTANTS` or an
        empty dict / list / tuple / set literal counts as permissive.
        A logged-then-return-conservative shape (e.g. an except block
        that first logs then returns a non-permissive value) is fine.
        Only returns AT the shallow top of the handler body count --
        an ``except`` whose handler contains a raise / re-raise on
        the primary path and a return only inside a nested branch
        needs finer analysis; today the rule fires on any handler
        whose primary body ends in a permissive return.
        """
        # Walk shallow -- a nested def inside the handler has its own
        # scope and its own name-marker check.
        for stmt in _HonestyVisitor._iter_handler_shallow(handler):
            if not isinstance(stmt, ast.Return):
                continue
            val = stmt.value
            if val is None:
                return stmt
            if isinstance(val, ast.Constant):
                v = val.value
                # Boolean False is the fail-closed answer for a verify /
                # authorisation path ("not verified" / "not allowed");
                # only True is permissive. Numeric zero, empty string,
                # and True itself count as permissive.
                if v is True:
                    return stmt
                if v is False or v is None:
                    # v is None already handled by the top-level `val is
                    # None` check; v is False is intentionally NOT a
                    # finding (see docstring).
                    if v is None:
                        return stmt
                    continue
                # ``type(v) is int`` distinguishes 0 from False (0 == False
                # is True in Python; the explicit type check prevents the
                # False branch from bleeding into the 0 branch).
                if type(v) is int and v == 0:
                    return stmt
                if type(v) is float and v == 0.0:
                    return stmt
                if type(v) is str and v == "":
                    return stmt
                continue
            if isinstance(val, ast.Dict) and not val.keys:
                return stmt
            if (
                isinstance(val, (ast.List, ast.Tuple, ast.Set))
                and not val.elts
            ):
                return stmt
        return None

    @staticmethod
    def _iter_handler_shallow(handler: ast.ExceptHandler):
        """Yield every statement in ``handler`` body, stopping at nested defs."""
        stack: list[ast.AST] = list(handler.body)
        while stack:
            stmt = stack.pop(0)
            yield stmt
            if isinstance(stmt, _NESTED_DEF_TYPES):
                continue
            stack.extend(ast.iter_child_nodes(stmt))

    def _check_close_without_infra_classification(
        self, tree: ast.Module,
    ) -> None:
        """Rule 53: close_without_infra_classification -- a finalizer
        closes an investigation as a negative without consulting the
        infra-death classifier.

        A finalize-marked function (name in
        :data:`_FINALIZER_NAME_MARKERS`) whose body calls a close
        marker (:data:`_CLOSE_CALLABLE_MARKERS`) must also reference
        :class:`InfraDeathClassifier` -- either as an import-visible
        name, an ``InfraDeathClassifier.classify(...)`` call, or an
        instance attribute of the enclosing service. Without that
        reference the finalizer records an infra-killed branch as a
        clean negative that disappears from the operator's re-run
        queue (RFC-07 Motivation, malware investigation_finalizers
        row).

        The audit file names the markers and would otherwise flag
        itself; the classifier's own home file (when it lands under
        platform/services/) is exempted by naming the classifier
        symbol in its own module.
        """
        normalized = self.filename.replace("\\", "/")
        if normalized.endswith("tools/honesty_audit.py"):
            return
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            if not _function_name_matches(
                node.name, _FINALIZER_NAME_MARKERS,
            ):
                continue
            body_calls = _call_names_in_body(node)
            close_hits = body_calls & _CLOSE_CALLABLE_MARKERS
            if not close_hits:
                continue
            body_ids = _identifier_names_in_body(node)
            has_classifier = (
                _INFRA_CLASSIFIER_NAME in body_ids
                or bool(body_calls & _INFRA_CLASSIFIER_METHODS)
            )
            if has_classifier:
                continue
            self._emit(
                node.lineno,
                "close_without_infra_classification",
                (
                    f"close_without_infra_classification: finalizer "
                    f"'{node.name}' calls {sorted(close_hits)!r} without "
                    "consulting InfraDeathClassifier -- an infra-killed "
                    "branch closed as a clean negative disappears from "
                    "the operator's re-run queue (RFC-07)"
                ),
            )

    def _check_heal_without_journal(self, tree: ast.Module) -> None:
        """Rule 54: heal_without_journal -- a recovery function mutates run
        state without writing a checkpointed recovery event.

        A heal-marked function (name in
        :data:`_HEAL_FUNCTION_MARKERS`) whose body calls any state-
        mutation marker (:data:`_STATE_MUTATION_MARKERS`) must also
        call a journal-write marker
        (:data:`_JOURNAL_WRITE_MARKERS`). Otherwise the heal is
        silent: the operator sees the run state change but has no
        audit trail to reconstruct what fired the change or when.
        RFC-07's contract is that recovery is itself auditable.

        Files that OWN the journal / event / state-mutation
        primitives are exempt via :data:`_JOURNAL_SELF_EXEMPT_SUFFIXES`
        so the rule does not fire on the LedgerService itself or on
        the low-level mutation helpers the higher-level heal paths
        compose (the heal itself lives ABOVE those helpers and is
        where the journal write belongs).
        """
        normalized = self.filename.replace("\\", "/")
        if normalized.endswith("tools/honesty_audit.py"):
            return
        for suffix in _JOURNAL_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            if not _function_name_matches(
                node.name, _HEAL_FUNCTION_MARKERS,
            ):
                continue
            body_calls = _call_names_in_body(node)
            mutation_hits = body_calls & _STATE_MUTATION_MARKERS
            if not mutation_hits:
                continue
            if body_calls & _JOURNAL_WRITE_MARKERS:
                continue
            self._emit(
                node.lineno,
                "heal_without_journal",
                (
                    f"heal_without_journal: recovery function '{node.name}' "
                    f"mutates run state via {sorted(mutation_hits)!r} but "
                    "writes no recovery event (LedgerService.append_general, "
                    "record_signal, record_and_check, or an equivalent "
                    "journal-write). RFC-07 requires every heal to leave "
                    "an audit trail"
                ),
            )

    def _check_ledger_write_encapsulation(self, tree: ast.Module) -> None:
        """Rule 51: ledger_write_bypass -- a direct write to the
        investigation_ledger table outside LedgerService (RFC-13 #68).

        LedgerService owns the append-only invariant and the idempotency
        key. A pg_insert / insert of the record, a session.add of one, or a
        raw INSERT into the table anywhere else reopens the write path and
        drifts from that single owner. Append through
        LedgerService.append_general instead. The service file itself and
        the alembic migration (which creates the table) are exempt.
        """
        normalized = self.filename.replace("\\", "/")
        if normalized.endswith(_LEDGER_SERVICE_PATH_SUFFIX):
            return
        # The audit tool itself names the table and the verb in this rule's
        # own strings, so it is self-exempt like the noqa rule.
        if normalized.endswith("tools/honesty_audit.py"):
            return
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return
        insert_verb = "insert " + "into "
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_ledger_write_call(node):
                self._emit(
                    node.lineno,
                    "ledger_write_bypass",
                    "ledger_write_bypass: append through "
                    "LedgerService.append_general; a direct write to the "
                    "ledger table outside LedgerService reopens the "
                    "append-only path",
                )
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and insert_verb in node.value.lower()
                and _LEDGER_TABLE_NAME in node.value.lower()
            ):
                self._emit(
                    node.lineno,
                    "ledger_write_bypass",
                    "ledger_write_bypass: raw INSERT against the ledger table; "
                    "append through LedgerService.append_general",
                )

    @staticmethod
    def _is_ledger_write_call(node: ast.Call) -> bool:
        """Return True for an insert(record) / pg_insert(record) / .add(record)."""
        func = node.func
        if (
            isinstance(func, ast.Name)
            and func.id in _LEDGER_INSERT_CALLABLES
            and node.args
            and _HonestyVisitor._names_ledger_record(node.args[0])
        ):
            return True
        return bool(
            isinstance(func, ast.Attribute)
            and func.attr == "add"
            and node.args
            and isinstance(node.args[0], ast.Call)
            and _HonestyVisitor._names_ledger_record(node.args[0].func)
        )

    @staticmethod
    def _names_ledger_record(node: ast.expr) -> bool:
        """Return True when *node* references the InvestigationLedgerRecord class."""
        if isinstance(node, ast.Name):
            return node.id == _LEDGER_RECORD_NAME
        return isinstance(node, ast.Attribute) and node.attr == _LEDGER_RECORD_NAME

    def _check_cost_read_stored_actual(
        self, tree: ast.Module, module_id: str,
    ) -> None:
        """Rule 39: cost_read_stored_actual -- a lifecycle api_router reads the
        dead ``cost_actual_usd`` column in a response instead of aggregating
        live cost.

        The ``cost_actual_usd`` column has no writers, so any read of it in a
        response body reports a permanent $0. The live gauge comes from
        ``compute_live_investigation_cost`` (sum LLMCostRecord by run_id). A
        handler that reads ``record.cost_actual_usd`` without an aggregator
        call in the same function has drifted back to the broken read. Scoped
        to the vr/malware api_router; the create-time ``cost_actual_usd=0.0``
        keyword is an insert, not an attribute read, so it never trips.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        if not self.filename.replace("\\", "/").endswith("/api_router.py"):
            return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            reads = [
                n for n in ast.walk(node)
                if isinstance(n, ast.Attribute)
                and n.attr == "cost_actual_usd"
                and isinstance(n.ctx, ast.Load)
            ]
            if not reads:
                continue
            has_aggregator = any(
                isinstance(c, ast.Call)
                and (
                    (isinstance(c.func, ast.Name)
                     and c.func.id == "compute_live_investigation_cost")
                    or (isinstance(c.func, ast.Attribute)
                        and c.func.attr == "compute_live_investigation_cost")
                )
                for c in ast.walk(node)
            )
            if has_aggregator:
                continue
            self._emit(
                reads[0].lineno,
                "cost_read_stored_actual",
                f"cost_read_stored_actual: '{node.name}' reads "
                "record.cost_actual_usd in a response; that column has no "
                "writers (always $0). Aggregate live cost via "
                "compute_live_investigation_cost instead",
            )

    def _check_lifecycle_handler_bypass(
        self, tree: ast.Module, module_id: str,
    ) -> None:
        """Rule 40: lifecycle_handler_bypass_service -- a pause / resume /
        re-enqueue route handler writes ``.status`` directly instead of
        routing through the platform investigation lifecycle service.

        The four-source-of-truth transition (inv row, cursor, taskrecord,
        ARQ) is a platform property; a handler that assigns ``.status``
        itself is the drift that left the malware lifecycle broken. Scoped to
        the vr/malware api_router pause / resume / re-enqueue routes. ``reset``
        is intentionally excluded: it is a full-wipe that legitimately resets
        ``status`` to CREATED and does not go through the lifecycle service.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        if not self.filename.replace("\\", "/").endswith("/api_router.py"):
            return
        _lifecycle_suffixes = ("/pause", "/resume", "/re-enqueue")
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = _endpoint_route_path(node)
            if route is None or not route.endswith(_lifecycle_suffixes):
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Assign):
                    continue
                if any(
                    isinstance(tgt, ast.Attribute) and tgt.attr == "status"
                    for tgt in sub.targets
                ):
                    self._emit(
                        sub.lineno,
                        "lifecycle_handler_bypass_service",
                        f"lifecycle_handler_bypass_service: '{node.name}' writes "
                        ".status directly; route pause / resume / re-enqueue "
                        "through the platform investigation lifecycle service",
                    )
                    break

    # ------------------------------------------------------------------
    # RFC-08 / RFC-09 / RFC-10 rules (55-63)
    # ------------------------------------------------------------------

    def _check_ungated_self_improvement_write(self, tree: ast.Module) -> None:
        """Rule 55: ungated_self_improvement_write -- a pattern-store
        write outside :class:`ExperienceWriter` and the store itself.

        The RFC-08 write path is:

            reviewed QuorumOutcome  ->  ExperienceWriter.record(...)
                                    ->  pattern_store.create(...)

        Every experience row must carry a reviewer-signed polarity
        (positive / negative). A direct ``.create(...)`` on the store
        from an agent turn, a workflow state, or a service reopens
        that write path and lets the module insert a "learned"
        pattern without ever passing the eval + quorum gate.

        The rule fires on any ``<recv>.<method>(...)`` call where
        ``<method>`` is one of :data:`_PATTERN_STORE_WRITE_METHODS` and
        the receiver's terminal name matches a pattern-store shape
        (:func:`_pattern_store_receiver_tail`). Files that OWN the
        write path (:data:`_PATTERN_STORE_SELF_EXEMPT_SUFFIXES`) are
        skipped; this file self-exempts because its rule strings
        name the methods.
        """
        normalized = self.filename.replace("\\", "/")
        if normalized.endswith("tools/honesty_audit.py"):
            return
        for suffix in _PATTERN_STORE_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in _PATTERN_STORE_WRITE_METHODS:
                continue
            tail = _pattern_store_receiver_tail(func.value)
            if tail is None:
                continue
            self._emit(
                node.lineno,
                "ungated_self_improvement_write",
                (
                    f"ungated_self_improvement_write: {tail}.{func.attr}(...) "
                    "writes a pattern-store row outside ExperienceWriter -- "
                    "route the write through ExperienceWriter.record(verdict=...) "
                    "so the RFC-08 eval + quorum gate signs the pattern"
                ),
            )

    def _check_self_labeled_reward(self, tree: ast.Module) -> None:
        """Rule 56: self_labeled_reward -- an agent runtime file sets
        its own reward / promotion score used for promotion.

        RFC-08's gate consumes reviewer-produced signals only. An
        agent that passes ``reward=`` / ``self_score=`` / ``agent_score=``
        kwargs (or assigns ``.reward = <x>`` on a record) writes the
        promotion field itself and short-circuits the gate. Confidence
        signals the LLM emits for its own reasoning are outside this
        set; the names in :data:`_SELF_LABELED_REWARD_NAMES` are the
        specific promotion-input shapes RFC-08 forbids.

        Scope: any file under ``platform/agents/`` or
        ``modules/*/agents/`` per :data:`_AGENT_RUNTIME_SCOPE_PATTERN`.
        Tests + eval-harness code that scores an agent for research
        purposes live outside these paths and are correctly out of
        scope.
        """
        normalized = self.filename.replace("\\", "/")
        if not _AGENT_RUNTIME_SCOPE_PATTERN.search(normalized):
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in _SELF_LABELED_REWARD_NAMES:
                        self._emit(
                            kw.value.lineno,
                            "self_labeled_reward",
                            (
                                f"self_labeled_reward: agent code passes "
                                f"'{kw.arg}=' as a promotion signal -- the RFC-08 "
                                "gate consumes reviewer-produced quorum outcomes, "
                                "not agent-labelled reward / score fields"
                            ),
                        )
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr in _SELF_LABELED_REWARD_NAMES
                    ):
                        self._emit(
                            target.lineno,
                            "self_labeled_reward",
                            (
                                f"self_labeled_reward: agent code assigns to "
                                f"'.{target.attr}' as a promotion signal -- the "
                                "RFC-08 gate reads reviewer-produced quorum "
                                "outcomes, not agent-set reward / score fields"
                            ),
                        )
            elif isinstance(node, ast.AnnAssign):
                target = node.target
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr in _SELF_LABELED_REWARD_NAMES
                    and node.value is not None
                ):
                    self._emit(
                        node.lineno,
                        "self_labeled_reward",
                        (
                            f"self_labeled_reward: agent code annotates + "
                            f"assigns '.{target.attr}' as a promotion signal -- "
                            "the RFC-08 gate reads reviewer-produced quorum "
                            "outcomes, not agent-set reward / score fields"
                        ),
                    )

    def _check_unversioned_config_promotion(self, tree: ast.Module) -> None:
        """Rule 57: unversioned_config_promotion -- a function writes a
        threshold-shaped config value without a versioned proposal row.

        RFC-08's propose-and-gate contract is that a live threshold only
        ever moves behind a :class:`CalibrationProposalRecord`. A function
        that calls ``.set("<x>_threshold", value)`` /
        ``.set("<x>_ceiling", value)`` / any threshold-shape key without
        also referencing :class:`CalibrationProposalRecord` or
        :class:`CalibrationProposer` in the same body is bumping the
        floor without leaving a reversible audit row -- exactly the
        drift RFC-08 exists to prevent.

        The rule fires per function so a helper that both drafts a
        proposal AND persists it (which references CalibrationProposal /
        CalibrationProposer) clears the check on the whole body. The
        calibration file itself is the canonical writer and is exempt;
        alembic migrations are skipped by the generic alembic guard.
        """
        normalized = self.filename.replace("\\", "/")
        for suffix in _CALIBRATION_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            first_hit: tuple[int, str] | None = None
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                if not (
                    isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "set"
                ):
                    continue
                key_node: ast.expr | None = None
                if sub.args:
                    key_node = sub.args[0]
                else:
                    for kw in sub.keywords:
                        if kw.arg == "key":
                            key_node = kw.value
                            break
                key_text = _string_constant_value(key_node)
                if key_text is None:
                    continue
                low = key_text.lower()
                if not any(tok in low for tok in _THRESHOLD_KEY_TOKENS):
                    continue
                first_hit = (sub.lineno, key_text)
                break
            if first_hit is None:
                continue
            body_ids = _identifier_names_in_body(node)
            if body_ids & _CALIBRATION_JOURNAL_MARKERS:
                continue
            line, key = first_hit
            self._emit(
                line,
                "unversioned_config_promotion",
                (
                    f"unversioned_config_promotion: '{node.name}' bumps a "
                    f"threshold-shaped config value ({key!r}) without "
                    "referencing CalibrationProposalRecord / CalibrationProposer "
                    "in the same body -- RFC-08 requires the change to sit "
                    "behind a versioned, reversible proposal row"
                ),
            )

    def _check_inline_prompt_literal(self, tree: ast.Module) -> None:
        """Rule 58: inline_prompt_literal -- a module-level ``_*_PROMPT*``
        constant binds a multi-line prompt string.

        RFC-09 puts prompt text under a resolver (:class:`PromptRegistry`
        reading a versioned ``.md`` file) so cost / seal / audit rows
        carry the resolved ``prompt_content_hash`` + ``prompt_version``.
        A multi-line literal bound to a module constant sidesteps that
        resolver: every call using it stamps a NULL prompt_version and
        the (cost, prompt) join goes empty on the row.

        The rule fires on a module-body Assign whose target name
        contains the uppercase token ``PROMPT`` and whose value is a
        string Constant with 3+ newlines and 200+ characters. Python's
        parser folds a parenthesised implicit-concat literal to a
        single Constant, so ``_SYSTEM_PROMPT = ("foo " "bar")`` and
        ``_SYSTEM_PROMPT = \"\"\"foo\\nbar\"\"\"`` both match without a
        special JoinedStr traversal.
        """
        normalized = self.filename.replace("\\", "/")
        for suffix in _INLINE_PROMPT_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            target_name: str | None = None
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and _INLINE_PROMPT_NAME_TOKEN in target.id
                ):
                    target_name = target.id
                    break
            if target_name is None:
                continue
            text = _string_constant_value(node.value)
            if text is None:
                continue
            if text.count("\n") < _INLINE_PROMPT_MIN_NEWLINES:
                continue
            if len(text) < _INLINE_PROMPT_MIN_LENGTH:
                continue
            self._emit(
                node.lineno,
                "inline_prompt_literal",
                (
                    f"inline_prompt_literal: module-level '{target_name}' "
                    f"binds a multi-line prompt string "
                    f"({text.count(chr(10)) + 1} lines); RFC-09 requires "
                    "prompts to be resolved through PromptRegistry from a "
                    "versioned .md file so cost / seal rows carry the "
                    "prompt_content_hash + prompt_version stamp"
                ),
            )

    def _check_untagged_llm_call(self, tree: ast.Module) -> None:
        """Rule 59: untagged_llm_call -- an LLM entry-point call reaches
        the model without ``correlation_scope`` / ``idempotent_llm_call``.

        RFC-09's join between cost and prompt runs through two
        columns: ``prompt_content_hash`` + ``prompt_version`` on
        :class:`LLMCostRecord` and :class:`AuditSealRecord`. Those
        values are stamped by ``correlation_scope(prompt_content_hash=,
        prompt_version=)`` (or its wrapper :func:`idempotent_llm_call`,
        which reads the ContextVar and stamps itself). A raw
        ``.chat(...)`` / ``.chat_json(...)`` / ``.chat_structured(...)``
        outside either wrapper reaches the client with NULL
        attribution -- the resulting row cannot be joined back to the
        prompt that produced it.

        The rule walks each function scope, collects every LLM entry-
        point call in the body, and fires on the first when no tag
        marker (:data:`_LLM_TAG_MARKERS`) appears anywhere in the
        enclosing function. Files whose whole purpose is to OWN the
        entry point (client, idempotent wrapper, routing) are exempt
        via :data:`_LLM_TAG_SELF_EXEMPT_SUFFIXES`.
        """
        normalized = self.filename.replace("\\", "/")
        for suffix in _LLM_TAG_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        parents = _build_parent_map(tree)
        # Group hits by enclosing function so a single function that
        # makes many raw chat calls fires only once (on the first).
        per_function: dict[int, tuple[int, str]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _LLM_CHAT_METHODS
            ):
                continue
            enclosing = _enclosing_function(node, parents)
            if enclosing is None:
                continue
            body_ids = _identifier_names_in_body(enclosing)
            if body_ids & _LLM_TAG_MARKERS:
                continue
            key = id(enclosing)
            if key in per_function:
                continue
            per_function[key] = (node.lineno, node.func.attr)
        for func_id, (line, method) in per_function.items():
            # func_id is retained above so a later shape can name the
            # function; the current message identifies the file+line.
            del func_id
            self._emit(
                line,
                "untagged_llm_call",
                (
                    f"untagged_llm_call: .{method}(...) is called without "
                    "correlation_scope(prompt_content_hash=, prompt_version=) "
                    "or idempotent_llm_call(...) in the enclosing function "
                    "body -- RFC-09 requires every LLM call to stamp the "
                    "prompt_content_hash + prompt_version so cost / seal rows "
                    "carry the attribution"
                ),
            )

    def _check_unaudited_alias_flip(self, tree: ast.Module) -> None:
        """Rule 60: unaudited_alias_flip -- a function writes a
        :class:`PromptAliasRecord` without also writing a matching
        :class:`PromptAliasChangeRecord`.

        :class:`PromptAliasRecord` is the mutable pointer;
        :class:`PromptAliasChangeRecord` is the append-only audit row.
        The canonical writer is ``PromptVersionStore.set_alias()`` --
        which does both in one transaction. Any function that
        constructs / adds / raw-UPDATEs the alias row without also
        emitting the change row has drifted from that pair-write and
        reopens the audit gap RFC-09 closed.

        The rule fires on any function-scope body that references
        :class:`PromptAliasRecord` (name in identifiers or a raw SQL
        literal touching ``prompt_aliases``) without also referencing
        :class:`PromptAliasChangeRecord`. The version_store file
        itself and alembic migrations are exempt.
        """
        normalized = self.filename.replace("\\", "/")
        for suffix in _ALIAS_FLIP_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body_ids = _identifier_names_in_body(node)
            writes_alias = _PROMPT_ALIAS_RECORD_NAME in body_ids
            raw_sql_line: int | None = None
            if not writes_alias:
                for sub in ast.walk(node):
                    if not (
                        isinstance(sub, ast.Constant)
                        and isinstance(sub.value, str)
                    ):
                        continue
                    low = sub.value.lower()
                    if _PROMPT_ALIAS_TABLE_NAME not in low:
                        continue
                    if "update " in low or "insert " in low or "into " in low:
                        raw_sql_line = sub.lineno
                        break
            if not writes_alias and raw_sql_line is None:
                continue
            if _PROMPT_ALIAS_CHANGE_RECORD_NAME in body_ids:
                continue
            hit_line = node.lineno if raw_sql_line is None else raw_sql_line
            self._emit(
                hit_line,
                "unaudited_alias_flip",
                (
                    f"unaudited_alias_flip: '{node.name}' writes "
                    f"{_PROMPT_ALIAS_RECORD_NAME} / prompt_aliases without "
                    "also emitting PromptAliasChangeRecord in the same body; "
                    "route alias flips through PromptVersionStore.set_alias() "
                    "or mirror its pair-write so the audit log stays complete"
                ),
            )

    def _check_promotion_without_gate(self, tree: ast.Module) -> None:
        """Rule 61: promotion_without_gate -- a function flips a version
        to production without the eval + quorum gate.

        The canonical promotion path is
        :meth:`AgentLifecycleController.promote`, which enforces two
        checks before ``set_alias(..., PRODUCTION_ALIAS, ...)``:

            1. ``_passing_evaluate(key, version)`` returned a
               passing eval verdict; and
            2. ``_distinct_approver_count(key, version) >=
               agent_promotion_quorum``.

        A function that constructs
        ``LifecycleTransitionRecord(to_stage=LifecycleStage.PRODUCTION)``
        or calls ``set_alias(..., "production", ...)`` outside the
        controller AND without any gate marker in its body
        (:data:`_PROMOTE_GATE_MARKERS`) is promoting without the gate.
        The controller itself and :class:`EvalRunner` (whose
        ``auto_promote`` path IS the gate on its own call) are exempt
        via :data:`_LIFECYCLE_CONTROLLER_SELF_EXEMPT_SUFFIXES`.
        """
        normalized = self.filename.replace("\\", "/")
        for suffix in _LIFECYCLE_CONTROLLER_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            hit_line: int | None = None
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                if (
                    _is_production_transition_construct(sub)
                    or _is_production_alias_flip(sub)
                ):
                    hit_line = sub.lineno
                    break
            if hit_line is None:
                continue
            body_ids = _identifier_names_in_body(node)
            if body_ids & _PROMOTE_GATE_MARKERS:
                continue
            self._emit(
                hit_line,
                "promotion_without_gate",
                (
                    f"promotion_without_gate: '{node.name}' flips a version "
                    "to production without referencing the eval + quorum gate "
                    "(_passing_evaluate, _distinct_approver_count, EvalRunner, "
                    "agent_promotion_quorum, AgentLifecycleController) -- "
                    "route through AgentLifecycleController.promote() (RFC-10)"
                ),
            )

    def _check_untransitioned_stage_change(self, tree: ast.Module) -> None:
        """Rule 62: untransitioned_stage_change -- a function assigns a
        :class:`LifecycleStage` value without writing a
        :class:`LifecycleTransitionRecord`.

        The RFC-10 stage machine is journaled: every observed stage
        change appends a row to ``lifecycle_transitions`` so the
        history answers "who moved this version to <stage> and when?"
        without replay. A function that writes
        ``.lifecycle_stage = LifecycleStage.<X>`` or passes
        ``to_stage=LifecycleStage.<X>`` / ``stage=LifecycleStage.<X>``
        to a call that is NOT the transition constructor / journaler
        has drifted from that history and needs a matching journal
        write in the same body.

        The controller file itself is exempt because it OWNS the
        journaler; every other stage-writer must mirror the
        constructor + journal pair.
        """
        normalized = self.filename.replace("\\", "/")
        for suffix in _LIFECYCLE_CONTROLLER_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stage_hits: list[int] = []
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign):
                    if not _references_lifecycle_stage(sub.value):
                        continue
                    for tgt in sub.targets:
                        if (
                            isinstance(tgt, ast.Attribute)
                            and tgt.attr in _LIFECYCLE_STAGE_KWARGS
                        ):
                            stage_hits.append(sub.lineno)
                            break
                elif isinstance(sub, ast.Call):
                    callee = _call_callee_simple_name(sub)
                    if callee in (
                        _LIFECYCLE_TRANSITION_RECORD_NAME,
                        _LIFECYCLE_JOURNAL_METHOD_NAME,
                    ):
                        continue
                    for kw in sub.keywords:
                        if (
                            kw.arg in _LIFECYCLE_STAGE_KWARGS
                            and _references_lifecycle_stage(kw.value)
                        ):
                            stage_hits.append(sub.lineno)
                            break
            if not stage_hits:
                continue
            body_ids = _identifier_names_in_body(node)
            if _LIFECYCLE_TRANSITION_RECORD_NAME in body_ids:
                continue
            call_names = _call_names_in_body(node)
            if _LIFECYCLE_JOURNAL_METHOD_NAME in call_names:
                continue
            self._emit(
                stage_hits[0],
                "untransitioned_stage_change",
                (
                    f"untransitioned_stage_change: '{node.name}' assigns a "
                    "LifecycleStage value without constructing a "
                    "LifecycleTransitionRecord or calling _journal(...) in "
                    "the same body -- every stage move must be journaled "
                    "(RFC-10)"
                ),
            )

    def _check_canary_below_min_sample(self, tree: ast.Module) -> None:
        """Rule 63: canary_below_min_sample -- a canary promotion path
        has no min-sample gate marker.

        RFC-10's canary contract is that promoting a candidate that
        never observed enough traffic is structurally impossible. A
        function whose name is on the canary-promotion API
        (:data:`_CANARY_PROMOTE_MARKERS`) must reference a
        min-sample identifier / call name (:data:`_CANARY_MIN_SAMPLE_MARKERS`)
        in its body so a reviewer sees the check.

        The check is name-based on the RFC-10 API surface. The audit
        tool self-exempts because its own rule strings name the
        markers.
        """
        normalized = self.filename.replace("\\", "/")
        if normalized.endswith("tools/honesty_audit.py"):
            return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _function_name_matches(node.name, _CANARY_PROMOTE_MARKERS):
                continue
            body_ids = _identifier_names_in_body(node)
            if body_ids & _CANARY_MIN_SAMPLE_MARKERS:
                continue
            call_names = _call_names_in_body(node)
            if call_names & _CANARY_MIN_SAMPLE_MARKERS:
                continue
            # A string-constant ConfigRegistry key literal also counts
            # (a function reading ``platform.agent_canary_min_sample``
            # via ``.get("platform", "agent_canary_min_sample")`` names
            # the marker as a Constant, not an identifier).
            has_key_literal = False
            for sub in ast.walk(node):
                text = _string_constant_value(sub)
                if text is None:
                    continue
                if text in _CANARY_MIN_SAMPLE_MARKERS:
                    has_key_literal = True
                    break
            if has_key_literal:
                continue
            self._emit(
                node.lineno,
                "canary_below_min_sample",
                (
                    f"canary_below_min_sample: canary promotion function "
                    f"'{node.name}' has no min-sample gate marker "
                    "(min_sample, min_samples, min_canary_sample, "
                    "sample_count, signal_count, agent_canary_min_sample) "
                    "in its body -- RFC-10 requires canary promotion to "
                    "verify a minimum observed-signal count before flipping"
                ),
            )

    def _check_second_embedding_path(self, tree: ast.Module) -> None:
        """Rule 64: second_embedding_path -- an embedding provider is
        constructed or selected outside the canonical embedding +
        knowledge service files.

        RFC-12 / #37 require ONE embedding path: a second provider
        writing vectors into the shared knowledge table makes
        cross-model cosine similarity meaningless. The embedding
        factory (:mod:`platform/services/embedding.py`) and the
        service that owns the store (:mod:`platform/services/
        knowledge.py`) are the only files that may build a provider.
        """
        normalized = self.filename.replace("\\", "/")
        if any(normalized.endswith(s) for s in _EMBEDDING_PATH_SELF_EXEMPT_SUFFIXES):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_callee_simple_name(node)
            if name in _EMBEDDING_PROVIDER_CALLEES:
                self._emit(
                    node.lineno,
                    "second_embedding_path",
                    (
                        f"second_embedding_path: embedding provider '{name}' "
                        "constructed outside the canonical embedding/knowledge "
                        "service -- a second embedding path writes incompatible "
                        "vectors into the shared table (#37); embed through "
                        "KnowledgeService.embed"
                    ),
                )

    def _check_vector_without_provenance(self, tree: ast.Module) -> None:
        """Rule 65: vector_without_provenance -- a KnowledgeEntryRecord is
        constructed with an embedding but no model_id.

        RFC-12 / #37 require every stored vector to carry its
        provenance (``model_id``) so a model swap triggers a re-embed
        sweep instead of silently invalidating the corpus. A record
        built with an ``embedding=`` kwarg but no ``model_id=`` kwarg
        stores an un-attributed vector.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_callee_simple_name(node) != _KNOWLEDGE_RECORD_NAME:
                continue
            kwargs = {kw.arg for kw in node.keywords if kw.arg}
            if "embedding" in kwargs and "model_id" not in kwargs:
                self._emit(
                    node.lineno,
                    "vector_without_provenance",
                    (
                        f"vector_without_provenance: {_KNOWLEDGE_RECORD_NAME} "
                        "constructed with an embedding but no model_id -- a "
                        "stored vector without provenance is silently "
                        "invalidated by a model swap (#37)"
                    ),
                )

    def _check_retrieval_without_gate(self, tree: ast.Module) -> None:
        """Rule 66: retrieval_without_gate -- agent-scope code calls the
        raw hybrid retrieve instead of the gated routed path.

        RFC-12 / #43: the raw ``.retrieve(`` returns ungated,
        unfloored hits; only ``retrieve_routed`` applies the relevance
        floor + sanitize/classify gate. Agent-runtime code
        (``platform/agents/**`` or ``modules/*/agents/**``) that
        reaches the knowledge base must go through the routed path so
        retrieved content is floored + sanitised before it can enter
        a prompt.
        """
        if not _AGENT_RUNTIME_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == _RAW_RETRIEVE_METHOD:
                self._emit(
                    node.lineno,
                    "retrieval_without_gate",
                    (
                        "retrieval_without_gate: agent-scope code calls raw "
                        "'.retrieve(' -- use 'retrieve_routed' so retrieved "
                        "hits are relevance-floored and sanitize/classify "
                        "gated before reaching a prompt (#43)"
                    ),
                )

    def _check_unsanitized_retrieved_content(self, tree: ast.Module) -> None:
        """Rule 67: unsanitized_retrieved_content -- the routed retrieval
        entry point stops applying the sanitize/classify gate.

        RFC-12 / #43: ``retrieve_routed`` is the single agent-facing
        retrieval entry, and every hit it returns MUST pass
        ``apply_gate`` / ``apply_gate_many`` so ``sanitized_content``
        is guaranteed. A ``retrieve_routed`` definition whose body no
        longer references the gate would hand raw retrieved content to
        a caller that emits it into a prompt.
        """
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != _ROUTED_RETRIEVE_METHOD:
                continue
            if _call_names_in_body(node) & _KNOWLEDGE_GATE_CALLS:
                continue
            self._emit(
                node.lineno,
                "unsanitized_retrieved_content",
                (
                    f"unsanitized_retrieved_content: '{_ROUTED_RETRIEVE_METHOD}' "
                    "does not apply the sanitize/classify gate (apply_gate / "
                    "apply_gate_many) -- retrieved content would reach a prompt "
                    "unsanitised (#43)"
                ),
            )


class HonestyAuditor:
    """Audit one or more Python source files for structural dishonesty.

    Runs as a pre-commit CI gate: ``python -m aila.tools.honesty_audit src/``
    exits with code 1 if any finding is reported, 0 if clean.  Run with
    ``--whitelist honesty_whitelist.py`` to suppress known acceptable violations.

    The whitelist file (honesty_whitelist.py at the project root) defines
    HONESTY_WHITELIST as a list of (filename_suffix, function_name, detail) string
    triples.  A finding is suppressed when all three fields match -- this prevents
    accidentally suppressing findings in other files with the same function name.

    All analysis is AST-based (D-04 constraint): no imports are executed, no
    runtime state is inspected.  This makes the auditor safe to run on any Python
    file regardless of its dependencies.

    Args:
        whitelist: Set of (filename_suffix, function_name, detail) triples
            that suppress matching findings.  Load via ``load_whitelist(path)``
            or pass an empty set (or None) to disable suppression.
    """

    def __init__(self, whitelist: Whitelist | None = None) -> None:
        self._whitelist: Whitelist = whitelist if whitelist is not None else set()

    def audit_file(self, path: Path) -> list[Finding]:
        """Parse *path* and return all honesty findings (unsuppressed)."""
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return []

        visitor = _HonestyVisitor(filename=str(path), whitelist=self._whitelist)
        visitor.visit(tree)
        # Module-level checks (not per-function)
        visitor._check_private_in_all(tree)
        visitor._check_bare_exception_wrap(tree)
        visitor._check_todo_in_code(source)
        visitor._check_silent_exception(tree)
        visitor._check_production_assert(tree)
        visitor._check_sync_session_in_async(tree)
        module_id = _owning_module_id(str(path))
        if module_id is not None:
            visitor._check_import_boundary(tree, module_id)
            visitor._check_hoisted_enum_redeclared(tree, module_id)
            visitor._check_unnamed_derived_constraint(tree, module_id)
            visitor._check_shadowed_platform_base(tree, module_id)
            visitor._check_service_copy_of_platform(tree)
            visitor._check_workflow_state_copy_of_platform(tree)
            visitor._check_cost_read_stored_actual(tree, module_id)
            visitor._check_lifecycle_handler_bypass(tree, module_id)
            visitor._check_agent_primitive_reimplementation(tree)
            visitor._check_agent_llm_chat_bypass(tree)
            visitor._check_agent_env_read(tree)
        if _is_boundary_guarded_file(str(path)):
            visitor._check_api_imports_modules(tree)
            visitor._check_platform_names_module(tree)
        if _is_module_file(str(path)):
            visitor._check_module_session_scope_import(tree)
            visitor._check_asyncio_in_module(tree)
            visitor._check_http_client_in_module(tree)
            visitor._check_direct_db_in_module(tree)
            visitor._check_private_platform_import(tree)
            visitor._check_raw_sql_platform_tables(tree)
        # Rules 19 and 20 apply to all router files (api/ and module routers alike)
        visitor._check_response_model_dict(tree)
        visitor._check_bare_dict_return_endpoint(tree)
        # Rule 21 applies to all Python source files (self-exemption handled inside)
        visitor._check_noqa_inline(source, str(path))
        # Rules 24–33: AI slop detection (apply to all Python source files)
        visitor._check_tautological_docstring(tree)
        visitor._check_commented_out_code(source, str(path))
        visitor._check_except_return_default(tree)
        visitor._check_nested_if_collapsible(tree)
        visitor._check_pointless_pass(tree)
        visitor._check_f_string_no_interpolation(tree)
        visitor._check_single_use_variable(tree)
        visitor._check_placeholder_return(tree)
        visitor._check_log_format_concat(tree)
        visitor._check_broad_exception_catch(tree)
        visitor._check_config_schema_base(tree)
        visitor._check_module_prefix_in_tool_name(tree)
        visitor._check_platform_owns_event_vocabulary(tree)
        # Rules 50-51: RFC-13 static-graph + ledger-encapsulation invariants
        # (apply to all Python source files; ledger rule self-exempts).
        visitor._check_static_node_mutation(tree)
        visitor._check_ledger_write_encapsulation(tree)
        # Rules 52-54: RFC-07 fail-closed posture, infra-death gating,
        # heal-writes-journal. Every file is in scope; each rule
        # self-exempts the files that would otherwise trip themselves
        # by owning the primitives the rule locks in.
        visitor._check_fail_open_recovery_path(tree)
        visitor._check_close_without_infra_classification(tree)
        visitor._check_heal_without_journal(tree)
        # Rules 55-63: RFC-08 self-improvement, RFC-09 prompt registry,
        # RFC-10 lifecycle. Each rule self-exempts the files that OWN
        # the primitive it locks in (ExperienceWriter, PromptVersionStore,
        # AgentLifecycleController, EvalRunner).
        visitor._check_ungated_self_improvement_write(tree)
        visitor._check_self_labeled_reward(tree)
        visitor._check_unversioned_config_promotion(tree)
        visitor._check_inline_prompt_literal(tree)
        visitor._check_untagged_llm_call(tree)
        visitor._check_unaudited_alias_flip(tree)
        visitor._check_promotion_without_gate(tree)
        visitor._check_untransitioned_stage_change(tree)
        visitor._check_canary_below_min_sample(tree)
        # Rules 64-67: RFC-12 knowledge-base integrity + retrieval gate.
        # Every file is in scope; each rule self-exempts or scopes to the
        # surface it locks in.
        visitor._check_second_embedding_path(tree)
        visitor._check_vector_without_provenance(tree)
        visitor._check_retrieval_without_gate(tree)
        visitor._check_unsanitized_retrieved_content(tree)
        return visitor.findings

    def audit_directory(self, directory: Path) -> list[Finding]:
        """Recursively audit all *.py files under *directory*."""
        findings: list[Finding] = []
        for py_file in sorted(directory.rglob("*.py")):
            findings.extend(self.audit_file(py_file))
        return findings


# ---------------------------------------------------------------------------
# __main__ entrypoint
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> tuple[Path, Path | None]:
    """Return (target_dir, whitelist_path | None) from *argv*."""
    if not argv:
        _log.error("Usage: python -m aila.tools.honesty_audit <directory> [--whitelist <path>]")
        sys.exit(2)

    target = Path(argv[0])
    whitelist_path: Path | None = None

    i = 1
    while i < len(argv):
        if argv[i] == "--whitelist" and i + 1 < len(argv):
            whitelist_path = Path(argv[i + 1])
            i += 2
        else:
            i += 1

    return target, whitelist_path


_DEFAULT_WHITELIST_NAMES: tuple[str, ...] = (
    "honesty_whitelist.py",
    "src/aila/tools/honesty_whitelist.py",
)


def _find_default_whitelist(target: Path) -> Path | None:
    """Look for honesty_whitelist.py relative to the target directory or cwd.

    Walks up from the target directory looking for the project root (where
    pyproject.toml lives), then checks standard locations.
    """
    # Walk up to find project root (contains pyproject.toml or src/)
    candidates = [target] + list(target.parents)
    for directory in candidates:
        for name in _DEFAULT_WHITELIST_NAMES:
            candidate = directory / name
            if candidate.exists():
                return candidate
    return None


def _main(argv: list[str]) -> int:
    """CLI entrypoint: audit target and print findings to stdout.

    When no --whitelist argument is given, automatically searches for
    honesty_whitelist.py relative to the target directory. This allows
    ``python -m aila.tools.honesty_audit src/`` to automatically load
    the project whitelist without requiring an explicit --whitelist flag.

    Args:
        argv: Command-line arguments excluding the script name.

    Returns:
        Exit code: 0 if no findings, 1 if findings exist, 2 on usage error.
    """
    target, whitelist_path = _parse_args(argv)

    # Auto-discover whitelist if not explicitly specified
    if whitelist_path is None:
        whitelist_path = _find_default_whitelist(target)
        if whitelist_path is not None:
            _log.debug("honesty_audit: auto-loaded whitelist from %s", whitelist_path)

    whitelist: Whitelist = set()
    if whitelist_path is not None:
        if not whitelist_path.exists():
            _log.error("whitelist file not found: %s", whitelist_path)
            return 2
        whitelist = load_whitelist(whitelist_path)

    auditor = HonestyAuditor(whitelist=whitelist)

    if target.is_file():
        findings = auditor.audit_file(target)
    elif target.is_dir():
        findings = auditor.audit_directory(target)
    else:
        _log.error("target not found: %s", target)
        return 2

    for f in findings:
        _log.warning("%s:%d: [%s] %s", f.file, f.line, f.rule, f.message)

    return 1 if findings else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    sys.exit(_main(sys.argv[1:]))
