"""RFC #148 -- platform symbolic-execution driver.

Concolic exploration of a single function under an operator-supplied
precondition. The driver runs miasm's DSE (dynamic symbolic execution)
engine over the function's bytes, records the reached basic-block
addresses + emitted path constraints, and pipes ONE
``symbolic.reached`` observation into the SAME platform observation
channel (RFC #137,
:func:`aila.platform.agents.observation.record_observation`) that the
``fuzz.*`` kinds already feed. Hypothesis kill-criteria scanning the
workspace-scoped ``{module}.observation.workspace.{workspace_id}``
knowledge bucket for ``fuzz.*`` rows consume ``symbolic.reached``
without any new plumbing -- same writer, same namespace shape, same
retrieval path.

Design contract
---------------
* **Optional dep.** Miasm is behind the ``[symbolic]`` extra in
  ``pyproject.toml``. Every miasm import is guarded by a call-time
  ``try/except ImportError`` so a base install (no extra) still
  imports this module cleanly and every :func:`explore` invocation
  returns :attr:`ExplorationStatus.UNAVAILABLE` instead of raising.
* **Config flag.** Gated by ``platform.symbolic_enabled`` (default
  False, behavior-preserving). With the flag OFF, :func:`explore`
  short-circuits to :attr:`ExplorationStatus.DISABLED` WITHOUT
  attempting the miasm import -- so a base install pays exactly
  nothing on the hot path.
* **No new table, no migration.** Observations land through the
  existing RFC #137 writer at
  ``{module}.observation.workspace.{workspace_id}``. Dedup identity
  is ``(module, workspace, subject, "symbolic.reached")`` so
  re-exploring the same function with a fresh precondition upserts
  the row (matches the ``fuzz.*`` behaviour on the same channel).
* **Never raises.** A miasm exception (invalid arch, malformed
  bytes, jitter runtime fault, DSE state error) is caught by a
  module-level SPECIFIC-exception tuple, converted to
  :attr:`ExplorationStatus.ERROR`, and returned. The caller's main
  path is never broken by a symbolic-execution defect.
* **Scope v1.** Single-function concolic constraint emission on a
  function whose bytes + arch + entry address are supplied by the
  caller. Whole-program exploration (inter-procedural walk, library-
  call modelling, syscall summaries, section stitching) is deferred
  to a later ``explore_program`` sibling that reuses the same
  observation writer.

SEAM: this driver expects the caller to supply the function bytes.
The AILA malware / VR path today reaches miasm through the
``ida_headless.miasm_emulate`` MCP tool; a follow-up should add a
platform helper that fetches bytes from an audit-mcp / ida-headless
adapter and hands them to :func:`explore` so the reasoning loop can
kick a concolic run without an operator marshalling bytes by hand.
That helper is NOT this slice.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.agents.observation import (
    ObservationPolarity,
    PlatformObservation,
    record_observation,
)
from aila.storage.registry import ConfigRegistry

__all__ = [
    "ExplorationResult",
    "ExplorationStatus",
    "FunctionRef",
    "Precondition",
    "SYMBOLIC_REACHED_KIND",
    "explore",
]

_log = logging.getLogger(__name__)

# The observation ``kind`` string is a stable public contract: it names
# the row shape hypothesis kill-criteria filter on. Exported so callers
# and tests can reference the exact value without re-typing the literal.
SYMBOLIC_REACHED_KIND: str = "symbolic.reached"

# SPECIFIC-exception tuple used to catch miasm faults without violating
# the "never bare ``except Exception``" rule. Miasm signals architecture
# / decoding / jitter faults through a mixed set of standard-library
# exceptions (no shared miasm base class covers every failure mode
# across the arch backends). The tuple is fail-CLOSED: any listed
# fault converts to :attr:`ExplorationStatus.ERROR` and returns
# cleanly, so the caller's tool-dispatch path is never broken.
_MIASM_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    MemoryError,
    NotImplementedError,
    AssertionError,
)


class ExplorationStatus(StrEnum):
    """Discriminator on :class:`ExplorationResult`.

    ``UNAVAILABLE`` and ``DISABLED`` are BOTH clean no-ops -- neither
    emits an observation, neither logs a warning. They tell the caller
    which of the two gates short-circuited so a health probe can
    distinguish "operator has not flipped the flag" from "operator
    flipped the flag but the ``[symbolic]`` extra is missing on this
    host".
    """

    # Flag is on but ``miasm`` is not importable in this process
    # (the ``[symbolic]`` extra is not installed on this host).
    UNAVAILABLE = "unavailable"
    # ``platform.symbolic_enabled`` is False. Byte-identical to the
    # pre-#148 path: no miasm import attempted, no observation
    # written, no warning logged.
    DISABLED = "disabled"
    # Miasm was imported and the driver started, but a fault inside
    # the concolic run raised. ``error`` is populated with the
    # exception's class + message. No observation is written on this
    # path -- a malformed exploration is not a fact worth persisting.
    ERROR = "error"
    # A concolic run completed and produced reachability +/- constraint
    # material. ``observation_id`` is populated when the observation
    # writer accepted the row.
    SUCCESS = "success"


class FunctionRef(BaseModel):
    """Reference to a single function the driver should explore.

    The caller supplies enough for miasm to load the bytes into a
    fresh jitter without I/O: ``code_bytes`` + ``entry_address`` +
    ``arch``. ``module`` + ``workspace_id`` scope the emitted
    observation to the same workspace-scoped knowledge bucket the
    ``fuzz.*`` kinds already write to.
    """

    model_config = ConfigDict(extra="forbid")

    # Owning module id -- matches ``_bridge_module_id`` on the
    # tool executor (``vr``, ``malware``, ...). Used to derive the
    # observation namespace via
    # :func:`aila.platform.agents.observation.observation_namespace`.
    module: str = Field(min_length=1, max_length=32)
    # Workspace scope this exploration belongs to. Same value the
    # module's retrieval path resolves off the investigation ->
    # target -> workspace chain.
    workspace_id: str = Field(min_length=1, max_length=64)
    # Human-readable symbol name (e.g. ``"sub_401000"`` or
    # ``"parse_header"``). Combined with ``entry_address`` to form
    # the observation subject; also used verbatim in the observation
    # content body so downstream retrieval matches on it.
    symbol_name: str = Field(min_length=1, max_length=128)
    # Miasm architecture string (e.g. ``"x86_32"``, ``"x86_64"``,
    # ``"arml"``, ``"aarch64l"``, ``"mips32b"``). Handed straight to
    # :class:`miasm.analysis.machine.Machine`. Invalid strings surface
    # as :attr:`ExplorationStatus.ERROR` -- validation is deferred
    # to miasm to avoid drifting our own arch table.
    arch: str = Field(min_length=1, max_length=32)
    # Byte-offset of the function's first instruction in the flat
    # memory map the jitter allocates. Also the entry point handed to
    # :meth:`jitter.init_run`.
    entry_address: int = Field(ge=0)
    # Raw instruction bytes covering the function body. The driver
    # allocates a single R+W+X page at ``entry_address`` sized to the
    # bytes and copies them in.
    code_bytes: bytes = Field(min_length=1)
    # Optional early-exit address. When the jitter's ``PC`` hits
    # ``end_address`` the exploration terminates cleanly (no error);
    # useful when the caller knows the function's ``ret`` site and
    # wants to bound the walk without waiting for the miasm runtime
    # to detect end-of-function through jit stubs.
    end_address: int | None = None


class Precondition(BaseModel):
    """Operator-supplied initial state for the concolic run.

    Concrete register values seed the jitter; ``symbolic_regs`` and
    ``symbolic_memory`` tell the DSE engine which slots to leave
    unbound so the emitted path constraints are expressed in terms
    of those symbolic inputs. Everything is optional -- an empty
    precondition explores the function under whatever the jitter's
    default init produces, which is a legitimate v1 use case.
    """

    model_config = ConfigDict(extra="forbid")

    # Concrete register values (register name -> integer). Names are
    # matched case-insensitively against the arch's register file
    # (e.g. ``{"eax": 0x41, "ecx": 0}``). Unknown names are logged at
    # DEBUG and skipped so a caller-supplied name that does not
    # correspond to this arch does not tank the whole run.
    initial_regs: dict[str, int] = Field(default_factory=dict)
    # Register names to leave symbolic under the DSE (case-
    # insensitive). Each becomes an ``ExprId`` of the register's
    # native width; downstream path constraints reference these ids
    # so the operator can read them.
    symbolic_regs: list[str] = Field(default_factory=list)
    # Symbolic memory regions. Each entry declares a base address, a
    # byte length, and a caller-friendly name. Bytes inside the
    # region are exposed as ``ExprMem`` -> per-byte ``ExprId``
    # symbols named ``"sym_{name}_{i}"``.
    symbolic_memory: list[dict[str, Any]] = Field(default_factory=list)
    # Wall-clock instruction budget. Reached even in a tight loop:
    # the jitter's per-instruction callback checks this counter and
    # halts the run at the ceiling. Default keeps a run bounded on
    # tight loops so a caller-supplied bogus precondition cannot
    # spin the worker.
    max_steps: int = Field(default=10_000, ge=1)
    # Cap on emitted path-constraint strings. The DSE can produce
    # dozens of assertions per branch; the writer truncates the
    # emitted observation body to this many entries so a large run
    # does not blow the knowledge row's usable size.
    max_constraints: int = Field(default=64, ge=1)


class ExplorationResult(BaseModel):
    """Discriminated-union return of :func:`explore`.

    Every field except ``status`` and ``subject`` is populated only
    on the :attr:`ExplorationStatus.SUCCESS` path (and, for
    ``error``, on :attr:`ExplorationStatus.ERROR`). Callers should
    switch on ``status`` first and read the payload conditionally.
    """

    model_config = ConfigDict(extra="forbid")

    status: ExplorationStatus
    # Stable identity for the explored function -- ``"{module}:{symbol}@0x{addr:x}"``.
    # Used as the observation subject so re-exploration upserts.
    subject: str
    # Distinct basic-block addresses the jitter's per-instruction
    # callback observed during the walk (order preserved).
    reached_addresses: list[int] = Field(default_factory=list)
    # Stringified path constraints from the DSE at the end of the
    # walk. Bounded by :attr:`Precondition.max_constraints`. When the
    # DSE surface is unavailable in the installed miasm version, the
    # list is empty and ``reached_addresses`` still populates.
    path_constraints: list[str] = Field(default_factory=list)
    # Number of instructions the callback observed (matches
    # ``len(reached_addresses)`` for a per-instruction callback; kept
    # separate so a later block-level callback can differ).
    steps_executed: int = 0
    # Populated on :attr:`ExplorationStatus.ERROR`. Shape:
    # ``"<ExcClass>: <message>"``.
    error: str | None = None
    # Populated on :attr:`ExplorationStatus.SUCCESS` when the
    # observation writer accepted the row. ``None`` on writer
    # failure (writer logs at WARNING; the run itself succeeded).
    observation_id: str | None = None


def _compose_subject(fn: FunctionRef) -> str:
    """Stable ``(module, workspace, subject, kind)`` identity fragment.

    Encodes both the symbol and the entry address so two functions
    that happen to share a symbol name in different translation units
    do not collide on the observation writer's dedup key.
    """
    return f"{fn.module}:{fn.symbol_name}@0x{fn.entry_address:x}"


def _compose_content(
    fn: FunctionRef,
    reached: list[int],
    constraints: list[str],
    steps: int,
) -> str:
    """Render the observation body.

    The body is what the knowledge store embeds for semantic recall,
    so it is a self-contained sentence: names the function, its arch,
    the reached block count, and the head of the constraint list.
    Constraints are rendered verbatim so an operator reading the
    retrieved row sees the same expressions the DSE emitted.
    """
    head_addrs = ", ".join(f"0x{a:x}" for a in reached[:8])
    if len(reached) > 8:
        head_addrs += f", ... ({len(reached) - 8} more)"
    body = (
        f"symbolic.reached: concolic run over {fn.symbol_name} "
        f"({fn.arch} @ 0x{fn.entry_address:x}) in workspace "
        f"{fn.workspace_id}. Steps: {steps}. Reached blocks: "
        f"{len(reached)} [{head_addrs or 'none'}]."
    )
    if constraints:
        rendered = "\n".join(f"  - {c}" for c in constraints)
        body += f"\nPath constraints ({len(constraints)}):\n{rendered}"
    else:
        body += "\nPath constraints: (none emitted -- DSE surface returned no assertions)."
    return body


async def _resolve_enabled() -> bool:
    """Read ``platform.symbolic_enabled`` via ConfigRegistry.

    Default False -- an unreadable / missing registry value degrades
    to the DISABLED short-circuit so a base install with a partially
    initialised config store still yields a clean no-op instead of
    raising. Matches the resilience shape used by every other
    platform flag (``otel_enabled``, ``mcp_tool_hash_strict``, ...).
    """
    try:
        raw = await ConfigRegistry().get("platform", "symbolic_enabled")
    except (OSError, RuntimeError, ValueError, TypeError, SQLAlchemyError):
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(raw, int):
        return raw != 0
    return False


def _run_concolic(
    fn: FunctionRef,
    pre: Precondition,
) -> tuple[list[int], list[str], int]:
    """Execute the miasm DSE walk. Raises on any miasm-side fault.

    Isolated in a helper so the miasm imports live behind a single
    try/except in :func:`explore` -- the base install never resolves
    this function's imports unless the flag is on AND miasm is
    present. Returns ``(reached_addresses, path_constraints, steps)``.

    The implementation uses miasm's public DSE surface. Register /
    memory symbolic overlay is defensively wrapped: an unknown register
    name or an unsupported symbolic-memory shape logs at DEBUG and
    skips rather than aborting the whole run, so a caller-supplied
    precondition that partly matches this arch still produces useful
    reachability material.
    """
    # miasm imports are DEFERRED to this call. The base install
    # (without the ``[symbolic]`` extra) never resolves these names,
    # so an ImportError here is genuinely "extra not installed" and
    # is converted to UNAVAILABLE by :func:`explore`.
    from miasm.analysis.dse import DSEEngine
    from miasm.analysis.machine import Machine
    from miasm.core.locationdb import LocationDB
    from miasm.expression.expression import ExprId, ExprInt, ExprMem
    from miasm.jitter.csts import PAGE_EXEC, PAGE_READ, PAGE_WRITE

    loc_db = LocationDB()
    machine = Machine(fn.arch)
    # ``python`` jit is portable and pure-Python -- no gcc/llvm on
    # the host required. Slower than the native backends but the v1
    # scope is a single function, so throughput is not the concern.
    jitter = machine.jitter(loc_db, jit_type="python")

    # One R+W+X page sized to the bytes. The jitter allocates its
    # own stack via ``init_stack``; the caller is not responsible
    # for stack setup.
    jitter.vm.add_memory_page(
        fn.entry_address,
        PAGE_READ | PAGE_WRITE | PAGE_EXEC,
        fn.code_bytes,
    )
    if hasattr(jitter, "init_stack"):
        jitter.init_stack()

    # Concrete register seed. Names are matched case-insensitively
    # against the CPU's attribute table so ``"eax"`` and ``"EAX"``
    # both work; unknown names log at DEBUG and skip.
    cpu_attrs = {name.lower() for name in dir(jitter.cpu)}
    for name, value in pre.initial_regs.items():
        attr = name.lower()
        if attr not in cpu_attrs:
            _log.debug(
                "symbolic.explore: unknown register %r for arch %s -- skipping",
                name, fn.arch,
            )
            continue
        try:
            setattr(jitter.cpu, attr, int(value) & ((1 << 64) - 1))
        except _MIASM_ERRORS as exc:
            _log.debug(
                "symbolic.explore: failed to set register %s=%r: %s",
                name, value, exc,
            )

    # Attach the DSE engine and sync its symbolic state to the
    # jitter's concrete state so unattributed slots start pinned to
    # their concrete values (matches miasm's documented DSE bring-
    # up sequence).
    dse = DSEEngine(machine)
    dse.attach(jitter)
    if hasattr(dse, "update_state_from_concrete"):
        dse.update_state_from_concrete()

    # Symbolic register overlay. Look the register up on the arch's
    # register table (``all_regs_ids_byname`` is the miasm-wide
    # accessor); if it is not present, log + skip.
    ir_arch = machine.ir(loc_db)
    regs_byname = getattr(ir_arch.arch.regs, "all_regs_ids_byname", {})
    for name in pre.symbolic_regs:
        upper = name.upper()
        reg = regs_byname.get(upper) if isinstance(regs_byname, dict) else None
        if reg is None:
            _log.debug(
                "symbolic.explore: unknown symbolic register %r -- skipping",
                name,
            )
            continue
        try:
            dse.update_state({reg: ExprId(f"sym_{upper}", reg.size)})
        except _MIASM_ERRORS as exc:
            _log.debug(
                "symbolic.explore: symbolic overlay for register %s failed: %s",
                name, exc,
            )

    # Symbolic memory overlay -- one ExprId per byte inside each
    # declared region, so path constraints reference individual
    # bytes (matches miasm's fine-grained symbolic-memory shape).
    addr_size = getattr(ir_arch, "addrsize", 32)
    for entry in pre.symbolic_memory:
        try:
            base = int(entry["addr"])
            length = int(entry["size"])
        except (KeyError, TypeError, ValueError) as exc:
            _log.debug(
                "symbolic.explore: malformed symbolic_memory entry %r: %s",
                entry, exc,
            )
            continue
        tag = str(entry.get("name") or f"mem_{base:x}")
        base_expr = ExprInt(base, addr_size)
        for i in range(max(0, length)):
            try:
                mem_expr = ExprMem(base_expr + ExprInt(i, addr_size), 8)
                dse.update_state({mem_expr: ExprId(f"sym_{tag}_{i}", 8)})
            except _MIASM_ERRORS as exc:
                _log.debug(
                    "symbolic.explore: memory overlay failed at 0x%x+%d: %s",
                    base, i, exc,
                )
                break

    reached: list[int] = []
    counter = [0]
    end_pc = fn.end_address
    step_cap = pre.max_steps

    def _step_cb(jitter_local: Any) -> bool:
        """Per-instruction callback -- record PC, enforce budget, honour early-exit."""
        pc = int(getattr(jitter_local, "pc", 0) or 0)
        reached.append(pc)
        counter[0] += 1
        if end_pc is not None and pc == end_pc:
            return False
        if counter[0] >= step_cap:
            return False
        return True

    if hasattr(jitter, "exec_cb"):
        jitter.exec_cb = _step_cb
    if hasattr(jitter, "init_run"):
        jitter.init_run(fn.entry_address)
    if hasattr(jitter, "continue_run"):
        try:
            jitter.continue_run()
        except _MIASM_ERRORS as exc:
            # Miasm signals end-of-code / bad-instruction / decoding
            # faults by raising through ``continue_run``. That is
            # NORMAL termination for a bounded single-function walk:
            # we recorded reachability up to the fault and want to
            # emit whatever the DSE has accumulated. Log at DEBUG
            # and fall through to constraint extraction.
            _log.debug(
                "symbolic.explore: jitter halted mid-walk on %s: %s",
                type(exc).__name__, exc,
            )

    # Constraint extraction. The DSE's constraint surface varies by
    # miasm version; we read the most stable public accessors in
    # order and stringify whatever we can find. Empty on any miasm
    # release whose DSE does not expose z3 assertions -- caller sees
    # ``reached_addresses`` populated + ``path_constraints`` empty,
    # which is still useful reachability material.
    constraints: list[str] = []
    solver = getattr(dse, "cur_solver", None)
    if solver is not None:
        assertions = getattr(solver, "assertions", None)
        if callable(assertions):
            try:
                for expr in assertions():
                    constraints.append(str(expr))
                    if len(constraints) >= pre.max_constraints:
                        break
            except _MIASM_ERRORS as exc:
                _log.debug(
                    "symbolic.explore: solver assertions read failed: %s", exc,
                )
    if not constraints:
        # Fall back to the symbolic-store view: every non-identity
        # binding is a fact the DSE derived (register X is now
        # expression E over the symbolic inputs). Bounded by
        # ``max_constraints`` so a heavily-symbolic run does not
        # dump the whole store.
        symbols = getattr(dse, "symbols", None)
        if symbols is not None:
            try:
                for key, value in symbols.items():  # type: ignore[union-attr]
                    if str(key) == str(value):
                        continue
                    constraints.append(f"{key} == {value}")
                    if len(constraints) >= pre.max_constraints:
                        break
            except _MIASM_ERRORS as exc:
                _log.debug(
                    "symbolic.explore: symbol-store read failed: %s", exc,
                )

    return reached, constraints, counter[0]


async def explore(
    function_ref: FunctionRef,
    precondition: Precondition | None = None,
    *,
    investigation_id: str | None = None,
    branch_id: str | None = None,
    turn_number: int | None = None,
    evidence_refs: list[str] | None = None,
) -> ExplorationResult:
    """Run a bounded concolic exploration of a single function.

    Two-gate short-circuit before any miasm import:

    1. If ``platform.symbolic_enabled`` is False, returns
       :attr:`ExplorationStatus.DISABLED` immediately (byte-identical
       to pre-#148 behaviour).
    2. If miasm is not importable, returns
       :attr:`ExplorationStatus.UNAVAILABLE` cleanly.

    On the SUCCESS path emits ONE ``symbolic.reached`` observation
    through :func:`aila.platform.agents.observation.record_observation`
    into ``{module}.observation.workspace.{workspace_id}`` -- the same
    namespace the ``fuzz.*`` kinds already land in. The writer is
    best-effort (per RFC #137 contract): a store failure returns a
    SUCCESS result with ``observation_id=None`` rather than raising
    or downgrading the status. Provenance fields
    (``investigation_id``, ``branch_id``, ``turn_number``,
    ``evidence_refs``) are forwarded to the observation so a
    retrieved row carries the same context the caller stamped.

    ``precondition`` defaults to an empty :class:`Precondition` so a
    caller that only wants reachability under the jitter's default
    initial state can omit it.

    Never raises: any miasm fault is captured by
    :data:`_MIASM_ERRORS` and returned as
    :attr:`ExplorationStatus.ERROR` with the exception summary.
    """
    if precondition is None:
        precondition = Precondition()

    subject = _compose_subject(function_ref)

    if not await _resolve_enabled():
        return ExplorationResult(
            status=ExplorationStatus.DISABLED,
            subject=subject,
        )

    try:
        reached, constraints, steps = _run_concolic(function_ref, precondition)
    except ImportError:
        # Extra not installed on this host. Distinct from ERROR:
        # this is not a defect, it is an environment gap that the
        # operator resolves by ``pip install .[symbolic]``.
        return ExplorationResult(
            status=ExplorationStatus.UNAVAILABLE,
            subject=subject,
        )
    except _MIASM_ERRORS as exc:
        _log.warning(
            "symbolic.explore: concolic run for %s failed with %s: %s",
            subject, type(exc).__name__, exc,
        )
        return ExplorationResult(
            status=ExplorationStatus.ERROR,
            subject=subject,
            error=f"{type(exc).__name__}: {exc}",
        )

    content = _compose_content(function_ref, reached, constraints, steps)
    observation = PlatformObservation(
        module=function_ref.module,
        workspace_id=function_ref.workspace_id,
        subject=subject,
        kind=SYMBOLIC_REACHED_KIND,
        polarity=ObservationPolarity.NEUTRAL,
        content=content,
        investigation_id=investigation_id,
        branch_id=branch_id,
        turn_number=turn_number,
        evidence_refs=list(evidence_refs or ()),
        extra={
            "symbol_name": function_ref.symbol_name,
            "arch": function_ref.arch,
            "entry_address": function_ref.entry_address,
            "end_address": function_ref.end_address,
            "reached_addresses": list(reached),
            "path_constraints": list(constraints),
            "steps_executed": steps,
            "source": "symbolic.explore",
        },
    )
    observation_id = await record_observation(observation)

    return ExplorationResult(
        status=ExplorationStatus.SUCCESS,
        subject=subject,
        reached_addresses=list(reached),
        path_constraints=list(constraints),
        steps_executed=steps,
        observation_id=observation_id,
    )
