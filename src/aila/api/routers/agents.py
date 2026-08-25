"""Platform agent registry router (req 31).

Publishes the ``persona-registry`` read surface the persona-model
routing config UI consumes: one entry per registered module, listing
the persona voices that module's :class:`PersonaRouter` binds and
the finite ``model_role`` / ``task_type`` values that router can
legally emit. A frontend ``<select>`` bound to that list replaces
the pre-req-31 free-text input so an operator cannot type a
``model_role`` no ``llm_model_{role}`` config resolves.

Ownership boundary (repo rule 5): the endpoint imports the
platform-owned :class:`PersonaRouter` base and iterates the module
registry, but NEVER imports ``aila.modules.<name>`` directly. Each
module contributes its subclass via the optional
:meth:`ModuleProtocol.persona_router` hook (added in the same
change); a persona-less module (``forensics``, ``hello_world``,
``_template``) returns ``None`` from that hook and appears in the
response with an empty ``personas`` list so the UI still enumerates
it.

Auth: operator+ (mirror :mod:`aila.api.routers.findings_workflow`
router auth). Rate limited to 120/minute per :mod:`aila.api.limiter`.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from aila.api.auth import ROLE_LEVELS, AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_OPERATOR
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.agents.persona_router import PersonaRouter

if TYPE_CHECKING:
    pass

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/platform/agents",
    tags=["platform-agents"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _require_operator(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    if ROLE_LEVELS.get(auth.role, -1) < ROLE_LEVELS[ROLE_OPERATOR]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Platform agent registry requires '{ROLE_OPERATOR}' role or higher; "
                f"current role: '{auth.role}'"
            ),
        )
    return auth


class PersonaRegistryPersona(BaseModel):
    """One persona binding a module's :class:`PersonaRouter` publishes."""

    model_config = ConfigDict(extra="forbid")

    voice: str
    role: str | None
    task_type_options: list[str]


class PersonaRegistryModule(BaseModel):
    """One registered module's persona-router surface (req 31)."""

    model_config = ConfigDict(extra="forbid")

    module_id: str
    module_label: str
    personas: list[PersonaRegistryPersona]


def _module_label_for(module_id: str) -> str:
    """Human label for a module_id.

    Short ids (<=3 chars, e.g. ``"vr"``) upper-case cleanly; longer
    ids (``"malware"``, ``"hello_world"``) render as title-cased words.
    """
    if len(module_id) <= 3:
        return module_id.upper()
    return module_id.replace("_", " ").title()


def _task_type_options_for(router_cls: type[PersonaRouter]) -> list[str]:
    """Return the sorted unique union of task_types the router emits.

    The finite set is the union of ``role_task_type.values()`` +
    ``persona_task_type.values()`` + ``{default_task_type}``. Same
    list on every persona of the module -- the router's dispatch
    picks one of these for any voice it recognises.
    """
    options: set[str] = set()
    for value in router_cls.role_task_type.values():
        options.add(str(value))
    for value in router_cls.persona_task_type.values():
        options.add(str(value))
    default = getattr(router_cls, "default_task_type", None)
    if default:
        options.add(str(default))
    return sorted(options)


def _personas_for_router(router_cls: type[PersonaRouter]) -> list[PersonaRegistryPersona]:
    """Build the persona list for one module's :class:`PersonaRouter`.

    Voice set is ``persona_role_map`` keys when non-empty (VR shape);
    otherwise ``persona_task_type`` keys (malware shape). ``role`` is
    the mapped :class:`PersonaRole` value for that voice, or ``None``
    when the module routes per-voice with no role indirection (the
    malware case).
    """
    if router_cls.persona_role_map:
        voices = list(router_cls.persona_role_map.keys())
    else:
        voices = list(router_cls.persona_task_type.keys())
    options = _task_type_options_for(router_cls)
    personas: list[PersonaRegistryPersona] = []
    for voice in voices:
        role_member = router_cls.persona_role_map.get(voice)
        role_value = role_member.value if role_member is not None else None
        voice_str = voice.value if hasattr(voice, "value") else str(voice)
        personas.append(
            PersonaRegistryPersona(
                voice=voice_str,
                role=role_value,
                task_type_options=list(options),
            )
        )
    return personas


def _module_entry(module) -> PersonaRegistryModule:
    """Build one :class:`PersonaRegistryModule` from a registered module.

    ``module.persona_router`` is consulted via :func:`hasattr` so a
    module that has not implemented the optional hook lists as
    persona-less (empty ``personas``) instead of crashing the endpoint.
    A hook that returns ``None`` (persona-less by design) has the
    same effect.
    """
    module_id = str(getattr(module, "module_id", "") or "")
    label = _module_label_for(module_id) if module_id else ""
    personas: list[PersonaRegistryPersona] = []
    if hasattr(module, "persona_router"):
        try:
            router_cls = module.persona_router()
        except (AttributeError, RuntimeError, TypeError) as exc:
            _log.debug(
                "persona_router() call failed for module %s (%s: %s); "
                "listing as persona-less.",
                module_id, type(exc).__name__, exc,
            )
            router_cls = None
        if router_cls is not None:
            personas = _personas_for_router(router_cls)
    return PersonaRegistryModule(
        module_id=module_id,
        module_label=label,
        personas=personas,
    )


def build_persona_registry(platform: object) -> list[PersonaRegistryModule]:
    """Assemble the persona-registry response body for ``platform``.

    Public pure helper so tests can exercise the introspection path
    against real module registrations without spinning the full app
    fixture. Iterates ``platform.runtime.module_registry.modules`` in
    registration order.
    """
    if platform is None:
        return []
    modules = list(platform.runtime.module_registry.modules)  # type: ignore[attr-defined]
    return [_module_entry(mod) for mod in modules]


@router.get(
    "/persona-registry",
    response_model=DataEnvelope[list[PersonaRegistryModule]],
    summary="List every registered module's persona-router bindings",
)
@limiter.limit("120/minute")
async def get_persona_registry(
    request: Request,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[list[PersonaRegistryModule]]:
    """Return one entry per registered module (req 31).

    The persona-model routing config UI drives its per-module,
    per-persona ``<select>`` from this response so an operator sees
    the finite set of ``model_role`` values each module's router can
    legally emit.
    """
    del auth
    platform = getattr(request.app.state, "platform", None)
    entries = build_persona_registry(platform)
    return DataEnvelope(data=entries)
