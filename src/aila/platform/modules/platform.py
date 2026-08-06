from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..config import ApplicationSettings
from ..contracts._common import JsonObject
from ..contracts.platform import (
    AddIntegrationPayload,
    DeleteIntegrationsPayload,
    ExecuteRemoteCommandPayload,
    ProgressUpdate,
    RegisteredSystem,
    RegistryResponse,
    RemoteCommandSelection,
)
from ..contracts.runtime import PlatformResponse
from ..exceptions import UpstreamError, ValidationError
from ..runtime.tools import ToolRegistry
from ..tools.registry import PermanentMemoryTool, SystemRegistryTool
from ..tools.ssh import SSHCommandTool
from .protocol import (
    ModuleCapabilityProfile,
    ModuleContext,
    ModuleProtocol,
    ModuleRequest,
    ModuleRuntime,
    action_id_for,
)

if TYPE_CHECKING:
    from ..llm import AilaLLMClient


@dataclass(slots=True)
class PlatformModuleRuntime:
    """The runtime instance for the built-in platform module.

    Handles the four platform-owned actions: list_integrations, add_integration,
    delete_integration, and execute_remote_command. SSH registry operations go
    directly through SystemRegistryTool; remote command execution uses the LLM
    to resolve which command and targets to use when not provided explicitly.
    """

    module_id: str
    registry_tool: SystemRegistryTool
    memory_tool: PermanentMemoryTool
    ssh_tool: SSHCommandTool
    runtime_model: AilaLLMClient
    capability_profiles: list[ModuleCapabilityProfile]
    list_action_id: str
    add_action_id: str
    delete_action_id: str
    execute_command_action_id: str

    async def handle(self, request: ModuleRequest) -> PlatformResponse:
        """Dispatch the request to the appropriate platform action handler.

        Raises ValueError for any action_id not owned by this module.
        """
        if request.action_id == self.execute_command_action_id:
            return await self._execute_remote_command(request)
        if request.action_id == self.list_action_id:
            return await self._list_integrations(request)
        if request.action_id == self.delete_action_id:
            return await self._delete_integrations(request)
        if request.action_id == self.add_action_id:
            return await self._add_integration(request)
        raise ValueError(
            f"Platform module cannot handle action {request.action_id!r}."
        )

    async def _list_integrations(self, request: ModuleRequest) -> PlatformResponse:
        registry_response = RegistryResponse.model_validate(
            await self.registry_tool.forward(action="list")
        )
        if request.execution_context.emitter is not None:
            from aila.platform.events import PlatformEvent
            request.execution_context.emitter.emit(PlatformEvent(
                stage="platform",
                action="registry_inspect",
                key="registry_inspected",
                message=registry_response.message,
                run_id=request.run_id,
            ))
        else:
            from aila.storage.memory import append_run_event as _are
            _are(request.run_state, "registry_inspected", registry_response.message)
        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=f"{registry_response.count} SSH integrations are configured.",
            route=request.run_state.route,
            module_payload={"query_mode": "ssh_registry", "registry": registry_response.model_dump(mode="json")},
            state_history=request.run_state.events,
        )

    async def _delete_integrations(self, request: ModuleRequest) -> PlatformResponse:
        payload = DeleteIntegrationsPayload.model_validate(request.payload or {})
        target_names = list(payload.target_names)
        if not target_names:
            raise ValueError("Delete integration flow requires at least one target name.")
        registry_response = RegistryResponse.model_validate(
            await self.registry_tool.forward(action="delete", names=target_names)
        )
        for name in target_names:
            await self.memory_tool.forward(
                action="forget",
                namespace="integration_profiles",
                key=name,
            )
        if request.execution_context.emitter is not None:
            from aila.platform.events import PlatformEvent
            request.execution_context.emitter.emit(PlatformEvent(
                stage="platform",
                action="registry_delete",
                key="registry_deleted",
                message=registry_response.message,
                run_id=request.run_id,
            ))
        else:
            from aila.storage.memory import append_run_event as _are
            _are(request.run_state, "registry_deleted", registry_response.message)
        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=registry_response.message,
            route=request.run_state.route,
            module_payload={"query_mode": "ssh_registry", "registry": registry_response.model_dump(mode="json")},
            state_history=request.run_state.events,
        )

    async def _add_integration(self, request: ModuleRequest) -> PlatformResponse:
        payload = AddIntegrationPayload.model_validate(request.payload or {})
        integration_payload = payload.integration
        registry_response = RegistryResponse.model_validate(
            await self.registry_tool.forward(action="upsert", integration=integration_payload)
        )
        await self.memory_tool.forward(
            action="remember",
            namespace="integration_profiles",
            key=integration_payload.name,
            payload={
                "host": integration_payload.host,
                "distro": integration_payload.distro,
                "description": integration_payload.description,
            },
        )
        if request.execution_context.emitter is not None:
            from aila.platform.events import PlatformEvent
            request.execution_context.emitter.emit(PlatformEvent(
                stage="platform",
                action="registry_update",
                key="registry_updated",
                message=registry_response.message,
                run_id=request.run_id,
            ))
        else:
            from aila.storage.memory import append_run_event as _are
            _are(request.run_state, "registry_updated", registry_response.message)
        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=registry_response.message,
            route=request.run_state.route,
            module_payload={"query_mode": "ssh_registry", "registry": registry_response.model_dump(mode="json")},
            state_history=request.run_state.events,
        )

    async def _execute_remote_command(self, request: ModuleRequest) -> PlatformResponse:
        available_systems = await self._list_registered_systems()
        if not available_systems:
            raise ValidationError("No registered SSH integrations are available for remote command execution.")
        selection = await self._resolve_remote_command_selection(request, available_systems)
        target_systems = await self._resolve_target_systems(selection, available_systems)
        self._emit_progress(
            request,
            "remote_command",
            f"Running remote command on {len(target_systems)} target(s).",
        )
        command_planned_message = (
            f"Selected {len(target_systems)} target(s) for remote command execution. "
            f"Command: {selection.command}"
        )
        if request.execution_context.emitter is not None:
            from aila.platform.events import PlatformEvent
            request.execution_context.emitter.emit(PlatformEvent(
                stage="platform",
                action="command_plan",
                key="command_planned",
                message=command_planned_message,
                run_id=request.run_id,
            ))
        else:
            from aila.storage.memory import append_run_event as _are
            _are(request.run_state, "command_planned", command_planned_message)
        results: list[dict[str, object]] = []
        total = len(target_systems)
        for index, system in enumerate(target_systems, start=1):
            self._emit_progress(
                request,
                "ssh_command",
                f"Running remote command on {system.name}.",
                current=index,
                total=total,
            )
            output = await self.ssh_tool.forward(
                integration=system.model_dump(mode="json"),
                command=selection.command,
            )
            results.append(
                {
                    "target_name": system.name,
                    "host": system.host,
                    "command": selection.command,
                    "stdout": output,
                }
            )
        message = (
            f"Executed remote command on {target_systems[0].name}."
            if len(target_systems) == 1
            else f"Executed remote command on {len(target_systems)} targets."
        )
        if request.execution_context.emitter is not None:
            from aila.platform.events import PlatformEvent
            request.execution_context.emitter.emit(PlatformEvent(
                stage="platform",
                action="command_execute",
                key="command_executed",
                message=message,
                run_id=request.run_id,
            ))
        else:
            from aila.storage.memory import append_run_event as _are
            _are(request.run_state, "command_executed", message)
        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=message,
            route=request.run_state.route,
            module_payload={
                "query_mode": "remote_command",
                "command": selection.command,
                "requested_targets": list(selection.target_names),
                "run_all_targets": selection.run_all_targets,
                "rationale": selection.rationale,
                "results": results,
            },
            state_history=request.run_state.events,
        )

    async def _resolve_remote_command_selection(
        self,
        request: ModuleRequest,
        available_systems: list[RegisteredSystem],
    ) -> RemoteCommandSelection:
        """Resolve the command and targets from the request payload or LLM model.

        If the payload already has an explicit command and targets, returns a
        RemoteCommandSelection directly without calling the LLM. Otherwise
        generates a JSON prompt including all registered systems and delegates
        target and command resolution to the runtime model.
        """
        payload = ExecuteRemoteCommandPayload.model_validate(request.payload or {})
        explicit_command = payload.command.strip() if isinstance(payload.command, str) else ""
        explicit_target_names = [name.strip() for name in payload.target_names if isinstance(name, str) and name.strip()]
        if explicit_command and (explicit_target_names or payload.run_all_targets):
            return RemoteCommandSelection(
                command=explicit_command,
                target_names=explicit_target_names,
                run_all_targets=payload.run_all_targets,
                rationale="Used structured command execution payload.",
            )
        prompt = (
            "Interpret the user's request for remote shell command execution.\n"
            "Return JSON only with fields: command, target_names, run_all_targets, rationale.\n"
            "command must be the literal shell command to execute.\n"
            "target_names must contain exact system names from the provided systems.\n"
            "Use run_all_targets=true only when the user explicitly asks for every/all systems.\n"
            "Do not invent targets or commands.\n"
            f"User query: {request.run_state.query}\n"
            f"Registered systems: {json.dumps([_system_prompt_payload(system) for system in available_systems], separators=(',', ':'))}\n"
            f"Explicit target_names from payload: {json.dumps(explicit_target_names, separators=(',', ':'))}"
        )
        try:
            response = await self.runtime_model.chat_json(
                "routing",
                [{"role": "user", "content": prompt}],
                RemoteCommandSelection.model_json_schema(),
            )
            content = response.content or "{}"
            selection = RemoteCommandSelection.model_validate(json.loads(content))
        except Exception as exc:
            raise UpstreamError("Platform command selector did not return a valid remote command selection.") from exc
        normalized_command = selection.command.strip()
        if not normalized_command:
            raise ValueError("Platform command selector returned an empty command.")
        normalized_targets = [name.strip() for name in selection.target_names if name.strip()]
        if not selection.run_all_targets and not normalized_targets:
            raise ValueError("Platform command selector did not identify a target system.")
        return RemoteCommandSelection(
            command=normalized_command,
            target_names=normalized_targets,
            run_all_targets=selection.run_all_targets,
            rationale=selection.rationale.strip(),
        )

    async def _resolve_target_systems(
        self,
        selection: RemoteCommandSelection,
        available_systems: list[RegisteredSystem],
    ) -> list[RegisteredSystem]:
        if selection.run_all_targets:
            return list(available_systems)
        requested_names = list(dict.fromkeys(selection.target_names))
        registry_response = RegistryResponse.model_validate(
            await self.registry_tool.forward(action="get", names=requested_names)
        )
        if registry_response.missing_names:
            missing = ", ".join(registry_response.missing_names)
            raise ValueError(f"Remote command target resolution failed for: {missing}.")
        if not registry_response.integrations:
            raise ValueError("Remote command target resolution returned no integrations.")
        return list(registry_response.integrations)

    async def _list_registered_systems(self) -> list[RegisteredSystem]:
        registry_response = RegistryResponse.model_validate(
            await self.registry_tool.forward(action="list")
        )
        return list(registry_response.integrations)

    @staticmethod
    def _emit_progress(
        request: ModuleRequest,
        stage: str,
        message: str,
        *,
        current: int | None = None,
        total: int | None = None,
    ) -> None:
        callback = request.execution_context.progress_callback
        if callback is None:
            return
        callback(
            ProgressUpdate(
                stage=stage,
                message=message,
                current=current,
                total=total,
            )
        )


def _system_prompt_payload(system: RegisteredSystem) -> dict[str, str]:
    return {
        "name": system.name,
        "host": system.host,
        "distro": system.distro,
        "description": system.description,
    }


class PlatformModule(ModuleProtocol):
    """The built-in platform module that owns SSH integration management.

    Handles four actions: list, add, delete, and execute_remote_command for
    registered SSH systems. This module's actions are dispatched outside the
    vulnerability workflow DAG -- the platform routes them directly here so
    registry management always works regardless of which feature modules are
    installed.
    """

    module_id = "platform"
    list_action_id = action_id_for(module_id, "list_integrations")
    add_action_id = action_id_for(module_id, "add_integration")
    delete_action_id = action_id_for(module_id, "delete_integration")
    execute_command_action_id = action_id_for(module_id, "execute_remote_command")

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.execute_command_action_id,
                description="Run an explicit shell command over SSH on one or more registered systems.",
                tools=["registry.systems", "ssh.command"],
                examples=[
                    "run this command on arch-vm: ls -al",
                    "execute uname -a on ubuntu-vm",
                    "run df -h on all registered systems",
                ],
            ),
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.list_action_id,
                description="List registered SSH integrations and summarize the current registry.",
                tools=["registry.systems"],
                examples=[
                    "how many SSH integrations are configured",
                    "count the registered ssh hosts",
                    "list the available ssh targets",
                ],
            ),
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.add_action_id,
                description="Add, update, or save an SSH integration for a managed host.",
                tools=["registry.systems", "memory.permanent"],
                examples=[
                    "add ssh integration",
                    "register a new host",
                    "save a server connection",
                ],
            ),
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.delete_action_id,
                description="Delete, remove, or unregister one or more SSH integrations from the permanent registry.",
                tools=["registry.systems", "memory.permanent"],
                examples=[
                    "delete ssh integration",
                    "remove a host from the registry",
                    "unregister an ssh target",
                ],
            ),
        ]

    def required_tools(self) -> list[str]:
        return ["registry.systems", "memory.permanent", "ssh.command"]

    def report_filter_keys(self) -> list[str]:
        return []

    async def register_tools(self, tool_registry: ToolRegistry, settings: ApplicationSettings, registry: Any = None, schema_registry: Any = None) -> None:
        del tool_registry, settings, schema_registry

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        return PlatformModuleRuntime(
            module_id=self.module_id,
            registry_tool=context.tool_registry.require("registry.systems", SystemRegistryTool),
            memory_tool=context.tool_registry.require("memory.permanent", PermanentMemoryTool),
            ssh_tool=context.tool_registry.require("ssh.command", SSHCommandTool),
            runtime_model=context.runtime_model,
            capability_profiles=self.capability_profiles(),
            list_action_id=self.list_action_id,
            add_action_id=self.add_action_id,
            delete_action_id=self.delete_action_id,
            execute_command_action_id=self.execute_command_action_id,
        )

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        del filters
        return list(rows)
