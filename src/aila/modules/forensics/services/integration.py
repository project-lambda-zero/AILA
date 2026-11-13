"""SSH integration payload that forensics investigation tasks receive.

``run_forensics_investigation`` takes the analyzer's SSH connection as its
``integration`` kwarg. The start route, the rerun route and the recovery
re-dispatch
(:func:`aila.modules.forensics.services.recovery_submit.prepare_recovery_submit`)
all build it here, so a re-driven investigation reaches the analyzer exactly
the way the original dispatch did.
"""
from __future__ import annotations

from aila.storage.db_models import ManagedSystemRecord

__all__ = ["build_integration_payload"]


def build_integration_payload(system: ManagedSystemRecord) -> dict[str, object]:
    """Return the SSH integration dict for ``system``.

    The password travels as ``password_secret_id`` and the key as
    ``private_key_path``; no credential material is inlined, so the dict is
    plain JSON for ``TaskQueue.submit`` kwargs.
    """
    return {
        "name": system.name,
        "host": system.host,
        "username": system.username,
        "port": system.port,
        "private_key_path": system.private_key_path,
        "password_secret_id": system.password_secret_id,
        "known_hosts_path": system.known_hosts_path,
        "host_key_fingerprint": system.host_key_fingerprint,
    }
