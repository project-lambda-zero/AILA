"""Template investigation-lifecycle state scaffolds (RFC-02).

Public exports are intentionally empty: the copy-me scaffolds under this
package are read by the module author when standing up a new
investigation-driven module. Consumers do not reach into this package;
the platform workflow engine imports concrete handlers via fully-
qualified paths after the module is renamed and registered.
"""
from __future__ import annotations

__all__: list[str] = []
