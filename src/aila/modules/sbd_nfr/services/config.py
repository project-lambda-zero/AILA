"""Module configuration service shim for the SbD NFR module.

SbdNfrConfig has been moved to contracts/config.py because it crosses the
service boundary. This module re-exports it for backwards compatibility so
any existing internal import paths continue to work.
"""

from __future__ import annotations

from aila.modules.sbd_nfr.contracts.config import SbdNfrConfig

__all__ = ["SbdNfrConfig"]
