"""AILA platform package."""

from __future__ import annotations

from .config import Settings, get_settings
from .platform.runtime import AILAPlatform

__all__ = ["AILAPlatform", "Settings", "get_settings"]
