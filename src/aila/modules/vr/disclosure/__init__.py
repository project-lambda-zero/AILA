"""Disclosure subsystem -- track plugins + registry + service.

v1 ships 4 built-in tracks (chrome_vrp / blog_post / vendor_direct /
cna_github_gsa). Additional tracks register at import time per GA-31
(each track is a Python class implementing the DisclosureTrack
protocol). YAML-driven configuration lands in v1.1.
"""
from __future__ import annotations

from .registry import (
    DisclosureTrack,
    available_tracks,
    get_track,
    track_info_list,
)
from .service import DisclosureService, DisclosureServiceError

__all__ = [
    "DisclosureService",
    "DisclosureServiceError",
    "DisclosureTrack",
    "available_tracks",
    "get_track",
    "track_info_list",
]
