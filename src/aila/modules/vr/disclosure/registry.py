"""Track registry -- lookup by track_id, list available tracks.

v1 is built-ins only. v1.1 adds YAML-defined tracks from
``data/disclosure_tracks/*.yaml``.
"""
from __future__ import annotations

from aila.modules.vr.contracts.disclosure import DisclosureTrackInfo

from .base import DisclosureTrack
from .builtin_tracks import BUILTIN_TRACKS
from .builtin_tracks_extra import ALL_EXTRA_TRACKS
from .builtin_tracks_kernel import ALL_KERNEL_TRACKS

__all__ = [
    "DisclosureTrack",
    "available_tracks",
    "get_track",
    "track_info_list",
]


_REGISTRY: dict[str, type[DisclosureTrack]] = {
    track.track_id: track
    for track in (*BUILTIN_TRACKS, *ALL_EXTRA_TRACKS, *ALL_KERNEL_TRACKS)
}


def get_track(track_id: str) -> type[DisclosureTrack] | None:
    """Return the track class for ``track_id`` or None when unknown."""
    return _REGISTRY.get(track_id)


def available_tracks() -> dict[str, type[DisclosureTrack]]:
    """Return a snapshot of the track registry."""
    return dict(_REGISTRY)


def track_info_list() -> list[DisclosureTrackInfo]:
    """Public projection: every registered track's TrackInfo."""
    return [t.info() for t in _REGISTRY.values()]
