"""Trajectory -> SFT/DPO corpus package (issue #158).

Public surface: the corpus contracts and the :class:`TrajectoryCorpusBuilder`
plus the :func:`export_corpus` top-level helper the ARQ task and the admin
endpoint both call.
"""
from __future__ import annotations

from .builder import (
    CorpusOutputPaths,
    TrajectoryCorpusBuilder,
    export_corpus,
    resolve_corpus_output_dir,
)
from .contracts import (
    CorpusManifest,
    DpoRecord,
    SftMessage,
    SftMeta,
    SftRecord,
)

__all__ = [
    "CorpusManifest",
    "CorpusOutputPaths",
    "DpoRecord",
    "SftMessage",
    "SftMeta",
    "SftRecord",
    "TrajectoryCorpusBuilder",
    "export_corpus",
    "resolve_corpus_output_dir",
]
