"""Load a benchmark-suite manifest from disk.

The manifest is a JSON file describing one published benchmark suite and
its tasks (each with a known reference answer and a pre-provisioned VR
target). The dataset root is resolved from the ``vr.eval_suite_dataset_root``
config key; the manifest for ``<suite>`` is ``<root>/<suite>/manifest.json``.

A missing root, missing file, malformed JSON, unknown suite name, or a task
whose ``suite`` field disagrees with the manifest raises a precise
``ManifestError`` so an operator sees exactly what to fix rather than an
empty run.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from .contracts import SUPPORTED_SUITES, BenchmarkTaskSpec, SuiteManifest

__all__ = ["ManifestError", "manifest_path", "load_suite_manifest"]


class ManifestError(ValueError):
    """Raised when a suite manifest cannot be loaded or is invalid."""


def manifest_path(dataset_root: str, suite: str) -> Path:
    """Return the manifest path for ``suite`` under ``dataset_root``."""
    return Path(dataset_root) / suite / "manifest.json"


def load_suite_manifest(dataset_root: str, suite: str) -> SuiteManifest:
    """Load and validate the manifest for ``suite``.

    Raises ``ManifestError`` on any resolution or validation failure.
    """
    if suite not in SUPPORTED_SUITES:
        raise ManifestError(
            f"unknown suite '{suite}'; supported suites are "
            f"{sorted(SUPPORTED_SUITES)}",
        )
    if not dataset_root:
        raise ManifestError(
            "vr.eval_suite_dataset_root is not configured; set it to the "
            "directory holding the benchmark datasets before running a suite",
        )

    path = manifest_path(dataset_root, suite)
    if not path.is_file():
        raise ManifestError(f"manifest not found for suite '{suite}': {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError(f"could not read manifest {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ManifestError(f"manifest {path} must be a JSON object")

    raw_tasks = raw.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ManifestError(f"manifest {path} has no 'tasks' list")

    tasks: list[BenchmarkTaskSpec] = []
    for index, entry in enumerate(raw_tasks):
        if not isinstance(entry, dict):
            raise ManifestError(f"manifest {path} task #{index} is not an object")
        merged = {"suite": suite, **entry}
        try:
            spec = BenchmarkTaskSpec.model_validate(merged)
        except ValidationError as exc:
            raise ManifestError(
                f"manifest {path} task #{index} is invalid: {exc}",
            ) from exc
        if spec.suite != suite:
            raise ManifestError(
                f"manifest {path} task '{spec.task_id}' declares suite "
                f"'{spec.suite}' but lives under '{suite}'",
            )
        tasks.append(spec)

    return SuiteManifest(suite=suite, tasks=tasks)
