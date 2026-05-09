"""Groind truth for loading the project `.env` file.

Both alembic and FastAPI will use this, handling configs from one hand is the best way im this kinda infra
"""
from __future__ import annotations

from pathlib import Path


def _find_repo_root(start: Path) -> Path | None:
    """Walk up from `start` until we find a directory containing `.env` or `.env.example`."""
    current = start.resolve()
    for parent in (current, *current.parents):
        if (parent / ".env").is_file() or (parent / ".env.example").is_file():
            return parent
    return None


def load_project_env() -> Path | None:
    """Load `.env` from the repo root if present."""
    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        return None

    repo_root = _find_repo_root(Path(__file__).parent)
    if repo_root is None:
        return None

    env_path = repo_root / ".env"
    if not env_path.is_file():
        return None

    load_dotenv(env_path, override=False)
    return env_path
