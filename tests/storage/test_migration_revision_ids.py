"""Static integrity checks for the Alembic revision graph."""
from __future__ import annotations

import ast
from pathlib import Path

__all__: list[str] = []

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MIGRATION_DIR = _REPO_ROOT / "src" / "aila" / "alembic" / "versions"
_EXPECTED_HEAD = "149_forensics_inv_lifecycle_cols"


def _assigned_literal(tree: ast.Module, name: str, path: Path) -> object:
    """Read a literal top-level assignment without importing the migration."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and node.value is not None
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{path.name}: missing literal {name!r} assignment")


def _migration_graph() -> dict[str, tuple[str, ...]]:
    paths = sorted(
        path for path in _MIGRATION_DIR.glob("*.py") if path.name != "__init__.py"
    )
    assert paths, f"no migrations found in {_MIGRATION_DIR}"

    graph: dict[str, tuple[str, ...]] = {}
    sources: dict[str, Path] = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        revision = _assigned_literal(tree, "revision", path)
        assert isinstance(revision, str) and revision, (
            f"{path.name}: revision must be a non-empty string"
        )
        assert len(revision) <= 32, (
            f"{path.name}: revision {revision!r} exceeds Alembic's 32-character limit"
        )
        assert revision not in graph, (
            f"duplicate revision {revision!r}: {sources[revision].name} and {path.name}"
        )

        down_revision = _assigned_literal(tree, "down_revision", path)
        if down_revision is None:
            parents: tuple[str, ...] = ()
        elif isinstance(down_revision, str):
            parents = (down_revision,)
        elif isinstance(down_revision, (tuple, list)) and all(
            isinstance(parent, str) for parent in down_revision
        ):
            parents = tuple(down_revision)
        else:
            raise AssertionError(
                f"{path.name}: down_revision must be None, a string, or a string tuple"
            )

        graph[revision] = parents
        sources[revision] = path

    return graph


def test_migration_revision_graph() -> None:
    graph = _migration_graph()

    for revision, parents in graph.items():
        for parent in parents:
            assert parent in graph, (
                f"migration {revision!r} has undefined down_revision {parent!r}"
            )

    referenced_parents = {
        parent for parents in graph.values() for parent in parents
    }
    heads = set(graph) - referenced_parents
    assert heads == {_EXPECTED_HEAD}, (
        f"expected one migration head {_EXPECTED_HEAD!r}, found {sorted(heads)!r}"
    )
