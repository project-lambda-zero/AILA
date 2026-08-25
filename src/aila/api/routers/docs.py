"""Read-only docs surface for the operator console (req 29).

Serves an allow-listed set of repo docs so the frontend Docs page can render
the same material shipped in the git tree. The URL slug is a lookup key into
a fixed table, never composed into a filesystem path.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from aila.api.auth import require_role
from aila.api.schemas.envelope import DataEnvelope

__all__ = ["router"]

_log = logging.getLogger(__name__)


class DocTopic(BaseModel):
    slug: str
    title: str


class DocTopicBody(BaseModel):
    slug: str
    title: str
    body: str


@dataclass(frozen=True, slots=True)
class _TopicSpec:
    slug: str
    title: str
    relpath: str


# docs.py is at src/aila/api/routers/docs.py, so parents[4] is the repo root:
# parents[0]=routers, [1]=api, [2]=aila, [3]=src, [4]=<repo root>.
_REPO_ROOT: Path = Path(__file__).resolve().parents[4]

_TOPICS: tuple[_TopicSpec, ...] = (
    _TopicSpec("quick-start", "quick start", "docs/QUICKSTART.md"),
    _TopicSpec("architecture", "architecture", "docs/ARCHITECTURE.md"),
    _TopicSpec("module-standard", "module standard", "docs/MODULE_STANDARD.md"),
    _TopicSpec(
        "frontend-module-standard",
        "frontend module standard",
        "docs/FRONTEND_MODULE_STANDARD.md",
    ),
    _TopicSpec("module-tutorial", "module tutorial", "docs/MODULE_TUTORIAL.md"),
    _TopicSpec("golden-rules", "golden rules", "docs/GOLDEN_RULES.md"),
    _TopicSpec("workflow-guide", "workflow guide", "docs/WORKFLOW_GUIDE.md"),
    _TopicSpec("security-model", "security model", "docs/SECURITY_MODEL.md"),
    _TopicSpec("honesty-audit", "honesty audit", "docs/HONESTY_AUDIT.md"),
    _TopicSpec("changelog", "changelog", "CHANGELOG.md"),
)

_TOPIC_INDEX: dict[str, _TopicSpec] = {spec.slug: spec for spec in _TOPICS}


def resolve_topic_path(slug: str) -> Path | None:
    """Return the on-disk path for an allow-listed slug, or None.

    The slug is a lookup key. It is never joined into a filesystem path,
    so escape sequences (``..``, url-encoded segments) simply miss the
    index and return None.
    """
    spec = _TOPIC_INDEX.get(slug)
    if spec is None:
        return None
    path = _REPO_ROOT / spec.relpath
    if not path.is_file():
        return None
    return path


def available_topics() -> list[DocTopic]:
    """List topics whose source file currently exists on disk."""
    return [
        DocTopic(slug=spec.slug, title=spec.title)
        for spec in _TOPICS
        if (_REPO_ROOT / spec.relpath).is_file()
    ]


def read_topic_body(slug: str) -> str | None:
    """Return the raw markdown for an allow-listed slug, or None."""
    path = resolve_topic_path(slug)
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _log.warning("failed to read docs topic %r at %s: %s", slug, path, exc)
        return None


router = APIRouter(
    prefix="/docs",
    tags=["docs"],
    dependencies=[Depends(require_role("operator"))],
)


@router.get(
    "/topics",
    response_model=DataEnvelope[list[DocTopic]],
    summary="List docs topics",
)
async def list_docs_topics() -> DataEnvelope[list[DocTopic]]:
    topics = available_topics()
    return DataEnvelope(data=topics)


@router.get(
    "/topics/{slug}",
    response_model=DataEnvelope[DocTopicBody],
    summary="Read one docs topic",
)
async def read_docs_topic(slug: str) -> DataEnvelope[DocTopicBody]:
    spec = _TOPIC_INDEX.get(slug)
    if spec is None:
        raise HTTPException(status_code=404, detail="topic not found")
    body = read_topic_body(slug)
    if body is None:
        raise HTTPException(status_code=404, detail="topic not found")
    return DataEnvelope(data=DocTopicBody(slug=slug, title=spec.title, body=body))
