"""Complete SAST skill catalog pinned to the vendored upstream commit."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from aila.modules.vr.sast.models import SastPhase, SastSkill

__all__ = [
    "SAST_CATALOG_VERSION",
    "SAST_DETECTION_SKILLS",
    "SAST_SKILLS",
    "SAST_UPSTREAM_COMMIT",
    "SAST_UPSTREAM_URL",
    "load_sast_skill",
]

SAST_CATALOG_VERSION = "1.0.0-aila"
SAST_UPSTREAM_URL = "https://github.com/utkusen/sast-skills"
SAST_UPSTREAM_COMMIT = "3a5bf8f0efe31d1d4731c164ca86abd9a3bbd166"


def _skill(skill_id: str, title: str, phase: SastPhase, digest: str) -> SastSkill:
    return SastSkill(id=skill_id, title=title, phase=phase, body_sha256=digest)


SAST_SKILLS: tuple[SastSkill, ...] = (
    _skill("sast-analysis", "Codebase analysis and threat modeling", SastPhase.ANALYSIS, "b2f526b6b6f59ea79e82736356da5e9a3c49c24e0dc28f78a337600c254432c1"),
    _skill("sast-idor", "Insecure direct object reference", SastPhase.DETECTION, "3e89c0fcc00b569d31384baf7835c85ebaa7dd41b2350c014008e92ce1472c7f"),
    _skill("sast-sqli", "SQL injection", SastPhase.DETECTION, "9ec06352619f6fd6b4a02db9ba43fa7daa6e4795fccd5a18e4675f33ca70c93c"),
    _skill("sast-ssrf", "Server-side request forgery", SastPhase.DETECTION, "57f9a5ef09e104028b93e0bc8f0296f1e6fd954653b4e34b297c8bcadb1a4245"),
    _skill("sast-xss", "Cross-site scripting", SastPhase.DETECTION, "034e4f5770d80cfccc56001878185a3362fecde735bf878ace37fbce248595fb"),
    _skill("sast-rce", "Remote code execution", SastPhase.DETECTION, "b989bcb6aa57c038fe3e3d756847d40adf253f6ce1f1043d644217cb72e5ab13"),
    _skill("sast-xxe", "XML external entity injection", SastPhase.DETECTION, "064a3413ded525d3ad5d44ea5672bfad8cf5e16645bfde72f9f302d6d1ccb776"),
    _skill("sast-fileupload", "Insecure file upload", SastPhase.DETECTION, "eaebd66f3e4960bdd9c3af6dd15fe6f366a5ff6c170875186aa56b953fc46619"),
    _skill("sast-pathtraversal", "Path and directory traversal", SastPhase.DETECTION, "1756514d03b3f70355c320966f9f5e4cba1cd1955d9900664103391cd8fe18c4"),
    _skill("sast-ssti", "Server-side template injection", SastPhase.DETECTION, "b3c4a6e6b5ede35a4c5a2c99473bebc7a85e63f232b821eb363732e0fb105302"),
    _skill("sast-jwt", "Insecure JWT implementations", SastPhase.DETECTION, "be3c5b27033169ec907dae6c9ff9e5ce8ed4d7d4e9c7e1e9248bdf9c94352588"),
    _skill("sast-missingauth", "Missing authentication and function-level authorization", SastPhase.DETECTION, "5cb01f507fd7baf25fef6ba1a0c8b7ac8f6f8ea62aa0bb4bc7afb6bdf6941d9b"),
    _skill("sast-businesslogic", "Business logic flaws", SastPhase.DETECTION, "a23b28dc1b725ddc8ea562653b3ae3a05bc801b13e2aa06092981f7fe4dfa915"),
    _skill("sast-graphql", "GraphQL injection", SastPhase.DETECTION, "e1718c34b7e4a041bb867fcf218c02b098863fc853d9434026dd3e62f37da309"),
    _skill("sast-hardcodedsecrets", "Hardcoded secrets", SastPhase.DETECTION, "17c09d94a2d3d2f2513f7742212d501b06642a89c00046ac6c70ee48eafb55c4"),
    _skill("sast-report", "Consolidated severity-ranked report", SastPhase.REPORT, "faea0813f944399dc30ed7e33d96a7a9f68de9e3482a8c468dd01b9cc93398f3"),
)
SAST_DETECTION_SKILLS = tuple(skill for skill in SAST_SKILLS if skill.phase is SastPhase.DETECTION)


def load_sast_skill(skill: SastSkill) -> str:
    """Load and authenticate the exact vendored upstream skill body."""
    body = (Path(__file__).parent / skill.resource_path).read_text(encoding="utf-8")
    actual = sha256(body.encode("utf-8")).hexdigest()
    if actual != skill.body_sha256:
        raise ValueError(f"SAST skill {skill.id} hash mismatch: expected {skill.body_sha256}, got {actual}")
    return body
