"""Deep review tests for src/aila/api/constants.py (FILE-13).

Proves every constant has at least one consumer outside constants.py,
naming is consistent UPPER_SNAKE_CASE, values are correct literals,
VALID_ROLES is a frozenset, and no unexported module-level constants exist.
"""
from __future__ import annotations

import re
import subprocess
import sys

import pytest

from aila.api import constants


class TestConstantsAllExported:
    """Every name in __all__ exists as a module attribute with a real value."""

    def test_all_entries_are_module_attributes(self) -> None:
        """Each __all__ entry is a real module-level attribute, not None."""
        for name in constants.__all__:
            assert hasattr(constants, name), f"{name} listed in __all__ but not defined"
            assert getattr(constants, name) is not None, f"{name} is None"

    def test_no_unexported_module_level_constants(self) -> None:
        """No UPPER_SNAKE_CASE names at module level are missing from __all__."""
        upper_snake = re.compile(r"^[A-Z][A-Z0-9_]+$")
        module_names = {
            n for n in dir(constants)
            if upper_snake.match(n) and not n.startswith("__")
        }
        all_set = set(constants.__all__)
        hidden = module_names - all_set
        assert hidden == set(), f"Unexported constants found: {hidden}"


class TestConstantsNamingConsistency:
    """All constant names follow UPPER_SNAKE_CASE with domain prefixes."""

    def test_all_names_upper_snake_case(self) -> None:
        """Every name in __all__ matches ^[A-Z][A-Z0-9_]+$."""
        pattern = re.compile(r"^[A-Z][A-Z0-9_]+$")
        for name in constants.__all__:
            assert pattern.match(name), f"{name} does not match UPPER_SNAKE_CASE"

    def test_prefix_grouping(self) -> None:
        """Constants are grouped by expected domain prefixes with correct counts."""
        prefixes: dict[str, list[str]] = {}
        for name in constants.__all__:
            parts = name.split("_", maxsplit=1)
            if len(parts) == 2:
                prefix = parts[0] + "_"
            else:
                prefix = name
            prefixes.setdefault(prefix, []).append(name)

        # ROLE_ group: ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER (3 values)
        assert len([n for n in constants.__all__ if n.startswith("ROLE_")]) == 3
        # VALID_ROLES is the only name without a standard prefix (it IS the group)
        assert "VALID_ROLES" in constants.__all__
        # JWT_ group: 3
        assert len([n for n in constants.__all__ if n.startswith("JWT_")]) == 3
        # TOKEN_TYPE_ group: 1
        assert len([n for n in constants.__all__ if n.startswith("TOKEN_")]) == 1
        # MEDIA_TYPE_ group: 1
        assert len([n for n in constants.__all__ if n.startswith("MEDIA_")]) == 1
        # AUDIT_ group: 25 (8 stages + 16 actions + 1 status)
        assert len([n for n in constants.__all__ if n.startswith("AUDIT_")]) == 25
        # TRACK_ group: 2
        assert len([n for n in constants.__all__ if n.startswith("TRACK_")]) == 2
        # MODULE_ID_ group: 1
        assert len([n for n in constants.__all__ if n.startswith("MODULE_")]) == 1


class TestConstantsValues:
    """Constant values match expected literal strings."""

    def test_role_values(self) -> None:
        assert constants.ROLE_ADMIN == "admin"
        assert constants.ROLE_OPERATOR == "operator"
        assert constants.ROLE_READER == "reader"

    def test_valid_roles_frozenset(self) -> None:
        assert isinstance(constants.VALID_ROLES, frozenset)
        assert constants.VALID_ROLES == frozenset({"admin", "operator", "reader"})

    def test_jwt_values(self) -> None:
        assert constants.JWT_ALGORITHM == "HS256"
        assert constants.JWT_TYP_ACCESS == "access"
        assert constants.JWT_TYP_REFRESH == "refresh"

    def test_token_type(self) -> None:
        assert constants.TOKEN_TYPE_BEARER == "bearer"

    def test_media_type(self) -> None:
        assert constants.MEDIA_TYPE_SSE == "text/event-stream"

    def test_audit_values(self) -> None:
        assert constants.AUDIT_STAGE_AUTH == "auth"
        assert constants.AUDIT_ACTION_CREATE_API_KEY == "create_api_key"
        assert constants.AUDIT_ACTION_REVOKE_API_KEY == "revoke_api_key"
        assert constants.AUDIT_STATUS_COMPLETED == "completed"

    def test_track_values(self) -> None:
        assert constants.TRACK_VULNERABILITY == "vulnerability"
        assert constants.TRACK_PLATFORM == "platform"

    def test_module_id(self) -> None:
        assert constants.MODULE_ID_PLATFORM == "__platform__"


class TestConstantsHaveConsumers:
    """Every constant in __all__ has at least one import outside constants.py."""

    @pytest.mark.parametrize("name", constants.__all__)
    def test_every_constant_has_consumer_outside_constants_py(self, name: str) -> None:
        """Use grep to verify each constant is imported/used outside constants.py."""
        result = subprocess.run(
            [
                sys.executable, "-c",
                (
                    "import subprocess, sys\n"
                    f"r = subprocess.run(['grep', '-rn', '{name}', 'src/aila/', '--include=*.py'], "
                    "capture_output=True, text=True)\n"
                    "lines = [l for l in r.stdout.splitlines() "
                    "if 'constants.py' not in l and '__pycache__' not in l]\n"
                    "print(len(lines))\n"
                ),
            ],
            capture_output=True,
            text=True,
            cwd="C:/Users/THEDEVIL/Documents/Playground",
        )
        count = int(result.stdout.strip()) if result.stdout.strip() else 0
        assert count >= 1, f"Constant {name} has 0 consumers outside constants.py -- orphaned!"
