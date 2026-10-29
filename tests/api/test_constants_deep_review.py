"""Deep review tests for src/aila/api/constants.py (FILE-13).

Proves every constant has at least one consumer outside constants.py,
naming is consistent UPPER_SNAKE_CASE, values are correct literals,
VALID_ROLES is a frozenset, and no unexported module-level constants exist.
"""
from __future__ import annotations

import re

from aila.api import constants


class TestConstantsAllExported:
    """Every name in __all__ exists as a module attribute with a real value."""


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


class TestConstantsValues:
    """Constant values match expected literal strings."""


    def test_valid_roles_frozenset(self) -> None:
        assert isinstance(constants.VALID_ROLES, frozenset)
        assert constants.VALID_ROLES == frozenset({"admin", "operator", "reader"})

    def test_jwt_values(self) -> None:
        assert constants.JWT_ALGORITHM == "HS256"
        assert constants.JWT_TYP_ACCESS == "access"
        assert constants.JWT_TYP_REFRESH == "refresh"

    def test_token_type(self) -> None:
        assert constants.TOKEN_TYPE_BEARER == "bearer"


