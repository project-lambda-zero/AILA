# vulture whitelist
# Suppressions for known false positives in the AILA codebase.
#
# Run: vulture src/ vulture_whitelist.py --min-confidence=80
#
# Exit code 0 = no findings (clean).
# Exit code 1 = findings exist (investigate before ignoring).
#
# As of Phase 6 (2026-04-01), vulture src/ --min-confidence=80 reports no
# findings. The whitelist is intentionally empty. Add suppressions here only
# when vulture flags a confirmed false positive from one of these categories:
#
#   a. @runtime_checkable Protocol methods (e.g., ModuleProtocol methods in
#      platform/contracts/) -- abstract methods vulture sees as unused.
#   b. Pydantic model validators / field aliases -- @field_validator,
#      @model_validator, @validator decorated methods called by Pydantic
#      internally.
#   c. __all__ re-export aliases -- names declared in __all__ but not imported
#      anywhere in-project (public API for external callers).
#   d. ABC abstractmethod bodies -- abstract methods whose body is ... flagged
#      as "unused code".
#   e. CLI command functions registered via @app.command() -- typer-registered
#      entry points that look unused to static analysis.
#
# Whitelist entry format:
#   from aila.some.module import SomeClass  # noqa: F401
#   SomeClass.some_method  # reason: category + explanation
