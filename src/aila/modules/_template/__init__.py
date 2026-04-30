"""Template module package.

Copy this folder, rename it to your module ID, and replace all
TEMPLATE/replace_with_* placeholders with concrete values.

Patterns demonstrated:
  - ModuleRouteSpec for API route declaration (module.py)
  - seed_data() with SeedVersionRecord idempotent pattern (module.py)
  - system_summary() for per-system dashboard contribution (module.py)
  - report_count() for per-report count breakdown (module.py)
  - health_checks() for module health monitoring (module.py)
  - VulnerabilityTool base class (tools/__init__.py)
  - SingleActionTool for single-action tools (tools/__init__.py)
  - emit_stage_result in workflow state handlers (workflow.py)
  - Google-style docstrings on all public classes and functions
  - Correct __all__ conventions (no underscore-prefixed names)
"""
from __future__ import annotations

__all__: list[str] = []
