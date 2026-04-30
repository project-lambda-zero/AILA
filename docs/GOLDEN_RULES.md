# Golden Rules

58 non-negotiable code quality rules.
Any code that enters this codebase must satisfy these.
Derived from: Linus Torvalds, Guido van Rossum, Richard Stallman,
an angry OSS standards developer, an AI slop detector, and a Reddit basher.

---

## Linus Torvalds — The Kernel Lord

> *"Talk is cheap. Show me the code."*

1. **No abstraction without justification.** If a class wraps one function call, delete the class.
2. **No inheritance chains deeper than 2.** If you need a third level, your design is wrong. *(Dismissed: framework inheritance is structural.)*
3. **Functions do ONE thing.** If it has "and" in the description, split it.
4. **No god objects.** A class with 10+ methods is a design failure.
5. **Error paths are first-class citizens.** Silent swallows are bugs you chose to keep.
6. **No clever code.** If a reviewer needs 30 seconds to understand a line, rewrite it.
7. **Comments explain WHY, never WHAT.** If the code needs a WHAT comment, the code is bad.
8. **Dead code is a lie.** If it's not called, it doesn't exist. Delete it.
9. **No TODO in committed code.** A TODO is a promise you already broke.
10. **Configuration belongs in ONE place.** Two sources of truth is zero sources of truth.

## Guido van Rossum — The BDFL

> *"There should be one — and preferably only one — obvious way to do it."*

11. **Follow PEP 8 without exception.** Not "mostly" — entirely.
12. **Type annotations on every public function.** `-> dict` is not a type, it's an abdication.
13. **No bare `except Exception`.** Catch what you expect, let the rest propagate.
14. **Flat is better than nested.** If indentation exceeds 4 levels, refactor.
15. **Explicit is better than implicit.** `**kwargs` passthrough hides the contract.
16. **Namespaces are honking great.** `__all__` on every module, no exceptions.
17. **Simple is better than complex.** A 5-parameter function is suspicious. 10 is guilty.
18. **Readability counts.** Variable names under 3 characters are banned outside loops.
19. **Don't repeat yourself.** Same pattern in 3+ places = extract it.
20. **`assert` is for tests, not production.** Production asserts are time bombs.

## Richard Stallman — The Freedom Enforcer

> *"Free software is a matter of liberty, not price."*

22. **No vendor lock-in.** Hardcoded third-party URLs are dependency chains.
23. **No telemetry, no phone-home.** Every outbound call must be documented and user-consented.
24. **Documentation is not optional.** Every public API must be documented for the community.
25. **Privacy by design.** Credentials, keys, and secrets must never appear in code or logs.
26. **No proprietary dependencies without alternatives.** Every import must be replaceable.
27. **Users must control their data.** DB schemas must be documented for data portability.
28. **README must explain what, why, and how to build.** If a newcomer can't build in 5 minutes, you failed.
29. **Contributor guidelines must exist.** OSS without contribution docs is a closed project pretending to be open.
30. **CHANGELOG exists and is maintained.** Users deserve to know what changed.

## The Angry OSS Standards Developer

> *"Your code violates 14 RFCs and I'm filing issues for each one."*

31. **Every module has `__init__.py` with `__all__`.** No implicit namespace packages.
32. **Imports are absolute, never relative across package boundaries.** Relative within a package is fine.
33. **No circular imports.** Not even "lazy" ones. Restructure.
34. **Test coverage floor is enforced and realistic.** A gate that always passes is decoration.
35. **Fixtures, not inline setup.** Test helpers that call `session.commit()` without cleanup are leaks.
36. **Semantic versioning.** If there's no version, there's no release discipline.
37. **CI/CD or it didn't happen.** If tests only run when a dev remembers, they don't run. *(Deferred: post-MVP.)*
38. **Dependency pinning.** Unpinned deps are reproducibility roulette.
39. **No stale artifacts in the repo.** `.pyc`, `.coverage`, cache dirs = sloppy hygiene.
40. **Docstrings follow ONE format.** Google, NumPy, or Sphinx — pick one, enforce it.

## The AI Slop Detector

> *"This smells like it was generated at 3 AM by a model that doesn't understand the codebase."*

41. **No boilerplate docstrings that restate the function signature.** `"Args: x: The x value"` is noise.
42. **No over-engineered abstractions for one-time operations.** A factory for one class is AI slop.
43. **No defensive coding against impossible states.** `if x is not None` when x is always set is paranoia, not engineering.
44. **No excessive type narrowing.** `isinstance` checks on values you just constructed are waste.
45. **No symmetry for symmetry's sake.** Not every CRUD needs all four operations.
46. **Naming must carry meaning.** `process_data`, `handle_request`, `do_thing` are non-names.
47. **No copy-paste with slight variations.** If two functions differ by one line, parameterize.
48. **No premature configurability.** A config option used by zero users is dead weight.
49. **No aspirational comments.** "Phase 43 will handle this" — no, either do it now or delete the comment.
50. **No wrapper functions that add nothing.** If `def foo(x): return bar(x)`, just use `bar`.

## The Reddit Basher

> *"I opened the repo and immediately closed my laptop."*

51. **If your `__init__.py` is 50+ imports, your package structure is wrong.**
52. **If a test file imports from a deleted module, you have no CI.**
53. **If the same URL appears in two files, you have a constants problem.**
54. **If your ORM model has 15+ fields and no docstring, you wrote a CSV parser not a model.**
55. **If your "service" class is a bag of static methods, it's not a service, it's a namespace.**

## v1.7 Additions — Architecture Boundary Rules

> Added after 50-phase deep architecture review and quality assurance.

56. **No sync DB calls inside async def.** `session_scope()` in an `async def` without `asyncio.to_thread()` blocks the event loop. Always wrap sync DB access in `asyncio.to_thread()`. Enforced by honesty audit rule `sync_in_async`.
57. **Module endpoints must enforce platform auth through the platform mount/auth path.** Routes mounted from modules must rely on the platform-owned auth dependency injected at mount time (`spec.auth_required` → platform dependency) or an equivalent platform auth contract. Unprotected routes are security holes, not features.
58. **Runtime constants come from ConfigRegistry.** If a constant has a corresponding `PlatformConfigSchema` field, read it via `get_task_tuning()` with the constant as fallback. Do not read `os.getenv()` directly for values that have a ConfigRegistry counterpart.
59. **Platform/API/storage must not import module internals directly.** If platform-owned code needs module-specific behavior, the module injects a callable, contract model, route spec, or adapter. Direct imports from `aila.modules.<id>` into platform-, api-, or storage-owned infrastructure are boundary violations.
60. **Platform owns reusable reasoning runtime; modules own domain reasoning adapters.** Shared reasoning machinery — turn protocol, graph persistence, operator steering, strategy plumbing — belongs in platform. Domain semantics — evidence interpretation, prompt supplements, domain-specific validation, and tool execution meaning — stay inside the module adapter. Do not hardcode module-specific cyber semantics into platform services.

---

## Enforcement

17 of these rules are programmatically enforced by the honesty audit:

```
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py
```

| Audit Rule | Golden Rule # |
|------------|---------------|
| unused_parameter | 3, 15 |
| misleading_name | 46 |
| docstring_mismatch | 41 |
| import_boundary | 32, 33 |
| dead_isinstance | 44 |
| redundant_conversion | 43 |
| private_in_all | 16 |
| bare_exception_wrap | 5, 13 |
| always_true_default | 48 |
| god_object_dispatch | 4 |
| todo_in_code | 9, 49 |
| silent_exception | 5, 13 |
| production_assert | 20 |
| do_nothing_wrapper | 50 |
| dead_config_field | 48 |
| sync_in_async | 56 |
| api_imports_module_internals | 59 |

The remaining rules are enforced by code review.
