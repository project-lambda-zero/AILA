# Changelog

All notable changes to AILA are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.0] - 2026-06-27 -- Initial public release

AILA is a modular AI security platform. This first public release
includes the platform core, four production-ready modules, a
React + Vite frontend, and a Docker deployment story.

### Platform

- FastAPI REST API with JWT, OIDC, and API-key authentication;
  per-team scoping enforced through the auth context.
- ARQ + Redis task queue with per-queue workers, the durable
  state machine cursor (`workflow_state_cursor`), and the
  workflow engine that drives every multi-step backend action.
- LLM gateway with per-task-type model routing, request-keyed
  idempotency cache, cost tracking, classification + verification
  + seal pipeline, and budget enforcement.
- `ConfigRegistry` -- typed configuration resolved env -> DB ->
  schema default, with TTL cache and per-namespace validators.
- MCP bridges to audit-mcp (source-code indexing + semantic
  search), ida-headless-mcp (binary decompilation), and
  android-mcp (APK analysis). A shared tool-registry layer
  exposes a uniform tool surface to every module.
- Module discovery -- drop a directory under `src/aila/modules/`
  with `module.py` + `create_module()` and the platform wires it
  at boot. Platform never imports from modules.
- Honesty audit (`python -m aila.tools.honesty_audit`) -- 33
  structural rules that enforce the architectural boundaries
  documented in `docs/GOLDEN_RULES.md` and `docs/HONESTY_AUDIT.md`.
- React + Vite + TypeScript frontend organized as a pnpm
  workspace. Tailwind v4 design system, shadcn/ui primitives,
  module-local extension points via the extension registry.
- Docker image for the API + workers; full-stack
  `docker-compose.full.yml` for development.

### Modules

- `vulnerability` -- CVE scanning, advisory ingestion, remediation
  scoring, inventory drift analysis, peer comparison across hosts.
- `forensics` -- DFIR investigation pipeline. Disk + memory image
  triage, evidence carving, freeflow LLM agent over example
  workflows, machine readiness checks for analyzer tooling.
- `vr` -- vulnerability research agent loop with multi-persona
  branch coordination, claim verification, pattern extraction,
  variant hunt with auto-spawned child investigations, PoC
  drafting, and ReportLab PDF export. Includes the OWASP MASVS
  L1/L2 audit framework and an Android APK + jadx + MobSF pipeline.
- `hello_world` -- reference module showing the minimal contract
  every new module must implement.

### Documentation

- 40+ docs covering architecture, deployment, the module
  standard, the frontend module standard, the config registry,
  the LLM integration layer, task queue ops, SSE, testing,
  the production rubric, and the honesty audit ruleset.
- Tutorial walkthrough for building a new module
  (`docs/MODULE_TUTORIAL.md`) and the contributor guide
  (`docs/CONTRIBUTING.md`).
