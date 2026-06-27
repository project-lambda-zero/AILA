# Security Policy

AILA is a security platform. We take vulnerabilities in AILA itself
seriously and want to fix them before public disclosure.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Preferred channel: GitHub Security Advisories.**
File a private advisory at
[github.com/project-lambda-zero/AILA/security/advisories/new](https://github.com/project-lambda-zero/AILA/security/advisories/new).

**Alternative:** open a public GitHub issue with the label `security:private`
and minimal detail; we will follow up by email for full reproduction context.

### What to include

- A concrete reproduction (target binary, test repo, config snippet, request body)
- The component affected (platform layer, module name, specific file)
- The AILA version or commit SHA you observed it on
- Your assessment of impact and exploitability

### Response timeline

- Acknowledgment within 5 business days
- Triage and severity assessment within 10 business days
- A fix landed and a public advisory published, with credit, when remediation is ready

### Scope

**In scope:**

- The AILA platform (`src/aila/platform/`)
- Any module under `src/aila/modules/`
- The frontend shell (`frontend/`)
- The bundled `Dockerfile` and `docker-compose` configuration

**Out of scope (report upstream where applicable):**

- Bugs in third-party dependencies (FastAPI, SQLModel, pgvector, React, ...) --
  report to the upstream project and we will track the fix on our side
- Issues that require local filesystem or shell access on the host running AILA --
  those sit outside the trust boundary of a network-exposed service
- Findings against an AILA deployment you do not own and have no authorization
  to test

### Credit

Responsible reporters are credited in the published advisory and in release
notes, unless you ask us not to.
