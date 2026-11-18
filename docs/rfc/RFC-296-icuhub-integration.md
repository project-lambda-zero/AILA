# RFC-296 -- ICUHUB: standalone integration hub as an optional AILA dependency

Status: Proposed.
Issue: #296.
ICUHUB repository: https://github.com/project-lambda-zero/icuhub (AGPL-3.0), included in
AILA as the git submodule `external/icuhub`.
ICUHUB design documents (authoritative for ICUHUB itself):
`external/icuhub/docs/BRD.md`, `external/icuhub/docs/HLD.md`,
`external/icuhub/docs/COMMATRIX.md`.

## 1. Problem

AILA needs to reach enterprise tools from agents and workflows: open fix pull requests,
pull scanner findings, query SIEM, block on WAF, file tickets, read cluster state. The
enterprise installation also contains a posture management console and other hubs that
need the same integrations.

If each platform builds its own connectors:

1. The same vendor code is written and maintained once per product.
2. Vendor credentials live in every product.
3. External side effects (WAF block, host isolation, PR creation) have no single policy
   and no single audit trail.
4. Every tool's format is parsed separately; findings do not correlate.
5. AI agents can reach production systems without one policy gate.

## 2. Decision

Integrations live in **ICUHUB**, a standalone repository and service (ICUHUB ADR-0001),
not inside `aila.platform` and not bound to the AILA codebase. ICUHUB owns:

- vendor connectors (one class per vendor, capability protocols, plain dict registry;
  SCM providers port the PR-Agent `GitProvider` approach and add the write side);
- connection store and credential broker (credentials injected server-side, never given to
  consumers);
- action policy and durable approvals (operations classified `read` / `write` /
  `destructive`; writes execute automatically only when deployment, tenant, and rule
  switches are all on);
- hash-chained audit of every external call;
- OCSF and SARIF 2.1.0 normalization through a shared schema package
  (`icuhub-schemas`). This standardization is required regardless of other choices
  (ICUHUB ADR-0003).

ICUHUB exposes four entry points: REST (`/v1`), MCP (`/mcp`), an event stream
(`icuhub.*` topics), and webhook ingress (`/hooks/{connection_id}`).

AILA is ICUHUB's first consumer. **ICUHUB is optional for AILA**: AILA installs, tests,
and runs without it. Features that need an external integration report that ICUHUB is not
configured instead of falling back to direct vendor calls.

## 3. What stays in AILA

| Concern | Owner |
|---|---|
| Agents, prompts, turn loop, claim verification, narratives | AILA |
| Workflows, investigations, cases, sandbox, PoV, fix loop | AILA |
| AI tool-call ledger, LLM cost, idempotency cache | AILA |
| Agent-level tool allowlists (`tool_authority`) and the operator UI for approvals | AILA (ICUHUB remains the enforcement point) |
| Vendor connectors, credentials, external action policy, external-call audit, normalization | ICUHUB |

Public, unauthenticated advisory feeds used by the vulnerability module
(`modules/vulnerability/providers/`: NVD, OSV, EPSS, GHSA, Alpine secdb) are module domain
data sources, not enterprise tool integrations, and stay in AILA. They are listed in the
boundary audit allowlist (section 5.5) by file, so the list is explicit and reviewable.

## 4. Submodule

| Item | Value |
|---|---|
| Path | `external/icuhub` |
| URL | `https://github.com/project-lambda-zero/icuhub.git` |
| Tracked branch | `main` (released state of ICUHUB) |
| Pin | The submodule commit recorded in AILA is the ICUHUB version AILA is tested against |
| Clone | `git clone --recurse-submodules` or `git submodule update --init external/icuhub` |
| Not required for | `pip install -e ".[dev]"`, `make check`, `make test`, running AILA |

Rules:

1. Nothing under `src/aila/` imports from `external/icuhub` source paths. AILA consumes
   ICUHUB only through its network contract and its published packages
   (`icuhub-schemas`, `icuhub-sdk`) once they exist.
2. The submodule exists so the contract (docs, OpenAPI, event schemas, schema package) is
   versioned next to AILA and so local development can run ICUHUB from the same checkout.
3. Updating the pin is a normal AILA change: bump the submodule commit, note it in the
   CHANGELOG, run the ICUHUB consumer tests (section 7).
4. AILA CI does not need the submodule until consumer contract tests exist (section 7);
   from then on CI checks out submodules.

## 5. Optional-dependency integration plan (AILA side)

### 5.1 Configuration (ConfigRegistry, not `os.getenv`)

| Config key | Env var | Meaning |
|---|---|---|
| `platform.icuhub_url` | `ICUHUB_URL` | Base URL of ICUHUB (for example `https://icuhub.acme.internal`). Unset means ICUHUB is not configured. |
| `platform.icuhub_client_id` | `ICUHUB_CLIENT_ID` | OIDC client-credentials client id for AILA's service identity |
| `platform.icuhub_client_secret` | `ICUHUB_CLIENT_SECRET` | Client secret (secret config value) |
| `platform.icuhub_token_url` | `ICUHUB_TOKEN_URL` | IdP token endpoint |
| `platform.icuhub_timeout_s` | `ICUHUB_TIMEOUT_S` | Per-call timeout, default 60 |

There is no separate `icuhub_enabled` flag: ICUHUB is configured exactly when
`icuhub_url` is set. This mirrors how `rea_mcp_url` / `reverser_belt_mcp_url` select a
remote server.

### 5.2 MCP registration

- Add one `ServerSpec` with `server_id="icuhub"`, `transport="mcp-http"`, URL from
  `platform.icuhub_url` + `/mcp`, bearer token from the client-credentials flow.
- When `icuhub_url` is unset the server is not registered, and no `icuhub` tools appear in
  any agent's tool list.
- Tool names are ICUHUB's `<connection_slug>.<operation>` (for example
  `gitlab-main.open_change_request`, `f5-prod.block`, `gti.lookup`); they appear under the
  `icuhub` server id.
- Modules allowlist the `icuhub` server in their `_AGENT_ALLOWED_SERVERS` per target kind,
  the same way `rea` and `reverser_belt` are allowlisted.
- AILA sets `X-Correlation-Id` to the investigation id on the MCP session and passes branch
  and turn in `_meta`, so ICUHUB's audit joins AILA's tool-call ledger.
- An ICUHUB result with `status: pending_approval` is a normal tool result. The agent sees
  it as an observable; AILA surfaces the pending approval in the operator UI.

### 5.3 REST client (workflows and backend)

- Deterministic workflow steps (for example opening the fix change request after the VR
  regression gates pass) call ICUHUB REST, not MCP, so prompt content cannot decide where a
  PR is opened.
- One platform-owned client in `aila/platform/services/` (single transport file), using
  the generated `icuhub-sdk` once published. Every write call sends an `Idempotency-Key`
  derived from the investigation id and step.

### 5.4 Event subscriber

- A platform-owned subscriber consumes `icuhub.scm.change_request.*`,
  `icuhub.finding.upserted`, and `icuhub.action.*` and starts or advances
  `DurableStateMachine` workflows.
- Blocked on ICUHUB decision D2 (event backbone). Until then AILA polls
  `GET /v1/actions/{id}` for action outcomes it initiated.
- Not started when `icuhub_url` is unset.

### 5.5 Boundary audit

- New check in `make check`: fail on vendor HTTP clients or vendor SDK imports for
  integrated vendor categories anywhere in `src/aila/` outside an explicit allowlist of
  transport files (MCP client, the ICUHUB client, sandbox backends, LLM client, the
  vulnerability module's public advisory providers).
- Enforces ICUHUB COMMATRIX flow X-01 (consumers never call integrated vendors directly).

### 5.6 Schemas

- AILA's canonical finding export uses `icuhub-schemas` (OCSF, SARIF 2.1.0) once the
  package is published. Until then AILA does not define a competing OCSF model.
- Dependency declaration: an optional extra `icuhub = ["icuhub-schemas", "icuhub-sdk"]` in
  `pyproject.toml`, added when the packages are published. Not added before then, so the
  default install never references unpublished packages.

### 5.7 Behaviour without ICUHUB

| Feature | Without ICUHUB |
|---|---|
| Agent tools for enterprise vendors | Not listed |
| VR fix delivery (open change request) | Patch and evidence stay in AILA; the outcome records `delivery: icuhub_not_configured` |
| Event-driven investigation start (MR opened) | Not available; investigations start from the AILA UI/API as today |
| Findings export | AILA's existing reports |

No direct-vendor fallback exists. Unconfigured is reported as such, never as success.

## 6. Phases

| Phase | Work | Depends on |
|---|---|---|
| A (this RFC) | RFC, ICUHUB repository with BRD/HLD/COMMATRIX and AI directives, submodule, notes in CLAUDE.md/AGENTS.md | -- |
| B | ICUHUB Phase 1: `icuhub-schemas` (OCSF pin + SARIF codecs) | ICUHUB D5, D6 |
| C | ICUHUB Phase 2: core (auth, tenancy, connections, credential broker, policy, approvals, audit, REST, MCP, webhooks) | ICUHUB D1, D3, D4, D7 |
| D | AILA consumer: config keys (5.1), MCP registration (5.2), REST client (5.3), boundary audit (5.5) | C |
| E | ICUHUB wave-1 connectors: GitHub, GitLab, Jira, F5, GTI | C, D8 |
| F | VR exploit-and-fix delivery through ICUHUB SCM (draft change request + SARIF upload) | D, E |
| G | AILA event subscriber (5.4) | ICUHUB D2 |
| H | AILA finding export on `icuhub-schemas`; `icuhub` optional extra in `pyproject.toml` | B published |

Each phase from D onward is a separate AILA issue referencing this RFC.

## 7. Verification

| Phase | Check |
|---|---|
| A | AILA installs and `make check` / targeted tests pass with and without `git submodule update --init` |
| D | With `icuhub_url` unset: no `icuhub` server registered, no tools listed. With a running ICUHUB: `tools/list` returns policy-filtered tools; a read operation round-trips; a write returns `pending_approval` |
| D | Boundary audit fails on a deliberately added direct vendor client, passes on the allowlist |
| F | End-to-end: VR investigation with a proven PoV and passing regression gates opens a draft change request through ICUHUB; ICUHUB audit carries the investigation id |
| G | Event `icuhub.scm.change_request.opened` starts an investigation exactly once under redelivery |

## 8. Risks

| Risk | Mitigation |
|---|---|
| Contract drift between AILA and ICUHUB | Submodule pin, versioned REST/MCP/events, consumer contract tests against a pinned ICUHUB image |
| ICUHUB unavailable at runtime | Calls fail with a clear error and an outcome note; investigations continue; no fallback to direct vendor calls |
| Agents trigger destructive actions | ICUHUB classification, three switches, approvals; AILA never auto-approves |
| Public submodule exposes design | Accepted: ICUHUB is public (AGPL-3.0), same as AILA |

## 9. References

- ICUHUB ADR-0001 (standalone repository), ADR-0002 (capability protocols and dict
  registry), ADR-0003 (OCSF and SARIF).
- ICUHUB HLD section 15 (consumer contract), section 16 (worked examples).
- ICUHUB COMMATRIX flows F-001, F-002, F-006, F-007, X-01.
