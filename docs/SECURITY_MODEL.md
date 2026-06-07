# AILA Security Model

Reference for authentication, authorization, JWT issuance, and the request-time
protections that wrap every endpoint.

---

## Overview

AILA accepts two credential types that resolve to the same JWT-Bearer auth
context:

1. **User accounts** — username + password (argon2id-hashed) → user JWT pair
   (`typ=user_access` + `typ=user_refresh`). Created by an admin via
   `POST /users` or auto-provisioned by OIDC. First-boot admin is created from
   `AILA_ADMIN_PASSWORD`.
2. **API keys** — `aila_sk_<32 hex>` raw secrets (bcrypt-hashed) → API-key JWT
   pair (`typ=access` + `typ=refresh`). Issued via `POST /auth/keys` (admin),
   the CLI (`aila create-api-key`), or the optional `AILA_BOOTSTRAP_KEY`
   first-boot path.

Both paths land in the same place: an HS256-signed JWT carried as
`Authorization: Bearer <token>`. The unified dependency `require_user_or_api_key`
(`src/aila/api/auth.py`) decodes either token type and returns an `AuthContext`
with `user_id`, `role`, `auth_type` (`"user"` or `"api_key"`), and `team_id`
(`None` for admin tokens, which see across teams).

OIDC providers (Microsoft, Google, generic) are layered on top of the user
account flow: a successful OIDC callback auto-provisions a `UserRecord` and
returns the same user JWT pair.

RBAC has three roles ordered by privilege:

```
admin (2) > operator (1) > reader (0)
```

Higher levels inherit lower-level access. `require_role("operator")` permits
`operator` and `admin`; `require_role("reader")` permits everyone.
---

## User Account Lifecycle

User accounts live in `user_records` (`UserRecord` in
`src/aila/storage/db_models.py`). Each row carries:

```
UserRecord:
  id:               UUID (used as user_id in user JWTs)
  username:         unique, 3..64 chars
  email:            optional
  hashed_password:  argon2id hash, or NULL for OIDC-only accounts
  role:             "admin" | "operator" | "reader"
  group_id:         optional team-scoping label
  is_active:        soft-delete flag (false = locked out)
  oidc_sub:         OIDC `sub` claim, set on auto-provisioned accounts
  last_login_at:    timestamp of last successful /auth/login
```

### First-boot admin

On startup the lifespan hook checks `user_records`. If the table is empty:

1. Read `AILA_ADMIN_PASSWORD` from the environment.
2. If unset, **startup fails with `RuntimeError`** — no unprotected admin
   account is ever created automatically.
3. If set, create user `admin` with that password (argon2id-hashed via
   `argon2-cffi`, OWASP defaults: time_cost=3, memory_cost=65536,
   parallelism=4, hash_len=32).
4. Any pre-existing `ApiKeyRecord` rows with a NULL `user_id` are attached to
   the new admin account (legacy-key migration path).
5. Log a notice instructing the operator to remove `AILA_ADMIN_PASSWORD` from
   the environment.

Subsequent boots skip the hook because `user_records` is no longer empty.

### Admin-issued accounts

`POST /users` (admin only) creates additional accounts:

- Password is validated against the HaveIBeenPwned k-anonymity range API
  (T-138-09 / D-19). Hits are rejected with 422.
- Password is hashed via `hash_user_password()` (argon2id) before storage.
- `role` must be one of `admin`, `operator`, `reader`.
- The creation event is dual-written to structlog and `AuditEventRecord`.

`PATCH /users/{user_id}` updates role, email, `is_active`, or password.
Soft-delete is `is_active=false`; the record stays in the table.

### Login (`POST /auth/login`)

Body: `{"username": ..., "password": ...}`. The handler:

1. Looks up `UserRecord` by `username`.
2. Returns **401 "Invalid credentials"** on missing user, `is_active=false`,
   OIDC-only account (no local password), or wrong password — the response
   string is identical for every failure mode (T-138-10: no username
   enumeration).
3. On success: issues a user JWT pair, updates `last_login_at`, writes a
   `login_success` audit event.
4. On failure: writes a `login_failed` audit event with the specific reason
   in `details_json` (server-side only; never reflected to the client).

Response shape:

```json
{
  "data": {
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "bearer",
    "expires_in": 31536000
  }
}
```

The refresh token is **also persisted** as SHA-256 in `refresh_token_records`
with the originating `ip_address` and `user_agent`, so refreshes can be
revoked server-side independent of JWT expiry.

### Refresh and logout

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/refresh/user?refresh_token=...` | Verify the refresh token row is not revoked and the user is still active, then issue a new access token. Refresh token is NOT rotated. |
| `POST /auth/logout?refresh_token=...` | Mark the `RefreshTokenRecord` row revoked. |
| `GET /auth/sessions` | List the caller's own non-revoked, non-expired refresh sessions (id, ip, user agent, timestamps — never the token hash). |
| `DELETE /auth/sessions/{session_id}` | Revoke one of the caller's own sessions by row id. |

---

## API Key Lifecycle

### Generation

API keys are generated with the `aila_sk_` prefix followed by 32 hex characters:

```
aila_sk_a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6
```

The raw key is shown **exactly once** at creation time. It is never stored -- only
its bcrypt hash is persisted in the `ApiKeyRecord` table.

### Creation paths

| Method | Command / Endpoint | Role Required |
|--------|-------------------|---------------|
| API | `POST /auth/keys` | admin |
| CLI | `aila create-api-key --role admin` | N/A (direct DB access) |
| Bootstrap | `AILA_BOOTSTRAP_KEY` env var | N/A (first start only) |

### Storage

```
ApiKeyRecord:
  id:          UUID (primary key, used as key_id in JWTs)
  hashed_key:  bcrypt hash of raw key
  key_prefix:  first 12 chars (e.g., "aila_sk_abcd") for identification
  role:        "admin" | "operator" | "reader"
  label:       optional human-readable label
  created_by:  key_id of the admin who created this key (or "system"/"bootstrap")
  created_at:  creation timestamp
  revoked_at:  null if active, timestamp if revoked
```

### Verification

On `POST /auth/token`, the client sends the raw API key. The server:

1. Iterates active (non-revoked) `ApiKeyRecord` rows matching the key prefix
2. Verifies the raw key against each `hashed_key` using bcrypt (`pwdlib`)
3. On match, issues a JWT access token and refresh token
4. On no match, returns 401

### Revocation

`DELETE /auth/keys/{key_id}` sets `revoked_at` to the current timestamp. This
immediately invalidates:

- All access tokens issued from this key (blacklist check on every request)
- All refresh tokens issued from this key (same key_id blacklist)
- The API key itself (cannot issue new tokens)

Revocation is **permanent and instant**. There is no un-revoke operation.

---

## JWT Token Lifecycle

### Access tokens

Issued in two flavours depending on the credential path:

| Path | Endpoint | `typ` claim | Default expiry |
|------|----------|-------------|----------------|
| User account | `POST /auth/login` | `user_access` | 1 year (`_USER_ACCESS_EXPIRY` in `auth.py`) |
| API key | `POST /auth/token` | `access` | 30 days, configurable via `platform.jwt_access_expiry_s` |

Both tokens share the same envelope (HS256, `AILA_JWT_SECRET_KEY`-signed) and
both are accepted by `require_user_or_api_key`.

**User-token claims (`typ=user_access`):**

| Claim | Type | Purpose |
|-------|------|---------|
| `user_id` | str | `UserRecord.id` |
| `role` | str | `admin` / `operator` / `reader` |
| `team_id` | str \| null | Team scope; `null` = admin (cross-team) |
| `typ` | str | `"user_access"` |
| `exp`, `iat` | int | Expiry, issued-at |

**API-key claims (`typ=access`):**

| Claim | Type | Purpose |
|-------|------|---------|
| `jti` | str | Unique token identifier (`uuid4().hex`) |
| `key_id` | str | Issuing `ApiKeyRecord.id` |
| `role` | str | Key's role |
| `typ` | str | `"access"` |
| `exp`, `iat` | int | Expiry, issued-at |

### Refresh tokens

Used to obtain new access tokens without re-presenting the original credential.

| Path | Endpoint | `typ` claim | Server-side row | Default expiry |
|------|----------|-------------|-----------------|----------------|
| User account | `POST /auth/refresh/user?refresh_token=...` | `user_refresh` | `RefreshTokenRecord` keyed by SHA-256 of the token | 1 year |
| API key | `POST /auth/refresh` (Bearer = refresh JWT) | `refresh` | None — revocation rides on `ApiKeyRecord.revoked_at` blacklist | 90 days, `platform.jwt_refresh_expiry_s` |

The API-key refresh issues both a new access token AND a new refresh token. The
old refresh token stays valid until its own `exp` — there is no single-use
enforcement.

The user refresh endpoint does NOT rotate the refresh token; revocation is
handled instead by setting `revoked_at` on the `RefreshTokenRecord` row
(`POST /auth/logout` or `DELETE /auth/sessions/{id}`).

### Signing

- **Algorithm:** HS256 (symmetric HMAC-SHA256)
- **Secret:** `AILA_JWT_SECRET_KEY` environment variable
- **Library:** PyJWT

**Production requirement:** `AILA_JWT_SECRET_KEY` MUST be set. Without it, a random
secret is generated on each process start, invalidating all existing tokens on restart.

### Blacklist check

On every authenticated request, the decoder runs:

1. Decode the JWT and verify the HS256 signature.
2. Reject if `typ` does not match the expected type for the caller dependency.
3. For API-key tokens (`typ=access`): look up `ApiKeyRecord` by `key_id` and
   reject if the row is missing or `revoked_at` is set.
4. For user tokens (`typ=user_access`): look up `UserRecord` by `user_id` and
   reject if missing or `is_active=false`.
5. Build `AuthContext(user_id, role, auth_type, team_id)` for the handler.

API-key revocation is therefore **zero-cache-window**: setting `revoked_at`
immediately invalidates every outstanding JWT signed against that key,
regardless of the JWT's own `exp`.

User refresh tokens add a second revocation surface: the SHA-256 hash row in
`refresh_token_records`. A refresh token is rejected if its row is missing or
`revoked_at` is set, even when the JWT signature itself is still valid.

`safe_exc_message()` (`src/aila/platform/workflows/log.py`) governs how
exception text is persisted in the audit log table — exceptions are redacted
to `type(exc).__name__` by default, so credential strings or stack traces
cannot leak into `workflowauditrecord` rows. Handler crash text still lands
in structlog server-side; only the durable audit row is sanitized.


---

## RBAC Model

### Role hierarchy

```
admin (level 2) > operator (level 1) > reader (level 0)
```

Higher roles inherit all permissions of lower roles. An operator token can access
all reader endpoints. An admin token can access all endpoints.

### Role levels

| Role | Level | Typical permissions |
|------|-------|-------------------|
| `reader` | 0 | Read-only access: GET endpoints for systems, findings, reports, tasks, sessions |
| `operator` | 1 | Reader + write operations: POST scans, create sessions, submit tasks, invoke tools |
| `admin` | 2 | Operator + administrative: create/revoke API keys, modify config, delete systems |

### Enforcement

**Router-level auth** (`require_api_key`):

Every protected router is mounted with `dependencies=[Depends(require_api_key)]`.
This ensures all endpoints under the router require a valid JWT. No per-endpoint
auth wiring is needed -- the platform applies it at mount time.

**Endpoint-level role check** (`require_role`):

Endpoints that need a specific role use the `require_role()` dependency factory:

```python
@router.post("/keys")
async def create_key(
    admin: ApiKeyRecord = Depends(require_role("admin")),
):
    ...
```

`require_role("admin")` returns a dependency that:
1. First runs `require_api_key` (JWT decode + blacklist check)
2. Then checks `ROLE_LEVELS[key.role] >= ROLE_LEVELS["admin"]`
3. Returns 403 if the caller's role level is too low

### Public endpoints

These endpoints do NOT require authentication:

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/login` | Username/password login → user JWT pair |
| `POST /auth/refresh/user` | Exchange a `user_refresh` token for a new access token |
| `POST /auth/logout` | Revoke a refresh-token session |
| `POST /auth/token` | Exchange an API key for the API-key JWT pair |
| `POST /auth/refresh` | Refresh an API-key access token |
| `GET /auth/oidc/providers/public` | List enabled OIDC providers for the login page |
| `GET /auth/oidc/authorize` | Begin an OIDC login flow |
| `GET /auth/oidc/callback` | Complete an OIDC login flow |
| `GET /health`, `GET /health/comprehensive` | Liveness + per-module readiness |
| `GET /status` | Server uptime + version |
| `GET /metrics` | Prometheus scrape endpoint |

All other endpoints require a valid Bearer JWT.

The public auth endpoints are rate-limited per slowapi keys derived from the
caller's `user_id`/`key_id` claim when present, otherwise the remote IP:
`POST /auth/login` at 10/minute, `POST /auth/token` and `POST /auth/refresh`
at 5/minute, the OIDC admin and provider-mutation endpoints at 60/minute.


---

## Bootstrap

First boot needs an admin credential of some kind. Two independent paths exist:

**1. Admin user (required when `user_records` is empty)**

- Set `AILA_ADMIN_PASSWORD=<strong-password>` before first start.
- The lifespan hook creates user `admin` with that password (argon2id).
- Startup raises `RuntimeError` if `user_records` is empty and the env var is
  missing — there is no implicit default password.
- Remove `AILA_ADMIN_PASSWORD` from the environment after first boot.
- Subsequent boots skip the hook because `user_records` is no longer empty.

**2. Legacy API key (optional)**

- Set `AILA_BOOTSTRAP_KEY=<long-random-secret>` before first start.
- On startup, if `ApiKeyRecord` has zero rows, the value is bcrypt-hashed and
  stored as an admin key with label `bootstrap`.
- Exchange the raw value at `POST /auth/token` to receive the API-key JWT pair.
- Remove `AILA_BOOTSTRAP_KEY` from the environment afterwards. The hook is
  idempotent: once any API key exists, the env var is ignored on restart.
- Pre-existing API keys with NULL `user_id` are auto-attached to the bootstrap
  admin user the first time the user-bootstrap hook runs (legacy migration).

Both bootstrap mechanisms are first-boot-only. Operators MUST also set
`AILA_JWT_SECRET_KEY` (generate with `openssl rand -hex 32`); when unset the
process logs a warning and synthesizes a random secret per start, which
invalidates every issued JWT on restart.


---

## Token Expiry Configuration

Token expiry is configurable via ConfigRegistry (no restart needed):

| Setting | Default | ConfigRegistry Key | Env Var Override |
|---------|---------|-------------------|-----------------|
| Access token | 30 days | `platform.jwt_access_expiry_s` | `AILA_PLATFORM_JWT_ACCESS_EXPIRY_S` |
| Refresh token | 90 days | `platform.jwt_refresh_expiry_s` | `AILA_PLATFORM_JWT_REFRESH_EXPIRY_S` |

Change at runtime:

```
PUT /config/platform/jwt_access_expiry_s
{"value": "3600"}
```

New tokens issued after the change use the updated expiry. Existing tokens retain
their original expiry.

---

## OIDC

`src/aila/api/routers/oidc.py` mounts an admin CRUD surface plus a public
login surface for OIDC-backed authentication:

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /auth/oidc/providers/public` | none | Enabled providers for the login chooser (id, display name, type only) |
| `GET /auth/oidc/authorize` | none | Returns the upstream authorization URL; sets a short-lived signed `oidc_state` cookie (CSRF) |
| `GET /auth/oidc/callback` | none | Exchanges code, verifies `id_token` against the issuer JWKS, auto-provisions a `UserRecord`, returns the user JWT pair |
| `GET /auth/oidc/providers` | admin | Full provider list (still never returns `client_secret`) |
| `POST /auth/oidc/providers` | admin | Create a provider (`microsoft` / `google` / `generic`); `client_secret` is stored encrypted via `SecretStore` |
| `PUT /auth/oidc/providers/{id}` | admin | Partial update |
| `DELETE /auth/oidc/providers/{id}` | admin | Delete a provider and its `SecretRecord` |

Implementation notes:

- The `oidc_state` cookie is a 10-minute signed JWT (`AILA_JWT_SECRET_KEY`).
- Provider secrets are encrypted at rest and never returned by any read
  endpoint.
- Well-known and JWKS documents are cached in-process for one hour and
  invalidated on provider mutation.
- Microsoft providers use `msal`; Google and generic providers build the
  authorize URL from the well-known document directly.

---

## Request-time protections

Every request flows through the same middleware chain (see `create_app()`
in `src/aila/api/app.py`):

| Layer | Effect |
|-------|--------|
| `CORSMiddleware` | Origins from `AILA_CORS_ORIGINS` (CSV). Dev default covers Vite ports 3000/4173/5173 on localhost and 127.0.0.1. |
| `IdempotencyMiddleware` | POSTs carrying an `Idempotency-Key` header are cached in Redis under `IDEM:{key}` for 24 h; duplicate requests replay the cached body with `X-Idempotency-Replayed: true`. Graceful degradation when Redis is down. |
| `CorrelationIdMiddleware` | Reads or generates `X-Correlation-ID`, binds it to structlog contextvars alongside `path` and `method`, and echoes the header in the response. |
| `_reject_oversized_requests` | Rejects any request with `Content-Length > 10 MB` with HTTP 413 + `PAYLOAD_TOO_LARGE`. |
| `_catch_unhandled_exceptions` | Last-resort 500 wrapper so unhandled exceptions never leak a stack trace to the client. |
| `_prometheus_request_middleware` | Counts requests and latency per `(method, endpoint, status_code)`. |
| slowapi `Limiter` | Per-authenticated-user rate-limit buckets derived from the JWT `user_id`/`key_id` claim (signature unverified — bucketing only) with IP fallback. Triggered limits return HTTP 429 via the slowapi exception handler. |

---

## Audit Trail

`AuditEventRecord` rows are immutable; query them via `GET /audit/events`
(filterable) or `GET /audit/events/{run_id}` (full trail for a single run).
The `auth` stage covers both credential paths:

| Action | Stage | Trigger |
|--------|-------|---------|
| `login_success` | `auth` | `POST /auth/login` accepts a credential |
| `login_failed` | `auth` | `POST /auth/login` rejects a credential — reason recorded server-side in `details_json` |
| `token_issue` | `auth` | `POST /auth/token` issues an API-key JWT |
| `token_refresh` | `auth` | `POST /auth/refresh` rotates an API-key JWT |
| `create_api_key` | `auth` | `POST /auth/keys` |
| `revoke_api_key` | `auth` | `DELETE /auth/keys/{key_id}` |

Other stages (`config`, `scan`, `session`, `system`, `task`, `tool`,
`finding`) carry the matching actions for their domain — see
`AUDIT_ACTION_*` constants in `src/aila/api/constants.py`. Seals for LLM
calls live in `AuditSealRecord`, queryable via `GET /audit/seals` (admin).


---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| HS256 over RS256 | Single-process deployment; no external token verifiers |
| Per-request blacklist check | Instant revocation without cache invalidation infrastructure |
| bcrypt for key hashing | Industry-standard, hardware-resistant, via pwdlib |
| No session cookies | Machine-to-machine auth; no browser dependency |
| Router-level Depends | Prevents per-endpoint auth drift (Pitfall 5) |
| key_prefix exposure | Operators can identify keys without seeing the raw value |
| jti on every token | Enables future per-token revocation if needed |

---

*Source: `src/aila/api/routers/auth.py`, `src/aila/api/routers/users.py`,
`src/aila/api/routers/oidc.py`, `src/aila/api/auth.py`, `src/aila/api/app.py`,
`src/aila/api/middleware/`, `src/aila/storage/db_models.py`.*
