# AILA Security Model

Complete reference for authentication, authorization, and key management in AILA.

---

## Overview

AILA uses a three-layer security model:

1. **API Keys** -- Machine credentials issued to operators (bcrypt-hashed, prefixed with `aila_sk_`)
2. **JWT Tokens** -- Short-lived access tokens and long-lived refresh tokens (HS256-signed)
3. **RBAC** -- Role-based access control with three roles (admin, operator, reader)

All protected endpoints require a valid JWT Bearer token. The token is verified on
every request, including a database check for key revocation (zero-cache-window blacklist).

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

Issued by `POST /auth/token` after successful API key verification.

**Claims:**

| Claim | Type | Purpose |
|-------|------|---------|
| `jti` | str | Unique token identifier (`uuid4().hex`) |
| `key_id` | str | Issuing API key's database ID |
| `role` | str | Key's role (`admin`, `operator`, `reader`) |
| `typ` | str | `"access"` |
| `exp` | int | Expiry timestamp |
| `iat` | int | Issued-at timestamp |

**Default expiry:** 30 days (configurable via `platform.jwt_access_expiry_s` in ConfigRegistry).

### Refresh tokens

Issued alongside access tokens. Used to obtain new access tokens without
re-submitting the raw API key.

**Claims:** Same as access tokens, but `typ` is `"refresh"` and default expiry is
90 days (configurable via `platform.jwt_refresh_expiry_s`).

**Refresh flow:**

```
POST /auth/refresh
Authorization: Bearer <refresh_token>

Response: { access_token, refresh_token, expires_in, token_type }
```

A new access token AND a new refresh token are issued on each refresh (rotation).
The old refresh token remains valid until its expiry (no single-use enforcement in v1.5).

### Signing

- **Algorithm:** HS256 (symmetric HMAC-SHA256)
- **Secret:** `AILA_JWT_SECRET_KEY` environment variable
- **Library:** PyJWT

**Production requirement:** `AILA_JWT_SECRET_KEY` MUST be set. Without it, a random
secret is generated on each process start, invalidating all existing tokens on restart.

### Blacklist check (D-11)

On every authenticated request, `decode_and_blacklist_check()`:

1. Decodes the JWT and verifies the HS256 signature
2. Checks `typ` matches the expected type (`access` for normal requests)
3. Extracts `key_id` from the payload
4. Queries `ApiKeyRecord` by `key_id`
5. Rejects if the key record is missing or `revoked_at` is not null

This provides **zero-cache-window revocation**: revoking a key immediately
invalidates all tokens, regardless of their `exp` claim.

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
| `POST /auth/token` | Exchange API key for JWT |
| `POST /auth/refresh` | Refresh an access token |
| `GET /health` | Health check (liveness) |
| `GET /status` | Server status (uptime, version) |

All other endpoints require a valid JWT Bearer token.

---

## Bootstrap Key Flow

For first-time deployment when no API keys exist:

1. Set `AILA_BOOTSTRAP_KEY=your-long-random-key-here` in the environment
2. Start the server
3. On startup, if the database has zero `ApiKeyRecord` rows:
   - The bootstrap key is hashed with bcrypt
   - An `ApiKeyRecord` is created with role `admin` and label `bootstrap`
4. Use the bootstrap key value with `POST /auth/token` to get a JWT
5. Use the JWT to create additional API keys via `POST /auth/keys`
6. **Remove `AILA_BOOTSTRAP_KEY` from the environment** after first start

The bootstrap is idempotent: if any API keys already exist, the bootstrap key
is ignored (prevents duplicate admin keys on restart).

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

## Audit Trail

All state-changing auth operations produce audit events:

| Action | Audit Event | Stage |
|--------|------------|-------|
| Create API key | `create_api_key` | `auth` |
| Revoke API key | `revoke_api_key` | `auth` |
| Issue token | `token_issue` | `auth` |
| Refresh token | `token_refresh` | `auth` |

Audit events are immutable `AuditEventRecord` rows. Query via `GET /audit`.

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

*Source: `src/aila/api/auth.py`, `src/aila/api/app.py`, `src/aila/storage/db_models.py`*
*Last updated: 2026-04-05*
