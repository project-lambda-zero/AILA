# ADR-001: JWT Authentication with HS256 and Per-Request Blacklist

**Status:** Accepted
**Date:** 2025 (v1.5)
**Supersedes:** None

## Context

AILA needs API authentication for its REST API. The platform runs as a single-process
uvicorn server with SQLite persistence. Requirements:

- Machine-to-machine authentication (CLI and future frontend clients)
- Role-based access control (admin, operator, reader)
- Instant revocation capability (an operator revokes a key, all its tokens stop working immediately)
- No external identity provider dependency for v1.5

Options considered:

1. **Session cookies** -- Unsuitable for machine-to-machine; requires browser context.
2. **Opaque tokens with DB lookup per request** -- Simple but no self-contained claims.
3. **JWT with HS256 + per-request blacklist check** -- Self-contained claims with instant revocation.
4. **JWT with RS256** -- Appropriate for multi-worker or external verifier, overkill for single-process.

## Decision

Use **JWT access tokens signed with HS256** (symmetric HMAC-SHA256), combined with a
**per-request blacklist check** against the `ApiKeyRecord` table.

### Token structure

Every JWT contains:

- `jti`: Unique token identifier (`uuid4().hex`)
- `key_id`: The issuing API key's database ID (UUID)
- `role`: The key's role claim (`admin`, `operator`, `reader`)
- `typ`: Token type (`access` or `refresh`)
- `exp`: Expiry timestamp
- `iat`: Issued-at timestamp

### Blacklist mechanism

On every authenticated request, `decode_and_blacklist_check()`:

1. Decodes the JWT and verifies the HS256 signature
2. Queries `ApiKeyRecord` by `key_id`
3. Rejects if `revoked_at` is not null

This provides **zero-cache-window revocation**: revoking an API key immediately
invalidates all JWTs issued from it, regardless of their expiry.

### Refresh tokens

Refresh tokens are JWTs with `typ: refresh` and a longer expiry (default 90 days).
They share the same `key_id` claim, so revoking the API key also invalidates
all refresh tokens. No separate refresh token table is needed for v1.5.

### Signing secret

`AILA_JWT_SECRET_KEY` must be set in production. Without it, a random 32-byte hex
secret is generated on each process start, invalidating all existing tokens on restart.

## Consequences

### Positive

- Instant revocation without token introspection infrastructure
- Self-contained role claims enable RBAC without extra DB queries for authorization
- Single signing secret simplifies key management for single-process deployment
- `jti` on every token enables future per-token revocation if needed

### Negative

- Per-request DB query for blacklist check adds latency (~1ms on SQLite, acceptable)
- HS256 requires all token verifiers to share the signing secret (limits to single-trust-domain)
- Switching to RS256 for multi-worker deployment requires a future migration

### Neutral

- PyJWT library handles encoding/decoding; pwdlib[bcrypt] handles API key hashing
- Token expiry defaults (30-day access, 90-day refresh) are configurable via ConfigRegistry

## References

- `src/aila/api/auth.py` -- JWT issuance, decode, blacklist check, role enforcement
- `src/aila/api/constants.py` -- JWT_ALGORITHM, role constants
- `src/aila/storage/db_models.py` -- ApiKeyRecord table
- Phase 64: Auth router deep review
- Phase 73: JWT internals deep review (signature tamper, alg=none, blacklist consistency)
