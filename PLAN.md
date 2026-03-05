# PLAN — signal-studio-auth
_Updated by Judge Agent v2 (2026-03-05)_

## Architecture Overview

```
Signal Studio Frontend
        │
        ▼
signal-studio-auth (FastAPI)
    ├── POST /auth/signup         → Supabase /auth/v1/signup
    ├── POST /auth/login          → Supabase /auth/v1/token
    ├── POST /auth/refresh        → Redis rotate + Supabase /auth/v1/token ✅
    ├── POST /auth/logout         → Redis revoke + Supabase /auth/v1/logout ✅
    ├── GET  /auth/me             → request.state.user (decoded by middleware)
    ├── POST /auth/invite-to-org  → Admin-only ✅ + org membership check (TODO-602)
    ├── POST /auth/reset-password → Supabase /auth/v1/recover (TODO-605)
    ├── POST /auth/update-password→ Supabase /auth/v1/user (TODO-605)
    ├── GET  /auth/audit-log      → Admin-only audit trail (TODO-604)
    └── Middleware: supabase_auth_middleware
            ├── SUPABASE mode → verify local JWT (PyJWT)
            ├── FORWARDLANE mode → verify via ForwardLane service
            └── DUAL mode → try Supabase first, fallback ForwardLane

Infrastructure:
    ├── Redis — rate limiting (sliding window) + refresh token store
    ├── Supabase — auth provider, user store, org/profile tables
    └── PostgreSQL (via Supabase) — organizations, user_profiles, RLS policies
```

## Completed Work
| TODO | Description | Status |
|------|-------------|--------|
| TODO-351 | Fix hardcoded JWT secrets | ✅ DONE |
| TODO-352 | In-memory rate limiting | ✅ DONE |
| TODO-353 | Admin role check on /invite-to-org | ✅ DONE |
| TODO-356 | `require_role()` RBAC dependency | ✅ DONE |
| TODO-402 | Redis-backed rate limiter | ✅ DONE |
| TODO-403 | Opaque refresh token rotation | ✅ DONE |

## Remaining Work (Priority Order)

### Wave 1 — P0 (Ship This Week)
| TODO | Description | Effort | Blocking |
|------|-------------|--------|---------|
| TODO-600 | httpx connection pooling | 1h | TODO-601, 602, 604 |
| TODO-404 | Pydantic v2 migration | 2h | — |
| TODO-601 | Redis integration tests | 4h | CI/CD |
| TODO-605 | Password reset / update routes | 2h | — |
| TODO-406 | Dockerfile + CI/CD | 2h | — |

### Wave 2 — P1 (This Sprint)
| TODO | Description | Effort | Blocking |
|------|-------------|--------|---------|
| TODO-602 | Org membership validation | 2h | TODO-600 |
| TODO-603 | Refresh token family tracking | 3h | TODO-601 |
| TODO-604 | Audit log migration + endpoint | 4h | TODO-600 |

### Wave 3 — P2 (Next Sprint)
| TODO | Description | Effort |
|------|-------------|--------|
| — | Social OAuth (Google/LinkedIn) | 4h |
| — | MFA/TOTP | 4h |
| — | Webhook auth events | 3h |
| — | OTel tracing | 3h |

## Dependency Graph

```
TODO-600 (httpx pooling)
    ├── TODO-601 (integration tests)
    │       └── TODO-603 (token family tracking)
    ├── TODO-602 (org membership)
    └── TODO-604 (audit log)
            └── TODO-605 (password reset — audit logging)

TODO-404 (Pydantic v2) — independent
TODO-406 (CI/CD) — depends on TODO-601 (need tests to run)
```

## Recommended Execution Order

1. **TODO-600** — httpx pooling (unblocks 3 others, 1h)
2. **TODO-404** — Pydantic v2 (clean before adding features, 2h)
3. **TODO-605** — Password reset routes (quick win, 2h)
4. **TODO-601** — Integration tests (4h, needed before CI)
5. **TODO-602** — Org membership validation (2h)
6. **TODO-603** — Token family tracking (3h)
7. **TODO-604** — Audit log (4h)
8. **TODO-406** — CI/CD pipeline (2h, runs after tests pass)

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Redis failure in production | Medium | High | Fallback to in-memory already implemented ✅ |
| Pydantic v2 `.model_dump()` breakage | High | Medium | Add backward compat shim, test before merge |
| Supabase rate limits on admin API | Low | Medium | Add retry with backoff on 429 |
| Token theft before family tracking | Medium | High | Priority P1 in Wave 2 |
| No CI → broken main branch | High | High | TODO-406 in Wave 1 |
