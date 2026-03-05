# BRAINSTORM — signal-studio-auth
_Updated by Judge Agent v2 (2026-03-05)_

## Current State Summary
FastAPI auth service bridging Supabase Auth with legacy ForwardLane JWTs. Core flows complete:
- ✅ signup/login/refresh/logout/me/invite-to-org
- ✅ Dual-mode JWT middleware (SUPABASE / FORWARDLANE / DUAL)
- ✅ Redis-backed rate limiting with in-memory fallback (TODO-402)
- ✅ Opaque refresh token rotation via Redis (TODO-403)
- ✅ Hardcoded JWT secrets removed (TODO-351)
- ✅ RBAC `require_role()` FastAPI dependency (TODO-353/356)
- ✅ `/invite-to-org` admin-only enforcement
- 3 SQL migrations (organizations, user_profiles, RLS)

**Completeness: ~75%** — Production hardening and enterprise features needed.

---

## 1. New Features (Revenue/Value Impact)

### 🔴 HIGH — Password Reset / Change Routes [S]
- `POST /auth/reset-password` → trigger Supabase password reset email
- `POST /auth/update-password` → authenticated user changes password
- Standard enterprise requirement; missing blocks SAAS self-service
- **Effort: S (2h)**

### 🔴 HIGH — Email Verification Flow [S]
- `POST /auth/resend-verification` → resend Supabase confirmation email
- `GET /auth/verify-email?token=...` → handle callback from email link
- Required for proper signup completion in production
- **Effort: S (2h)**

### 🟡 MEDIUM — Social OAuth Endpoints [M]
- `GET /auth/oauth/{provider}` → initiate OAuth (Google, LinkedIn, GitHub)
- `GET /auth/oauth/callback` → exchange code for tokens
- Needed for enterprise SSO adoption; Supabase has built-in support
- **Effort: M (4h)**

### 🟡 MEDIUM — MFA / TOTP Support [M]
- `POST /auth/mfa/enroll` → generate TOTP QR code
- `POST /auth/mfa/verify` → verify TOTP code + issue session
- Enterprise SOC2 requirement; Supabase supports TOTP natively
- **Effort: M (4h)**

### 🟡 MEDIUM — Audit Log Endpoint [S]
- `GET /auth/audit-log` → admin-only list of auth events
- Surface login/logout/invite/password-change events with timestamps, IP, user-agent
- Needed for compliance and enterprise security reviews
- **Effort: S (3h)**

### 🟢 LOW — Session Management Endpoints [S]
- `GET /auth/sessions` → list active sessions for current user
- `DELETE /auth/sessions/{session_id}` → revoke specific session
- Nice-to-have for enterprise users managing device access
- **Effort: S (2h)**

---

## 2. Code Quality

### 🔴 HIGH — httpx Connection Pooling [S]
- **Problem:** Every route creates `async with httpx.AsyncClient() as client:` — new TCP to Supabase per request
- **Impact:** +10-50ms latency, file descriptor exhaustion under load
- **Fix:** Module-level `AsyncClient` via FastAPI lifespan context manager
- `app.state.http_client = httpx.AsyncClient(timeout=30.0)`
- **Effort: S (1h)**

### 🔴 HIGH — Pydantic v2 Migration [S]
- **Problem:** `middleware/_compat.py` uses v1 `class Config`, `orm_mode`, `allow_population_by_field_name`
- `routes/auth_routes.py` uses deprecated `.dict(by_alias=True)`
- **Fix:** Migrate to `model_config = ConfigDict(...)` and `.model_dump()`
- **Effort: S (2h)**

### 🟡 MEDIUM — Org Membership Validation on /invite-to-org [S]
- **Problem:** Admin check passes but no validation that caller belongs to target org
- An admin of org A can currently invite to org B
- **Fix:** Query `organization_members` table to verify caller's org_id matches
- **Effort: S (2h)**

### 🟡 MEDIUM — Middleware Error Detail Leakage [S]
- **Problem:** `supabase_auth_middleware.py` may expose internal stack traces in production
- **Fix:** Catch all exceptions, log internally, return generic 401/500 response
- **Effort: S (1h)**

### 🟡 MEDIUM — Refresh Token Family Tracking [M]
- **Problem:** If stolen token is used, current system issues new token but doesn't detect theft
- **Fix:** Track parent→child token chain in Redis; on reuse of consumed token, revoke entire family
- **Effort: M (3h)**

### 🟢 LOW — Type Annotations Completeness [S]
- Many functions missing return type annotations
- Add `-> None`, `-> dict`, `-> JSONResponse` throughout routes
- **Effort: S (1h)**

---

## 3. Testing

### 🔴 HIGH — Integration Tests for Redis Paths [M]
- **Missing tests:**
  - `/refresh` Redis round-trip: token consumed + new token issued
  - `/refresh` with consumed token → 401 (token reuse detection)
  - `/logout` with Redis revocation verification
  - `/invite-to-org` role escalation attempt (analyst tries to invite)
  - Rate limit enforcement (6th request within window → 429)
- **Effort: M (4h)**

### 🟡 MEDIUM — E2E Auth Flow Tests [M]
- Full flow: signup → verify email → login → refresh → logout
- Use `pytest-asyncio` with testcontainers (Redis + Supabase mock)
- **Effort: M (4h)**

### 🟡 MEDIUM — RBAC Test Suite [S]
- `test_rbac.py` exists but may not cover all role combinations
- Test all 4 roles × all protected endpoints
- **Effort: S (2h)**

### 🟢 LOW — Coverage Reporting [S]
- Add `pytest-cov` to requirements-dev.txt
- Target 80% coverage threshold in CI
- **Effort: S (30min)**

---

## 4. Integrations

### 🟡 MEDIUM — Webhook Support for Auth Events [M]
- Emit webhooks on: user.signup, user.login, user.invite, password.reset
- Enable downstream services (Signal Studio, analytics) to react
- **Effort: M (3h)**

### 🟡 MEDIUM — Supabase Realtime User Presence [S]
- Integrate with Supabase Realtime for online/offline presence
- Useful for Signal Studio collaborative features
- **Effort: S (2h)**

### 🟢 LOW — Datadog / OpenTelemetry Tracing [M]
- Add OTel spans to auth routes for latency observability
- Track Supabase API call durations, Redis hit rates
- **Effort: M (3h)**

---

## 5. Workflows

### 🔴 HIGH — CI/CD Pipeline [S]
- No `.github/workflows/` found
- Add: lint (ruff), type-check (mypy), test (pytest), Docker build
- **Effort: S (2h)**

### 🟡 MEDIUM — Pre-commit Hooks [XS]
- Add `.pre-commit-config.yaml` with ruff, mypy, trailing-whitespace
- **Effort: XS (30min)**

### 🟡 MEDIUM — Docker Compose for Local Dev [S]
- `docker-compose.yml` with: auth service + Redis + Supabase local
- **Effort: S (2h)**

### 🟢 LOW — Makefile Targets [XS]
- `make dev`, `make test`, `make lint`, `make migrate`
- **Effort: XS (30min)**

---

## 6. Performance

### 🔴 HIGH — httpx Connection Pooling [see Code Quality]

### 🟡 MEDIUM — Redis Pipeline for Token Operations [S]
- `/refresh` currently does 2 sequential Redis ops (GET + SET + DELETE)
- Use Redis pipeline to batch → single round-trip
- **Effort: S (1h)**

### 🟡 MEDIUM — JWT Verification Caching [S]
- Cache decoded JWT claims (by `jti`) for 30s to avoid re-verification on burst requests
- **Effort: S (2h)**

---

## 7. Security

### 🟡 MEDIUM — Refresh Token Theft Detection [see Code Quality - family tracking]

### 🟡 MEDIUM — IP Binding for Refresh Tokens [S]
- Store client IP with refresh token in Redis
- Reject refresh if IP changes (optional: configurable flag)
- **Effort: S (1h)**

### 🟡 MEDIUM — Dependency Vulnerability Scan [XS]
- Add `pip-audit` to CI
- Check: PyJWT, httpx, FastAPI for known CVEs
- **Effort: XS (30min)**

### 🟡 MEDIUM — Missing Audit Migration [S]
- No migration for `auth_events` / `audit_log` table
- Add `migrations/004_audit_log.sql`
- **Effort: S (1h)**

### 🟢 LOW — CORS Policy Review [XS]
- Verify CORS origins are restricted to known Signal Studio domains
- Not wildcard in production
- **Effort: XS (30min)**

### 🟢 LOW — HTTP Security Headers [XS]
- Add HSTS, X-Content-Type-Options, X-Frame-Options via middleware
- **Effort: XS (30min)**

---

## Priority Matrix

| Priority | Item | Effort |
|----------|------|--------|
| 🔴 P0 | httpx connection pooling | 1h |
| 🔴 P0 | Integration tests (Redis/refresh/logout) | 4h |
| 🔴 P0 | Pydantic v2 migration | 2h |
| 🔴 P0 | CI/CD pipeline | 2h |
| 🔴 P0 | Password reset routes | 2h |
| 🟡 P1 | Org membership validation | 2h |
| 🟡 P1 | Refresh token family tracking | 3h |
| 🟡 P1 | Audit log migration + endpoint | 4h |
| 🟡 P1 | Email verification flow | 2h |
| 🟡 P1 | Docker Compose local dev | 2h |
| 🟡 P1 | Pre-commit hooks | 30min |
| 🟢 P2 | Social OAuth | 4h |
| 🟢 P2 | MFA/TOTP | 4h |
| 🟢 P2 | OTel tracing | 3h |
| 🟢 P2 | Webhook auth events | 3h |
