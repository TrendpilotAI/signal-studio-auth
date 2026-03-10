# BRAINSTORM.md — signal-studio-auth

_Last updated: 2026-07-08 · Post SSA-001/002/003 audit_

## Current State Summary

FastAPI auth proxy for Signal Studio using Supabase. Solid foundation with meaningful gaps blocking production deployment.

**What exists:**
- Dual-mode JWT middleware (Supabase + legacy ForwardLane fallback)
- Redis-backed refresh token rotation with theft detection (family tracking)
- RBAC `require_role()` FastAPI dependency
- Sliding-window rate limiting (Redis primary, in-memory fallback)
- Password reset + update endpoints with complexity validation
- Org membership validation on invite
- SecurityHeadersMiddleware (HSTS, CSP, X-Frame-Options, etc.)
- Shared httpx.AsyncClient connection pool (lifespan-managed)
- 8 test files, ~2470 lines of tests

**Recent commits:**
- **SSA-001:** Removed dead `_build_rate_limiter()` + duplicate `_get_caller_role()` import
- **SSA-002:** Added `SecurityHeadersMiddleware` class
- **SSA-003:** Pinned all dependency versions, fixed pip-audit CVEs

**Scores:** revenue_potential=6 · strategic_value=8 · completeness=7 · urgency=6 · effort_remaining=7

---

## ⚠️ Critical Issues Found (Post SSA-001/002/003)

These are bugs and dead code in the current codebase, not feature requests.

### CRIT-1: Duplicate + Conflicting Security Headers
**Severity: HIGH (correctness bug)**

`main.py` has TWO security header mechanisms:
1. `app.add_middleware(SecurityHeadersMiddleware)` — the SSA-002 class
2. `@app.middleware("http") async def security_headers_middleware(...)` — an inline middleware

They set **conflicting values**:

| Header | SecurityHeadersMiddleware (class) | Inline middleware |
|--------|-----------------------------------|-------------------|
| HSTS | `max-age=31536000; includeSubDomains; preload` | `max-age=31536000; includeSubDomains` (no preload) |
| CSP | `default-src 'none'; frame-ancestors 'none'; form-action 'self'` | `default-src 'self'` |
| X-XSS-Protection | `1; mode=block` | `0` |
| Permissions-Policy | ✅ Set | ❌ Not set |

The inline middleware runs **after** the class middleware (FastAPI middleware stack is LIFO), so it **overwrites** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and X-XSS-Protection with its values. Permissions-Policy survives because the inline middleware doesn't touch it.

**Net effect:** The carefully crafted SSA-002 class headers are silently overwritten. The inline one is the SSA-002 *artifact* that should have been removed when the class was added.

**Fix:** Delete the inline `@app.middleware("http")` in `main.py` (lines ~56-65). Keep the class. **Effort: 5 min.**

### CRIT-2: `_rotate_family_token()` is Dead Code
**Severity: MEDIUM (DRY violation, maintenance trap)**

The function exists (lines ~180-220 in `auth_routes.py`) with full theft detection logic, but the `/refresh` route **never calls it**. Instead, `/refresh` duplicates all the same logic inline:
- Check if token exists in Redis
- Check if consumed → theft detection → family revocation
- Mark old token consumed
- Issue new child token

This happened because the refresh route was written before the helper was extracted (or vice versa) and they drifted apart.

**Fix:** Refactor `/refresh` to call `_rotate_family_token()`. Remove the inline duplication. **Effort: 30 min** (need to adjust return values + test assertions).

### CRIT-3: `PasswordUpdateRequest.validate_password_complexity()` is Dead
**Severity: MEDIUM (false sense of security)**

The classmethod exists but is **missing the `@field_validator("new_password")` decorator**. Pydantic v2 never calls it. Meanwhile, `update_password()` route re-implements the same 4 checks manually with `if` blocks + `HTTPException`.

**Two problems:**
1. Dead code that looks like it should be doing something
2. If someone adds a new endpoint that uses `PasswordUpdateRequest`, they'll assume validation runs. It doesn't.

**Fix:** Either (a) add `@field_validator("new_password", mode="before")` and remove the route-level checks, or (b) delete the classmethod and keep the route-level checks as the single source. Option (a) is cleaner — Pydantic validation fires before the route, giving better error messages. **Effort: 15 min.**

### CRIT-4: Rate Limiter Instantiation per Request
**Severity: MEDIUM (performance, GC pressure)**

`_redis_or_memory_check()` creates **new** `RedisStorage` + `SlidingWindowRateLimiter` objects on every single rate-limited request:

```python
storage = RedisStorage(REDIS_URL)      # new connection each time
limiter = SlidingWindowRateLimiter(storage)  # new object each time
limit_item = parse_limit(...)          # re-parsed each time
```

Under load, this means hundreds of Redis connections opened/closed per second plus constant object allocation. The `limits` library is designed for singleton usage.

**Fix:** Create module-level singletons with lazy init:
```python
_redis_storage: RedisStorage | None = None
_sliding_limiter: SlidingWindowRateLimiter | None = None

def _get_limiter():
    global _redis_storage, _sliding_limiter
    if _redis_storage is None:
        _redis_storage = RedisStorage(REDIS_URL)
        _sliding_limiter = SlidingWindowRateLimiter(_redis_storage)
    return _sliding_limiter
```
**Effort: 20 min.**

### CRIT-5: `update_password()` Redis Scan Comment is Misleading
**Severity: LOW (misleading comment, not a bug)**

The route has a comment "Revoke all existing opaque refresh tokens for this user in Redis / We do a best-effort scan" but never actually scans or iterates Redis keys. It just calls Supabase admin logout. The Redis token family for the user is left intact.

**Fix:** Either (a) actually scan `rt:*` keys for matching `user_id` and delete them, or (b) update the comment to reflect reality. Option (a) is correct behavior — after a password change, all refresh tokens should be invalidated. **Effort: 30 min** for proper implementation with `SCAN`.

### CRIT-6: X-Forwarded-For Spoofing
**Severity: MEDIUM (rate limit bypass)**

`_client_ip()` trusts the first value in `X-Forwarded-For` unconditionally:
```python
return forwarded_for.split(",")[0].strip()
```

An attacker can set `X-Forwarded-For: 1.2.3.4` to any IP, bypassing per-IP rate limits entirely. Behind Railway's proxy, the **last** (rightmost) value before the load balancer's append is the real IP.

**Fix:** Configure trusted proxy depth. Railway adds one hop, so use the **last** IP in the chain, or better: use Railway's `X-Real-IP` header if available. **Effort: 20 min.**

### CRIT-7: No Startup Validation for Required Env Vars
**Severity: MEDIUM (silent misconfiguration)**

`SUPABASE_URL`, `SUPABASE_JWT_SECRET`, and `SUPABASE_SERVICE_KEY` are read via plain `os.environ.get()` with empty string defaults. If unset, the app starts fine but every auth request fails with cryptic errors.

Only `AUTH_SECRET_KEY` uses `_require_secret()`. The Supabase variables should too.

**Fix:** Add startup validation in `supabase_config.py` or a `@app.on_event("startup")` hook. **Effort: 15 min.**

### CRIT-8: Response Models Defined But Never Used
**Severity: LOW (dead code)**

`models.py` defines `UserResponse`, `LoginResponse`, and `SignupResponse` but no route uses `response_model=...`. The actual responses are raw `dict` returns from Supabase.

**Fix:** Either wire them into routes (better API docs + validation) or delete the file. Wiring them in is the right call — it gives you OpenAPI schema docs for free. **Effort: 45 min.**

---

## 1. New Features

### 🔴 HIGH PRIORITY

**A. CORS Configuration** ← BLOCKS FRONTEND
- No CORS middleware configured anywhere
- Signal Studio frontend (Next.js) calls this service from the browser → blocked by CORS
- This is a **deployment blocker**, not a nice-to-have
- Effort: **10 min** (add `CORSMiddleware` with configured origins)
- Must support: Signal Studio prod domain, localhost:3000 for dev

**B. Admin Token Revocation Endpoint**
- `DELETE /auth/admin/users/{user_id}/sessions` — force-revoke all Redis tokens for a user
- Critical for security incident response (compromised account)
- Uses `SCAN` to find all `rt:*` keys with matching `user_id`, then deletes + family cleanup
- Effort: **1-2 hours** (includes tests)

**C. Magic Link / OTP Authentication**
- Add `/auth/magic-link` endpoint to send Supabase magic link emails
- Add `/auth/verify-otp` for OTP-based login flows
- Effort: **Small** (Supabase already supports it, just need proxy route + rate limit)
- Value: Reduces friction for Signal Studio onboarding

**D. Session Listing Endpoint**
- `GET /auth/sessions` — list active sessions for the authenticated user
- Shows device, IP, created_at, last_used from Redis token metadata
- Effort: **Medium** (need to store metadata at token issuance time)
- Value: Trust + transparency for end users

### 🟡 MEDIUM PRIORITY

**E. OAuth Provider Support**
- Add `/auth/oauth/{provider}` endpoints (Google, LinkedIn)
- Required for enterprise B2B onboarding (ForwardLane clients use Google SSO)
- Effort: **Medium**

**F. Webhook Receiver for Supabase Auth Events**
- Endpoint to receive Supabase `user.created`, `user.deleted` webhooks
- Sync org memberships, send welcome emails, provision downstream services
- Effort: **Medium**

**G. API Key Authentication**
- Lightweight API key auth for machine-to-machine calls (e.g., cron jobs, internal services)
- Keys stored in Redis with TTL and rate limits per key
- Effort: **Medium**

---

## 2. Code Quality

| Issue | Severity | Effort | Ref |
|-------|----------|--------|-----|
| Delete inline security headers middleware in `main.py` | 🔴 HIGH | 5 min | CRIT-1 |
| Refactor `/refresh` to call `_rotate_family_token()` | 🟡 MED | 30 min | CRIT-2 |
| Fix `validate_password_complexity()` decorator | 🟡 MED | 15 min | CRIT-3 |
| Singleton rate limiter objects | 🟡 MED | 20 min | CRIT-4 |
| Fix `update_password()` Redis token cleanup | 🟡 MED | 30 min | CRIT-5 |
| Wire or delete response models in `models.py` | 🟠 LOW | 45 min | CRIT-8 |
| Add return type annotations to `_supabase_headers()`, `_client_ip()` | 🟠 LOW | 10 min | — |
| Replace `@app.middleware("http")` auth with proper `add_middleware()` | 🟠 LOW | 15 min | — |

### Additional DRY Opportunities
- `_supabase_headers()` is called with `service=True` in 3 places — consider a `_service_headers()` shortcut
- The Supabase URL construction (`f"{SUPABASE_URL}/auth/v1/..."`) is repeated ~8 times — consider a `_supabase_auth_url(path)` helper
- Rate limiter shim classes exist solely for test backward-compat — consider refactoring tests to not reach into internals

---

## 3. Testing

### Missing Coverage

**A. Middleware Auth Mode Switching** (HIGH)
- `AUTH_MODE=dual` path not fully tested
- ForwardLane fallback when `_legacy_available=False` → returns 501, but no test for this
- Dual mode with ambiguous token (not clearly Supabase or ForwardLane)
- Effort: **Small**

**B. Security Header Conflict Detection** (HIGH — given CRIT-1)
- Test that the *final* response headers match expected values
- Currently `test_security_headers.py` only tests the class middleware in isolation
- Need an integration test that hits the full app stack
- Effort: **Small**

**C. Theft Detection Race Conditions** (MEDIUM)
- No test for concurrent token refresh (two requests with same token, racing)
- No test for family revocation when Redis key expires mid-flow
- Effort: **Small-Medium**

**D. Rate Limiter Redis Path** (MEDIUM)
- Current rate limit tests only exercise the in-memory fallback
- Need tests with a mock or real Redis to verify the `limits` library path
- Effort: **Small**

**E. Startup Validation Tests** (MEDIUM — when CRIT-7 is fixed)
- Test that missing `SUPABASE_URL` raises `RuntimeError` on import
- Test that weak `SUPABASE_JWT_SECRET` is rejected
- Effort: **Small**

**F. E2E Integration Tests Against Real Supabase** (LOW priority, HIGH value)
- Current tests mock all Supabase responses
- Need a test Supabase project + pytest fixtures for real auth flow
- Effort: **Medium**

**G. Load/Stress Tests** (LOW)
- No benchmarks for rate limiter performance under concurrent load
- Use `locust` or `pytest-benchmark`
- Effort: **Medium**

---

## 4. Integrations

**A. Audit Logging (→ structured event store)**
- All auth events should write immutable audit log entries
- Events: `login`, `login_failed`, `signup`, `logout`, `token_refresh`, `theft_detected`, `password_reset_requested`, `password_changed`, `session_revoked`, `invite_sent`
- Schema: `{event_id, timestamp, event_type, user_id, ip, user_agent, metadata}`
- Start with structured JSON logs → ship to a log aggregator
- Upgrade path: write to Postgres `auth_audit_log` table for SOC2/compliance
- Effort: **Medium** (2-4 hours for the logging layer + tests)

**B. Sentry Error Tracking**
- Add `sentry-sdk[fastapi]` for automatic exception capture
- Especially important for Redis connection failures and Supabase upstream errors
- Effort: **Small** (30 min)

**C. Structured Logging → Datadog/Grafana**
- Replace `logger.warning/info` with structured JSON logs (python-json-logger)
- Add correlation IDs (`X-Request-ID`) to all log lines
- Ship to Datadog or a log aggregator for production observability
- Effort: **Medium**

**D. Security Alert Channel (Slack/Discord)**
- When token theft is detected, post to a security alert channel
- `logger.warning` alone is easy to miss in production
- Effort: **Small** (webhook call in theft detection path)

**E. PostHog / Segment Analytics**
- Track auth events (login, signup, logout, password reset) anonymously
- Enables funnel analysis for Signal Studio onboarding
- Effort: **Medium**

---

## 5. Workflows / DevOps

### 🔴 DEPLOYMENT BLOCKERS

**A. Dockerfile** (BLOCKS DEPLOY)
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
- Add `.dockerignore` (exclude `.git`, `.venv`, `__pycache__`, `.pytest_cache`)
- Include `docker-compose.yml` with Redis service for local dev
- Effort: **30 min**

**B. `.env.example`** (BLOCKS ONBOARDING)
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_JWT_SECRET=your-jwt-secret-from-supabase-settings
SUPABASE_SERVICE_KEY=your-service-role-key
REDIS_URL=redis://localhost:6379/0
AUTH_MODE=dual
AUTH_SECRET_KEY=your-forwardlane-jwt-secret-min-32-chars
```
- Effort: **5 min**

**C. GitHub Actions CI** (HIGH)
```yaml
# .github/workflows/ci.yml
jobs:
  test:
    - ruff check + format --check
    - mypy --strict (or at least --warn-return-any)
    - pytest --cov --cov-fail-under=80
    - bandit -r . -x tests
    - pip-audit
```
- Run on every PR + push to main
- Effort: **1 hour**

### 🟡 NICE TO HAVE

**D. Pre-commit Hooks**
- `ruff format`, `ruff check`, `mypy`, `bandit`
- Prevents bad commits reaching CI
- Effort: **30 min**

**E. Railway Deploy Config**
- `railway.toml` with build/start commands
- Or `Procfile`: `web: uvicorn main:app --host 0.0.0.0 --port $PORT`
- Effort: **15 min**

---

## 6. Performance

| Issue | Impact | Effort | Ref |
|-------|--------|--------|-----|
| Singleton rate limiter objects | HIGH — eliminates per-request Redis connection + object churn | 20 min | CRIT-4 |
| Cache org membership lookups in Redis (30s TTL) | MEDIUM — `/invite-to-org` makes Supabase REST call every time | 30 min | — |
| Lazy import `limits` library | LOW — imported inside function body on every call | 10 min | CRIT-4 |
| Connection pool tuning based on actual load profile | LOW — current defaults (100 max, 20 keepalive) are reasonable | When deployed | — |

---

## 7. Security

| Issue | Severity | Effort | Ref |
|-------|----------|--------|-----|
| **CORS middleware** (blocks frontend) | 🔴 CRITICAL | 10 min | — |
| **X-Forwarded-For spoofing** (rate limit bypass) | 🔴 HIGH | 20 min | CRIT-6 |
| **Startup env validation** (silent misconfiguration) | 🟡 MED | 15 min | CRIT-7 |
| Add `bandit` to CI | 🟡 MED | 10 min | — |
| Add `pip-audit` to CI (CVE monitoring) | 🟡 MED | 10 min | — |
| Audit logging for all auth events | 🟡 MED | 2-4 hours | — |
| JWT `nbf` (not-before) claim validation | 🟠 LOW | 10 min | — |
| Consider `argon2` or `bcrypt` for any local password hashing | 🟠 LOW | N/A (Supabase handles) | — |
| Rate limit the `/refresh` endpoint (currently unlimited) | 🟡 MED | 15 min | — |
| Add `Sec-Fetch-*` header validation for anti-CSRF | 🟠 LOW | 30 min | — |

---

## Priority Matrix — Execution Order

### Phase 1: "Make It Deployable" (< 1 day)

| # | Task | Effort | Why |
|---|------|--------|-----|
| 1 | Delete inline security headers middleware (CRIT-1) | 5 min | Bug — conflicting headers |
| 2 | Add CORS middleware | 10 min | Frontend calls blocked without it |
| 3 | Create `.env.example` | 5 min | Onboarding blocker |
| 4 | Add startup env validation (CRIT-7) | 15 min | Silent misconfiguration |
| 5 | Fix `validate_password_complexity()` decorator (CRIT-3) | 15 min | Dead code masking missing validation |
| 6 | Singleton rate limiter (CRIT-4) | 20 min | Performance under load |
| 7 | Fix XFF spoofing (CRIT-6) | 20 min | Rate limit bypass |
| 8 | Create Dockerfile + docker-compose | 30 min | Can't deploy without it |
| 9 | Refactor `/refresh` to use `_rotate_family_token()` (CRIT-2) | 30 min | DRY, maintenance risk |

**Total: ~2.5 hours**

### Phase 2: "Make It Observable" (1-2 days)

| # | Task | Effort | Why |
|---|------|--------|-----|
| 10 | GitHub Actions CI (lint + test + security scan) | 1 hour | No CI = no safety net |
| 11 | Audit logging for auth events | 2-4 hours | SOC2 readiness, incident response |
| 12 | Structured JSON logging + request IDs | 1-2 hours | Observability |
| 13 | Sentry integration | 30 min | Error tracking |
| 14 | Fix `update_password()` Redis token cleanup (CRIT-5) | 30 min | Password change should revoke tokens |
| 15 | Rate limit `/refresh` endpoint | 15 min | Abuse vector |
| 16 | Wire response models to routes (CRIT-8) | 45 min | OpenAPI docs, type safety |

### Phase 3: "Make It Feature-Complete" (1-2 weeks)

| # | Task | Effort | Why |
|---|------|--------|-----|
| 17 | Admin token revocation endpoint | 1-2 hours | Security incident response |
| 18 | Session listing endpoint | 2-3 hours | User trust + transparency |
| 19 | Magic link / OTP auth | 2-3 hours | Onboarding friction reduction |
| 20 | OAuth provider support (Google, LinkedIn) | 4-6 hours | Enterprise requirement |
| 21 | Webhook receiver for Supabase events | 2-3 hours | Cross-service sync |
| 22 | E2E tests against real Supabase | 4-6 hours | Confidence in real flows |
| 23 | Security alert channel (Slack/Discord) | 1 hour | Theft detection visibility |

---

## Architectural Notes

### What's Working Well
- **Token family tracking** — sophisticated theft detection pattern, well-implemented
- **Dual-mode auth** — clean abstraction for Supabase ↔ ForwardLane migration
- **Graceful degradation** — Redis unavailable? Falls back to in-memory. No ForwardLane? Returns 501. Good resilience.
- **Connection pooling** — lifespan-managed httpx.AsyncClient with proper shutdown
- **Test coverage** — 2470 lines across 8 files; password reset, RBAC, rate limiting, Redis integration all covered

### What Needs Attention
- **The SSA-002 security headers introduced a conflict** — the inline middleware wasn't removed, creating silent header overwrites. This is the kind of bug that slips through without integration tests that check final response headers.
- **Dead code accumulation** — SSA-001 removed some, but `_rotate_family_token()`, `validate_password_complexity()`, and `models.py` response models are still dead. Each creates a maintenance trap where someone assumes the code is active.
- **No CORS = no browser clients** — this is the single biggest deployment blocker. A 10-minute fix that gates everything else.

### Deployment Path (Railway)
1. Fix CRIT-1 through CRIT-7 (Phase 1)
2. Add Dockerfile + `railway.toml`
3. Configure env vars on Railway (using `.env.example` as reference)
4. Wire Redis from existing Railway Redis service
5. Set CORS origins to Signal Studio production URL
6. Deploy → smoke test `/health`, `/auth/login`, `/auth/me`
