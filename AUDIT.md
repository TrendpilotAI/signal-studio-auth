# AUDIT.md — signal-studio-auth Code Quality Audit

---

## v2 Audit (post SSA-001/002/003)

_Auditor: Honey (Code Optimization Agent) · 2026-07-15_
_Scope: Full re-audit after SSA-001 (dead code removal), SSA-002 (SecurityHeadersMiddleware), SSA-003 (dep pinning + pip-audit)_

---

### SSA Commit Verification

| Commit | Claimed Change | Status |
|--------|---------------|--------|
| SSA-001 | Removed dead `_build_rate_limiter()` + duplicate `_get_caller_role()` | ✅ Confirmed — neither exists in codebase. `_get_caller_role()` lives only in `middleware/rbac.py` (single source of truth). |
| SSA-002 | Added `SecurityHeadersMiddleware` class in `middleware/security_headers.py` | ⚠️ Class added, but **inline middleware was NOT removed** — see Finding #1. |
| SSA-003 | Pinned all deps + ran pip-audit | ✅ All 11 deps pinned in `requirements.txt` (2026-03-08). PyJWT 2.11.0 is clean per Snyk. |

---

### 🔴 Finding #1: DUPLICATE SECURITY HEADERS — SILENT POLICY DOWNGRADE (HIGH)

**Files:** `main.py:50` + `main.py:56-67` + `middleware/security_headers.py:1-44`

**What happens:**
SSA-002 added `SecurityHeadersMiddleware` (class-based, strict) and registered it at `main.py:50`:
```python
app.add_middleware(SecurityHeadersMiddleware)  # line 50
```
But `main.py:53-67` still has an `@app.middleware("http")` function setting the **same 6 headers** with **weaker values**.

**Starlette middleware ordering:** `@app.middleware("http")` wraps **outside** `add_middleware()` calls. Execution order:
1. Inline function receives request → calls `call_next()`
2. `SecurityHeadersMiddleware.dispatch()` runs → sets **strict** headers
3. Response returns to inline function → **overwrites** headers with **weaker** values

**Header-by-header conflict (verified via TestClient):**

| Header | Class (strict) | Inline (wins) | Impact |
|--------|---------------|---------------|--------|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; form-action 'self'` | `default-src 'self'` | 🔴 **Drops frame-ancestors + form-action. Widens from 'none' to 'self'.** |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | `max-age=31536000; includeSubDomains` | 🟡 **Drops `preload` directive** |
| `X-XSS-Protection` | `1; mode=block` | `0` | 🟡 Contradictory values (modern best practice IS `0`, but inconsistency is a code smell) |
| `X-Frame-Options` | `DENY` | `DENY` | ✅ Same |
| `X-Content-Type-Options` | `nosniff` | `nosniff` | ✅ Same |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `strict-origin-when-cross-origin` | ✅ Same |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), interest-cohort=()` | _(not set by inline)_ | ✅ Survives (class value persists) |

**Severity: HIGH** — The carefully crafted CSP from the class middleware is silently clobbered in production. `frame-ancestors 'none'` (clickjacking protection) and `form-action 'self'` (form hijacking protection) are lost.

**Fix:** Delete `main.py` lines 53-67 entirely. The class middleware is the single source of truth.

---

### 🟡 Finding #2: DEAD FUNCTION `_rotate_family_token()` (MEDIUM)

**File:** `routes/auth_routes.py:227-268`

**Status: CONFIRMED — never called.** `grep -rn "_rotate_family_token" routes/` returns only the `def` line.

The `POST /refresh` route handler (`routes/auth_routes.py:299-357`) duplicates ALL of its logic inline:
- Redis `hgetall` lookup (line 306 vs 241)
- `consumed == "1"` check (line 311 vs 248)
- Family revocation pipeline (lines 314-320 vs 253-259)
- `logger.warning` with identical message (line 321 vs 261)
- HTTP 401 raise (line 325 vs 266)
- Mark old token consumed (line 329 vs 271)
- `_issue_family_token()` call (lines 349-353 vs 273-277)

**Fix:** Replace the inline logic in `/refresh` with a single call to `_rotate_family_token(old_token_id, new_supabase_rt)`. ~50 lines removed.

---

### 🟡 Finding #3: DEAD METHOD `PasswordUpdateRequest.validate_password_complexity()` (MEDIUM)

**File:** `routes/auth_routes.py:382-392`

**Status: CONFIRMED — Pydantic v2 never calls it.** It's decorated `@classmethod` but lacks `@field_validator("new_password")`. Pydantic v2 requires the decorator to wire it into validation.

The `POST /update-password` route handler (`routes/auth_routes.py:468-475`) independently re-implements the same 4 checks:
1. `len(password) < 8` (line 469)
2. `any(c.isupper() ...)` (line 471)
3. `any(c.islower() ...)` (line 473)
4. `any(c.isdigit() ...)` (line 475)

**Fix:** Either:
- (a) Add `@field_validator("new_password", mode="before")` to the classmethod and remove inline checks, OR
- (b) Delete the classmethod entirely (keep inline checks — they return proper HTTPExceptions with 422 status)

Option (b) is simpler since the route's HTTPException messages are more useful than Pydantic's `ValueError` wrapping.

---

### 🟡 Finding #4: RATE LIMITER OBJECT CREATION IN HOT PATH (MEDIUM)

**File:** `routes/auth_routes.py:114-127` (inside `_redis_or_memory_check` → `_check` closure)

On EVERY rate-limited request (login, signup, reset-password, update-password), the Redis path creates:
```python
storage = RedisStorage(REDIS_URL)          # line 118 — new connection/pool per call
limiter = SlidingWindowRateLimiter(storage) # line 119 — new strategy object per call
limit_item = parse_limit(...)               # line 120 — re-parses string per call
```

Under load, this creates significant GC pressure and redundant Redis connection churn.

**Fix:** Module-level lazy singletons:
```python
_redis_storage: RedisStorage | None = None
_sliding_limiter: SlidingWindowRateLimiter | None = None

def _get_redis_limiter():
    global _redis_storage, _sliding_limiter
    if _redis_storage is None:
        _redis_storage = RedisStorage(REDIS_URL)
        _sliding_limiter = SlidingWindowRateLimiter(_redis_storage)
    return _sliding_limiter
```

---

### 🟡 Finding #5: REDIS SCAN NOT IMPLEMENTED in `update_password()` (MEDIUM — SECURITY)

**File:** `routes/auth_routes.py:483-494`

**Status: CONFIRMED.** The code comment at line 481 says:
> "Revoke all existing opaque refresh tokens for this user in Redis. We do a best-effort scan..."

But the actual code (lines 484-492) only calls Supabase admin logout:
```python
await client.post(f"{SUPABASE_URL}/auth/v1/admin/users/{user_sub}/logout", ...)
```

**No Redis `SCAN` or `HSCAN` is performed.** All `rt:{token_id}` keys with matching `user_id` remain valid for up to 7 days (TTL). An attacker with a stolen refresh token can continue using it after the legitimate user changes their password.

**Fix:** After Supabase logout, scan Redis for matching tokens:
```python
cursor = 0
while True:
    cursor, keys = r.scan(cursor, match="rt:*", count=100)
    for key in keys:
        if key.startswith("rt:family:"):
            continue
        uid = r.hget(key, "user_id")
        if uid == user_sub:
            fid = r.hget(key, "family_id")
            r.delete(key)
            if fid:
                r.srem(f"rt:family:{fid}", key.split(":")[-1])
    if cursor == 0:
        break
```

**Note:** SCAN is O(N) on total keyspace. For production scale, maintain a reverse index `rt:user:{user_id}` SET of all token_ids per user.

---

### 🟡 Finding #6 (NEW): `test_security_headers.py` DOES NOT CATCH THE DUPLICATE BUG

**File:** `tests/test_security_headers.py:1-62`

The test fixture creates an isolated app with ONLY the class middleware:
```python
def app_with_headers():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)  # No inline middleware!
```

All 7 tests pass because they test the class in isolation. They verify:
- HSTS includes `includeSubDomains` ✅ (but don't check for `preload`)
- CSP includes `frame-ancestors 'none'` ✅
- XSS = `1; mode=block` ✅

**In production, none of these assertions hold.** The inline middleware overwrites CSP (dropping `frame-ancestors`) and XSS (to `0`).

**Fix:** Add an integration test that uses the actual `app` from `main.py`:
```python
def test_production_csp_not_overwritten():
    from main import app
    client = TestClient(app)
    resp = client.get("/health")
    csp = resp.headers["content-security-policy"]
    assert "frame-ancestors" in csp, "CSP frame-ancestors was silently dropped"
```

---

### 🟢 Finding #7 (NEW): `pytest-asyncio==1.3.0` — Potentially Stale Pin

**File:** `requirements.txt:9`

`pytest-asyncio` 1.3.0 is from ~2024. Current stable is 0.25.x (the project reset version numbering). Version 1.3.0 may be a fork or an older release. Confirm compatibility with `pytest==9.0.2`.

**Severity: LOW** — functional risk only, no known CVE.

---

### Dependency Security Status (post SSA-003)

Pinned 2026-03-08. Manual CVE check performed 2026-07-15:

| Package | Version | Status |
|---------|---------|--------|
| PyJWT | 2.11.0 | ✅ **Clean** — Snyk confirms no known issues. CVE-2025-45768 affected 2.10.1, fixed in 2.11.0. |
| fastapi | 0.135.1 | ✅ **Clean** — 2026 CVEs (2026-2975 through 2026-2978) affect `fastapi-admin`, NOT core `fastapi`. |
| httpx | 0.28.1 | ✅ **Clean** — No 2026 CVEs. Snyk: "No known security issues." |
| pydantic | 2.12.5 | ✅ **Clean** — 2026 CVEs (2026-25580, 2026-25640, 2026-25904) affect `pydantic-ai`, NOT core `pydantic`. |
| redis | 7.2.1 | ✅ No reported CVEs. |
| uvicorn | 0.41.0 | ✅ No reported CVEs. |
| limits | 5.8.0 | ✅ No reported CVEs. |
| email-validator | 2.3.0 | ✅ No reported CVEs. |
| pytest | 9.0.2 | ✅ Dev dep, no security impact. |
| pytest-asyncio | 1.3.0 | 🟡 Stale version — verify compatibility. |
| pytest-cov | 7.0.0 | ✅ Dev dep, no security impact. |

**pip-audit could not run** (sandbox missing `python3-venv`). Recommend adding `pip-audit` to CI pipeline.

---

### Items Carried Forward from v1 Audit (Still Open)

| v1 Finding | Status | Notes |
|-----------|--------|-------|
| No CORS policy (HIGH) | 🔴 **Still open** | `main.py` has no `CORSMiddleware`. |
| X-Forwarded-For spoofing (MEDIUM) | 🟡 **Still open** | `_client_ip()` trusts header blindly. |
| Missing startup env var validation (LOW) | 🟡 **Still open** | Empty `SUPABASE_SERVICE_KEY` would break JWT verification silently. |
| Missing `_rotate_family_token` unit tests | 🟡 **Still open** | Function is dead code — tests moot until it's wired in or deleted. |
| No `ruff`/`mypy`/`bandit` in CI | 🟡 **Still open** | |

---

## Summary Scorecard (v2)

| Dimension | v1 Score | v2 Score | Trend | Notes |
|-----------|----------|----------|-------|-------|
| Dead code | 🟡 Medium | 🟡 Medium | → | SSA-001 fixed 2 items; 2 remain (`_rotate_family_token`, `validate_password_complexity`) |
| DRY | 🔴 Issues | 🔴 Issues | → | Theft detection + password validation still duplicated |
| Security | 🟡 Medium | 🔴 HIGH | ↓ | **SSA-002 introduced duplicate headers bug** — CSP silently weakened |
| Dependencies | ✅ Good | ✅ Good | → | SSA-003 pinned all; no new CVEs found |
| Test coverage | 🟡 Good | 🟡 Good | → | New test file doesn't catch the bug it was written for |
| Performance | 🟡 Medium | 🟡 Medium | → | Rate limiter singleton fix still pending |

### Priority Fix Order

1. **🔴 P0 — Delete inline middleware** (`main.py:53-67`). 15 seconds to fix. CSP is silently broken in production RIGHT NOW.
2. **🟡 P1 — Wire `_rotate_family_token()` into `/refresh` route** OR delete it. ~50 lines of duplication.
3. **🟡 P1 — Fix or delete `validate_password_complexity()`**. Dead code that looks alive is worse than no code.
4. **🟡 P1 — Implement Redis token scan** in `update_password()`. Security gap: stolen tokens survive password change.
5. **🟡 P2 — Rate limiter singletons.** Performance under load.
6. **🟡 P2 — Add integration test** for production header values.
7. **🟢 P3 — Add CORS, startup validation, XFF trust config** (carried from v1).

---
---

## v1 Audit (Original)

_Generated by Judge Agent v2 · 2026-03-09_

---

## 1. Dead Code / Unused Imports

### routes/auth_routes.py

**Line 6:** `from contextlib import asynccontextmanager` — imported but the `asynccontextmanager` decorator is used only in `_http_client`. Keep.

**Line 7:** `from threading import Lock` — used by in-memory rate limiters. Keep.

**Line 8:** `from typing import Optional` — used in `_issue_family_token`. Keep.

**PasswordUpdateRequest.validate_password_complexity (lines ~330-341):**
```python
@classmethod
def validate_password_complexity(cls, v: str) -> str:
    ...
```
This method is **dead code** — it's a `@classmethod` but NOT decorated with `@field_validator`. Pydantic v2 will never call it. The `/update-password` route independently re-implements the same 4 checks manually. One of these implementations must be removed and the other made authoritative.

**_rotate_family_token() function (lines ~220-260):**
This function exists but is **never called** from the route handlers. The `/refresh` route duplicates all its logic inline. Either call `_rotate_family_token` from the route or delete the function.

---

## 2. DRY Violations (Duplicated Logic)

### A. Theft Detection — 2 Implementations

**Location 1:** `_rotate_family_token()` in `routes/auth_routes.py` ~line 222–250
**Location 2:** `POST /refresh` route handler ~line 380–410

Both implement:
1. `r.hgetall(f"rt:{token_id}")`
2. Check `consumed == "1"`
3. `r.smembers(f"rt:family:{family_id}")`
4. Pipeline delete all family members
5. `logger.warning("Refresh token theft detected...")`
6. Raise HTTP 401

**Fix:** The `/refresh` route should call `_rotate_family_token(old_token_id, new_sb_token)` exclusively.

### B. Password Complexity Checks — 2 Implementations

**Location 1:** `PasswordUpdateRequest.validate_password_complexity()` (~line 330)
**Location 2:** `update_password()` route handler (~line 490)

Identical 4-check logic appears twice. 

**Fix:** Add `@field_validator("new_password", mode="before")` to `PasswordUpdateRequest.validate_password_complexity` and remove inline checks from the route.

### C. `_client_ip()` duplicated pattern

The header extraction `request.headers.get("X-Forwarded-For")` pattern is used identically across all rate-limit check call sites. This is adequately centralized in `_client_ip()` — no issue.

### D. `_supabase_headers()` called with repeated patterns

`_supabase_headers(service=True)` is called in many places. Fine — it's already a helper.

---

## 3. Security Issues

### A. No CORS Policy (HIGH)
**File:** `main.py`
No `CORSMiddleware` configured. If the Signal Studio React frontend calls this API directly from a browser, all requests will fail with CORS errors — or worse, if added permissively in production.
**Fix:** Add `CORSMiddleware` with explicit `ALLOWED_ORIGINS` env var.

### B. Missing `nbf` Validation (LOW)
**File:** `middleware/supabase_auth_middleware.py`, line ~46
PyJWT's `decode()` validates `exp` and `aud` by default. Confirm `nbf` is also enforced (it is by default in PyJWT — mark as low risk but worth explicit test).

### C. X-Forwarded-For Spoofing (MEDIUM)
**File:** `routes/auth_routes.py`, `_client_ip()` function
`X-Forwarded-For` is taken at face value. If this service is not behind a trusted reverse proxy (Railway injects this), a client can spoof their IP to bypass rate limits.
**Fix:** Only trust `X-Forwarded-For` if `TRUSTED_PROXY_IPS` env var is set; otherwise use `request.client.host`.

### D. No Secrets at Rest Validation (LOW)
**File:** `config/supabase_config.py`
Config loads env vars but does not validate they're non-empty at startup. A misconfigured deploy with empty `SUPABASE_SERVICE_KEY` would accept any JWT (PyJWT would fail to verify).
**Fix:** Add startup validation: raise `RuntimeError` if required env vars are missing/empty.

### E. Redis Key Scan for User Sessions (FUTURE RISK)
**File:** `routes/auth_routes.py`, `update_password()` ~line 545
The comment says "best-effort scan" to revoke Redis tokens. Currently no implementation exists — it calls Supabase admin logout but does NOT actually scan and delete Redis `rt:*` keys for the user. If the Supabase admin logout fails, opaque tokens remain valid in Redis until TTL expiry (7 days).
**Fix:** Implement Redis SCAN with `HGETALL` field match on `user_id` in the revocation path.

---

## 4. Dependency Health

### Requirements (pinned 2026-03-08)
```
PyJWT==2.11.0       ✅ recent
fastapi==0.135.1    ✅ recent
httpx==0.28.1       ✅ recent
pydantic==2.12.5    ✅ v2, recent
redis==7.2.1        ✅ recent
uvicorn==0.41.0     ✅ recent
limits==5.8.0       ✅ recent
pytest==9.0.2       ✅ recent
```

All dependencies appear recent and pinned. **No known CVEs identified** in this set (as of audit date), but `pip-audit` should be added to CI to continuously monitor.

**Missing dev deps:**
- `ruff` (linting/formatting) — not in requirements
- `mypy` (type checking) — not in requirements
- `bandit` (security scanner) — not in requirements
- `pre-commit` — not configured

---

## 5. Test Coverage Assessment

### Existing Tests
| File | Lines | Coverage Area |
|------|-------|---------------|
| test_auth.py | 231 | Basic login/signup/logout/refresh |
| test_security.py | 491 | Rate limiting, security headers, token validation |
| test_rbac.py | 193 | require_role() dependency |
| test_password_reset.py | 448 | reset-password, update-password routes |
| test_rate_limit_and_tokens.py | 425 | Rate limiters, opaque token logic |
| test_redis_integration.py | 502 | Redis token store, family tracking |
| test_connection_pool.py | 117 | httpx connection pool / lifespan |

### Missing Coverage
- **`AUTH_MODE=dual` middleware switching** — not tested
- **ForwardLane fallback** when `_legacy_available=False` — not tested
- **`_rotate_family_token()` direct unit tests** — function exists but has no direct tests
- **Concurrent token refresh race** — two simultaneous refresh requests with same token
- **Redis key expiry mid-rotation** — token expires between `hgetall` and `hset consumed`
- **Admin session revocation** (endpoint doesn't exist yet)
- **org membership cache** (not implemented yet)
- **`_client_ip()` with missing `request.client`** — returns "unknown", untested

---

## 6. Performance Bottlenecks

### A. Rate Limiter Object Creation (HIGH)
**File:** `routes/auth_routes.py`, `_redis_or_memory_check()` inner function, ~line 105
```python
def _check(key: str) -> None:
    r = get_redis()
    if r is not None:
        storage = RedisStorage(REDIS_URL)          # ← NEW OBJECT every call
        limiter = SlidingWindowRateLimiter(storage) # ← NEW OBJECT every call
        limit_item = parse_limit(...)               # ← parsed every call
```
These 3 objects are recreated on every rate-limited request. Under load (e.g., 1000 req/s), this creates significant GC pressure and redundant Redis connections.
**Fix:** Module-level singletons with lazy initialization.

### B. Org Membership — No Caching
**File:** `routes/auth_routes.py`, `invite_to_org()`, ~line 610
Every `/invite-to-org` call makes a synchronous Supabase REST query to check caller org membership. Under repeated calls, this adds ~50-100ms latency.
**Fix:** Redis cache with 30s TTL: `org:member:{caller_id}:{org_id}`.

### C. Dual HTTP Clients in invite_to_org
**File:** `routes/auth_routes.py`, `invite_to_org()`, ~line 615
Two separate `async with _http_client(request) as client` blocks — membership check + admin API. When using the shared pool this is fine (same pool, different logical requests). Not a bug, but consider if membership check can be batched.

### D. No Response Compression
**File:** `main.py`
No `GZipMiddleware`. Auth responses are small JSON so this is low priority, but worth adding for future response payloads.

---

## Summary Scorecard (v1)

| Dimension | Score | Notes |
|-----------|-------|-------|
| Dead code | 🟡 Medium | `_rotate_family_token` unused, dead `validate_password_complexity` |
| DRY | 🔴 Issues | Theft detection + password validation both duplicated |
| Security | 🟡 Medium | No CORS, XFF spoofing risk, missing startup validation |
| Dependencies | ✅ Good | All pinned and recent; add pip-audit to CI |
| Test coverage | 🟡 Good | Solid base, missing dual-mode + concurrency tests |
| Performance | 🟡 Medium | Rate limiter object creation needs singleton pattern |
