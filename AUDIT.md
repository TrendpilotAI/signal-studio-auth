# AUDIT — signal-studio-auth
_Updated by Judge Agent v2 (2026-03-05)_

## Summary
| Severity | Count | Change vs Prior |
|----------|-------|-----------------|
| CRITICAL | 0 | -1 ✅ (CRITICAL-1 invite-to-org admin check FIXED) |
| HIGH | 3 | same (HIGH-2 formerly in-memory rate limiter FIXED ✅) |
| MEDIUM | 6 | +1 (new: org membership gap) |
| LOW | 3 | same |

---

## CRITICAL (All Resolved ✅)

### [CRITICAL-1] ~~No Admin Role Check on /invite-to-org~~ — FIXED ✅
**Fix committed:** `routes/auth_routes.py` line 475 — `require_role("admin")` enforced via `Depends()`.

---

## HIGH

### [HIGH-1] No httpx Connection Pooling
**File:** `routes/auth_routes.py` — 6 separate `async with httpx.AsyncClient() as client:` blocks  
**Lines:** ~90, ~140, ~200, ~280, ~360, ~430 (approximate — each route handler)  
**Issue:** Opens new TCP connection to Supabase on every request. Adds 10-50ms latency per call. Under concurrent load, risks exhausting OS file descriptors.  
**Fix:** Module-level `AsyncClient` with FastAPI lifespan context manager.  
**TODO:** TODO-600  
**Effort:** 1h

### [HIGH-2] Missing Integration Tests for Redis Paths
**Files:** `tests/` — `test_rate_limit_and_tokens.py` exists but missing:
- `/refresh` Redis round-trip: token consumed + new token issued
- `/refresh` with consumed token → 401
- `/logout` Redis revocation verification
- `/invite-to-org` role escalation attempts
- Rate limit enforcement (6th request → 429)  
**TODO:** TODO-601  
**Effort:** 4h

### [HIGH-3] Pydantic v1 Compat in `_compat.py`
**File:** `middleware/_compat.py`  
**Issue:** `class Config` with `allow_population_by_field_name = True` and `orm_mode = True` are Pydantic v1 syntax. Pydantic v2 silently ignores these.  
`routes/auth_routes.py` `/me` handler calls `.dict(by_alias=True)` — deprecated in v2.  
**Fix:** Migrate to `model_config = ConfigDict(from_attributes=True, populate_by_name=True)`, use `.model_dump()`.  
**TODO:** TODO-404  
**Effort:** 2h

---

## MEDIUM

### [MEDIUM-1] No Org Membership Validation on /invite-to-org
**File:** `routes/auth_routes.py` lines 460-520  
**Issue:** Admin role is checked (CRITICAL-1 fixed) but no check that caller belongs to target org. Admin of org A can invite to org B.  
**Fix:** Query `organization_members` table after role check.  
**TODO:** TODO-602  
**Effort:** 2h

### [MEDIUM-2] No Refresh Token Family Tracking
**File:** `routes/auth_routes.py` — refresh token rotation logic  
**Issue:** Reuse of consumed token returns 401 but does NOT revoke the entire token chain. Attacker who steals + rotates a token first leaves legitimate user unable to refresh while attacker's new chain continues.  
**Fix:** Track parent→child in Redis; on reuse of consumed token, revoke entire family.  
**TODO:** TODO-603  
**Effort:** 3h

### [MEDIUM-3] Middleware Error Detail Leakage
**File:** `middleware/supabase_auth_middleware.py`  
**Issue:** Internal exceptions may bubble up as 500 with stack traces in production.  
**Fix:** Catch all exceptions in middleware, log internally, return generic `{"detail": "Authentication failed"}` with 401.  
**Effort:** 1h  
**TODO:** Create new TODO

### [MEDIUM-4] No Audit Logging
**Files:** All route handlers  
**Issue:** No record of auth events (login, logout, signup, invite, password reset) for compliance/SOC2.  
**Fix:** Add `_log_audit_event()` helper + `migrations/004_audit_log.sql`.  
**TODO:** TODO-604  
**Effort:** 4h

### [MEDIUM-5] Missing Password Reset Routes
**File:** `routes/auth_routes.py` — no `/reset-password` or `/update-password`  
**Issue:** Users cannot self-service password recovery. Blocks production for new signups.  
**TODO:** TODO-605  
**Effort:** 2h

### [MEDIUM-6] No CI/CD Pipeline
**File:** Missing `.github/workflows/`  
**Issue:** No automated lint, type-check, test, or Docker build on push.  
**TODO:** TODO-406  
**Effort:** 2h

---

## LOW

### [LOW-1] Missing OpenAPI Security Annotations
**File:** `routes/auth_routes.py`  
**Issue:** No `security` parameter on protected endpoints — Swagger UI doesn't show auth requirements.  
**Fix:** Add `dependencies=[Depends(HTTPBearer())]` to router or individual protected routes.  
**Effort:** 30min

### [LOW-2] No Docker/docker-compose for Local Dev
**Issue:** Developers must manually configure Redis + Supabase locally.  
**Fix:** Add `docker-compose.yml` with Redis + Supabase local.  
**Effort:** 2h

### [LOW-3] No Pre-commit Hooks
**Issue:** No `.pre-commit-config.yaml` — ruff/mypy not enforced on commit.  
**Fix:** Add ruff + mypy + trailing-whitespace hooks.  
**Effort:** 30min

---

## Dead Code

- `middleware/_compat.py` — the entire compatibility shim will be deleted after Pydantic v2 migration (TODO-404)
- `routes/auth_routes.py` — `_build_rate_limiter()` in-memory fallback branch (lines ~60-100): should be retained as fallback but can simplify once Redis is confirmed stable in prod

## Dependency Health

| Package | Current | Concern |
|---------|---------|---------|
| `PyJWT>=2.8.0` | ✅ | Recent, no known CVEs |
| `fastapi>=0.100.0` | ⚠️ | 0.100 is old; latest 0.115+ has security fixes |
| `pydantic[email]>=1.10.0` | ⚠️ | Pinned to v1; v2 available and required |
| `httpx>=0.25.0` | ✅ | Recent |
| `redis>=4.6.0` | ✅ | Recent |
| `limits>=3.0.0` | ✅ | Recent |

**Recommendation:** `pip install pip-audit && pip-audit` to check for CVEs.
