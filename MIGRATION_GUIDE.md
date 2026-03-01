# Signal Studio — Supabase Auth Migration Guide

## Overview

Replace ForwardLane Django JWT authentication with Supabase Auth. The migration uses a **dual mode** to avoid downtime.

---

## Phase 1: Setup Supabase Project

1. **Create Supabase project** (or use existing one)
2. **Run SQL migrations** in order:
   ```
   migrations/001_organizations.sql
   migrations/002_user_profiles.sql
   migrations/003_rls_existing_tables.sql  (adapt template per table)
   ```
3. **Set environment variables:**
   ```env
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_JWT_SECRET=your-jwt-secret    # Settings → API → JWT Secret
   SUPABASE_SERVICE_KEY=your-service-key  # Settings → API → service_role key
   AUTH_MODE=dual                         # Start in dual mode
   ```
4. **Install dependencies:**
   ```bash
   pip install PyJWT httpx
   ```

## Phase 2: Deploy in Dual Mode

1. **Add the middleware** to your FastAPI app:
   ```python
   # Replace the old middleware import:
   # from core.middlewares.auth_middleware import auth_middleware
   
   # With:
   from middleware.supabase_auth_middleware import supabase_auth_middleware
   
   app.middleware("http")(supabase_auth_middleware)
   ```
2. **Add auth routes:**
   ```python
   from routes.auth_routes import router as auth_router
   app.include_router(auth_router)
   ```
3. **Set `AUTH_MODE=dual`** — existing ForwardLane tokens keep working, new Supabase tokens are also accepted.
4. **Deploy and verify** both token types work.

## Phase 3: Migrate Users

For each ForwardLane user, create a corresponding Supabase user with matching metadata:

```python
from mapping.user_mapping import forwardlane_to_supabase_metadata
import httpx

async def migrate_user(fl_user: dict, supabase_url: str, service_key: str):
    meta = forwardlane_to_supabase_metadata(fl_user)
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{supabase_url}/auth/v1/admin/users",
            headers={
                "apikey": service_key,
                "Authorization": f"Bearer {service_key}",
                "Content-Type": "application/json",
            },
            json={
                "email": fl_user["email"],
                "email_confirm": True,
                "app_metadata": meta["app_metadata"],
                "user_metadata": meta["user_metadata"],
            },
        )
        return resp.json()
```

**Important:** Set `legacy_user_id` in `app_metadata` so the middleware maps back to the original integer ID.

## Phase 4: Switch to Supabase-Only

1. Verify all users have been migrated and are using Supabase tokens
2. Set `AUTH_MODE=supabase`
3. Deploy
4. Monitor for 401 errors (indicates unmigrated users)

## Phase 5: Remove ForwardLane Dependency

1. Remove `FORWARDLANE_API_URL` env var
2. Remove `apps/web_services/forwardlane.py`
3. Remove `core/middlewares/auth_middleware.py` (old middleware)
4. Remove `SB_FL_AUTH_TOKEN` env var
5. Remove `fastapi-jwt-auth` dependency (if no longer needed elsewhere)
6. Set `AUTH_MODE=supabase` permanently

---

## Architecture

```
┌─────────────┐     JWT (HS256)      ┌──────────────────────┐
│  Frontend   │ ──────────────────→  │  supabase_auth_mw    │
└─────────────┘                      │                      │
                                     │  1. Decode JWT       │
                                     │  2. Verify signature │
                                     │  3. Map to User obj  │
                                     │  4. Set request.state │
                                     └──────────┬───────────┘
                                                │
                                     ┌──────────▼───────────┐
                                     │  Signal Builder API   │
                                     │  (existing routes)    │
                                     └──────────────────────┘
```

**Key difference from old flow:** No network call to ForwardLane Django. JWT is verified locally using the Supabase project's JWT secret.

## Rollback

Set `AUTH_MODE=forwardlane` to revert to the original behavior at any time during phases 2-4.
