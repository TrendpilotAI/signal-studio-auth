# signal-studio-auth

FastAPI authentication service for Signal Studio.

This service sits in front of Supabase Auth and gives the frontend a controlled auth API with:
- server-side use of the Supabase service role key
- rate limiting on sensitive auth flows
- opaque refresh token rotation with family tracking and reuse detection
- Redis-backed token and limiter storage with in-memory fallback
- security headers applied consistently at the app boundary

## What it does

### Auth flows
- `POST /auth/signup` — create a user in Supabase Auth and return session tokens
- `POST /auth/login` — exchange email/password for Supabase tokens
- `POST /auth/refresh` — rotate the opaque refresh token and return a new session
- `POST /auth/logout` — revoke the opaque refresh token and call Supabase logout
- `GET /auth/me` — return the authenticated user injected by middleware
- `POST /auth/invite-to-org` — admin-only organization invite flow
- `POST /auth/reset-password` — start password recovery flow
- `POST /auth/update-password` — update a password using the current access token
- `GET /health` — liveness check

### Security model
- Supabase remains the identity provider
- this service keeps the Supabase service key on the server side
- refresh tokens returned to clients are replaced with opaque UUIDs
- opaque refresh tokens are tracked in Redis so the service can:
  - rotate on every refresh
  - mark the parent token as consumed
  - detect refresh token reuse
  - revoke the whole token family on suspected theft
- security headers are applied by `middleware/security_headers.py`

## Architecture

### Request flow
1. Client calls `signal-studio-auth`
2. Service validates/rate-limits the request
3. Service calls Supabase Auth or Admin APIs
4. Service wraps the Supabase refresh token in an opaque server-tracked token
5. Service returns the response to the client

### Refresh token rotation
Initial login/signup:
1. Supabase issues an access token and refresh token
2. The service stores the Supabase refresh token in Redis under an opaque UUID
3. The client only receives the opaque UUID refresh token

Refresh flow:
1. Client submits the opaque refresh token to `POST /auth/refresh`
2. Service looks up the real Supabase refresh token in Redis
3. Service exchanges it with Supabase for a fresh session
4. Service marks the previous opaque token as consumed
5. Service issues a new opaque child token in the same family
6. Service returns the new opaque refresh token to the client

Reuse/theft detection:
- if a previously consumed opaque refresh token is used again, the service treats it as token reuse
- the full token family is revoked from Redis
- the request fails with `401 Refresh token reuse detected — all sessions revoked`

## Redis

Redis is used for two things:
- refresh token storage and token-family tracking
- sliding-window rate limiting

Data model:
- `rt:{token_id}` → Redis hash containing `user_id`, `family_id`, `parent_id`, `supabase_token`, `consumed`
- `rt:family:{family_id}` → Redis set of all token ids in the family

Behavior when Redis is unavailable:
- the app still starts
- rate limiting falls back to in-memory storage
- opaque refresh tokens degrade to non-persistent UUID behavior
- reuse detection and cross-replica coordination are no longer guaranteed

That fallback is useful for local development, but production should use Redis.

## Rate limits

Current limits:
- `POST /auth/login` → 5 requests per 60 seconds per IP
- `POST /auth/signup` → 3 requests per 60 seconds per IP
- `POST /auth/reset-password` → 3 requests per hour per IP
- `POST /auth/update-password` → 5 requests per hour per IP

Implementation notes:
- Redis-backed sliding window when Redis is reachable
- in-memory fallback otherwise
- `Retry-After` header is returned on `429` responses
- client IP is derived from `X-Forwarded-For` first, then `request.client.host`

## Security headers

Canonical policy is defined in `middleware/security_headers.py`.

Current policy:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; form-action 'self'`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()`
- `X-XSS-Protection: 1; mode=block`

## Environment setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

Then edit `.env` with your real values. Never commit a populated `.env` file.

### Required in non-test environments

| Variable | Description |
|---|---|
| `SUPABASE_URL` | Supabase project URL (Settings → API → Project URL) |
| `SUPABASE_JWT_SECRET` | JWT secret for verifying Supabase-issued access tokens (Settings → API → JWT Secret) |
| `SUPABASE_SERVICE_KEY` | Service role key for admin operations — **keep server-side only** |
| `AUTH_SECRET_KEY` | Strong secret (≥ 32 chars) for legacy/dual auth mode; also referred to as `JWT_SECRET` in related services |

Generate a strong `AUTH_SECRET_KEY`:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Optional

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | _(none)_ | Redis connection URL. If unset, falls back to in-memory storage (not safe for multi-replica deployments) |
| `CORS_ORIGINS` | _(none)_ | Comma-separated list of allowed CORS origins, e.g. `https://app.example.com` |
| `AUTH_MODE` | `dual` | Auth backend: `supabase`, `forwardlane`, or `dual` |
| `FORWARDLANE_API_URL` | `http://0.0.0.0:8000` | Legacy ForwardLane API base URL (only needed in `dual`/`forwardlane` mode) |

### Quick-start example

```bash
export SUPABASE_URL="https://your-project-ref.supabase.co"
export SUPABASE_JWT_SECRET="your-supabase-jwt-secret"
export SUPABASE_SERVICE_KEY="your-service-role-key"
export AUTH_SECRET_KEY="$(python -c "import secrets; print(secrets.token_hex(32))")"
export REDIS_URL="redis://localhost:6379/0"
export AUTH_MODE="supabase"
```

## Local development

Install dependencies:
```bash
pip install -r requirements.txt
```

Run the app:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Run tests:
```bash
pytest -q
```

## Deployment notes

### Reverse proxy / platform
Deploy behind a TLS terminator or managed platform ingress (Railway, Render, Fly.io, ECS/ALB, etc.).

Recommendations:
- terminate HTTPS before traffic reaches the app
- pass `X-Forwarded-For` so per-IP limits remain meaningful
- do not expose the service role key to clients
- provide a real Redis instance in production
- run multiple replicas only with Redis enabled, otherwise rate limiting and token tracking become replica-local

### Production checklist
- set all required environment variables
- use a strong `AUTH_SECRET_KEY` (32+ random chars)
- configure `REDIS_URL`
- keep the service behind HTTPS
- verify `/health` is used for liveness checks
- confirm the frontend uses the opaque refresh token returned by this service, not the raw Supabase one

### Failure modes to understand
- no Redis: app works, but auth hardening is degraded
- missing required Supabase settings: app should fail fast at startup
- reused refresh token: family is revoked and the user must log in again

## Testing focus

Notable test coverage includes:
- security headers middleware values
- app-level header regression checks to catch duplicate/downgraded headers
- shared `httpx.AsyncClient` lifespan behavior
- rate limiting behavior and `Retry-After` headers
- refresh token family rotation and theft detection
- password reset/update behavior
- RBAC protection

## Repository notes

The duplicate inline security-header middleware issue was previously fixed by removing the competing `@app.middleware("http")` path from `main.py`. The canonical header policy now lives in `middleware/security_headers.py`, with regression tests asserting the final response headers from the real app.
