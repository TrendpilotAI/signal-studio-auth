"""
Supabase Auth Configuration for Signal Studio.

Environment variables:
  SUPABASE_URL          - Supabase project URL
  SUPABASE_JWT_SECRET   - JWT secret from Supabase project settings
  SUPABASE_SERVICE_KEY  - Service role key (admin ops only)
  AUTH_MODE             - "supabase" | "forwardlane" | "dual"
  AUTH_SECRET_KEY       - Legacy ForwardLane JWT secret (REQUIRED in non-test environments)
"""

import os
import sys
from enum import Enum

# Known weak/default secrets that must never be used in production
_INSECURE_DEFAULTS = {
    "very_secure_secret",
    "secret",
    "changeme",
    "password",
    "jwt_secret",
    "",
}

_TESTING = "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST") is not None


def _require_secret(env_var: str, fallback: str = "") -> str:
    """Load a secret from an env var. Fails fast if missing or using a known weak value."""
    value = os.environ.get(env_var, fallback)
    if not _TESTING and value.lower() in _INSECURE_DEFAULTS:
        raise RuntimeError(
            f"[signal-studio-auth] FATAL: {env_var} is missing or set to an insecure "
            f"default. Set a strong secret in the environment before starting the service."
        )
    if not _TESTING and len(value) < 32:
        raise RuntimeError(
            f"[signal-studio-auth] FATAL: {env_var} is too short (got {len(value)} chars, "
            f"minimum 32). Use a cryptographically random secret."
        )
    return value


def _require_env(var_name: str) -> str:
    """Load a required env var. Raises RuntimeError at startup if missing (unless in testing)."""
    value = os.environ.get(var_name, "")
    if not _TESTING and not value:
        raise RuntimeError(
            f"[signal-studio-auth] FATAL: {var_name} is required but not set. "
            f"Set this environment variable before starting the service."
        )
    return value


class AuthMode(str, Enum):
    SUPABASE = "supabase"
    FORWARDLANE = "forwardlane"
    DUAL = "dual"


# Supabase settings — fail fast at startup if critical vars are missing
SUPABASE_URL: str = _require_env("SUPABASE_URL")
SUPABASE_JWT_SECRET: str = _require_env("SUPABASE_JWT_SECRET")
SUPABASE_SERVICE_KEY: str = _require_env("SUPABASE_SERVICE_KEY")
SUPABASE_JWT_ALGORITHM: str = "HS256"
SUPABASE_JWT_AUDIENCE: str = "authenticated"

# Auth mode toggle
AUTH_MODE: AuthMode = AuthMode(os.environ.get("AUTH_MODE", "dual"))

# Legacy ForwardLane settings (imported from existing settings when in dual/forwardlane mode)
FORWARDLANE_API_URL: str = os.environ.get("FORWARDLANE_API_URL", "http://0.0.0.0:8000")
FORWARDLANE_JWT_SECRET: str = _require_secret("AUTH_SECRET_KEY")
