"""
Map Supabase JWT claims to the existing Signal Builder User schema.

Supabase JWT structure:
{
  "sub": "uuid",
  "email": "user@example.com",
  "app_metadata": {
    "organization_id": 123,
    "organization_name": "Acme",
    "organization_vertical": "finance",
    "role": "analyst"
  },
  "user_metadata": {
    "first_name": "Jane",
    "last_name": "Doe"
  }
}

Existing User schema expects:
  user_id (int), username (str), email (str),
  organization: { id (int), name (str), vertical (str) }
"""

from __future__ import annotations

from typing import Any, Optional


def supabase_claims_to_user_dict(claims: dict[str, Any]) -> dict[str, Any]:
    """Convert Supabase JWT claims into the dict expected by the existing User model."""
    app_meta = claims.get("app_metadata", {})
    user_meta = claims.get("user_metadata", {})

    # The existing User model uses int IDs. Supabase uses UUIDs.
    # We store a numeric mapping in app_metadata.legacy_user_id during migration,
    # falling back to a hash-based int for new users.
    legacy_id = app_meta.get("legacy_user_id")
    if legacy_id is None:
        # Deterministic int from UUID for compatibility
        legacy_id = _uuid_to_int(claims.get("sub", ""))

    email = claims.get("email", "")
    first_name = user_meta.get("first_name", "")
    last_name = user_meta.get("last_name", "")
    username = email.split("@")[0] if email else f"user-{legacy_id}"

    return {
        "user_id": legacy_id,
        "username": username,
        "email": email,
        "organization": {
            "id": app_meta.get("organization_id", 0),
            "name": app_meta.get("organization_name", "default"),
            "vertical": app_meta.get("organization_vertical", "general"),
        },
    }


def forwardlane_to_supabase_metadata(
    fl_user: dict[str, Any],
) -> dict[str, Any]:
    """
    Build Supabase app_metadata / user_metadata from a ForwardLane user record.
    Used during the one-time user migration.
    """
    org = fl_user.get("organization", {})
    return {
        "app_metadata": {
            "legacy_user_id": fl_user.get("user_id") or fl_user.get("id"),
            "organization_id": org.get("id"),
            "organization_name": org.get("name"),
            "organization_vertical": org.get("vertical"),
            "role": fl_user.get("role", "viewer"),
        },
        "user_metadata": {
            "first_name": fl_user.get("first_name", ""),
            "last_name": fl_user.get("last_name", ""),
        },
    }


def _uuid_to_int(uuid_str: str) -> int:
    """Deterministic positive int from a UUID string (last 8 hex chars → 32-bit)."""
    clean = uuid_str.replace("-", "")
    if not clean:
        return 0
    return int(clean[-8:], 16)
