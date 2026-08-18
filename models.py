"""
Typed response models for signal-studio-auth routes.

Pydantic v2 compatible.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class OrganizationResponse(BaseModel):
    """Nested organization payload attached to /auth/me (see mapping/user_mapping.py)."""

    model_config = ConfigDict(populate_by_name=True)

    id: int
    name: str
    vertical: str


class UserResponse(BaseModel):
    """
    Represents authenticated user info returned from /auth/me.

    user_id is an int — mapping/user_mapping.py's supabase_claims_to_user_dict()
    derives a deterministic legacy int id from the Supabase UUID (or uses a
    stored legacy_user_id), and middleware/_compat.py's User model dumps it
    under the "user_id" alias.
    """

    model_config = ConfigDict(populate_by_name=True)

    user_id: int
    email: str
    username: Optional[str] = None
    organization: Optional[OrganizationResponse] = None


class LoginResponse(BaseModel):
    """Tokens returned after a successful login."""

    model_config = ConfigDict(populate_by_name=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: Optional[Any] = None


class SignupResponse(BaseModel):
    """
    Response returned after successful signup.

    Supabase's /auth/v1/signup response shape varies with project config:
    when email confirmation is required it returns a nested {"user", "session"}
    (session may be null); otherwise it returns the same flat token shape as
    /auth/v1/token (access_token/refresh_token/...). All fields are therefore
    optional so both shapes validate, and _wrap_with_opaque_token()'s opaque
    refresh_token swap is passed straight through.
    """

    model_config = ConfigDict(populate_by_name=True)

    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    user: Optional[Any] = None
    session: Optional[Any] = None
