"""
Typed response models for signal-studio-auth routes.

Pydantic v2 compatible.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class UserResponse(BaseModel):
    """Represents authenticated user info returned from /auth/me."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: str
    email: str
    username: Optional[str] = None
    organization: Optional[Any] = None


class LoginResponse(BaseModel):
    """Tokens returned after a successful login."""

    model_config = ConfigDict(populate_by_name=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: Optional[Any] = None


class SignupResponse(BaseModel):
    """Response returned after successful signup."""

    model_config = ConfigDict(populate_by_name=True)

    user: Optional[Any] = None
    session: Optional[Any] = None
