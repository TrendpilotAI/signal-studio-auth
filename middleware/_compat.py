"""
Lightweight stand-ins for the legacy Signal Builder User/AnonymousUser models.
Used when the middleware runs outside the legacy codebase (tests, standalone).
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Any


class UserOrganization(BaseModel):
    id: int
    name: str
    vertical: str

    def as_tenant_org(self) -> dict[str, Any]:
        from re import sub as re_sub
        slug = re_sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")
        return {
            "external_id": self.id,
            "schema_name": f"{slug}-{self.id}",
            "vertical": self.vertical,
        }


class User(BaseModel):
    id: int = Field(alias="user_id")
    username: str
    email: str
    organization: UserOrganization

    class Config:
        orm_mode = True
        populate_by_name = True
        # pydantic v1 compat
        allow_population_by_field_name = True

    @property
    def is_authenticated(self) -> bool:
        return True


class AnonymousUser(BaseModel):
    @property
    def is_authenticated(self) -> bool:
        return False
