"""
Lightweight stand-ins for the legacy Signal Builder User/AnonymousUser models.
Used when the middleware runs outside the legacy codebase (tests, standalone).

TODO-404: Migrated to Pydantic v2 (ConfigDict, model_dump, model_validate).
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserOrganization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

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
    model_config = ConfigDict(
        populate_by_name=True,
        from_attributes=True,  # replaces orm_mode=True
    )

    id: int = Field(alias="user_id")
    username: str
    email: str
    organization: UserOrganization

    @property
    def is_authenticated(self) -> bool:
        return True

    def model_dump(self, **kwargs) -> dict[str, Any]:
        return super().model_dump(**kwargs)

    # Backward-compat alias so existing code using .dict() still works during migration
    def dict(self, **kwargs) -> dict[str, Any]:  # noqa: D102
        return self.model_dump(**kwargs)


class AnonymousUser(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    @property
    def is_authenticated(self) -> bool:
        return False
