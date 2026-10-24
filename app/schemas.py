from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class UserCreate(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserRoleUpdate(BaseModel):
    role: Literal["administrator", "owner", "viewer"]


class UserStatusUpdate(BaseModel):
    is_active: bool


class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(default="General", max_length=100)


class DocumentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = Field(default=None, min_length=1, max_length=100)


class DocumentResponse(BaseModel):
    id: int
    owner_id: int
    title: str
    category: str
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class DocumentSearchResult(BaseModel):
    id: int
    owner_id: int
    title: str
    category: str
    created_at: datetime
    updated_at: datetime | None = None
    is_owner: bool = False
    can_read: bool = True
    can_edit: bool = False

    model_config = ConfigDict(from_attributes=True)


class PermissionGrant(BaseModel):
    user_id: int = Field(gt=0)
    can_read: bool = True
    can_edit: bool = False


class AuditEventResponse(BaseModel):
    id: int
    actor_id: int | None = None
    action: str
    document_id: int | None = None
    details: str
    prev_hash: str | None = None
    hash: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditVerificationResult(BaseModel):
    is_valid: bool
    total_events: int
    verified_events: int
    message: str
    tampered_event_id: int | None = None
