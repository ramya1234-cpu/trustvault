
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

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(default="General", max_length=100)


class DocumentResponse(BaseModel):
    id: int
    owner_id: int
    title: str
    category: str
    created_at: object

    model_config = ConfigDict(from_attributes=True)


class PermissionGrant(BaseModel):
    user_id: int = Field(gt=0)
    can_read: bool = True
    can_edit: bool = False
