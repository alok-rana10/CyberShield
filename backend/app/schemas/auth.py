"""Pydantic schemas for authentication and RBAC."""

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.security.hashing import validate_password_strength


class UserRole(str, Enum):
    """Permitted user roles in CyberShield."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserRegisterRequest(BaseModel):
    """Schema for user registration."""

    email: EmailStr = Field(..., description="Valid corporate or user email address")
    password: str = Field(..., min_length=8, max_length=128, description="Strong user password")
    full_name: str | None = Field(default=None, max_length=150, description="Full name of the user")
    role: UserRole = Field(default=UserRole.ANALYST, description="Requested access role")

    @field_validator("password")
    @classmethod
    def check_password_complexity(cls, v: str) -> str:
        valid, msg = validate_password_strength(v)
        if not valid:
            raise ValueError(msg)
        return v


class UserLoginRequest(BaseModel):
    """Schema for user login credentials."""

    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., description="User password")


class UserResponse(BaseModel):
    """Safe public user profile schema."""

    id: str
    email: EmailStr
    full_name: str | None
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """JWT bearer token response schema."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
