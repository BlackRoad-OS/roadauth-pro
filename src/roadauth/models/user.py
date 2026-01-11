"""
User Models
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user fields."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)


class UserCreate(UserBase):
    """User creation request."""
    password: str = Field(..., min_length=8)


class UserResponse(BaseModel):
    """User response (no password)."""
    id: str
    email: str
    username: str
    is_active: bool = True
    is_verified: bool = False
    mfa_enabled: bool = False
    roles: List[str] = ["user"]


class User(UserBase):
    """Full user model."""
    id: str
    hashed_password: str
    is_active: bool = True
    is_verified: bool = False
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    roles: List[str] = ["user"]
    created_at: datetime
    updated_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    """Token response."""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None


class MFASetupResponse(BaseModel):
    """MFA setup response."""
    secret: str
    qr_code: str  # Base64 PNG
    message: str
