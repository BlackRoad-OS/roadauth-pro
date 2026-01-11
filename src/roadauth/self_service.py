"""
RoadAuth Pro Self-Service Flows

Features:
- User registration with email verification
- Password reset flow
- Email change with verification
- Account deletion
- Profile management
- Session management for users
"""

import secrets
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel, EmailStr, validator
import re


class VerificationType(str, Enum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    EMAIL_CHANGE = "email_change"
    ACCOUNT_DELETION = "account_deletion"


@dataclass
class VerificationToken:
    token: str
    token_hash: str
    user_id: str
    type: VerificationType
    email: str
    created_at: int
    expires_at: int
    used_at: Optional[int] = None
    metadata: Dict[str, Any] = None


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None
    terms_accepted: bool = False

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain an uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain a lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain a number')
        return v


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    password: str

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v


class EmailChangeRequest(BaseModel):
    new_email: EmailStr
    password: str  # Current password for verification


class SelfServiceManager:
    """
    Manages self-service authentication flows.
    """

    def __init__(
        self,
        storage,
        email_sender,
        base_url: str,
        token_expiry_hours: int = 24,
    ):
        self.storage = storage
        self.email_sender = email_sender
        self.base_url = base_url
        self.token_expiry_hours = token_expiry_hours

    # Registration Flow

    async def register(
        self,
        email: str,
        password: str,
        name: Optional[str] = None,
        terms_accepted: bool = False,
    ) -> Dict[str, Any]:
        """
        Register a new user and send verification email.
        """
        from .auth.password import hash_password

        # Check terms
        if not terms_accepted:
            return {"success": False, "error": "Terms must be accepted"}

        # Check if email exists
        existing = await self.storage.get_user_by_email(email)
        if existing:
            return {"success": False, "error": "Email already registered"}

        # Create user (unverified)
        user_id = f"user_{secrets.token_hex(8)}"
        user = {
            "id": user_id,
            "email": email,
            "name": name,
            "hashed_password": hash_password(password),
            "is_active": True,
            "is_verified": False,
            "mfa_enabled": False,
            "roles": ["user"],
            "created_at": datetime.utcnow().isoformat(),
            "terms_accepted_at": datetime.utcnow().isoformat() if terms_accepted else None,
        }

        await self.storage.create_user(user)

        # Create verification token
        token = await self._create_verification_token(
            user_id=user_id,
            email=email,
            type=VerificationType.EMAIL_VERIFICATION,
        )

        # Send verification email
        verification_url = f"{self.base_url}/verify-email?token={token}"
        await self.email_sender.send_verification_email(
            to=email,
            name=name or email.split("@")[0],
            verification_url=verification_url,
        )

        return {
            "success": True,
            "user_id": user_id,
            "message": "Verification email sent",
        }

    async def verify_email(self, token: str) -> Dict[str, Any]:
        """
        Verify email with token.
        """
        # Validate token
        verification = await self._validate_token(
            token,
            VerificationType.EMAIL_VERIFICATION,
        )

        if not verification["valid"]:
            return {"success": False, "error": verification["error"]}

        token_data = verification["token_data"]

        # Mark email as verified
        await self.storage.update_user(token_data.user_id, {
            "is_verified": True,
            "verified_at": datetime.utcnow().isoformat(),
        })

        # Mark token as used
        await self._mark_token_used(token_data.token_hash)

        return {
            "success": True,
            "user_id": token_data.user_id,
            "message": "Email verified successfully",
        }

    async def resend_verification(self, email: str) -> Dict[str, Any]:
        """
        Resend verification email.
        """
        user = await self.storage.get_user_by_email(email)
        if not user:
            # Don't reveal if email exists
            return {"success": True, "message": "If email exists, verification email sent"}

        if user.get("is_verified"):
            return {"success": False, "error": "Email already verified"}

        # Create new token
        token = await self._create_verification_token(
            user_id=user["id"],
            email=email,
            type=VerificationType.EMAIL_VERIFICATION,
        )

        verification_url = f"{self.base_url}/verify-email?token={token}"
        await self.email_sender.send_verification_email(
            to=email,
            name=user.get("name", email.split("@")[0]),
            verification_url=verification_url,
        )

        return {"success": True, "message": "Verification email sent"}

    # Password Reset Flow

    async def request_password_reset(self, email: str) -> Dict[str, Any]:
        """
        Request password reset email.
        """
        user = await self.storage.get_user_by_email(email)

        # Always return success to prevent email enumeration
        response = {"success": True, "message": "If email exists, reset email sent"}

        if not user:
            return response

        # Create reset token
        token = await self._create_verification_token(
            user_id=user["id"],
            email=email,
            type=VerificationType.PASSWORD_RESET,
        )

        reset_url = f"{self.base_url}/reset-password?token={token}"
        await self.email_sender.send_password_reset_email(
            to=email,
            name=user.get("name", email.split("@")[0]),
            reset_url=reset_url,
        )

        return response

    async def reset_password(
        self,
        token: str,
        new_password: str,
    ) -> Dict[str, Any]:
        """
        Reset password with token.
        """
        from .auth.password import hash_password

        # Validate token
        verification = await self._validate_token(
            token,
            VerificationType.PASSWORD_RESET,
        )

        if not verification["valid"]:
            return {"success": False, "error": verification["error"]}

        token_data = verification["token_data"]

        # Update password
        await self.storage.update_user(token_data.user_id, {
            "hashed_password": hash_password(new_password),
            "password_changed_at": datetime.utcnow().isoformat(),
        })

        # Mark token as used
        await self._mark_token_used(token_data.token_hash)

        # Invalidate all sessions (security)
        await self.storage.invalidate_user_sessions(token_data.user_id)

        # Send notification email
        user = await self.storage.get_user(token_data.user_id)
        if user:
            await self.email_sender.send_password_changed_notification(
                to=user["email"],
                name=user.get("name", user["email"].split("@")[0]),
            )

        return {
            "success": True,
            "message": "Password reset successfully",
        }

    # Email Change Flow

    async def request_email_change(
        self,
        user_id: str,
        new_email: str,
        current_password: str,
    ) -> Dict[str, Any]:
        """
        Request email change (requires password verification).
        """
        from .auth.password import verify_password

        user = await self.storage.get_user(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        # Verify current password
        if not verify_password(current_password, user["hashed_password"]):
            return {"success": False, "error": "Invalid password"}

        # Check if new email is taken
        existing = await self.storage.get_user_by_email(new_email)
        if existing:
            return {"success": False, "error": "Email already in use"}

        # Create verification token with new email
        token = await self._create_verification_token(
            user_id=user_id,
            email=new_email,
            type=VerificationType.EMAIL_CHANGE,
            metadata={"old_email": user["email"]},
        )

        verify_url = f"{self.base_url}/verify-email-change?token={token}"
        await self.email_sender.send_email_change_verification(
            to=new_email,
            name=user.get("name", user["email"].split("@")[0]),
            verification_url=verify_url,
            old_email=user["email"],
        )

        return {
            "success": True,
            "message": "Verification email sent to new address",
        }

    async def verify_email_change(self, token: str) -> Dict[str, Any]:
        """
        Verify and complete email change.
        """
        verification = await self._validate_token(
            token,
            VerificationType.EMAIL_CHANGE,
        )

        if not verification["valid"]:
            return {"success": False, "error": verification["error"]}

        token_data = verification["token_data"]
        old_email = token_data.metadata.get("old_email") if token_data.metadata else None

        # Update email
        await self.storage.update_user(token_data.user_id, {
            "email": token_data.email,
            "email_changed_at": datetime.utcnow().isoformat(),
        })

        # Mark token as used
        await self._mark_token_used(token_data.token_hash)

        # Notify old email
        if old_email:
            user = await self.storage.get_user(token_data.user_id)
            await self.email_sender.send_email_changed_notification(
                to=old_email,
                name=user.get("name", old_email.split("@")[0]),
                new_email=token_data.email,
            )

        return {
            "success": True,
            "message": "Email changed successfully",
        }

    # Account Deletion Flow

    async def request_account_deletion(
        self,
        user_id: str,
        password: str,
    ) -> Dict[str, Any]:
        """
        Request account deletion (requires password verification).
        """
        from .auth.password import verify_password

        user = await self.storage.get_user(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        # Verify password
        if not verify_password(password, user["hashed_password"]):
            return {"success": False, "error": "Invalid password"}

        # Create deletion token
        token = await self._create_verification_token(
            user_id=user_id,
            email=user["email"],
            type=VerificationType.ACCOUNT_DELETION,
        )

        confirm_url = f"{self.base_url}/confirm-deletion?token={token}"
        await self.email_sender.send_deletion_confirmation(
            to=user["email"],
            name=user.get("name", user["email"].split("@")[0]),
            confirmation_url=confirm_url,
        )

        return {
            "success": True,
            "message": "Confirmation email sent",
        }

    async def confirm_account_deletion(self, token: str) -> Dict[str, Any]:
        """
        Confirm and execute account deletion.
        """
        verification = await self._validate_token(
            token,
            VerificationType.ACCOUNT_DELETION,
        )

        if not verification["valid"]:
            return {"success": False, "error": verification["error"]}

        token_data = verification["token_data"]

        # Soft delete (mark as deleted)
        await self.storage.update_user(token_data.user_id, {
            "is_active": False,
            "deleted_at": datetime.utcnow().isoformat(),
            "deletion_scheduled_at": (datetime.utcnow() + timedelta(days=30)).isoformat(),
        })

        # Invalidate all sessions
        await self.storage.invalidate_user_sessions(token_data.user_id)

        # Mark token as used
        await self._mark_token_used(token_data.token_hash)

        return {
            "success": True,
            "message": "Account scheduled for deletion in 30 days",
        }

    # Profile Management

    async def update_profile(
        self,
        user_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Update user profile.
        """
        # Allowed fields for self-service update
        allowed = {"name", "avatar", "timezone", "language", "preferences"}
        filtered = {k: v for k, v in updates.items() if k in allowed}

        if not filtered:
            return {"success": False, "error": "No valid fields to update"}

        await self.storage.update_user(user_id, filtered)

        return {
            "success": True,
            "updated": list(filtered.keys()),
        }

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> Dict[str, Any]:
        """
        Change password (requires current password).
        """
        from .auth.password import hash_password, verify_password

        user = await self.storage.get_user(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        # Verify current password
        if not verify_password(current_password, user["hashed_password"]):
            return {"success": False, "error": "Current password is incorrect"}

        # Update password
        await self.storage.update_user(user_id, {
            "hashed_password": hash_password(new_password),
            "password_changed_at": datetime.utcnow().isoformat(),
        })

        return {"success": True, "message": "Password changed successfully"}

    # Session Management for Users

    async def list_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        List active sessions for user.
        """
        sessions = await self.storage.get_user_sessions(user_id)
        return [
            {
                "id": s["id"],
                "device": s.get("device", "Unknown"),
                "browser": s.get("browser", "Unknown"),
                "ip_address": s.get("ip_address"),
                "location": s.get("location"),
                "created_at": s.get("created_at"),
                "last_active": s.get("last_active"),
                "is_current": s.get("is_current", False),
            }
            for s in sessions
        ]

    async def revoke_session(
        self,
        user_id: str,
        session_id: str,
    ) -> Dict[str, Any]:
        """
        Revoke a specific session.
        """
        success = await self.storage.revoke_session(user_id, session_id)
        return {
            "success": success,
            "message": "Session revoked" if success else "Session not found",
        }

    async def revoke_all_sessions(
        self,
        user_id: str,
        except_current: bool = True,
        current_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Revoke all sessions except current.
        """
        count = await self.storage.invalidate_user_sessions(
            user_id,
            except_session_id=current_session_id if except_current else None,
        )
        return {
            "success": True,
            "revoked_count": count,
        }

    # Helper methods

    async def _create_verification_token(
        self,
        user_id: str,
        email: str,
        type: VerificationType,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a verification token.
        """
        import time

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        verification = VerificationToken(
            token=token,
            token_hash=token_hash,
            user_id=user_id,
            type=type,
            email=email,
            created_at=int(time.time()),
            expires_at=int(time.time()) + (self.token_expiry_hours * 3600),
            metadata=metadata,
        )

        await self.storage.store_verification_token(verification)

        return token

    async def _validate_token(
        self,
        token: str,
        expected_type: VerificationType,
    ) -> Dict[str, Any]:
        """
        Validate a verification token.
        """
        import time

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        token_data = await self.storage.get_verification_token(token_hash)

        if not token_data:
            return {"valid": False, "error": "Invalid or expired token"}

        if token_data.type != expected_type:
            return {"valid": False, "error": "Invalid token type"}

        if token_data.expires_at < int(time.time()):
            return {"valid": False, "error": "Token has expired"}

        if token_data.used_at:
            return {"valid": False, "error": "Token has already been used"}

        return {"valid": True, "token_data": token_data}

    async def _mark_token_used(self, token_hash: str) -> None:
        """
        Mark a token as used.
        """
        import time
        await self.storage.mark_token_used(token_hash, int(time.time()))
