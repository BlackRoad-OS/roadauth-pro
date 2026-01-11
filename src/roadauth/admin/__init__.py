"""
RoadAuth Pro Admin Dashboard

Features:
- User management (list, create, update, delete)
- Role management
- Session management
- Audit log viewer
- System statistics
- Security settings
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field


router = APIRouter(prefix="/admin", tags=["admin"])


# Models
class UserListItem(BaseModel):
    id: str
    email: str
    username: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    roles: List[str]
    created_at: str
    last_login: Optional[str] = None


class UserListResponse(BaseModel):
    users: List[UserListItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class UserCreateAdmin(BaseModel):
    email: EmailStr
    username: str
    password: str
    roles: List[str] = Field(default=["user"])
    is_active: bool = True
    is_verified: bool = False
    send_welcome_email: bool = True


class UserUpdateAdmin(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    mfa_enabled: Optional[bool] = None
    roles: Optional[List[str]] = None


class RoleDefinition(BaseModel):
    name: str
    description: str
    permissions: List[str]


class SessionInfo(BaseModel):
    id: str
    user_id: str
    user_email: str
    created_at: str
    expires_at: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool


class AuditLogEntry(BaseModel):
    id: str
    timestamp: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    resource: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    details: Optional[Dict[str, Any]] = None


class SystemStats(BaseModel):
    total_users: int
    active_users: int
    verified_users: int
    mfa_enabled_users: int
    total_sessions: int
    active_sessions: int
    logins_today: int
    logins_this_week: int
    failed_logins_today: int
    new_users_today: int
    new_users_this_week: int


class SecuritySettings(BaseModel):
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = False
    session_timeout_minutes: int = 60
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    require_mfa_for_admins: bool = True
    allowed_email_domains: List[str] = Field(default_factory=list)


# In-memory stores (use Redis/DB in production)
users_db: Dict[str, dict] = {}
sessions_db: Dict[str, dict] = {}
audit_log: List[dict] = []
roles_db: Dict[str, RoleDefinition] = {
    "user": RoleDefinition(
        name="user",
        description="Standard user",
        permissions=["read:profile", "update:profile"],
    ),
    "admin": RoleDefinition(
        name="admin",
        description="Administrator",
        permissions=["*"],
    ),
    "moderator": RoleDefinition(
        name="moderator",
        description="Content moderator",
        permissions=["read:users", "update:users", "read:content", "moderate:content"],
    ),
}
security_settings = SecuritySettings()


def log_audit(
    action: str,
    resource: str,
    resource_id: Optional[str] = None,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
    details: Optional[Dict] = None,
):
    """Add entry to audit log."""
    entry = {
        "id": f"audit_{len(audit_log) + 1}",
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user_id,
        "user_email": user_email,
        "action": action,
        "resource": resource,
        "resource_id": resource_id,
        "ip_address": ip_address,
        "status": status,
        "details": details,
    }
    audit_log.append(entry)

    # Keep last 10000 entries
    if len(audit_log) > 10000:
        audit_log.pop(0)


# Admin check dependency
async def require_admin(current_user: dict) -> dict:
    """Require admin role."""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# User Management
@router.get("/users", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_verified: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List all users with pagination and filters."""
    # Filter users
    filtered = list(users_db.values())

    if search:
        search_lower = search.lower()
        filtered = [
            u for u in filtered
            if search_lower in u["email"].lower() or search_lower in u["username"].lower()
        ]

    if role:
        filtered = [u for u in filtered if role in u.get("roles", [])]

    if is_active is not None:
        filtered = [u for u in filtered if u.get("is_active") == is_active]

    if is_verified is not None:
        filtered = [u for u in filtered if u.get("is_verified") == is_verified]

    # Sort
    reverse = sort_order == "desc"
    filtered.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)

    # Paginate
    total = len(filtered)
    total_pages = (total + page_size - 1) // page_size
    start = (page - 1) * page_size
    end = start + page_size
    page_users = filtered[start:end]

    return UserListResponse(
        users=[UserListItem(**u) for u in page_users],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("/users", response_model=UserListItem)
async def create_user(user_data: UserCreateAdmin):
    """Create a new user (admin)."""
    from ..auth.password import hash_password

    # Check for duplicate email
    if any(u["email"] == user_data.email for u in users_db.values()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user_id = f"user_{len(users_db) + 1}"
    user = {
        "id": user_id,
        "email": user_data.email,
        "username": user_data.username,
        "hashed_password": hash_password(user_data.password),
        "is_active": user_data.is_active,
        "is_verified": user_data.is_verified,
        "mfa_enabled": False,
        "mfa_secret": None,
        "roles": user_data.roles,
        "created_at": datetime.utcnow().isoformat(),
    }

    users_db[user_id] = user

    log_audit(
        action="create",
        resource="user",
        resource_id=user_id,
        details={"email": user_data.email, "roles": user_data.roles},
    )

    return UserListItem(**user)


@router.get("/users/{user_id}", response_model=UserListItem)
async def get_user(user_id: str):
    """Get user details."""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    return UserListItem(**users_db[user_id])


@router.patch("/users/{user_id}", response_model=UserListItem)
async def update_user(user_id: str, update_data: UserUpdateAdmin):
    """Update user."""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    user = users_db[user_id]
    update_dict = update_data.model_dump(exclude_unset=True)

    for key, value in update_dict.items():
        user[key] = value

    log_audit(
        action="update",
        resource="user",
        resource_id=user_id,
        details=update_dict,
    )

    return UserListItem(**user)


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, soft_delete: bool = True):
    """Delete user."""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    if soft_delete:
        users_db[user_id]["is_active"] = False
        users_db[user_id]["deleted_at"] = datetime.utcnow().isoformat()
    else:
        del users_db[user_id]

    log_audit(
        action="delete",
        resource="user",
        resource_id=user_id,
        details={"soft_delete": soft_delete},
    )

    return {"status": "deleted", "user_id": user_id, "soft_delete": soft_delete}


@router.post("/users/{user_id}/reset-password")
async def admin_reset_password(user_id: str, new_password: str):
    """Admin reset user password."""
    from ..auth.password import hash_password

    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    users_db[user_id]["hashed_password"] = hash_password(new_password)

    log_audit(
        action="reset_password",
        resource="user",
        resource_id=user_id,
    )

    return {"status": "password_reset", "user_id": user_id}


@router.post("/users/{user_id}/disable-mfa")
async def admin_disable_mfa(user_id: str):
    """Admin disable user MFA."""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    users_db[user_id]["mfa_enabled"] = False
    users_db[user_id]["mfa_secret"] = None

    log_audit(
        action="disable_mfa",
        resource="user",
        resource_id=user_id,
    )

    return {"status": "mfa_disabled", "user_id": user_id}


# Role Management
@router.get("/roles", response_model=List[RoleDefinition])
async def list_roles():
    """List all roles."""
    return list(roles_db.values())


@router.post("/roles", response_model=RoleDefinition)
async def create_role(role: RoleDefinition):
    """Create a new role."""
    if role.name in roles_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role already exists",
        )

    roles_db[role.name] = role

    log_audit(
        action="create",
        resource="role",
        resource_id=role.name,
        details={"permissions": role.permissions},
    )

    return role


@router.delete("/roles/{role_name}")
async def delete_role(role_name: str):
    """Delete a role."""
    if role_name in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete built-in roles",
        )

    if role_name not in roles_db:
        raise HTTPException(status_code=404, detail="Role not found")

    del roles_db[role_name]

    log_audit(
        action="delete",
        resource="role",
        resource_id=role_name,
    )

    return {"status": "deleted", "role": role_name}


# Session Management
@router.get("/sessions", response_model=List[SessionInfo])
async def list_sessions(
    user_id: Optional[str] = None,
    active_only: bool = True,
):
    """List all sessions."""
    sessions = list(sessions_db.values())

    if user_id:
        sessions = [s for s in sessions if s.get("user_id") == user_id]

    if active_only:
        now = datetime.utcnow()
        sessions = [
            s for s in sessions
            if datetime.fromisoformat(s["expires_at"]) > now
        ]

    return [SessionInfo(**s) for s in sessions]


@router.delete("/sessions/{session_id}")
async def revoke_session(session_id: str):
    """Revoke a session."""
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")

    session = sessions_db[session_id]
    del sessions_db[session_id]

    log_audit(
        action="revoke",
        resource="session",
        resource_id=session_id,
        user_id=session.get("user_id"),
    )

    return {"status": "revoked", "session_id": session_id}


@router.delete("/sessions/user/{user_id}")
async def revoke_user_sessions(user_id: str):
    """Revoke all sessions for a user."""
    to_delete = [
        sid for sid, s in sessions_db.items()
        if s.get("user_id") == user_id
    ]

    for sid in to_delete:
        del sessions_db[sid]

    log_audit(
        action="revoke_all",
        resource="session",
        user_id=user_id,
        details={"count": len(to_delete)},
    )

    return {"status": "revoked", "count": len(to_delete)}


# Audit Log
@router.get("/audit-log", response_model=List[AuditLogEntry])
async def get_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    status: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
):
    """Get audit log with filters."""
    filtered = audit_log.copy()

    if user_id:
        filtered = [e for e in filtered if e.get("user_id") == user_id]

    if action:
        filtered = [e for e in filtered if e.get("action") == action]

    if resource:
        filtered = [e for e in filtered if e.get("resource") == resource]

    if status:
        filtered = [e for e in filtered if e.get("status") == status]

    if from_date:
        filtered = [e for e in filtered if e.get("timestamp", "") >= from_date]

    if to_date:
        filtered = [e for e in filtered if e.get("timestamp", "") <= to_date]

    # Sort by timestamp descending
    filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Paginate
    start = (page - 1) * page_size
    end = start + page_size

    return [AuditLogEntry(**e) for e in filtered[start:end]]


# System Statistics
@router.get("/stats", response_model=SystemStats)
async def get_system_stats():
    """Get system statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    users = list(users_db.values())
    sessions = list(sessions_db.values())

    # Count logins from audit log
    logins_today = len([
        e for e in audit_log
        if e.get("action") == "login"
        and e.get("timestamp", "") >= today_start.isoformat()
    ])

    logins_this_week = len([
        e for e in audit_log
        if e.get("action") == "login"
        and e.get("timestamp", "") >= week_start.isoformat()
    ])

    failed_logins_today = len([
        e for e in audit_log
        if e.get("action") == "login"
        and e.get("status") == "failed"
        and e.get("timestamp", "") >= today_start.isoformat()
    ])

    new_users_today = len([
        u for u in users
        if u.get("created_at", "") >= today_start.isoformat()
    ])

    new_users_this_week = len([
        u for u in users
        if u.get("created_at", "") >= week_start.isoformat()
    ])

    active_sessions = len([
        s for s in sessions
        if datetime.fromisoformat(s["expires_at"]) > now
    ])

    return SystemStats(
        total_users=len(users),
        active_users=len([u for u in users if u.get("is_active")]),
        verified_users=len([u for u in users if u.get("is_verified")]),
        mfa_enabled_users=len([u for u in users if u.get("mfa_enabled")]),
        total_sessions=len(sessions),
        active_sessions=active_sessions,
        logins_today=logins_today,
        logins_this_week=logins_this_week,
        failed_logins_today=failed_logins_today,
        new_users_today=new_users_today,
        new_users_this_week=new_users_this_week,
    )


# Security Settings
@router.get("/security", response_model=SecuritySettings)
async def get_security_settings():
    """Get security settings."""
    return security_settings


@router.put("/security", response_model=SecuritySettings)
async def update_security_settings(settings: SecuritySettings):
    """Update security settings."""
    global security_settings
    security_settings = settings

    log_audit(
        action="update",
        resource="security_settings",
        details=settings.model_dump(),
    )

    return security_settings
