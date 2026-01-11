"""
Audit Logging Middleware
Track all authentication events
"""

import json
import time
from datetime import datetime
from typing import Optional, Callable, Any
from functools import wraps
from dataclasses import dataclass, asdict
from enum import Enum

from fastapi import Request


class AuditEventType(str, Enum):
    """Types of audit events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    REGISTER = "register"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    MFA_SETUP = "mfa_setup"
    MFA_VERIFY = "mfa_verify"
    MFA_DISABLE = "mfa_disable"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOKE = "token_revoke"
    ACCOUNT_LOCK = "account_lock"
    ACCOUNT_UNLOCK = "account_unlock"
    PERMISSION_CHANGE = "permission_change"
    API_KEY_CREATE = "api_key_create"
    API_KEY_REVOKE = "api_key_revoke"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


@dataclass
class AuditEvent:
    """Audit event record."""
    id: str
    timestamp: float
    event_type: AuditEventType
    user_id: Optional[str]
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    success: bool
    details: Optional[dict] = None
    risk_score: int = 0  # 0-100

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "event_type": self.event_type.value,
            "timestamp_iso": datetime.fromtimestamp(self.timestamp).isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """Audit event logger with risk scoring."""

    def __init__(self, storage_backend: Optional[Any] = None):
        self.storage = storage_backend
        self.events: list[AuditEvent] = []  # In-memory for demo
        self.failed_attempts: dict[str, list[float]] = {}  # IP -> timestamps

    def _get_client_info(self, request: Request) -> tuple[str, str]:
        """Extract client IP and user agent."""
        ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if not ip:
            ip = request.headers.get("X-Real-IP", "")
        if not ip and request.client:
            ip = request.client.host

        user_agent = request.headers.get("User-Agent", "unknown")

        return ip, user_agent

    def _calculate_risk_score(
        self,
        event_type: AuditEventType,
        ip: str,
        success: bool,
    ) -> int:
        """Calculate risk score for the event."""
        score = 0

        # Base score by event type
        high_risk_events = {
            AuditEventType.LOGIN_FAILURE: 20,
            AuditEventType.PASSWORD_RESET_REQUEST: 15,
            AuditEventType.MFA_DISABLE: 30,
            AuditEventType.SUSPICIOUS_ACTIVITY: 50,
            AuditEventType.ACCOUNT_LOCK: 40,
        }
        score += high_risk_events.get(event_type, 0)

        # Check for brute force patterns
        if ip in self.failed_attempts:
            recent_failures = [
                t for t in self.failed_attempts[ip]
                if t > time.time() - 300  # Last 5 minutes
            ]
            if len(recent_failures) >= 5:
                score += 30
            elif len(recent_failures) >= 3:
                score += 15

        # Failed attempt increases score
        if not success:
            score += 10

        return min(100, score)

    async def log(
        self,
        request: Request,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        success: bool = True,
        details: Optional[dict] = None,
    ) -> AuditEvent:
        """Log an audit event."""
        ip, user_agent = self._get_client_info(request)

        # Track failed attempts
        if not success and event_type == AuditEventType.LOGIN_FAILURE:
            if ip not in self.failed_attempts:
                self.failed_attempts[ip] = []
            self.failed_attempts[ip].append(time.time())

        risk_score = self._calculate_risk_score(event_type, ip, success)

        event = AuditEvent(
            id=f"audit_{int(time.time() * 1000)}_{len(self.events)}",
            timestamp=time.time(),
            event_type=event_type,
            user_id=user_id,
            ip_address=ip,
            user_agent=user_agent,
            endpoint=str(request.url.path),
            method=request.method,
            success=success,
            details=details,
            risk_score=risk_score,
        )

        self.events.append(event)

        # Trigger alerts for high risk
        if risk_score >= 50:
            await self._trigger_alert(event)

        return event

    async def _trigger_alert(self, event: AuditEvent):
        """Trigger security alert for high-risk events."""
        print(f"🚨 SECURITY ALERT: {event.event_type.value} (risk: {event.risk_score})")
        print(f"   IP: {event.ip_address}, User: {event.user_id}")
        # In production: send to SIEM, Slack, email, etc.

    def get_events(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        min_risk: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events."""
        filtered = self.events

        if user_id:
            filtered = [e for e in filtered if e.user_id == user_id]

        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]

        if min_risk > 0:
            filtered = [e for e in filtered if e.risk_score >= min_risk]

        return sorted(filtered, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_suspicious_ips(self, threshold: int = 5) -> list[dict]:
        """Get IPs with multiple failed attempts."""
        now = time.time()
        suspicious = []

        for ip, timestamps in self.failed_attempts.items():
            recent = [t for t in timestamps if t > now - 3600]  # Last hour
            if len(recent) >= threshold:
                suspicious.append({
                    "ip": ip,
                    "failed_attempts": len(recent),
                    "last_attempt": max(recent),
                })

        return sorted(suspicious, key=lambda x: x["failed_attempts"], reverse=True)


# Global audit logger
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def audit_log(event_type: AuditEventType):
    """Decorator for automatic audit logging."""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            logger = get_audit_logger()
            user_id = kwargs.get("current_user", {}).get("id")

            try:
                result = await func(request, *args, **kwargs)
                await logger.log(
                    request=request,
                    event_type=event_type,
                    user_id=user_id,
                    success=True,
                )
                return result

            except Exception as e:
                await logger.log(
                    request=request,
                    event_type=event_type,
                    user_id=user_id,
                    success=False,
                    details={"error": str(e)},
                )
                raise

        return wrapper

    return decorator
