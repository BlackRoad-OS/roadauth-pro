"""
Rate Limiting Middleware
Protect endpoints from abuse
"""

import time
from typing import Optional, Callable
from functools import wraps
from collections import defaultdict

from fastapi import Request, HTTPException, status


class RateLimiter:
    """Token bucket rate limiter with sliding window."""

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_size: int = 10,
    ):
        self.rpm = requests_per_minute
        self.rph = requests_per_hour
        self.burst = burst_size

        # In-memory storage (use Redis in production)
        self.minute_buckets: dict[str, list[float]] = defaultdict(list)
        self.hour_buckets: dict[str, list[float]] = defaultdict(list)

    def _get_client_key(self, request: Request) -> str:
        """Get unique client identifier."""
        # Try to get real IP from headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _cleanup_old_requests(self, bucket: list[float], window_seconds: int) -> list[float]:
        """Remove requests outside the time window."""
        cutoff = time.time() - window_seconds
        return [t for t in bucket if t > cutoff]

    async def check_rate_limit(self, request: Request) -> bool:
        """Check if request should be rate limited."""
        client_key = self._get_client_key(request)
        now = time.time()

        # Clean up old requests
        self.minute_buckets[client_key] = self._cleanup_old_requests(
            self.minute_buckets[client_key], 60
        )
        self.hour_buckets[client_key] = self._cleanup_old_requests(
            self.hour_buckets[client_key], 3600
        )

        # Check limits
        minute_count = len(self.minute_buckets[client_key])
        hour_count = len(self.hour_buckets[client_key])

        if minute_count >= self.rpm:
            return False

        if hour_count >= self.rph:
            return False

        # Record request
        self.minute_buckets[client_key].append(now)
        self.hour_buckets[client_key].append(now)

        return True

    def get_remaining(self, request: Request) -> dict[str, int]:
        """Get remaining requests for client."""
        client_key = self._get_client_key(request)

        self.minute_buckets[client_key] = self._cleanup_old_requests(
            self.minute_buckets[client_key], 60
        )
        self.hour_buckets[client_key] = self._cleanup_old_requests(
            self.hour_buckets[client_key], 3600
        )

        return {
            "minute_remaining": max(0, self.rpm - len(self.minute_buckets[client_key])),
            "hour_remaining": max(0, self.rph - len(self.hour_buckets[client_key])),
        }


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def rate_limit(
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000,
):
    """Decorator for rate limiting endpoints."""

    def decorator(func: Callable):
        limiter = RateLimiter(
            requests_per_minute=requests_per_minute,
            requests_per_hour=requests_per_hour,
        )

        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            if not await limiter.check_rate_limit(request):
                remaining = limiter.get_remaining(request)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={
                        "X-RateLimit-Remaining-Minute": str(remaining["minute_remaining"]),
                        "X-RateLimit-Remaining-Hour": str(remaining["hour_remaining"]),
                        "Retry-After": "60",
                    },
                )

            response = await func(request, *args, **kwargs)
            return response

        return wrapper

    return decorator


class RateLimitMiddleware:
    """ASGI middleware for global rate limiting."""

    def __init__(self, app, limiter: Optional[RateLimiter] = None):
        self.app = app
        self.limiter = limiter or get_rate_limiter()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        if not await self.limiter.check_rate_limit(request):
            response = HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
            )
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"detail": "Rate limit exceeded"}',
            })
            return

        await self.app(scope, receive, send)
