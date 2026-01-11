"""
IP Filtering Middleware
Block/allow IPs, detect VPNs, geo-blocking
"""

import ipaddress
from typing import Optional, Set
from functools import wraps

from fastapi import Request, HTTPException, status


class IPFilter:
    """IP address filtering and blocking."""

    def __init__(
        self,
        allowlist: Optional[Set[str]] = None,
        blocklist: Optional[Set[str]] = None,
        block_private: bool = False,
        allowed_countries: Optional[Set[str]] = None,
        blocked_countries: Optional[Set[str]] = None,
    ):
        self.allowlist = allowlist or set()
        self.blocklist = blocklist or set()
        self.block_private = block_private
        self.allowed_countries = allowed_countries
        self.blocked_countries = blocked_countries or set()

        # Temporary blocks (IP -> expiry timestamp)
        self.temp_blocks: dict[str, float] = {}

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "0.0.0.0"

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def _matches_cidr(self, ip: str, cidrs: Set[str]) -> bool:
        """Check if IP matches any CIDR range."""
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in cidrs:
                if "/" in cidr:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if addr in network:
                        return True
                elif ip == cidr:
                    return True
        except ValueError:
            pass
        return False

    def add_to_blocklist(self, ip: str):
        """Add IP to permanent blocklist."""
        self.blocklist.add(ip)

    def remove_from_blocklist(self, ip: str):
        """Remove IP from blocklist."""
        self.blocklist.discard(ip)

    def temp_block(self, ip: str, duration_seconds: int = 3600):
        """Temporarily block an IP."""
        import time
        self.temp_blocks[ip] = time.time() + duration_seconds

    def unblock(self, ip: str):
        """Remove temporary block."""
        self.temp_blocks.pop(ip, None)

    def is_blocked(self, ip: str) -> tuple[bool, str]:
        """
        Check if IP is blocked.
        Returns (blocked: bool, reason: str)
        """
        import time

        # Check allowlist first (always allowed)
        if self._matches_cidr(ip, self.allowlist):
            return False, ""

        # Check permanent blocklist
        if self._matches_cidr(ip, self.blocklist):
            return True, "IP is blocklisted"

        # Check temporary blocks
        if ip in self.temp_blocks:
            if time.time() < self.temp_blocks[ip]:
                return True, "IP is temporarily blocked"
            else:
                del self.temp_blocks[ip]

        # Check private IP blocking
        if self.block_private and self._is_private_ip(ip):
            return True, "Private IPs not allowed"

        return False, ""

    def check_country(self, request: Request) -> tuple[bool, str]:
        """
        Check country-based restrictions.
        Uses CF-IPCountry header from Cloudflare.
        """
        country = request.headers.get("CF-IPCountry", "").upper()

        if not country:
            return False, ""

        if self.allowed_countries and country not in self.allowed_countries:
            return True, f"Country {country} not allowed"

        if country in self.blocked_countries:
            return True, f"Country {country} is blocked"

        return False, ""

    async def check(self, request: Request) -> tuple[bool, str]:
        """
        Full IP check.
        Returns (allowed: bool, reason: str if blocked)
        """
        ip = self._get_client_ip(request)

        # Check IP blocklist
        blocked, reason = self.is_blocked(ip)
        if blocked:
            return False, reason

        # Check country
        blocked, reason = self.check_country(request)
        if blocked:
            return False, reason

        return True, ""

    def get_stats(self) -> dict:
        """Get filtering statistics."""
        import time
        active_temp_blocks = sum(
            1 for exp in self.temp_blocks.values()
            if exp > time.time()
        )

        return {
            "allowlist_count": len(self.allowlist),
            "blocklist_count": len(self.blocklist),
            "temp_blocks_count": active_temp_blocks,
            "blocked_countries": list(self.blocked_countries),
        }


# Global filter instance
_ip_filter: Optional[IPFilter] = None


def get_ip_filter() -> IPFilter:
    """Get or create IP filter instance."""
    global _ip_filter
    if _ip_filter is None:
        _ip_filter = IPFilter()
    return _ip_filter


def ip_filter():
    """Decorator for IP filtering on endpoints."""

    def decorator(func):
        filter_instance = get_ip_filter()

        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            allowed, reason = await filter_instance.check(request)

            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=reason,
                )

            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


class IPFilterMiddleware:
    """ASGI middleware for IP filtering."""

    def __init__(self, app, filter_instance: Optional[IPFilter] = None):
        self.app = app
        self.filter = filter_instance or get_ip_filter()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        allowed, reason = await self.filter.check(request)

        if not allowed:
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({
                "type": "http.response.body",
                "body": f'{{"detail": "{reason}"}}'.encode(),
            })
            return

        await self.app(scope, receive, send)
