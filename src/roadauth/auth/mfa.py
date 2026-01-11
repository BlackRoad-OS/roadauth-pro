"""
Multi-Factor Authentication (TOTP)
"""

import base64
import io
from typing import Optional

import pyotp
import qrcode


def generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def get_current_totp(secret: str) -> str:
    """Get the current TOTP code (for testing)."""
    totp = pyotp.TOTP(secret)
    return totp.now()


def generate_qr_code(uri: str) -> str:
    """Generate a QR code as base64 PNG."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return base64.b64encode(buffer.getvalue()).decode()


def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate backup codes for account recovery."""
    import secrets
    return [secrets.token_hex(4).upper() for _ in range(count)]
