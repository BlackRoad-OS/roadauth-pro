"""
RoadAuth Pro - Main FastAPI Application
Enterprise-grade authentication service
"""

from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from .auth.jwt import create_access_token, create_refresh_token, decode_token
from .auth.password import hash_password, verify_password
from .auth.mfa import generate_totp_secret, verify_totp, generate_qr_code
from .models.user import User, UserCreate, UserResponse, TokenResponse
from .db.repository import UserRepository
from .config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    # Startup
    print("🔐 RoadAuth Pro starting...")
    yield
    # Shutdown
    print("🔐 RoadAuth Pro shutting down...")


app = FastAPI(
    title="RoadAuth Pro",
    description="Enterprise Authentication Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


# In-memory store for demo (use Redis/DB in production)
users_db: dict[str, dict] = {}
sessions_db: dict[str, dict] = {}
refresh_tokens_db: dict[str, str] = {}


# Dependency
async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Validate JWT and return current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if payload is None:
        raise credentials_exception

    user_id = payload.get("sub")
    if user_id is None or user_id not in users_db:
        raise credentials_exception

    return users_db[user_id]


# Routes
@app.get("/")
async def root():
    """API information."""
    return {
        "name": "RoadAuth Pro",
        "version": "0.1.0",
        "description": "Enterprise Authentication Platform",
        "endpoints": {
            "register": "POST /auth/register",
            "login": "POST /auth/token",
            "refresh": "POST /auth/refresh",
            "me": "GET /auth/me",
            "mfa_setup": "POST /auth/mfa/setup",
            "mfa_verify": "POST /auth/mfa/verify",
            "logout": "POST /auth/logout",
        },
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "roadauth-pro"}


@app.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    """Register a new user."""
    if user_data.email in [u["email"] for u in users_db.values()]:
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
        "is_active": True,
        "is_verified": False,
        "mfa_enabled": False,
        "mfa_secret": None,
        "roles": ["user"],
        "created_at": datetime.utcnow().isoformat(),
    }

    users_db[user_id] = user

    return UserResponse(
        id=user_id,
        email=user["email"],
        username=user["username"],
        is_active=user["is_active"],
        is_verified=user["is_verified"],
        mfa_enabled=user["mfa_enabled"],
        roles=user["roles"],
    )


@app.post("/auth/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 password flow login."""
    # Find user by username or email
    user = None
    for u in users_db.values():
        if u["username"] == form_data.username or u["email"] == form_data.username:
            user = u
            break

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Check if MFA is required
    if user["mfa_enabled"]:
        # Return partial token that requires MFA verification
        mfa_token = create_access_token(
            data={"sub": user["id"], "mfa_required": True},
            expires_delta=timedelta(minutes=5),
        )
        return TokenResponse(
            access_token=mfa_token,
            token_type="mfa_required",
            expires_in=300,
        )

    # Generate tokens
    access_token = create_access_token(
        data={"sub": user["id"], "roles": user["roles"]},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    refresh_token = create_refresh_token(data={"sub": user["id"]})

    # Store refresh token
    refresh_tokens_db[refresh_token] = user["id"]

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token."""
    if refresh_token not in refresh_tokens_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = refresh_tokens_db[refresh_token]
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    user = users_db[user_id]

    # Generate new tokens
    new_access_token = create_access_token(
        data={"sub": user["id"], "roles": user["roles"]},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    new_refresh_token = create_refresh_token(data={"sub": user["id"]})

    # Rotate refresh token
    del refresh_tokens_db[refresh_token]
    refresh_tokens_db[new_refresh_token] = user_id

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile."""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        username=current_user["username"],
        is_active=current_user["is_active"],
        is_verified=current_user["is_verified"],
        mfa_enabled=current_user["mfa_enabled"],
        roles=current_user["roles"],
    )


@app.post("/auth/mfa/setup")
async def setup_mfa(current_user: dict = Depends(get_current_user)):
    """Set up MFA for current user."""
    if current_user["mfa_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    # Generate TOTP secret
    secret = generate_totp_secret()

    # Store temporarily (not enabled until verified)
    users_db[current_user["id"]]["mfa_secret"] = secret

    # Generate QR code
    qr_uri = f"otpauth://totp/RoadAuth:{current_user['email']}?secret={secret}&issuer=RoadAuth"
    qr_code = generate_qr_code(qr_uri)

    return {
        "secret": secret,
        "qr_code": qr_code,
        "message": "Scan QR code with authenticator app, then verify with /auth/mfa/verify",
    }


@app.post("/auth/mfa/verify")
async def verify_mfa(
    code: str,
    current_user: dict = Depends(get_current_user),
):
    """Verify MFA code and enable MFA."""
    secret = current_user.get("mfa_secret")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not set up. Call /auth/mfa/setup first",
        )

    if not verify_totp(secret, code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Enable MFA
    users_db[current_user["id"]]["mfa_enabled"] = True

    return {"message": "MFA enabled successfully"}


@app.post("/auth/mfa/authenticate")
async def authenticate_mfa(mfa_token: str, code: str):
    """Complete login with MFA code."""
    payload = decode_token(mfa_token)
    if not payload or not payload.get("mfa_required"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )

    user_id = payload.get("sub")
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    user = users_db[user_id]

    if not verify_totp(user["mfa_secret"], code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Generate full tokens
    access_token = create_access_token(
        data={"sub": user["id"], "roles": user["roles"]},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    refresh_token = create_refresh_token(data={"sub": user["id"]})
    refresh_tokens_db[refresh_token] = user_id

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@app.post("/auth/logout")
async def logout(
    refresh_token: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Logout and invalidate tokens."""
    if refresh_token and refresh_token in refresh_tokens_db:
        del refresh_tokens_db[refresh_token]

    return {"message": "Logged out successfully"}


# OAuth2 endpoints for external providers
@app.get("/auth/oauth/{provider}")
async def oauth_redirect(provider: str, redirect_uri: str):
    """Initiate OAuth flow with external provider."""
    supported = ["google", "github", "microsoft", "okta"]
    if provider not in supported:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Provider not supported. Use: {supported}",
        )

    # In production, redirect to provider's auth URL
    return {
        "provider": provider,
        "redirect_uri": redirect_uri,
        "message": f"Redirect to {provider} OAuth flow",
    }


@app.post("/auth/oauth/{provider}/callback")
async def oauth_callback(provider: str, code: str, state: Optional[str] = None):
    """Handle OAuth callback from external provider."""
    # In production, exchange code for tokens and create/link user
    return {
        "provider": provider,
        "message": "OAuth callback received",
        "code": code[:10] + "...",
    }


def cli():
    """CLI entry point."""
    import uvicorn
    uvicorn.run(
        "roadauth.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    cli()
