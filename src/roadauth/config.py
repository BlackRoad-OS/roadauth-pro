"""
RoadAuth Pro Configuration
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings."""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # JWT
    jwt_secret_key: str = "your-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = "postgresql+asyncpg://localhost/roadauth"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # CORS
    cors_origins: List[str] = ["*"]

    # OAuth Providers
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    microsoft_client_id: str = ""
    microsoft_client_secret: str = ""

    class Config:
        env_prefix = "ROADAUTH_"
        env_file = ".env"


settings = Settings()
