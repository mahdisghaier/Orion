"""Application configuration via Pydantic Settings.

Loads from environment variables / .env file.
Never commit the .env file — it contains secrets.
"""
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized configuration. Access via `settings` singleton below."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # ignore unknown env vars
    )

    # ─── App ───────────────────────────────────────────────
    APP_NAME: str = "ORION"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True

    # ─── Database ──────────────────────────────────────────
    DATABASE_URL: str

    # ─── Auth (JWT) ────────────────────────────────────────
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ─── Encryption (Fernet, for siem_connections.config_encrypted) ─
    SIEM_ENCRYPTION_KEY: str

    # ─── SIEM Connections (Phase 4+, optional until then) ─
    ELASTIC_CLOUD_URL: Optional[str] = None
    ELASTIC_API_KEY: Optional[str] = None
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    SENTINEL_WORKSPACE_ID: Optional[str] = None

    # ─── LLM (Phase 8+) ──────────────────────────────────────
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-3.6-flash"

# Singleton — import this everywhere: `from app.core.config import settings`
settings = Settings()