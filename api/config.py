"""
config.py — Application settings loaded from environment variables.

Pydantic-settings validates types, provides defaults, and raises a clear
error at startup if a required variable is missing — no more silent None values.

Usage:
    from config import settings
    print(settings.database_url)
"""

from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        case_sensitive=False,
        extra='ignore',
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str           # postgresql+asyncpg://user:pass@host:5432/db
    # Sync URL for Alembic (uses psycopg2, not asyncpg)
    @property
    def sync_database_url(self) -> str:
        return self.database_url.replace('postgresql+asyncpg://', 'postgresql://')

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str              # redis://:password@redis:6379/0

    # ── JWT ───────────────────────────────────────────────────────────────────
    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expire_minutes: int = 480   # 8 hours — long enough for a pentest day

    # ── Admin bootstrap ───────────────────────────────────────────────────────
    admin_password: str

    # ── Host path (for Docker volume mounts in scan containers) ───────────────
    host_project_path: str

    # ── ZAP ───────────────────────────────────────────────────────────────────
    zap_api_key: str
    zap_api_url: str = 'http://owasp-zap:8080'

    # ── CORS origins (comma-separated) ────────────────────────────────────────
    # The React SPA origin must be listed here
    cors_origins: str = 'http://localhost:5173,http://localhost:80,https://localhost'

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(',')]

    # ── Testing flag ──────────────────────────────────────────────────────────
    testing: bool = False

    @field_validator('jwt_secret')
    @classmethod
    def jwt_secret_min_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('JWT_SECRET must be at least 32 characters')
        return v


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance — import this everywhere."""
    return Settings()


settings = get_settings()
