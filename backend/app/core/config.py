"""Application settings, loaded from environment / .env (no hardcoded secrets)."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.enums import AIProviderKind


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # General
    environment: str = "development"
    log_level: str = "INFO"
    app_name: str = "ForgeShield OT"
    api_prefix: str = "/api"
    backend_cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Database
    postgres_user: str = "forgeshield"
    postgres_password: str = "forgeshield_dev_pw"
    postgres_db: str = "forgeshield"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    database_url_override: str | None = Field(default=None, alias="DATABASE_URL")

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Auth (Supabase Cloud)
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_key: str = ""
    supabase_jwt_secret: str = "dev-insecure-jwt-secret-change-me"
    supabase_jwt_aud: str = "authenticated"
    auth_dev_bypass: bool = False
    demo_user_password: str = "Demo!ForgeShield123"

    # AI provider
    ai_provider: AIProviderKind = AIProviderKind.LOCAL_FOUNDATION_SEC
    ai_base_url: str = "http://localhost:8000/v1"
    ai_api_key: str = "not-needed-for-local"
    ai_model_name: str = "Foundation-Sec-8B-Reasoning"
    ai_temperature: float = 0.2
    ai_max_tokens: int = 1400
    ai_timeout_seconds: int = 60
    ai_rate_limit: str = "20/minute"
    ai_vector_enabled: bool = False

    # Reports
    reports_pdf_enabled: bool = False

    # Seeding
    seed_on_start: bool = True

    # File uploads
    max_upload_bytes: int = 5 * 1024 * 1024  # 5 MB

    @field_validator("ai_provider", mode="before")
    @classmethod
    def _coerce_provider(cls, v: object) -> object:
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.backend_cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def supabase_issuer(self) -> str:
        base = self.supabase_url.rstrip("/")
        return f"{base}/auth/v1" if base else ""

    @property
    def supabase_jwks_url(self) -> str:
        """JWKS endpoint for asymmetric (ES256/RS256) access-token verification.

        Newer Supabase projects sign user access tokens with rotating asymmetric
        keys (the "JWT signing keys" feature) rather than the legacy HS256 shared
        secret. The public keys are published here.
        """
        issuer = self.supabase_issuer
        return f"{issuer}/.well-known/jwks.json" if issuer else ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
