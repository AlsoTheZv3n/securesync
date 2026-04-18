from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Application ──
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    SECRET_KEY: str = Field(min_length=32)
    JWT_ALGORITHM: Literal["HS256", "RS256"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    INVITATION_TTL_DAYS: int = 7

    # ── Datastores ──
    DATABASE_URL: PostgresDsn
    REDIS_URL: RedisDsn

    # ── Wazuh ──
    WAZUH_API_URL: str | None = None
    WAZUH_USERNAME: str | None = None
    WAZUH_PASSWORD: str | None = None
    # Wazuh ships self-signed certs by default. Disable verification in dev;
    # in production, mount the CA bundle and flip this back to True.
    WAZUH_VERIFY_SSL: bool = True

    # ── Greenbone ──
    GREENBONE_HOST: str | None = None
    GREENBONE_USERNAME: str | None = None
    GREENBONE_PASSWORD: str | None = None

    # ── ZAP ──
    ZAP_URL: str | None = None
    ZAP_API_KEY: str | None = None

    # ── DefectDojo ──
    DEFECTDOJO_URL: str | None = None
    DEFECTDOJO_API_KEY: str | None = None

    # ── External APIs ──
    EPSS_API_URL: str = "https://api.first.org/data/v1"
    NVD_API_KEY: str | None = None
    HIBP_API_KEY: str | None = None

    # ── NinjaOne ──
    NINJAONE_CLIENT_ID: str | None = None
    NINJAONE_CLIENT_SECRET: str | None = None
    NINJAONE_API_URL: str = "https://app.ninjarmm.com"

    # ── Observability ──
    SENTRY_DSN_BACKEND: str | None = None
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings instance — load once per process."""
    return Settings()  # type: ignore[call-arg]
