from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AI-SOC API"
    environment: str = "local"
    database_url: str = "postgresql+asyncpg://aisoc:aisoc@postgres:5432/aisoc"
    jwt_secret: str = Field(default="change-me-in-production", min_length=16)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60 * 8
    otp_ttl_minutes: int = 10
    ingest_token: str = Field(default="local-ingest-token", min_length=8)
    internal_token: str = Field(default="local-internal-token", min_length=8)
    kafka_bootstrap_servers: str | None = None
    kafka_security_events_topic: str = "security_events"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]
    enable_sql_echo: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
