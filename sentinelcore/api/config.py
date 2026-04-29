from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_env: str = "development"
    app_secret_key: str = "change-me"
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinelcore"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret_key: str = "change-me-jwt"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    virustotal_api_key: str = ""
    otx_api_key: str = ""

    # Stripe billing
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_enterprise: str = ""

    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    free_tier_scans_per_day: int = 5
    pro_tier_scans_per_day: int = 10000

    max_file_size_mb: int = 100
    upload_dir: str = "/tmp/sentinel_uploads"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
