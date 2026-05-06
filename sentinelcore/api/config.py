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

    # Email notifications (Resend — resend.com, free tier 3k/mo)
    resend_api_key: str = ""
    email_from: str = "RedGuard <alerts@redgaurd.com>"
    app_base_url: str = "http://localhost:3000"

    # MISP integration — Enterprise tier
    misp_url: str = ""
    misp_key: str = ""
    misp_verify_ssl: bool = True

    # Shopify billing
    shopify_webhook_secret: str = ""   # Settings → Notifications → Webhooks → signing secret
    shopify_store_url: str = ""        # e.g. https://redgaurd.myshopify.com
    shopify_pro_url: str = ""          # direct product page URL (optional override)
    shopify_enterprise_url: str = ""   # direct product page URL (optional override)
    shopify_bundle_url: str = ""       # direct product page URL (optional override)

    # RedGuard VPN — WireGuard server config
    vpn_server_public_key: str = ""   # wg pubkey < /etc/wireguard/server_private.key
    vpn_server_endpoint: str = ""     # e.g. vpn1.redgaurd.com:51820
    vpn_dns: str = "1.1.1.1, 1.0.0.1"

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
