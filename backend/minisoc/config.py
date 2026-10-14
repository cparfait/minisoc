"""Configuration lue dans les variables d'environnement (préfixe MINISOC_)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MINISOC_", env_file=".env", extra="ignore")

    # Stockage
    database_url: str = "postgresql+asyncpg://minisoc:minisoc@postgres:5432/minisoc"
    redis_url: str = "redis://redis:6379/0"
    clickhouse_host: str = "clickhouse"
    clickhouse_port: int = 8123
    clickhouse_user: str = "minisoc"
    clickhouse_password: str = ""
    clickhouse_database: str = "minisoc"

    # Application
    rules_dir: str = "/app/rules"
    public_url: str = "https://localhost"
    master_key: str = ""  # 32 octets en base64url : chiffre les secrets stockés en base
    session_hours: int = 8
    session_idle_minutes: int = 30
    cookie_secure: bool = True
    timezone: str = "Europe/Paris"

    # Enrichissement : bases GeoIP au format MMDB (MaxMind GeoLite2-City / -Country / -ASN, ou DB-IP Lite)
    geoip_dir: str = "/app/data/geoip"

    # Réception
    ingest_token: str = ""  # jeton partagé avec Vector
    bitdefender_token: str = ""  # valeur attendue dans l'en-tête Authorization du push GravityZone
    bitdefender_allowed_ips: list[str] = []  # vide = pas de filtrage (à restreindre en production)
    bitdefender_console_url: str = "https://cloudgz.gravityzone.bitdefender.com"

    # Connecteur HarfangLab
    harfanglab_url: str = ""
    harfanglab_token: str = ""
    harfanglab_verify_tls: bool = True
    harfanglab_poll_seconds: int = 60

    # Notifications
    notify_routes: dict[str, list[str]] = {
        "critical": ["ntfy", "teams", "email"],
        "high": ["teams", "email"],
        "medium": ["email"],
        "low": [],
        "info": [],
    }
    business_hours_only: list[str] = ["medium"]
    business_hours: tuple[int, int] = (8, 18)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: list[str] = []
    teams_webhook_url: str = ""
    ntfy_url: str = ""  # ex. https://ntfy.sh ou une instance auto-hébergée
    ntfy_topic: str = ""
    ntfy_token: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
