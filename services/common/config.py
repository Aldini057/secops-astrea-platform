"""
SecOps Astrea Platform - Central Configuration Module.
Loads environment variables and configuration for PostgreSQL, Wazuh API, n8n,
and Threat Intelligence (CTI) using pydantic-settings.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _normalize_wazuh_url(host: str, port: int = 55000) -> str:
    """
    Normaliza el host y puerto de Wazuh en una URL base limpia.
    Maneja esquemas http/https, puertos redundantes y barras finales.
    """
    host_clean = host.strip().rstrip("/")
    if not host_clean.startswith(("http://", "https://")):
        host_clean = f"https://{host_clean}"

    parsed = urlparse(host_clean)
    netloc = parsed.netloc
    if ":" not in netloc and port:
        netloc = f"{netloc}:{port}"

    return urlunparse(parsed._replace(netloc=netloc)).rstrip("/")


class Settings(BaseSettings):
    """
    Configuración global de la plataforma SecOps Astrea.
    Carga variables de entorno desde el sistema o archivo .env.
    Los valores por defecto concuerdan con '.env.example'.
    """

    # Búsqueda de archivo .env en directorio actual y raíz del proyecto
    model_config = SettingsConfigDict(
        env_file=(
            ".env",
            str(Path(__file__).resolve().parent.parent.parent / ".env"),
            str(Path(__file__).resolve().parent.parent.parent / ".env.example"),
        ),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -------------------------------------------------------------------------
    # Base de Datos PostgreSQL
    # -------------------------------------------------------------------------
    postgres_user: str = Field(
        default="secops_user",
        validation_alias="POSTGRES_USER",
        description="Usuario de conexión a PostgreSQL",
    )
    postgres_password: str = Field(
        default="secops_secure_password",
        validation_alias="POSTGRES_PASSWORD",
        description="Contraseña de PostgreSQL",
    )
    postgres_db: str = Field(
        default="secops_astrea_db",
        validation_alias="POSTGRES_DB",
        description="Nombre de la base de datos",
    )
    postgres_host: str = Field(
        default="postgres",
        validation_alias="POSTGRES_HOST",
        description="Host del servidor PostgreSQL",
    )
    postgres_port: int = Field(
        default=5432,
        validation_alias="POSTGRES_PORT",
        description="Puerto de PostgreSQL",
    )

    # -------------------------------------------------------------------------
    # Orquestador n8n
    # -------------------------------------------------------------------------
    n8n_host: str = Field(
        default="localhost",
        validation_alias="N8N_HOST",
        description="Host del orquestador n8n",
    )
    n8n_port: int = Field(
        default=5678,
        validation_alias="N8N_PORT",
        description="Puerto del servicio n8n",
    )
    n8n_webhook_url: str = Field(
        default="http://localhost:5678/",
        validation_alias="N8N_WEBHOOK_URL",
        description="URL base para webhooks de n8n",
    )

    # -------------------------------------------------------------------------
    # Wazuh Manager API (Active Response & EDR)
    # -------------------------------------------------------------------------
    wazuh_api_host: str = Field(
        default="https://127.0.0.1",
        validation_alias="WAZUH_API_HOST",
        description="Host o IP del Wazuh Manager API",
    )
    wazuh_api_port: int = Field(
        default=55000,
        validation_alias="WAZUH_API_PORT",
        description="Puerto del Wazuh Manager API (por defecto 55000)",
    )
    wazuh_api_user: str = Field(
        default="wazuh-wui",
        validation_alias="WAZUH_API_USER",
        description="Usuario de la API de Wazuh",
    )
    wazuh_api_password: str = Field(
        default="wazuh-wui-password",
        validation_alias="WAZUH_API_PASSWORD",
        description="Contraseña de la API de Wazuh",
    )
    wazuh_api_verify_ssl: bool = Field(
        default=False,
        validation_alias="WAZUH_API_VERIFY_SSL",
        description="Verificar certificados SSL de la API de Wazuh (False para labs/certificados autofirmados)",
    )
    wazuh_api_timeout: float = Field(
        default=15.0,
        validation_alias="WAZUH_API_TIMEOUT",
        description="Tiempo de espera en segundos para solicitudes a la API de Wazuh",
    )

    # -------------------------------------------------------------------------
    # Threat Intelligence APIs (CTI)
    # -------------------------------------------------------------------------
    nvd_api_key: Optional[str] = Field(
        default=None,
        validation_alias="NVD_API_KEY",
        description="Clave de API para NIST NVD API 2.0",
    )
    abuseipdb_api_key: Optional[str] = Field(
        default=None,
        validation_alias="ABUSEIPDB_API_KEY",
        description="Clave de API para AbuseIPDB",
    )
    virustotal_api_key: Optional[str] = Field(
        default=None,
        validation_alias="VIRUSTOTAL_API_KEY",
        description="Clave de API para VirusTotal",
    )
    otx_api_key: Optional[str] = Field(
        default=None,
        validation_alias="OTX_API_KEY",
        description="Clave de API para AlienVault OTX",
    )

    # -------------------------------------------------------------------------
    # Canales de Notificación
    # -------------------------------------------------------------------------
    telegram_bot_token: Optional[str] = Field(
        default=None,
        validation_alias="TELEGRAM_BOT_TOKEN",
        description="Token del bot de Telegram",
    )
    telegram_chat_id: Optional[str] = Field(
        default=None,
        validation_alias="TELEGRAM_CHAT_ID",
        description="ID del chat de destino en Telegram",
    )

    # -------------------------------------------------------------------------
    # Propiedades Computadas
    # -------------------------------------------------------------------------
    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        """URL síncrona para conexión a PostgreSQL (psycopg2)."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def async_database_url(self) -> str:
        """URL asíncrona para conexión a PostgreSQL (asyncpg)."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def wazuh_base_url(self) -> str:
        """URL base normalizada para la API de Wazuh (ej. https://127.0.0.1:55000)."""
        return _normalize_wazuh_url(self.wazuh_api_host, self.wazuh_api_port)


@lru_cache()
def get_settings() -> Settings:
    """Retorna una instancia singleton cacheada de Settings."""
    return Settings()
