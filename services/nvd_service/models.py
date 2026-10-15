"""
Data models and schemas for NVD Vulnerability Service.
Contains SQLAlchemy ORM models matching PostgreSQL 'nvd_vulnerabilities' table
and Pydantic schemas for request validation and response serialization.
"""

from datetime import datetime
from decimal import Decimal
from typing import List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from sqlalchemy import (
    Column,
    String,
    Text,
    Numeric,
    Boolean,
    DateTime,
    func
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


# ============================================================================
# SQLAlchemy ORM Models
# ============================================================================

class NVDVulnerability(Base):
    """
    SQLAlchemy ORM model for cached CVE vulnerabilities.
    Mapped to PostgreSQL table 'nvd_vulnerabilities'.
    """
    __tablename__ = "nvd_vulnerabilities"

    cve_id = Column(String(50), primary_key=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    cvss_score = Column(Numeric(3, 1), nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    cwe_id = Column(String(50), nullable=True)
    has_active_exploit = Column(Boolean, default=False, nullable=True)
    published_date = Column(DateTime(timezone=True), nullable=True)
    last_modified_date = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<NVDVulnerability(cve_id='{self.cve_id}', severity='{self.severity}', cvss_score={self.cvss_score})>"

    def to_dict(self) -> dict:
        """Convert ORM object to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": float(self.cvss_score) if self.cvss_score is not None else None,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "has_active_exploit": bool(self.has_active_exploit),
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "source": "CACHE"
        }


# ============================================================================
# Pydantic Schemas (Request / Response)
# ============================================================================

class VulnerabilityCheckRequest(BaseModel):
    """
    Payload for vulnerability query endpoint.
    Allows searching by software name + version or direct CVE ID.
    """
    software_name: Optional[str] = Field(
        default=None,
        description="Nombre del software o producto a consultar (ej. Apache, OpenSSL, Nginx)",
        examples=["Apache", "Nginx", "OpenSSL"]
    )
    version: Optional[str] = Field(
        default=None,
        description="Versión específica del software (ej. 2.4.49, 1.18.0)",
        examples=["2.4.49", "1.18.0"]
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Identificador CVE específico opcional (ej. CVE-2021-41773)",
        examples=["CVE-2021-41773"]
    )
    force_refresh: bool = Field(
        default=False,
        description="Forzar la consulta directa a NVD API omitiendo la caché local"
    )

    @model_validator(mode="after")
    def validate_request_inputs(self) -> "VulnerabilityCheckRequest":
        """Ensure either software_name or cve_id is provided."""
        has_software = bool(self.software_name and self.software_name.strip())
        has_cve = bool(self.cve_id and self.cve_id.strip())

        if not has_software and not has_cve:
            raise ValueError("Debe proporcionar al menos 'software_name' o 'cve_id'.")

        if self.software_name:
            self.software_name = self.software_name.strip()
        if self.version:
            self.version = self.version.strip()
        if self.cve_id:
            self.cve_id = self.cve_id.strip().upper()

        return self


class VulnerabilityItem(BaseModel):
    """
    Individual vulnerability representation.
    """
    model_config = ConfigDict(from_attributes=True)

    cve_id: str = Field(..., description="Identificador único CVE", examples=["CVE-2021-41773"])
    description: Optional[str] = Field(None, description="Descripción técnica de la vulnerabilidad")
    cvss_score: Optional[float] = Field(None, description="Puntaje CVSS v3.1 / base score", examples=[7.5])
    cvss_vector: Optional[str] = Field(None, description="Vector de ataque CVSS v3.1", examples=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"])
    severity: Optional[str] = Field(None, description="Severidad cualitativa (CRITICAL, HIGH, MEDIUM, LOW)", examples=["HIGH"])
    cwe_id: Optional[str] = Field(None, description="Identificador de debilidad CWE", examples=["CWE-22"])
    has_active_exploit: bool = Field(default=False, description="Indica si existe exploit activo o está catalogado en CISA KEV")
    published_date: Optional[datetime] = Field(None, description="Fecha de publicación original en NVD")
    last_modified_date: Optional[datetime] = Field(None, description="Fecha de última modificación en NVD")
    source: Optional[str] = Field(default="NVD_API", description="Origen de los datos: CACHE o NVD_API")

    @field_validator("cvss_score", mode="before")
    @classmethod
    def parse_cvss_score(cls, v: Union[float, Decimal, int, str, None]) -> Optional[float]:
        if v is None:
            return None
        try:
            return float(v)
        except (ValueError, TypeError):
            return None


class VulnerabilityCheckResponse(BaseModel):
    """
    Response schema for vulnerability checks.
    """
    query: str = Field(..., description="Término o identificador consultado")
    software_name: Optional[str] = Field(None, description="Nombre del software analizado")
    version: Optional[str] = Field(None, description="Versión analizada")
    cve_id: Optional[str] = Field(None, description="CVE ID analizado")
    total_vulnerabilities: int = Field(..., description="Cantidad total de vulnerabilidades identificadas")
    cached: bool = Field(..., description="Indica si la respuesta fue obtenida de la caché PostgreSQL")
    vulnerabilities: List[VulnerabilityItem] = Field(default_factory=list, description="Lista de vulnerabilidades encontradas")
    message: Optional[str] = Field(None, description="Información adicional sobre el resultado")


class HealthResponse(BaseModel):
    """
    Response schema for service health status.
    """
    status: str = Field(..., description="Estado general del servicio (healthy, degraded)")
    database: str = Field(..., description="Estado de conectividad con PostgreSQL")
    nvd_api_configured: bool = Field(..., description="Indica si NVD_API_KEY está configurada")
    timestamp: datetime = Field(..., description="Marca de tiempo actual del servidor")
    version: str = Field(default="1.0.0", description="Versión del microservicio")
