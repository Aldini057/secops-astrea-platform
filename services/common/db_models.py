"""
SecOps Astrea Platform - Database Models and Data Contracts.
Contains SQLAlchemy ORM models matching PostgreSQL tables in 'database/init.sql':
- agents_inventory
- nvd_vulnerabilities
- security_incidents
Also provides Pydantic validation schemas and enumeration constants.
"""

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.types import JSON

Base = declarative_base()


# ============================================================================
# Enum Types
# ============================================================================

class AgentStatus(str, enum.Enum):
    ACTIVE = "active"
    ISOLATED = "isolated"
    DISCONNECTED = "disconnected"
    PENDING = "pending"
    NEVER_CONNECTED = "never_connected"


class IncidentSource(str, enum.Enum):
    SPLUNK = "SPLUNK"
    WAZUH_MANAGER = "WAZUH_MANAGER"
    HYBRID = "HYBRID"


class IncidentStatus(str, enum.Enum):
    NEW = "NEW"
    ENRICHED = "ENRICHED"
    CONTAINED_AUTOMATICALLY = "CONTAINED_AUTOMATICALLY"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ActiveResponseAction(str, enum.Enum):
    ISOLATE_AGENT = "ISOLATE_AGENT"
    BLOCK_SRC_IP = "BLOCK_SRC_IP"
    KILL_PID = "KILL_PID"
    NONE = "NONE"


class ActiveResponseStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"
    SKIPPED = "SKIPPED"


# ============================================================================
# SQLAlchemy ORM Models
# ============================================================================

class AgentInventory(Base):
    """
    1. Tabla de Agentes / Hosts Registrados (Monitoreados por Wazuh).
    Corresponde a 'agents_inventory' en database/init.sql.
    """
    __tablename__ = "agents_inventory"

    agent_id = Column(String(50), primary_key=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(
        INET().with_variant(String(45), "sqlite"),
        nullable=False,
    )
    os_name = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    status = Column(String(50), default=AgentStatus.ACTIVE.value, nullable=True)
    last_keepalive = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True,
    )

    incidents = relationship("SecurityIncident", back_populates="agent")

    def __repr__(self) -> str:
        return f"<AgentInventory(agent_id='{self.agent_id}', hostname='{self.hostname}', status='{self.status}')>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip_address": str(self.ip_address) if self.ip_address is not None else None,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "status": self.status,
            "last_keepalive": self.last_keepalive.isoformat() if self.last_keepalive else None,
        }


class NVDVulnerability(Base):
    """
    2. Tabla de Inteligencia de Vulnerabilidades (NVD Cache).
    Corresponde a 'nvd_vulnerabilities' en database/init.sql.
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
        nullable=False,
    )

    incidents = relationship("SecurityIncident", back_populates="cve")

    def __repr__(self) -> str:
        return f"<NVDVulnerability(cve_id='{self.cve_id}', severity='{self.severity}', score={self.cvss_score})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": float(self.cvss_score) if self.cvss_score is not None else None,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "has_active_exploit": bool(self.has_active_exploit),
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SecurityIncident(Base):
    """
    3. Tabla de Incidentes y Alertas Integradas (Splunk + Wazuh + SOAR).
    Corresponde a 'security_incidents' en database/init.sql.
    """
    __tablename__ = "security_incidents"

    incident_id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source_detection = Column(String(50), nullable=False)  # SPLUNK, WAZUH_MANAGER, HYBRID
    alert_name = Column(String(255), nullable=False)
    rule_id = Column(String(100), nullable=True)

    # Origen y Destino
    src_ip = Column(
        INET().with_variant(String(45), "sqlite"),
        nullable=True,
    )
    src_country = Column(String(50), nullable=True)
    src_reputation_score = Column(Integer, nullable=True)  # AbuseIPDB / OTX Score (0-100)
    dst_ip = Column(
        INET().with_variant(String(45), "sqlite"),
        nullable=True,
    )
    dst_port = Column(Integer, nullable=True)
    agent_id = Column(
        String(50),
        ForeignKey("agents_inventory.agent_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Contexto de Vulnerabilidad
    affected_software = Column(String(255), nullable=True)
    associated_cve = Column(
        String(50),
        ForeignKey("nvd_vulnerabilities.cve_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Evaluación de Riesgo y Estado
    calculated_risk_score = Column(Numeric(4, 1), nullable=True)
    status = Column(String(50), default=IncidentStatus.NEW.value, nullable=True)

    # Acciones de Respuesta Activa (EDR Wazuh)
    active_response_executed = Column(String(100), nullable=True)
    active_response_status = Column(String(50), nullable=True)
    response_payload = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=True,
    )

    detected_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relaciones ORM
    agent = relationship("AgentInventory", back_populates="incidents")
    cve = relationship("NVDVulnerability", back_populates="incidents")

    __table_args__ = (
        Index("idx_incidents_detected_at", detected_at.desc()),
        Index("idx_incidents_status", status),
        Index("idx_incidents_risk_score", calculated_risk_score.desc()),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityIncident(id='{self.incident_id}', alert='{self.alert_name}', "
            f"status='{self.status}', risk={self.calculated_risk_score})>"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": str(self.incident_id),
            "source_detection": self.source_detection,
            "alert_name": self.alert_name,
            "rule_id": self.rule_id,
            "src_ip": str(self.src_ip) if self.src_ip is not None else None,
            "src_country": self.src_country,
            "src_reputation_score": self.src_reputation_score,
            "dst_ip": str(self.dst_ip) if self.dst_ip is not None else None,
            "dst_port": self.dst_port,
            "agent_id": self.agent_id,
            "affected_software": self.affected_software,
            "associated_cve": self.associated_cve,
            "calculated_risk_score": float(self.calculated_risk_score) if self.calculated_risk_score is not None else None,
            "status": self.status,
            "active_response_executed": self.active_response_executed,
            "active_response_status": self.active_response_status,
            "response_payload": self.response_payload,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


# ============================================================================
# Pydantic Schemas / Contratos de Datos
# ============================================================================

class AgentInventorySchema(BaseModel):
    """Esquema de validación para registro o actualización de agentes."""
    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(..., description="ID del agente en Wazuh")
    hostname: str = Field(..., description="Hostname del agente")
    ip_address: str = Field(..., description="Dirección IP del agente")
    os_name: Optional[str] = Field(default=None, description="Nombre del sistema operativo")
    os_version: Optional[str] = Field(default=None, description="Versión del SO")
    status: str = Field(default="active", description="Estado de conectividad")
    last_keepalive: Optional[datetime] = Field(default=None, description="Último keepalive registrado")


class ActiveResponsePayload(BaseModel):
    """Esquema para payload de ejecución de respuesta activa."""
    command: str = Field(..., description="Nombre del comando a ejecutar")
    arguments: Optional[list] = Field(default=None, description="Argumentos posicionales")
    custom: bool = Field(default=False, description="Indica comando personalizado")
    alert: Optional[Dict[str, Any]] = Field(default=None, description="Contexto de la alerta")


class SecurityIncidentSchema(BaseModel):
    """Esquema de validación y serialización de incidentes."""
    model_config = ConfigDict(from_attributes=True)

    incident_id: Optional[uuid.UUID] = None
    source_detection: str = Field(..., description="Origen de detección (SPLUNK, WAZUH_MANAGER, HYBRID)")
    alert_name: str = Field(..., description="Título de la alerta")
    rule_id: Optional[str] = None
    src_ip: Optional[str] = None
    src_country: Optional[str] = None
    src_reputation_score: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    agent_id: Optional[str] = None
    affected_software: Optional[str] = None
    associated_cve: Optional[str] = None
    calculated_risk_score: Optional[Decimal] = None
    status: str = Field(default="NEW")
    active_response_executed: Optional[str] = None
    active_response_status: Optional[str] = None
    response_payload: Optional[Dict[str, Any]] = None
    detected_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
