"""
SecOps Astrea Platform - SOC Dashboard Database Connector.
Provides optimized, cached database access to PostgreSQL (or SQLite test DB)
using SQLAlchemy and contracts from database/init.sql and services/common.
"""

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("dashboard_bid.db_connector")

# Add project root and services to sys.path to enable imports from services.common
_current_dir = Path(__file__).resolve().parent
_dashboard_dir = _current_dir.parent
_services_dir = _dashboard_dir.parent
_repo_root = _services_dir.parent

for _p in [str(_repo_root), str(_services_dir), str(_dashboard_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Try importing get_settings from services.common.config
try:
    from services.common.config import get_settings
    _HAS_SETTINGS = True
except Exception:
    get_settings = None
    _HAS_SETTINGS = False


# Global engine reference (allows override during testing)
_CUSTOM_ENGINE: Optional[Engine] = None


def set_custom_engine(engine: Optional[Engine]) -> None:
    """Configura un motor SQLAlchemy personalizado (útil para pruebas unitarias)."""
    global _CUSTOM_ENGINE
    _CUSTOM_ENGINE = engine


def get_database_url() -> str:
    """
    Resuelve la URL de conexión a PostgreSQL priorizando:
    1. Variable de entorno DATABASE_URL.
    2. services.common.config.get_settings() si está disponible.
    3. Variables de entorno individuales (DB_* o POSTGRES_*).
    """
    direct_url = os.getenv("DATABASE_URL")
    if direct_url:
        return direct_url

    if _HAS_SETTINGS and get_settings is not None:
        try:
            settings = get_settings()
            return settings.database_url
        except Exception as e:
            logger.debug(f"No se pudo cargar settings de services.common: {e}")

    # Fallback a variables de entorno estándar
    host = os.getenv("DB_HOST") or os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("DB_PORT") or os.getenv("POSTGRES_PORT", "5432")
    user = os.getenv("DB_USER") or os.getenv("POSTGRES_USER", "secops_user")
    password = os.getenv("DB_PASSWORD") or os.getenv("POSTGRES_PASSWORD", "secops_secure_password")
    db_name = os.getenv("DB_NAME") or os.getenv("POSTGRES_DB", "secops_astrea_db")

    return f"postgresql://{user}:{password}@{host}:{port}/{db_name}"


def get_engine() -> Engine:
    """Retorna una instancia compartida del motor SQLAlchemy con pool_pre_ping."""
    global _CUSTOM_ENGINE
    if _CUSTOM_ENGINE is not None:
        return _CUSTOM_ENGINE

    db_url = get_database_url()
    # SQLite para tests en memoria
    if db_url.startswith("sqlite"):
        return create_engine(db_url, connect_args={"check_same_thread": False})

    return create_engine(
        db_url,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=5,
        max_overflow=10,
        connect_args={"connect_timeout": 5},
    )


def get_connection_status() -> Dict[str, Any]:
    """
    Verifica la conectividad activa con el motor de base de datos.
    Retorna un diccionario con el estado, host, puerto, base de datos y error si existe.
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        # Extraer información de conexión
        url = engine.url
        return {
            "connected": True,
            "host": url.host or "localhost",
            "port": url.port or 5432,
            "database": url.database or "secops_astrea_db",
            "error": None,
        }
    except Exception as exc:
        logger.warning(f"Error comprobando conexión a BD: {exc}")
        db_url = get_database_url()
        return {
            "connected": False,
            "host": os.getenv("DB_HOST") or os.getenv("POSTGRES_HOST", "localhost"),
            "port": os.getenv("DB_PORT") or os.getenv("POSTGRES_PORT", "5432"),
            "database": os.getenv("DB_NAME") or os.getenv("POSTGRES_DB", "secops_astrea_db"),
            "error": str(exc),
        }


# ============================================================================
# Funciones de Consulta Cacheadas con @st.cache_data(ttl=10)
# ============================================================================

@st.cache_data(ttl=10)
def get_kpis() -> Dict[str, Any]:
    """
    Calcula los KPIs ejecutivos del SOC Command Center:
    - Total de incidentes registrados.
    - Críticos activos (P1: score >= 75 o CVE crítico, no resueltos).
    - Hosts aislados (EDR Wazuh: status = 'isolated').
    - Tiempo promedio de contención (MTTC en formato legible).
    - Tasa de contención automática (%).
    """
    default_kpis = {
        "total_incidents": 0,
        "critical_active": 0,
        "isolated_agents": 0,
        "avg_containment_time": "N/A",
        "avg_containment_seconds": 0.0,
        "containment_rate_pct": 0.0,
    }

    try:
        engine = get_engine()
        with engine.connect() as conn:
            # 1. Total incidentes y métricas de contención
            inc_query = text("""
                SELECT 
                    COUNT(*) AS total_incidents,
                    SUM(CASE 
                        WHEN (i.calculated_risk_score >= 75 OR v.severity = 'CRITICAL')
                             AND i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE') 
                        THEN 1 ELSE 0 
                    END) AS critical_active,
                    SUM(CASE 
                        WHEN i.status = 'CONTAINED_AUTOMATICALLY' 
                             OR i.active_response_status = 'SUCCESS' 
                        THEN 1 ELSE 0 
                    END) AS contained_auto,
                    AVG(CASE 
                        WHEN i.resolved_at IS NOT NULL AND i.detected_at IS NOT NULL
                             AND i.resolved_at >= i.detected_at
                        THEN (julianday(i.resolved_at) - julianday(i.detected_at)) * 86400
                        ELSE NULL 
                    END) AS avg_duration_sec
                FROM security_incidents i
                LEFT JOIN nvd_vulnerabilities v ON i.associated_cve = v.cve_id
            """)

            # En caso de PostgreSQL nativo usamos EXTRACT(EPOCH FROM ...)
            if not str(engine.url).startswith("sqlite"):
                inc_query = text("""
                    SELECT 
                        COUNT(*) AS total_incidents,
                        SUM(CASE 
                            WHEN (i.calculated_risk_score >= 75 OR v.severity = 'CRITICAL')
                                 AND i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE') 
                            THEN 1 ELSE 0 
                        END) AS critical_active,
                        SUM(CASE 
                            WHEN i.status = 'CONTAINED_AUTOMATICALLY' 
                                 OR i.active_response_status = 'SUCCESS' 
                            THEN 1 ELSE 0 
                        END) AS contained_auto,
                        AVG(CASE 
                            WHEN i.resolved_at IS NOT NULL AND i.detected_at IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (i.resolved_at - i.detected_at))
                            ELSE NULL 
                        END) AS avg_duration_sec
                    FROM security_incidents i
                    LEFT JOIN nvd_vulnerabilities v ON i.associated_cve = v.cve_id
                """)

            row = conn.execute(inc_query).mappings().first()
            if row:
                total = int(row["total_incidents"] or 0)
                crit = int(row["critical_active"] or 0)
                auto = int(row["contained_auto"] or 0)
                dur = float(row["avg_duration_sec"]) if row["avg_duration_sec"] is not None else 0.0

                rate = round((auto / total) * 100.0, 1) if total > 0 else 0.0

                # Formateo de tiempo de contención
                if dur <= 0:
                    time_str = "N/A"
                elif dur < 60:
                    time_str = f"{dur:.0f}s"
                elif dur < 3600:
                    time_str = f"{dur / 60.0:.1f}m"
                else:
                    time_str = f"{dur / 3600.0:.1f}h"

                default_kpis["total_incidents"] = total
                default_kpis["critical_active"] = crit
                default_kpis["containment_rate_pct"] = rate
                default_kpis["avg_containment_seconds"] = dur
                default_kpis["avg_containment_time"] = time_str

            # 2. Agentes aislados
            agent_query = text("""
                SELECT COUNT(*) AS isolated_count 
                FROM agents_inventory 
                WHERE LOWER(status) = 'isolated'
            """)
            agent_row = conn.execute(agent_query).mappings().first()
            if agent_row:
                default_kpis["isolated_agents"] = int(agent_row["isolated_count"] or 0)

    except Exception as exc:
        logger.warning(f"Error consultando get_kpis: {exc}")

    return default_kpis


@st.cache_data(ttl=10)
def get_recent_incidents(
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
) -> pd.DataFrame:
    """
    Obtiene la lista de incidentes recientes con soporte de filtrado por:
    - status (NEW, CONTAINED_AUTOMATICALLY, RESOLVED, etc.)
    - severity (CRITICAL, HIGH, MEDIUM, LOW)
    - source (SPLUNK, WAZUH_MANAGER, HYBRID)
    Retorna un DataFrame de Pandas estructurado y seguro ante datos vacíos.
    """
    columns = [
        "incident_id",
        "detected_at",
        "alert_name",
        "source_detection",
        "rule_id",
        "src_ip",
        "dst_ip",
        "agent_id",
        "hostname",
        "affected_software",
        "associated_cve",
        "cvss_score",
        "calculated_risk_score",
        "severity",
        "status",
        "active_response_executed",
        "active_response_status",
        "response_payload",
    ]

    try:
        engine = get_engine()
        where_clauses = []
        params: Dict[str, Any] = {"limit": limit}

        if status and status.upper() not in ("TODOS", "ALL"):
            where_clauses.append("i.status = :status")
            params["status"] = status

        if source and source.upper() not in ("TODAS", "ALL"):
            where_clauses.append("i.source_detection = :source")
            params["source"] = source

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        query = text(f"""
            SELECT 
                CAST(i.incident_id AS TEXT) AS incident_id,
                i.detected_at,
                i.alert_name,
                i.source_detection,
                i.rule_id,
                CAST(i.src_ip AS TEXT) AS src_ip,
                CAST(i.dst_ip AS TEXT) AS dst_ip,
                i.agent_id,
                COALESCE(a.hostname, 'N/A') AS hostname,
                i.affected_software,
                i.associated_cve,
                CAST(v.cvss_score AS FLOAT) AS cvss_score,
                CAST(i.calculated_risk_score AS FLOAT) AS calculated_risk_score,
                CASE 
                    WHEN i.calculated_risk_score >= 80 THEN 'CRITICAL'
                    WHEN i.calculated_risk_score >= 60 THEN 'HIGH'
                    WHEN i.calculated_risk_score >= 40 THEN 'MEDIUM'
                    WHEN i.calculated_risk_score IS NOT NULL THEN 'LOW'
                    WHEN v.severity IS NOT NULL THEN v.severity
                    ELSE 'MEDIUM'
                END AS severity,
                i.status,
                i.active_response_executed,
                i.active_response_status,
                i.response_payload
            FROM security_incidents i
            LEFT JOIN agents_inventory a ON i.agent_id = a.agent_id
            LEFT JOIN nvd_vulnerabilities v ON i.associated_cve = v.cve_id
            {where_sql}
            ORDER BY i.detected_at DESC
            LIMIT :limit
        """)

        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn, params=params)

        if df.empty:
            return pd.DataFrame(columns=columns)

        # Normalizar incident_id a formato UUID con guiones
        if "incident_id" in df.columns:
            def _norm_uuid(val):
                try:
                    return str(uuid.UUID(str(val).replace("-", "")))
                except Exception:
                    return str(val)
            df["incident_id"] = df["incident_id"].apply(_norm_uuid)

        # Filtrado adicional por severidad si fue solicitado
        if severity and severity.upper() not in ("TODAS", "ALL"):
            df = df[df["severity"] == severity.upper()]

        # Conversión de fechas y tipos
        if "detected_at" in df.columns:
            df["detected_at"] = pd.to_datetime(df["detected_at"])

        return df

    except Exception as exc:
        logger.warning(f"Error consultando get_recent_incidents: {exc}")
        return pd.DataFrame(columns=columns)


@st.cache_data(ttl=10)
def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Retorna el detalle completo de un incidente, incluyendo el payload JSON
    de Active Response, metadata de agente y datos de vulnerabilidad NVD.
    """
    if not incident_id:
        return None

    try:
        raw_id = str(incident_id).strip()
        clean_id = raw_id.replace("-", "").lower()

        engine = get_engine()
        query = text("""
            SELECT 
                CAST(i.incident_id AS TEXT) AS incident_id,
                i.source_detection,
                i.alert_name,
                i.rule_id,
                CAST(i.src_ip AS TEXT) AS src_ip,
                i.src_country,
                i.src_reputation_score,
                CAST(i.dst_ip AS TEXT) AS dst_ip,
                i.dst_port,
                i.agent_id,
                a.hostname,
                a.os_name,
                a.os_version,
                a.status AS agent_status,
                i.affected_software,
                i.associated_cve,
                v.description AS cve_description,
                CAST(v.cvss_score AS FLOAT) AS cvss_score,
                v.cvss_vector,
                v.severity AS cve_severity,
                v.cwe_id,
                v.has_active_exploit,
                CAST(i.calculated_risk_score AS FLOAT) AS calculated_risk_score,
                CASE 
                    WHEN i.calculated_risk_score >= 80 THEN 'CRITICAL'
                    WHEN i.calculated_risk_score >= 60 THEN 'HIGH'
                    WHEN i.calculated_risk_score >= 40 THEN 'MEDIUM'
                    WHEN i.calculated_risk_score IS NOT NULL THEN 'LOW'
                    WHEN v.severity IS NOT NULL THEN v.severity
                    ELSE 'MEDIUM'
                END AS severity,
                i.status,
                i.active_response_executed,
                i.active_response_status,
                i.response_payload,
                i.detected_at,
                i.resolved_at
            FROM security_incidents i
            LEFT JOIN agents_inventory a ON i.agent_id = a.agent_id
            LEFT JOIN nvd_vulnerabilities v ON i.associated_cve = v.cve_id
            WHERE CAST(i.incident_id AS TEXT) = :raw_id
               OR REPLACE(CAST(i.incident_id AS TEXT), '-', '') = :clean_id
            LIMIT 1
        """)

        with engine.connect() as conn:
            row = conn.execute(query, {"raw_id": raw_id, "clean_id": clean_id}).mappings().first()

        if not row:
            return None

        data = dict(row)

        # Normalizar incident_id a UUID estándar
        try:
            data["incident_id"] = str(uuid.UUID(str(data["incident_id"]).replace("-", "")))
        except Exception:
            data["incident_id"] = str(data["incident_id"])

        # Parsear response_payload si es string
        payload = data.get("response_payload")
        if isinstance(payload, str):
            try:
                data["response_payload"] = json.loads(payload)
            except Exception:
                pass

        return data


    except Exception as exc:
        logger.warning(f"Error consultando get_incident_by_id: {exc}")
        return None


@st.cache_data(ttl=10)
def get_agents_status() -> pd.DataFrame:
    """
    Obtiene el inventario completo de agentes monitoreados por Wazuh con su estado:
    (active, isolated, disconnected), datos de sistema y conteo de incidentes vinculados.
    """
    columns = [
        "agent_id",
        "hostname",
        "ip_address",
        "os_name",
        "os_version",
        "status",
        "last_keepalive",
        "total_incidents",
        "active_incidents",
    ]

    try:
        engine = get_engine()
        query = text("""
            SELECT 
                a.agent_id,
                a.hostname,
                CAST(a.ip_address AS TEXT) AS ip_address,
                a.os_name,
                a.os_version,
                a.status,
                a.last_keepalive,
                COUNT(i.incident_id) AS total_incidents,
                SUM(CASE WHEN i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE') THEN 1 ELSE 0 END) AS active_incidents
            FROM agents_inventory a
            LEFT JOIN security_incidents i ON a.agent_id = i.agent_id
            GROUP BY a.agent_id, a.hostname, a.ip_address, a.os_name, a.os_version, a.status, a.last_keepalive
            ORDER BY a.hostname ASC
        """)

        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn)

        if df.empty:
            return pd.DataFrame(columns=columns)

        if "last_keepalive" in df.columns:
            df["last_keepalive"] = pd.to_datetime(df["last_keepalive"])

        return df

    except Exception as exc:
        logger.warning(f"Error consultando get_agents_status: {exc}")
        return pd.DataFrame(columns=columns)


@st.cache_data(ttl=10)
def get_cve_distribution() -> pd.DataFrame:
    """
    Conteo y desglose de CVEs registrados en nvd_vulnerabilities por severidad CVSS,
    con conteo de exploits activos y promedios.
    """
    columns = ["severity", "cve_count", "active_exploits", "avg_cvss"]

    try:
        engine = get_engine()
        query = text("""
            SELECT 
                COALESCE(severity, 'UNKNOWN') AS severity,
                COUNT(*) AS cve_count,
                SUM(CASE WHEN has_active_exploit = TRUE OR has_active_exploit = 1 THEN 1 ELSE 0 END) AS active_exploits,
                AVG(CAST(cvss_score AS FLOAT)) AS avg_cvss
            FROM nvd_vulnerabilities
            GROUP BY severity
            ORDER BY 
                CASE 
                    WHEN severity = 'CRITICAL' THEN 1
                    WHEN severity = 'HIGH' THEN 2
                    WHEN severity = 'MEDIUM' THEN 3
                    WHEN severity = 'LOW' THEN 4
                    ELSE 5 
                END
        """)

        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn)

        if df.empty:
            return pd.DataFrame(columns=columns)

        if "avg_cvss" in df.columns:
            df["avg_cvss"] = df["avg_cvss"].fillna(0.0).round(1)

        return df

    except Exception as exc:
        logger.warning(f"Error consultando get_cve_distribution: {exc}")
        return pd.DataFrame(columns=columns)


@st.cache_data(ttl=10)
def get_nvd_vulnerabilities(
    limit: int = 100,
    severity: Optional[str] = None,
    only_exploits: bool = False,
) -> pd.DataFrame:
    """
    Obtiene la lista detallada de vulnerabilidades NVD para el Vuln Explorer.
    """
    columns = [
        "cve_id",
        "severity",
        "cvss_score",
        "cvss_vector",
        "cwe_id",
        "has_active_exploit",
        "description",
        "published_date",
        "last_modified_date",
        "correlated_incidents",
    ]

    try:
        engine = get_engine()
        where_clauses = []
        params: Dict[str, Any] = {"limit": limit}

        if severity and severity.upper() not in ("TODAS", "ALL"):
            where_clauses.append("v.severity = :severity")
            params["severity"] = severity.upper()

        if only_exploits:
            where_clauses.append("(v.has_active_exploit = TRUE OR v.has_active_exploit = 1)")

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        query = text(f"""
            SELECT 
                v.cve_id,
                v.severity,
                CAST(v.cvss_score AS FLOAT) AS cvss_score,
                v.cvss_vector,
                v.cwe_id,
                v.has_active_exploit,
                v.description,
                v.published_date,
                v.last_modified_date,
                COUNT(i.incident_id) AS correlated_incidents
            FROM nvd_vulnerabilities v
            LEFT JOIN security_incidents i ON v.cve_id = i.associated_cve
            {where_sql}
            GROUP BY v.cve_id, v.severity, v.cvss_score, v.cvss_vector, v.cwe_id,
                     v.has_active_exploit, v.description, v.published_date, v.last_modified_date
            ORDER BY v.cvss_score DESC NULLS LAST, v.published_date DESC NULLS LAST
            LIMIT :limit
        """)

        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn, params=params)

        if df.empty:
            return pd.DataFrame(columns=columns)

        if "published_date" in df.columns:
            df["published_date"] = pd.to_datetime(df["published_date"])

        return df

    except Exception as exc:
        logger.warning(f"Error consultando get_nvd_vulnerabilities: {exc}")
        return pd.DataFrame(columns=columns)


@st.cache_data(ttl=10)
def get_hourly_incident_trends(hours: int = 24) -> pd.DataFrame:
    """
    Calcula la serie temporal de alertas detectadas en las últimas N horas.
    """
    columns = ["time_bucket", "incident_count"]

    try:
        engine = get_engine()
        # Query adaptable a PostgreSQL y SQLite
        if str(engine.url).startswith("sqlite"):
            query = text("""
                SELECT 
                    strftime('%Y-%m-%d %H:00', detected_at) AS time_bucket,
                    COUNT(*) AS incident_count
                FROM security_incidents
                WHERE detected_at IS NOT NULL
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
                LIMIT :hours
            """)
        else:
            query = text("""
                SELECT 
                    TO_CHAR(DATE_TRUNC('hour', detected_at), 'YYYY-MM-DD HH24:00') AS time_bucket,
                    COUNT(*) AS incident_count
                FROM security_incidents
                WHERE detected_at >= (CURRENT_TIMESTAMP - (INTERVAL '1 hour' * :hours))
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """)

        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn, params={"hours": hours})

        if df.empty:
            return pd.DataFrame(columns=columns)

        return df

    except Exception as exc:
        logger.warning(f"Error consultando get_hourly_incident_trends: {exc}")
        return pd.DataFrame(columns=columns)


def clear_cache() -> None:
    """Limpia la caché en memoria de todas las consultas de db_connector."""
    try:
        get_kpis.clear()
        get_recent_incidents.clear()
        get_incident_by_id.clear()
        get_agents_status.clear()
        get_cve_distribution.clear()
        get_nvd_vulnerabilities.clear()
        get_hourly_incident_trends.clear()
    except Exception as exc:
        logger.debug(f"Error limpiando caché de Streamlit: {exc}")

