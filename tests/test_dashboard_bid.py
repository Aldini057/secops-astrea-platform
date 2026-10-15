"""
Unit and integration tests for SecOps Astrea - Dashboard BID (Streamlit Frontend).
Tests database connector, KPI calculations, incident retrieval, NVD intelligence,
and graceful handling of empty or disconnected database scenarios.
"""

import json
import uuid
from datetime import datetime, timezone
import pytest
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.common.db_models import (
    ActiveResponseAction,
    ActiveResponseStatus,
    AgentInventory,
    AgentStatus,
    Base,
    IncidentSource,
    IncidentStatus,
    NVDVulnerability,
    SecurityIncident,
)
from services.dashboard_bid.app.db_connector import (
    clear_cache,
    get_agents_status,
    get_connection_status,
    get_cve_distribution,
    get_hourly_incident_trends,
    get_incident_by_id,
    get_kpis,
    get_nvd_vulnerabilities,
    get_recent_incidents,
    set_custom_engine,
)


@pytest.fixture(autouse=True)
def reset_engine():
    """Limpia el custom engine y la caché de Streamlit antes y después de cada prueba."""
    clear_cache()
    yield
    set_custom_engine(None)
    clear_cache()



# ============================================================================
# 1. Tests con Base de Datos Desconectada / No Disponible
# ============================================================================

def test_disconnected_db_graceful_handling():
    """Valida que db_connector no lance excepciones no capturadas ante fallos de conexión."""
    # Configurar un engine inválido que simula fallo de red
    bad_engine = create_engine("sqlite:///non_existent_dir_12345/unreachable.db")
    set_custom_engine(bad_engine)

    # 1. Connection status debe reportar connected=False
    status = get_connection_status()
    assert status["connected"] is False
    assert status["error"] is not None

    # 2. get_kpis debe retornar valores por defecto seguros
    kpis = get_kpis()
    assert kpis["total_incidents"] == 0
    assert kpis["critical_active"] == 0
    assert kpis["isolated_agents"] == 0
    assert kpis["containment_rate_pct"] == 0.0
    assert kpis["avg_containment_time"] == "N/A"

    # 3. Consultas tabulares deben retornar DataFrames vacíos con columnas esperadas
    df_incidents = get_recent_incidents()
    assert isinstance(df_incidents, pd.DataFrame)
    assert df_incidents.empty
    assert "incident_id" in df_incidents.columns
    assert "severity" in df_incidents.columns

    # 4. Detalle de incidente debe ser None
    assert get_incident_by_id("non-existent-id") is None

    # 5. Inventario de agentes vacío
    df_agents = get_agents_status()
    assert isinstance(df_agents, pd.DataFrame)
    assert df_agents.empty
    assert "agent_id" in df_agents.columns

    # 6. Distribución CVE vacía
    df_cve = get_cve_distribution()
    assert isinstance(df_cve, pd.DataFrame)
    assert df_cve.empty

    # 7. Vulnerabilidades NVD vacía
    df_vulns = get_nvd_vulnerabilities()
    assert isinstance(df_vulns, pd.DataFrame)
    assert df_vulns.empty

    # 8. Tendencias temporales vacía
    df_trends = get_hourly_incident_trends()
    assert isinstance(df_trends, pd.DataFrame)
    assert df_trends.empty


# ============================================================================
# 2. Tests con Base de Datos Inicializada pero Vacía
# ============================================================================

def test_empty_database_graceful_handling():
    """Valida el comportamiento cuando las tablas existen pero no contienen registros."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    set_custom_engine(engine)

    # Conexión debe ser exitosa
    status = get_connection_status()
    assert status["connected"] is True

    # KPIs en ceros
    kpis = get_kpis()
    assert kpis["total_incidents"] == 0
    assert kpis["critical_active"] == 0
    assert kpis["isolated_agents"] == 0
    assert kpis["containment_rate_pct"] == 0.0
    assert kpis["avg_containment_time"] == "N/A"

    # Tablas vacías
    assert get_recent_incidents().empty
    assert get_agents_status().empty
    assert get_cve_distribution().empty
    assert get_nvd_vulnerabilities().empty
    assert get_hourly_incident_trends().empty
    assert get_incident_by_id(str(uuid.uuid4())) is None


# ============================================================================
# 3. Tests con Datos Poblados (Flujo Completo EDR + SIEM)
# ============================================================================

def test_populated_database_queries_and_kpis():
    """Valida los cálculos analíticos y consultas con datos poblados."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    set_custom_engine(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    # 1. Crear agentes
    agent1 = AgentInventory(
        agent_id="001",
        hostname="web-prod-01",
        ip_address="192.168.1.10",
        os_name="Ubuntu",
        os_version="22.04 LTS",
        status=AgentStatus.ISOLATED.value,
    )
    agent2 = AgentInventory(
        agent_id="002",
        hostname="db-prod-01",
        ip_address="192.168.1.20",
        os_name="Red Hat Enterprise Linux",
        os_version="9.2",
        status=AgentStatus.ACTIVE.value,
    )
    session.add_all([agent1, agent2])

    # 2. Crear vulnerabilidades NVD
    cve1 = NVDVulnerability(
        cve_id="CVE-2023-44487",
        description="HTTP/2 Rapid Reset DDoS vulnerability",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        severity="HIGH",
        cwe_id="CWE-400",
        has_active_exploit=True,
    )
    cve2 = NVDVulnerability(
        cve_id="CVE-2021-44228",
        description="Apache Log4j2 JNDI RCE",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity="CRITICAL",
        cwe_id="CWE-502",
        has_active_exploit=True,
    )
    session.add_all([cve1, cve2])

    # 3. Crear incidentes
    inc1_id = uuid.uuid4()
    inc1 = SecurityIncident(
        incident_id=inc1_id,
        source_detection=IncidentSource.WAZUH_MANAGER.value,
        alert_name="Ransomware Activity Detected - Lateral Movement",
        rule_id="100201",
        src_ip="203.0.113.45",
        src_country="CN",
        src_reputation_score=95,
        dst_ip="192.168.1.10",
        dst_port=443,
        agent_id="001",
        affected_software="nginx 1.18",
        associated_cve="CVE-2023-44487",
        calculated_risk_score=83.0,
        status=IncidentStatus.CONTAINED_AUTOMATICALLY.value,
        active_response_executed=ActiveResponseAction.ISOLATE_AGENT.value,
        active_response_status=ActiveResponseStatus.SUCCESS.value,
        response_payload={
            "command": "active-response/bin/isolate.sh",
            "agent": "001",
            "action": "isolate",
            "status": "applied",
        },
        detected_at=datetime(2026, 10, 15, 8, 0, 0, tzinfo=timezone.utc),
        resolved_at=datetime(2026, 10, 15, 8, 2, 30, tzinfo=timezone.utc),
    )

    inc2_id = uuid.uuid4()
    inc2 = SecurityIncident(
        incident_id=inc2_id,
        source_detection=IncidentSource.SPLUNK.value,
        alert_name="Suspicious Outbound SSH Connection",
        rule_id="200300",
        src_ip="192.168.1.20",
        dst_ip="198.51.100.99",
        dst_port=22,
        agent_id="002",
        calculated_risk_score=45.0,
        status=IncidentStatus.NEW.value,
        active_response_executed=ActiveResponseAction.NONE.value,
        active_response_status=ActiveResponseStatus.SKIPPED.value,
        detected_at=datetime(2026, 10, 15, 9, 30, 0, tzinfo=timezone.utc),
    )
    session.add_all([inc1, inc2])
    session.commit()

    # Validar KPIs
    kpis = get_kpis()
    assert kpis["total_incidents"] == 2
    assert kpis["critical_active"] == 1  # inc1 tiene score 83.0 y estado CONTAINED_AUTOMATICALLY (no resuelto)
    assert kpis["isolated_agents"] == 1  # agent1 tiene status 'isolated'
    assert kpis["containment_rate_pct"] == 50.0  # 1 de 2 incidentes auto-contenido

    # Validar get_recent_incidents
    df_recent = get_recent_incidents(limit=10)
    assert len(df_recent) == 2
    assert "web-prod-01" in df_recent["hostname"].values

    # Validar filtrado por severidad
    df_crit = get_recent_incidents(severity="CRITICAL")
    assert len(df_crit) == 1
    assert df_crit.iloc[0]["alert_name"] == "Ransomware Activity Detected - Lateral Movement"

    # Validar filtrado por estado
    df_new = get_recent_incidents(status="NEW")
    assert len(df_new) == 1
    assert df_new.iloc[0]["agent_id"] == "002"

    # Validar get_incident_by_id con parseo JSON de Active Response
    detail = get_incident_by_id(str(inc1_id))
    assert detail is not None
    assert detail["alert_name"] == "Ransomware Activity Detected - Lateral Movement"
    assert detail["active_response_executed"] == "ISOLATE_AGENT"
    assert detail["active_response_status"] == "SUCCESS"
    assert isinstance(detail["response_payload"], dict)
    assert detail["response_payload"]["action"] == "isolate"

    # Validar get_agents_status
    df_agents = get_agents_status()
    assert len(df_agents) == 2
    isolated_host = df_agents[df_agents["status"] == "isolated"]
    assert len(isolated_host) == 1
    assert isolated_host.iloc[0]["hostname"] == "web-prod-01"

    # Validar get_cve_distribution
    df_cve = get_cve_distribution()
    assert not df_cve.empty
    severities = df_cve["severity"].tolist()
    assert "CRITICAL" in severities or "HIGH" in severities
