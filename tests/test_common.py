"""
Unit tests for SecOps Astrea Platform - services/common package:
- Configuration (config.py)
- Wazuh EDR Client (wazuh_client.py: WazuhClient & AsyncWazuhClient)
- Database Models & Data Contracts (db_models.py)
"""

import json
import time
from decimal import Decimal
import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.common import (
    ActiveResponseAction,
    ActiveResponsePayload,
    ActiveResponseStatus,
    AgentInventory,
    AgentInventorySchema,
    AgentStatus,
    AsyncWazuhClient,
    Base,
    IncidentSource,
    IncidentStatus,
    NVDVulnerability,
    SecurityIncident,
    SecurityIncidentSchema,
    Settings,
    WazuhAgentNotFoundError,
    WazuhAuthError,
    WazuhClient,
    WazuhCommandError,
    WazuhConnectionError,
    get_settings,
)
from services.common.config import _normalize_wazuh_url


# ============================================================================
# 1. Tests for Configuration (config.py)
# ============================================================================

def test_settings_defaults():
    """Verifica que los valores por defecto coincidan con .env.example."""
    settings = Settings()

    assert settings.postgres_user == "secops_user"
    assert settings.postgres_password == "secops_secure_password"
    assert settings.postgres_db == "secops_astrea_db"
    assert settings.postgres_host == "postgres"
    assert settings.postgres_port == 5432

    assert settings.n8n_host == "localhost"
    assert settings.n8n_port == 5678
    assert settings.n8n_webhook_url == "http://localhost:5678/"

    assert settings.wazuh_api_port == 55000
    assert settings.wazuh_api_user == "wazuh-wui"
    assert settings.wazuh_api_password == "wazuh-wui-password"
    assert settings.wazuh_api_verify_ssl is False

    # URLs computadas
    assert settings.database_url == "postgresql://secops_user:secops_secure_password@postgres:5432/secops_astrea_db"
    assert settings.async_database_url == "postgresql+asyncpg://secops_user:secops_secure_password@postgres:5432/secops_astrea_db"
    assert settings.wazuh_base_url == "https://127.0.0.1:55000"


def test_normalize_wazuh_url_variations():
    """Verifica la correcta normalización de URLs con distintos formatos."""
    assert _normalize_wazuh_url("127.0.0.1", 55000) == "https://127.0.0.1:55000"
    assert _normalize_wazuh_url("https://127.0.0.1", 55000) == "https://127.0.0.1:55000"
    assert _normalize_wazuh_url("https://127.0.0.1:55000/", 55000) == "https://127.0.0.1:55000"
    assert _normalize_wazuh_url("http://wazuh-manager", 55000) == "http://wazuh-manager:55000"
    assert _normalize_wazuh_url("wazuh.local:9000", 55000) == "https://wazuh.local:9000"


def test_get_settings_cache():
    """Verifica que get_settings devuelva la instancia cacheada."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


# ============================================================================
# 2. Tests for Synchronous WazuhClient (wazuh_client.py)
# ============================================================================

def test_wazuh_client_auth_success():
    """Verifica autenticación exitosa y almacenamiento del token JWT."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/security/user/authenticate"
        assert request.headers.get("Authorization", "").startswith("Basic ")
        return httpx.Response(
            200,
            json={"data": {"token": "mock-jwt-token-xyz"}, "error": 0},
        )

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    token = client.authenticate()
    assert token == "mock-jwt-token-xyz"
    assert client._token == "mock-jwt-token-xyz"


def test_wazuh_client_auth_invalid_credentials():
    """Verifica que credenciales inválidas levanten WazuhAuthError."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Invalid user or password", "error": 401})

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(WazuhAuthError) as exc_info:
        client.authenticate()
    assert "Fallo de autenticación" in str(exc_info.value)


def test_wazuh_client_auto_token_renewal_on_401():
    """Verifica que peticiones con token expirado (401) renueven el token y reintenten."""
    auth_calls = 0
    agents_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal auth_calls, agents_calls
        if request.url.path == "/security/user/authenticate":
            auth_calls += 1
            return httpx.Response(200, json={"data": {"token": f"token-v{auth_calls}"}, "error": 0})
        elif request.url.path == "/agents":
            agents_calls += 1
            auth_header = request.headers.get("Authorization", "")
            if auth_header == "Bearer expired-token-0":
                return httpx.Response(401, json={"message": "Token expired", "error": 401})
            elif auth_header == "Bearer token-v1":
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "affected_items": [{"id": "001", "name": "ubuntu-srv", "status": "active"}],
                            "total_affected_items": 1,
                        },
                        "error": 0,
                    },
                )
        return httpx.Response(404)

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )
    client._token = "expired-token-0"
    client._token_obtained_at = time.time()  # Vigente según timestamp, pero rechazado con 401 por el servidor

    agent = client.get_agent("001")
    assert agent["name"] == "ubuntu-srv"
    assert auth_calls == 1  # Renovó a token-v2
    assert agents_calls == 2  # 1 fallido 401 + 1 exitoso 200


def test_wazuh_client_get_agent_success():
    """Verifica consulta de información de host con GET /agents?agents_list={agent_id}."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/agents":
            assert "agents_list=001" in request.url.query.decode()
            return httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "srv-prod-01",
                                "ip": "10.0.1.25",
                                "status": "active",
                                "os": {"name": "Debian", "version": "12"},
                            }
                        ],
                        "total_affected_items": 1,
                        "failed_items": [],
                    },
                    "error": 0,
                },
            )
        return httpx.Response(404)

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    agent = client.get_agent("001")
    assert agent is not None
    assert agent["id"] == "001"
    assert agent["name"] == "srv-prod-01"
    assert agent["ip"] == "10.0.1.25"


def test_wazuh_client_get_agent_not_found():
    """Verifica comportamiento cuando el agente no existe."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [],
                    "total_affected_items": 0,
                    "failed_items": [{"id": ["999"], "error": {"code": 1701, "message": "Agent does not exist"}}],
                },
                "error": 0,
            },
        )

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    # Con raise_if_not_found=True (por defecto)
    with pytest.raises(WazuhAgentNotFoundError):
        client.get_agent("999")

    # Con raise_if_not_found=False
    agent = client.get_agent("999", raise_if_not_found=False)
    assert agent is None


def test_wazuh_client_list_agents():
    """Verifica listado de agentes registrados y filtrado por estado."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert "status=active" in request.url.query.decode()
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {"id": "001", "name": "host-1", "status": "active"},
                        {"id": "002", "name": "host-2", "status": "active"},
                    ],
                    "total_affected_items": 2,
                },
                "error": 0,
            },
        )

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    agents = client.list_agents(status="active")
    assert len(agents) == 2
    assert agents[0]["id"] == "001"
    assert agents[1]["id"] == "002"


def test_wazuh_client_run_active_response_put():
    """Verifica ejecución de Active Response vía PUT /active-response."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.url.path == "/active-response"
        assert "agents_list=001" in request.url.query.decode()
        body = json.loads(request.read())
        assert body["command"] == "custom-restart"
        assert body["arguments"] == ["arg1"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": ["001"],
                    "total_affected_items": 1,
                    "failed_items": [],
                },
                "error": 0,
            },
        )

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    res = client.run_active_response("001", "custom-restart", ["arg1"])
    assert res["data"]["total_affected_items"] == 1


def test_wazuh_client_run_active_response_fallback_post():
    """Verifica fallback automático de PUT a POST si el endpoint responde 405."""
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.method)
        if request.method == "PUT":
            return httpx.Response(405, json={"error": 405, "message": "Method Not Allowed"})
        elif request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "data": {"affected_items": ["001"], "total_affected_items": 1, "failed_items": []},
                    "error": 0,
                },
            )
        return httpx.Response(400)

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    res = client.run_active_response("001", "test-cmd", ["a"])
    assert attempts == ["PUT", "POST"]
    assert res["data"]["total_affected_items"] == 1


def test_wazuh_client_isolate_agent_wrapper():
    """Verifica wrapper de aislamiento de red isolate_agent."""
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        if request.url.path == "/active-response":
            called = True
            body = json.loads(request.read())
            assert body["command"] == "isolate-agent"
            assert body["arguments"] == ["isolate"]
            assert body["custom"] is True
            return httpx.Response(
                200,
                json={"data": {"affected_items": ["001"], "total_affected_items": 1, "failed_items": []}, "error": 0},
            )
        return httpx.Response(404)

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    client.isolate_agent("001")
    assert called is True


def test_wazuh_client_block_ip_wrapper():
    """Verifica wrapper de bloqueo de firewall block_ip."""
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        if request.url.path == "/active-response":
            called = True
            body = json.loads(request.read())
            assert body["command"] == "firewall-drop"
            assert body["arguments"] == ["-", "198.51.100.42", "3600"]
            assert body["alert"]["data"]["srcip"] == "198.51.100.42"
            return httpx.Response(
                200,
                json={"data": {"affected_items": ["001"], "total_affected_items": 1, "failed_items": []}, "error": 0},
            )
        return httpx.Response(404)

    client = WazuhClient(base_url="https://mock-wazuh:55000")
    client._token = "valid-token"
    client._token_obtained_at = time.time()
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    client.block_ip("001", "198.51.100.42", duration=3600)
    assert called is True


# ============================================================================
# 3. Tests for Asynchronous AsyncWazuhClient
# ============================================================================

@pytest.mark.anyio
async def test_async_wazuh_client_lifecycle():
    """Verifica el flujo completo asíncrono de autenticación, consulta y respuesta activa."""
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "async-token-123"}, "error": 0})
        elif path == "/agents":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [{"id": "002", "name": "win-workstation", "status": "active"}],
                        "total_affected_items": 1,
                    },
                    "error": 0,
                },
            )
        elif path == "/active-response":
            return httpx.Response(
                200,
                json={
                    "data": {"affected_items": ["002"], "total_affected_items": 1, "failed_items": []},
                    "error": 0,
                },
            )
        return httpx.Response(404)

    client = AsyncWazuhClient(base_url="https://mock-wazuh:55000")
    client._client = httpx.AsyncClient(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    async with client:
        # 1. Autenticación
        token = await client.authenticate()
        assert token == "async-token-123"

        # 2. Obtener agente
        agent = await client.get_agent("002")
        assert agent["name"] == "win-workstation"

        # 3. Aislamiento de red
        res_iso = await client.isolate_agent("002")
        assert res_iso["data"]["total_affected_items"] == 1

        # 4. Bloqueo de IP
        res_blk = await client.block_ip("002", "203.0.113.5")
        assert res_blk["data"]["total_affected_items"] == 1


# ============================================================================
# 4. Tests for Database Models and Contracts (db_models.py)
# ============================================================================

def test_database_models_in_sqlite():
    """Verifica compatibilidad de db_models con creación de tablas e inserciones."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # 1. Crear Agente
    agent = AgentInventory(
        agent_id="001",
        hostname="production-web-01",
        ip_address="192.168.10.50",
        os_name="Ubuntu",
        os_version="24.04",
        status=AgentStatus.ACTIVE.value,
    )
    session.add(agent)

    # 2. Crear Vulnerabilidad NVD
    vuln = NVDVulnerability(
        cve_id="CVE-2024-12345",
        description="Remote Code Execution vulnerability in WebServer",
        cvss_score=Decimal("9.8"),
        severity="CRITICAL",
        has_active_exploit=True,
    )
    session.add(vuln)
    session.commit()

    # 3. Crear Incidente de Seguridad
    incident = SecurityIncident(
        source_detection=IncidentSource.WAZUH_MANAGER.value,
        alert_name="Potential RCE Exploit Detected",
        agent_id="001",
        associated_cve="CVE-2024-12345",
        src_ip="198.51.100.99",
        calculated_risk_score=Decimal("88.5"),
        status=IncidentStatus.CONTAINED_AUTOMATICALLY.value,
        active_response_executed=ActiveResponseAction.ISOLATE_AGENT.value,
        active_response_status=ActiveResponseStatus.SUCCESS.value,
        response_payload={"action": "isolate", "agent_id": "001"},
    )
    session.add(incident)
    session.commit()

    # Verificar consultas y relaciones ORM
    fetched = session.query(SecurityIncident).first()
    assert fetched is not None
    assert fetched.agent.hostname == "production-web-01"
    assert fetched.cve.severity == "CRITICAL"
    assert fetched.status == "CONTAINED_AUTOMATICALLY"

    # Verificar to_dict
    dict_repr = fetched.to_dict()
    assert dict_repr["agent_id"] == "001"
    assert dict_repr["alert_name"] == "Potential RCE Exploit Detected"
    assert dict_repr["calculated_risk_score"] == 88.5

    session.close()


def test_pydantic_schemas_validation():
    """Verifica esquemas de datos Pydantic."""
    schema = AgentInventorySchema(
        agent_id="003",
        hostname="node-03",
        ip_address="10.20.30.40",
        status="active",
    )
    assert schema.agent_id == "003"
    assert schema.hostname == "node-03"

    payload = ActiveResponsePayload(
        command="firewall-drop",
        arguments=["-", "1.2.3.4"],
    )
    assert payload.command == "firewall-drop"
    assert payload.arguments == ["-", "1.2.3.4"]
