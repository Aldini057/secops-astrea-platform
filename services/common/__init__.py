"""
SecOps Astrea Platform - Common Utilities, Configuration, and EDR Client Package.
Provides centralized settings, Wazuh Manager EDR integration, and database models.
"""

from services.common.config import Settings, get_settings
from services.common.db_models import (
    ActiveResponseAction,
    ActiveResponsePayload,
    ActiveResponseStatus,
    AgentInventory,
    AgentInventorySchema,
    AgentStatus,
    Base,
    IncidentSource,
    IncidentStatus,
    NVDVulnerability,
    SecurityIncident,
    SecurityIncidentSchema,
)
from services.common.wazuh_client import (
    AsyncWazuhClient,
    WazuhAgentNotFoundError,
    WazuhAuthError,
    WazuhClient,
    WazuhCommandError,
    WazuhConnectionError,
    WazuhError,
)

__all__ = [
    # Configuration
    "Settings",
    "get_settings",
    # EDR / Wazuh Clients
    "WazuhClient",
    "AsyncWazuhClient",
    # Wazuh Exceptions
    "WazuhError",
    "WazuhAuthError",
    "WazuhConnectionError",
    "WazuhCommandError",
    "WazuhAgentNotFoundError",
    # Database ORM Models
    "Base",
    "AgentInventory",
    "NVDVulnerability",
    "SecurityIncident",
    # Enumerations
    "AgentStatus",
    "IncidentSource",
    "IncidentStatus",
    "ActiveResponseAction",
    "ActiveResponseStatus",
    # Pydantic Schemas
    "AgentInventorySchema",
    "SecurityIncidentSchema",
    "ActiveResponsePayload",
]
