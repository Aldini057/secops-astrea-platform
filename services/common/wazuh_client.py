"""
SecOps Astrea Platform - Wazuh Manager REST API Client (EDR & Active Response).
Provides both synchronous (WazuhClient) and asynchronous (AsyncWazuhClient)
clients for interacting with Wazuh Manager API v4.x+.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse, urlunparse

import httpx

from services.common.config import Settings, get_settings

logger = logging.getLogger("secops.wazuh_client")


# ============================================================================
# Custom Exceptions
# ============================================================================

class WazuhError(Exception):
    """Excepción base para errores relacionados con la API de Wazuh."""
    pass


class WazuhAuthError(WazuhError):
    """Lanzada cuando la autenticación o renovación de token JWT falla."""
    pass


class WazuhConnectionError(WazuhError):
    """Lanzada cuando no es posible conectar con el Wazuh Manager (red, timeout, DNS)."""
    pass


class WazuhCommandError(WazuhError):
    """
    Lanzada cuando la API de Wazuh devuelve un código de error o falla
    la ejecución de un comando de Active Response.
    """
    def __init__(
        self,
        message: str,
        error_code: Optional[int] = None,
        details: Optional[Any] = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.details = details


class WazuhAgentNotFoundError(WazuhCommandError):
    """Lanzada cuando un agente especificado no existe o no está registrado."""
    pass


# ============================================================================
# Helper Functions
# ============================================================================

def _normalize_base_url(host: str, port: int = 55000) -> str:
    """Normaliza host y puerto en una URL base https://host:port."""
    cleaned = host.strip().rstrip("/")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    netloc = parsed.netloc
    if ":" not in netloc and port:
        netloc = f"{netloc}:{port}"

    return urlunparse(parsed._replace(netloc=netloc)).rstrip("/")


# ============================================================================
# Synchronous Wazuh Client
# ============================================================================

class WazuhClient:
    """
    Cliente síncrono para la API REST de Wazuh Manager v4.x+.
    Maneja autenticación JWT automática, reintentos en 401, consulta de inventario
    y ejecución de Active Response (aislamiento y bloqueo de IPs).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[float] = None,
        settings: Optional[Settings] = None,
    ):
        cfg = settings or get_settings()

        self.base_url = (
            _normalize_base_url(base_url, cfg.wazuh_api_port)
            if base_url
            else cfg.wazuh_base_url
        )
        self.username = username or cfg.wazuh_api_user
        self.password = password or cfg.wazuh_api_password
        self.verify_ssl = (
            verify_ssl if verify_ssl is not None else cfg.wazuh_api_verify_ssl
        )
        self.timeout = timeout if timeout is not None else cfg.wazuh_api_timeout

        self._token: Optional[str] = None
        self._token_obtained_at: float = 0.0
        self._token_ttl_seconds: float = 850.0  # Wazuh default is 900s (15 min)

        self._client = httpx.Client(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

    def __enter__(self) -> "WazuhClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        """Cierra la conexión HTTP subyacente."""
        self._client.close()

    def to_async(self) -> "AsyncWazuhClient":
        """Crea una instancia asíncrona AsyncWazuhClient con la misma configuración."""
        return AsyncWazuhClient(
            base_url=self.base_url,
            username=self.username,
            password=self.password,
            verify_ssl=self.verify_ssl,
            timeout=self.timeout,
        )

    # ------------------------------------------------------------------------
    # Autenticación y Token JWT
    # ------------------------------------------------------------------------

    def authenticate(self) -> str:
        """
        Obtiene un nuevo token JWT Bearer autenticándose en
        POST /security/user/authenticate con credenciales Basic Auth.
        """
        url = "/security/user/authenticate"
        try:
            response = self._client.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
            )
        except httpx.RequestError as exc:
            msg = f"Error de conexión con Wazuh Manager al autenticar ({self.base_url}): {exc}"
            logger.error(msg)
            raise WazuhConnectionError(msg) from exc

        if response.status_code in (401, 403):
            msg = f"Fallo de autenticación en Wazuh API ({response.status_code}): Credenciales inválidas."
            logger.error(msg)
            raise WazuhAuthError(msg)

        if response.status_code >= 400:
            msg = f"Error HTTP {response.status_code} al autenticar en Wazuh: {response.text}"
            logger.error(msg)
            raise WazuhAuthError(msg)

        try:
            data = response.json()
        except Exception as exc:
            msg = f"Respuesta no JSON recibida de Wazuh Manager: {response.text}"
            logger.error(msg)
            raise WazuhAuthError(msg) from exc

        token = data.get("data", {}).get("token")
        if not token:
            msg = f"La respuesta de autenticación de Wazuh no contiene 'token': {data}"
            logger.error(msg)
            raise WazuhAuthError(msg)

        self._token = token
        self._token_obtained_at = time.time()
        logger.info("Token JWT de Wazuh Manager obtenido exitosamente.")
        return token

    def _get_valid_token(self) -> str:
        """Retorna el token actual o solicita uno nuevo si expiró o no existe."""
        if not self._token or (time.time() - self._token_obtained_at) >= self._token_ttl_seconds:
            return self.authenticate()
        return self._token

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        retry_on_401: bool = True,
    ) -> Dict[str, Any]:
        """
        Ejecuta una petición autenticada a la API de Wazuh con soporte
        de auto-renovación de token en 401.
        """
        token = self._get_valid_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            response = self._client.request(
                method=method,
                url=endpoint,
                params=params,
                json=json_data,
                headers=headers,
            )
        except httpx.RequestError as exc:
            msg = f"Fallo de conexión al comunicarse con Wazuh en {endpoint}: {exc}"
            logger.error(msg)
            raise WazuhConnectionError(msg) from exc

        # Auto-renovación si el token expiró en el servidor
        if response.status_code == 401 and retry_on_401:
            logger.warning("Token JWT rechazado (HTTP 401). Renovando token y reintentando...")
            self.authenticate()
            return self._request(
                method=method,
                endpoint=endpoint,
                params=params,
                json_data=json_data,
                retry_on_401=False,
            )

        # Parsear respuesta JSON
        try:
            payload = response.json()
        except Exception:
            payload = {"raw_text": response.text}

        if response.status_code >= 400:
            err_code = payload.get("error", response.status_code) if isinstance(payload, dict) else response.status_code
            msg = payload.get("message", response.text) if isinstance(payload, dict) else response.text
            logger.error("Wazuh API devolvió error HTTP %d: %s", response.status_code, msg)
            raise WazuhCommandError(
                f"Wazuh API Error ({response.status_code}): {msg}",
                error_code=err_code,
                details=payload,
            )

        if isinstance(payload, dict) and payload.get("error", 0) != 0:
            err_code = payload.get("error")
            msg = payload.get("message", "Error reportado por Wazuh API")
            logger.error("Wazuh API error interno %s: %s", err_code, msg)
            raise WazuhCommandError(
                f"Wazuh API Error (code {err_code}): {msg}",
                error_code=err_code,
                details=payload,
            )

        return payload

    # ------------------------------------------------------------------------
    # Métodos de Inventario de Agentes
    # ------------------------------------------------------------------------

    def get_agent(self, agent_id: str, raise_if_not_found: bool = True) -> Optional[Dict[str, Any]]:
        """
        Consulta información de un host registrado en 'GET /agents?agents_list={agent_id}'.

        Args:
            agent_id: ID del agente en Wazuh (ej. '001', '002').
            raise_if_not_found: Si True, lanza WazuhAgentNotFoundError si el agente no existe.

        Returns:
            Diccionario con la información del agente o None si no existe y raise_if_not_found=False.
        """
        endpoint = "/agents"
        params = {"agents_list": str(agent_id)}
        response = self._request("GET", endpoint, params=params)

        affected = response.get("data", {}).get("affected_items", [])
        if affected:
            return affected[0]

        failed = response.get("data", {}).get("failed_items", [])
        if raise_if_not_found:
            msg = f"Agente '{agent_id}' no encontrado en Wazuh Manager."
            logger.warning(msg)
            raise WazuhAgentNotFoundError(msg, error_code=1701, details=failed)

        return None

    def list_agents(
        self,
        status: Optional[str] = "active",
        limit: int = 500,
        offset: int = 0,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lista agentes registrados en el Wazuh Manager.

        Args:
            status: Filtro por estado ('active', 'disconnected', 'pending', 'never_connected', o None/'all').
            limit: Límite de resultados a retornar (por defecto 500).
            offset: Desplazamiento para paginación.
            select: Campos específicos separados por coma (ej. 'id,name,ip,status,os').
            q: Filtro avanzado de consulta Wazuh.

        Returns:
            Lista de diccionarios con la información de cada agente.
        """
        endpoint = "/agents"
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status and status.lower() != "all":
            params["status"] = status
        if select:
            params["select"] = select
        if q:
            params["q"] = q

        response = self._request("GET", endpoint, params=params)
        return response.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------------
    # Métodos de Active Response
    # ------------------------------------------------------------------------

    def run_active_response(
        self,
        agent_id: str,
        command: str,
        arguments: Optional[List[str]] = None,
        custom: bool = False,
        alert: Optional[Dict[str, Any]] = None,
        method: str = "PUT",
    ) -> Dict[str, Any]:
        """
        Ejecuta un comando de Active Response en un host vía 'PUT /active-response'
        (o 'POST /active-response' con fallback automático si PUT devuelve 405).

        Args:
            agent_id: ID del agente objetivo.
            command: Nombre del comando configurado en ossec.conf o script (!script).
            arguments: Lista de argumentos posicionales para el script de respuesta activa.
            custom: Indica si es un comando personalizado.
            alert: Estructura de alerta simulada (ej. {"data": {"srcip": "..."}}).
            method: Método HTTP preferido ('PUT' por defecto en Wazuh 4.x).

        Returns:
            Diccionario de respuesta con 'affected_items' y estado de ejecución.
        """
        endpoint = "/active-response"
        params = {"agents_list": str(agent_id)}
        payload: Dict[str, Any] = {
            "command": command,
            "custom": custom,
        }
        if arguments is not None:
            payload["arguments"] = list(arguments)
        if alert is not None:
            payload["alert"] = alert

        preferred_method = method.upper()
        try:
            response = self._request(
                preferred_method,
                endpoint,
                params=params,
                json_data=payload,
            )
        except WazuhCommandError as exc:
            # Fallback a POST si el gateway o servidor responde 405 Method Not Allowed en PUT
            if exc.error_code == 405 and preferred_method == "PUT":
                logger.info("PUT /active-response devolvió 405. Reintentando con POST...")
                response = self._request(
                    "POST",
                    endpoint,
                    params=params,
                    json_data=payload,
                )
            else:
                raise

        # Validar si el agente falló en la ejecución
        data = response.get("data", {})
        total_failed = data.get("total_failed_items", 0)
        total_affected = data.get("total_affected_items", 0)
        failed_items = data.get("failed_items", [])

        if total_failed > 0 and total_affected == 0:
            msg = f"Fallo al ejecutar Active Response '{command}' en agente '{agent_id}': {failed_items}"
            logger.error(msg)
            raise WazuhCommandError(msg, details=failed_items)

        logger.info(
            "Active Response '%s' ejecutado exitosamente en agente '%s'.",
            command,
            agent_id,
        )
        return response

    def isolate_agent(
        self,
        agent_id: str,
        command: str = "isolate-agent",
        arguments: Optional[List[str]] = None,
        custom: bool = True,
    ) -> Dict[str, Any]:
        """
        Wrapper de alto nivel para ejecutar el script de aislamiento de red en el endpoint.

        Args:
            agent_id: ID del agente a aislar.
            command: Nombre del script o comando de aislamiento en ossec.conf (ej. 'isolate-agent').
            arguments: Argumentos opcionales (por defecto ['isolate']).
            custom: True para scripts personalizados.

        Returns:
            Resultado de la ejecución del Active Response.
        """
        args = arguments if arguments is not None else ["isolate"]
        logger.warning("Ejecutando aislamiento de red en agente ID '%s'...", agent_id)
        return self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
        )

    def unisolate_agent(
        self,
        agent_id: str,
        command: str = "isolate-agent",
        arguments: Optional[List[str]] = None,
        custom: bool = True,
    ) -> Dict[str, Any]:
        """
        Wrapper de alto nivel para restaurar la conectividad de red de un agente previamente aislado.
        """
        args = arguments if arguments is not None else ["unisolate"]
        logger.info("Restaurando conectividad de red en agente ID '%s'...", agent_id)
        return self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
        )

    def block_ip(
        self,
        agent_id: str,
        src_ip: str,
        command: str = "firewall-drop",
        duration: Optional[int] = None,
        custom: bool = False,
    ) -> Dict[str, Any]:
        """
        Wrapper de alto nivel para agregar una regla de drop/bloqueo de IP en el firewall del endpoint.

        Args:
            agent_id: ID del agente donde se aplicará la regla.
            src_ip: Dirección IP origen a bloquear.
            command: Comando de firewall de Wazuh (por defecto 'firewall-drop').
            duration: Duración en segundos del bloqueo temporal (opcional).
            custom: True si se utiliza un script de firewall no estándar.

        Returns:
            Resultado de la ejecución del Active Response.
        """
        args = ["-", src_ip]
        if duration is not None:
            args.append(str(duration))

        alert_context = {
            "data": {
                "srcip": src_ip,
            }
        }

        logger.warning(
            "Aplicando bloqueo de IP '%s' en firewall del agente ID '%s'...",
            src_ip,
            agent_id,
        )
        return self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
            alert=alert_context,
        )

    def unblock_ip(
        self,
        agent_id: str,
        src_ip: str,
        command: str = "firewall-drop",
        custom: bool = False,
    ) -> Dict[str, Any]:
        """
        Wrapper de alto nivel para remover la regla de bloqueo de IP en el firewall del endpoint.
        """
        args = ["-delete", src_ip]
        alert_context = {
            "data": {
                "srcip": src_ip,
            }
        }
        logger.info("Removiendo bloqueo de IP '%s' en agente ID '%s'...", src_ip, agent_id)
        return self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
            alert=alert_context,
        )


# ============================================================================
# Asynchronous Wazuh Client
# ============================================================================

class AsyncWazuhClient:
    """
    Cliente asíncrono para la API REST de Wazuh Manager v4.x+.
    Permite integración de alto rendimiento con FastAPI, microservicios asyncio y workers.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[float] = None,
        settings: Optional[Settings] = None,
    ):
        cfg = settings or get_settings()

        self.base_url = (
            _normalize_base_url(base_url, cfg.wazuh_api_port)
            if base_url
            else cfg.wazuh_base_url
        )
        self.username = username or cfg.wazuh_api_user
        self.password = password or cfg.wazuh_api_password
        self.verify_ssl = (
            verify_ssl if verify_ssl is not None else cfg.wazuh_api_verify_ssl
        )
        self.timeout = timeout if timeout is not None else cfg.wazuh_api_timeout

        self._token: Optional[str] = None
        self._token_obtained_at: float = 0.0
        self._token_ttl_seconds: float = 850.0

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

    async def __aenter__(self) -> "AsyncWazuhClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self) -> None:
        """Cierra el cliente asíncrono."""
        await self._client.aclose()

    # ------------------------------------------------------------------------
    # Autenticación y Token JWT
    # ------------------------------------------------------------------------

    async def authenticate(self) -> str:
        """Obtiene un nuevo token JWT asíncronamente vía Basic Auth."""
        url = "/security/user/authenticate"
        try:
            response = await self._client.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
            )
        except httpx.RequestError as exc:
            msg = f"Error de conexión con Wazuh Manager al autenticar ({self.base_url}): {exc}"
            logger.error(msg)
            raise WazuhConnectionError(msg) from exc

        if response.status_code in (401, 403):
            msg = f"Fallo de autenticación en Wazuh API ({response.status_code}): Credenciales inválidas."
            logger.error(msg)
            raise WazuhAuthError(msg)

        if response.status_code >= 400:
            msg = f"Error HTTP {response.status_code} al autenticar en Wazuh: {response.text}"
            logger.error(msg)
            raise WazuhAuthError(msg)

        try:
            data = response.json()
        except Exception as exc:
            msg = f"Respuesta no JSON recibida de Wazuh Manager: {response.text}"
            logger.error(msg)
            raise WazuhAuthError(msg) from exc

        token = data.get("data", {}).get("token")
        if not token:
            msg = f"La respuesta de autenticación de Wazuh no contiene 'token': {data}"
            logger.error(msg)
            raise WazuhAuthError(msg)

        self._token = token
        self._token_obtained_at = time.time()
        logger.info("Token JWT asíncrono obtenido exitosamente.")
        return token

    async def _get_valid_token(self) -> str:
        """Retorna el token actual o solicita uno nuevo si expiró."""
        if not self._token or (time.time() - self._token_obtained_at) >= self._token_ttl_seconds:
            return await self.authenticate()
        return self._token

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        retry_on_401: bool = True,
    ) -> Dict[str, Any]:
        """Ejecuta una petición asíncrona autenticada con renovación automática en 401."""
        token = await self._get_valid_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            response = await self._client.request(
                method=method,
                url=endpoint,
                params=params,
                json=json_data,
                headers=headers,
            )
        except httpx.RequestError as exc:
            msg = f"Fallo de conexión al comunicarse con Wazuh en {endpoint}: {exc}"
            logger.error(msg)
            raise WazuhConnectionError(msg) from exc

        if response.status_code == 401 and retry_on_401:
            logger.warning("Token JWT expirado en petición asíncrona. Renovando...")
            await self.authenticate()
            return await self._request(
                method=method,
                endpoint=endpoint,
                params=params,
                json_data=json_data,
                retry_on_401=False,
            )

        try:
            payload = response.json()
        except Exception:
            payload = {"raw_text": response.text}

        if response.status_code >= 400:
            err_code = payload.get("error", response.status_code) if isinstance(payload, dict) else response.status_code
            msg = payload.get("message", response.text) if isinstance(payload, dict) else response.text
            raise WazuhCommandError(
                f"Wazuh API Error ({response.status_code}): {msg}",
                error_code=err_code,
                details=payload,
            )

        if isinstance(payload, dict) and payload.get("error", 0) != 0:
            err_code = payload.get("error")
            msg = payload.get("message", "Error reportado por Wazuh API")
            raise WazuhCommandError(
                f"Wazuh API Error (code {err_code}): {msg}",
                error_code=err_code,
                details=payload,
            )

        return payload

    # ------------------------------------------------------------------------
    # Métodos Asíncronos de Agentes
    # ------------------------------------------------------------------------

    async def get_agent(self, agent_id: str, raise_if_not_found: bool = True) -> Optional[Dict[str, Any]]:
        """Consulta asíncrona de información de host en 'GET /agents?agents_list={agent_id}'."""
        endpoint = "/agents"
        params = {"agents_list": str(agent_id)}
        response = await self._request("GET", endpoint, params=params)

        affected = response.get("data", {}).get("affected_items", [])
        if affected:
            return affected[0]

        failed = response.get("data", {}).get("failed_items", [])
        if raise_if_not_found:
            msg = f"Agente '{agent_id}' no encontrado en Wazuh Manager."
            raise WazuhAgentNotFoundError(msg, error_code=1701, details=failed)

        return None

    async def list_agents(
        self,
        status: Optional[str] = "active",
        limit: int = 500,
        offset: int = 0,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lista agentes registrados de forma asíncrona."""
        endpoint = "/agents"
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status and status.lower() != "all":
            params["status"] = status
        if select:
            params["select"] = select
        if q:
            params["q"] = q

        response = await self._request("GET", endpoint, params=params)
        return response.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------------
    # Métodos Asíncronos de Active Response
    # ------------------------------------------------------------------------

    async def run_active_response(
        self,
        agent_id: str,
        command: str,
        arguments: Optional[List[str]] = None,
        custom: bool = False,
        alert: Optional[Dict[str, Any]] = None,
        method: str = "PUT",
    ) -> Dict[str, Any]:
        """Ejecuta un comando de Active Response asíncronamente con fallback a POST."""
        endpoint = "/active-response"
        params = {"agents_list": str(agent_id)}
        payload: Dict[str, Any] = {
            "command": command,
            "custom": custom,
        }
        if arguments is not None:
            payload["arguments"] = list(arguments)
        if alert is not None:
            payload["alert"] = alert

        preferred_method = method.upper()
        try:
            response = await self._request(
                preferred_method,
                endpoint,
                params=params,
                json_data=payload,
            )
        except WazuhCommandError as exc:
            if exc.error_code == 405 and preferred_method == "PUT":
                logger.info("PUT /active-response devolvió 405. Reintentando con POST...")
                response = await self._request(
                    "POST",
                    endpoint,
                    params=params,
                    json_data=payload,
                )
            else:
                raise

        data = response.get("data", {})
        total_failed = data.get("total_failed_items", 0)
        total_affected = data.get("total_affected_items", 0)
        failed_items = data.get("failed_items", [])

        if total_failed > 0 and total_affected == 0:
            msg = f"Fallo al ejecutar Active Response '{command}' en agente '{agent_id}': {failed_items}"
            logger.error(msg)
            raise WazuhCommandError(msg, details=failed_items)

        return response

    async def isolate_agent(
        self,
        agent_id: str,
        command: str = "isolate-agent",
        arguments: Optional[List[str]] = None,
        custom: bool = True,
    ) -> Dict[str, Any]:
        """Wrapper asíncrono para aislamiento de red."""
        args = arguments if arguments is not None else ["isolate"]
        return await self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
        )

    async def unisolate_agent(
        self,
        agent_id: str,
        command: str = "isolate-agent",
        arguments: Optional[List[str]] = None,
        custom: bool = True,
    ) -> Dict[str, Any]:
        """Wrapper asíncrono para restaurar conectividad de red."""
        args = arguments if arguments is not None else ["unisolate"]
        return await self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
        )

    async def block_ip(
        self,
        agent_id: str,
        src_ip: str,
        command: str = "firewall-drop",
        duration: Optional[int] = None,
        custom: bool = False,
    ) -> Dict[str, Any]:
        """Wrapper asíncrono para bloquear IP en el firewall del endpoint."""
        args = ["-", src_ip]
        if duration is not None:
            args.append(str(duration))

        alert_context = {
            "data": {
                "srcip": src_ip,
            }
        }
        return await self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
            alert=alert_context,
        )

    async def unblock_ip(
        self,
        agent_id: str,
        src_ip: str,
        command: str = "firewall-drop",
        custom: bool = False,
    ) -> Dict[str, Any]:
        """Wrapper asíncrono para remover bloqueo de IP en el firewall del endpoint."""
        args = ["-delete", src_ip]
        alert_context = {
            "data": {
                "srcip": src_ip,
            }
        }
        return await self.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=args,
            custom=custom,
            alert=alert_context,
        )
