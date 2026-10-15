"""
NIST NVD API 2.0 Asynchronous Client.
Handles rate-limits, exponential backoff, retry mechanisms, and data parsing.
"""

import asyncio
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("nvd_service.client")
logger.setLevel(logging.INFO)


class NVDClientError(Exception):
    """Base exception for NVD client operations."""
    pass


class NVDRateLimitError(NVDClientError):
    """Raised when NVD API rate limit is exceeded and retries are exhausted."""
    pass


class NVDTimeoutError(NVDClientError):
    """Raised when NVD API request times out."""
    pass


class NVDClient:
    """
    Asynchronous client for NIST NVD API 2.0.
    Documentation: https://nvd.nist.gov/developers/vulnerabilities
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3
    ):
        """
        Initialize the NVD client.
        Reads NVD_API_KEY from environment if not explicitly provided.
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY", "").strip() or None
        self.timeout = timeout
        self.max_retries = max_retries

        # Rate limiting control:
        # Without key: 5 requests / 30 seconds -> ~6.0s spacing
        # With key: 50 requests / 30 seconds -> ~0.6s spacing
        self.min_interval = 0.6 if self.api_key else 6.0
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

        headers = {
            "User-Agent": "SecOps-Astrea-Platform/1.0 (Vulnerability Management)",
            "Accept": "application/json"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
            logger.info("NVDClient initialized with API Key (Rate limit: 50 req / 30s)")
        else:
            logger.warning(
                "NVDClient initialized WITHOUT API Key. "
                "Operating under public rate limits (5 req / 30s). Consider setting NVD_API_KEY."
            )

        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=True
        )

    async def _throttle(self) -> None:
        """Enforces minimum interval between outbound API requests to avoid rate limits."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                logger.debug(f"Throttling NVD API request for {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
            self._last_request_time = time.monotonic()

    async def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes HTTP GET request to NVD API 2.0 with retry and backoff handling.
        """
        attempt = 0
        while attempt <= self.max_retries:
            await self._throttle()
            try:
                attempt += 1
                logger.info(f"Querying NVD API 2.0 with params: {params} (Attempt {attempt}/{self.max_retries + 1})")
                response = await self._client.get(self.BASE_URL, params=params)

                # Check for rate limiting status codes (403 is often returned by NIST when rate limited)
                if response.status_code in (403, 429):
                    retry_after_hdr = response.headers.get("Retry-After")
                    if retry_after_hdr:
                        try:
                            sleep_duration = float(retry_after_hdr) + 1.0
                        except ValueError:
                            sleep_duration = (self.min_interval * 2 ** attempt) + random.uniform(0.5, 1.5)
                    else:
                        # Exponential backoff with jitter
                        base_backoff = 6.0 if not self.api_key else 2.0
                        sleep_duration = (base_backoff * (2 ** (attempt - 1))) + random.uniform(0.5, 1.5)

                    if attempt <= self.max_retries:
                        logger.warning(
                            f"NVD API Rate limit encountered (HTTP {response.status_code}). "
                            f"Sleeping for {sleep_duration:.2f}s before retry {attempt}/{self.max_retries}..."
                        )
                        await asyncio.sleep(sleep_duration)
                        continue
                    else:
                        error_msg = f"NVD API rate limit exceeded after {self.max_retries} retries."
                        logger.error(error_msg)
                        raise NVDRateLimitError(error_msg)

                # Check for standard server errors (500, 502, 503, 504)
                if response.status_code in (500, 502, 503, 504):
                    if attempt <= self.max_retries:
                        sleep_duration = (2.0 * attempt) + random.uniform(0.2, 0.8)
                        logger.warning(
                            f"NVD API Server Error (HTTP {response.status_code}). "
                            f"Retrying in {sleep_duration:.2f}s..."
                        )
                        await asyncio.sleep(sleep_duration)
                        continue

                response.raise_for_status()
                return response.json()

            except httpx.TimeoutException as exc:
                logger.warning(f"Timeout querying NVD API on attempt {attempt}: {exc}")
                if attempt > self.max_retries:
                    raise NVDTimeoutError(f"NVD API request timed out after {self.max_retries} retries") from exc
                await asyncio.sleep(2.0 * attempt)

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    logger.info(f"NVD API returned 404 Not Found for params: {params}")
                    return {"vulnerabilities": [], "totalResults": 0}
                if attempt > self.max_retries:
                    raise NVDClientError(f"NVD API returned HTTP {exc.response.status_code}: {exc.response.text}") from exc

            except Exception as exc:
                if isinstance(exc, (NVDRateLimitError, NVDTimeoutError)):
                    raise
                logger.error(f"Unexpected error querying NVD API on attempt {attempt}: {exc}")
                if attempt > self.max_retries:
                    raise NVDClientError(f"Unexpected NVD Client error: {str(exc)}") from exc
                await asyncio.sleep(2.0 * attempt)

        raise NVDClientError("Failed to fetch data from NVD API after maximum retries")

    def _parse_cve_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses a single vulnerability element from NVD API 2.0 response.
        Extracts CVE ID, description, CVSS v3.1 / v3.0 / v2 metrics, CWE, and active exploit indicators.
        """
        cve = item.get("cve", {})
        cve_id = cve.get("id", "").strip().upper()

        # 1. Description (prefer English 'en')
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                desc_text = desc.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        # 2. CVSS Metrics (Priority: v3.1 -> v3.0 -> v2)
        metrics = cve.get("metrics", {})
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        severity: Optional[str] = None

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            # Pick primary metric if available, otherwise first
            metric_entry = metrics["cvssMetricV31"][0]
            for m in metrics["cvssMetricV31"]:
                if m.get("type") == "Primary":
                    metric_entry = m
                    break
            cvss_data = metric_entry.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity") or metric_entry.get("baseSeverity")

        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            metric_entry = metrics["cvssMetricV30"][0]
            for m in metrics["cvssMetricV30"]:
                if m.get("type") == "Primary":
                    metric_entry = m
                    break
            cvss_data = metric_entry.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity") or metric_entry.get("baseSeverity")

        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            metric_entry = metrics["cvssMetricV2"][0]
            cvss_data = metric_entry.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = metric_entry.get("baseSeverity")

        if severity:
            severity = severity.upper()
        elif cvss_score is not None:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0.0:
                severity = "LOW"
            else:
                severity = "NONE"
        else:
            severity = "UNKNOWN"

        # 3. CWE (Weakness identifier)
        cwe_id = None
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for w_desc in w.get("description", []):
                val = w_desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_id = val
                    break
            if cwe_id:
                break

        # 4. Active Exploit Detection (CISA KEV, exploit tags in references)
        has_active_exploit = False
        if cve.get("cisaExploitAdd") or cve.get("cisaActionDue"):
            has_active_exploit = True
        else:
            references = cve.get("references", [])
            for ref in references:
                tags = [t.lower() for t in ref.get("tags", [])]
                if "exploit" in tags:
                    has_active_exploit = True
                    break

            # Fallback to textual indicators in description
            if not has_active_exploit and desc_text:
                lower_desc = desc_text.lower()
                if "in the wild" in lower_desc or "actively exploited" in lower_desc:
                    has_active_exploit = True

        # 5. Timestamps
        published_date = None
        if cve.get("published"):
            try:
                published_date = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
            except ValueError:
                pass

        last_modified_date = None
        if cve.get("lastModified"):
            try:
                last_modified_date = datetime.fromisoformat(cve["lastModified"].replace("Z", "+00:00"))
            except ValueError:
                pass

        return {
            "cve_id": cve_id,
            "description": desc_text,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "cwe_id": cwe_id,
            "has_active_exploit": has_active_exploit,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            "source": "NVD_API"
        }

    async def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Direct lookup for a specific CVE identifier (e.g. CVE-2021-41773).
        """
        clean_cve = cve_id.strip().upper()
        params = {"cveId": clean_cve}
        data = await self._make_request(params)
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return self._parse_cve_item(vulnerabilities[0])

    async def search_vulnerabilities(
        self,
        software_name: str,
        version: Optional[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Searches NVD API 2.0 using keywordSearch for software name and version.
        """
        software_clean = software_name.strip()
        if version and version.strip():
            version_clean = version.strip()
            # If version is not already part of software_name, concatenate
            if version_clean.lower() not in software_clean.lower():
                query = f"{software_clean} {version_clean}"
            else:
                query = software_clean
        else:
            query = software_clean

        params = {
            "keywordSearch": query,
            "resultsPerPage": max(1, min(limit, 100))
        }

        data = await self._make_request(params)
        raw_items = data.get("vulnerabilities", [])
        results: List[Dict[str, Any]] = []

        for item in raw_items:
            try:
                parsed = self._parse_cve_item(item)
                if parsed.get("cve_id"):
                    results.append(parsed)
            except Exception as e:
                logger.error(f"Error parsing CVE item: {e}")
                continue

        return results

    async def close(self) -> None:
        """Closes the underlying HTTP client session."""
        await self._client.aclose()

    async def __aenter__(self) -> "NVDClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
