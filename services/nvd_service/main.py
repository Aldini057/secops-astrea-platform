"""
SecOps Astrea Platform - NVD Vulnerability Analyst Microservice.
FastAPI service to query software vulnerabilities against NIST NVD API 2.0
with local PostgreSQL persistence and caching in 'nvd_vulnerabilities'.
"""

import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Generator, List, Optional
from urllib.parse import quote_plus

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

# Support relative or absolute imports depending on how uvicorn is launched
try:
    from models import (
        Base,
        HealthResponse,
        NVDVulnerability,
        VulnerabilityCheckRequest,
        VulnerabilityCheckResponse,
        VulnerabilityItem,
    )
    from client_nvd import (
        NVDClient,
        NVDClientError,
        NVDRateLimitError,
        NVDTimeoutError,
    )
except ImportError:
    from app.models import (
        Base,
        HealthResponse,
        NVDVulnerability,
        VulnerabilityCheckRequest,
        VulnerabilityCheckResponse,
        VulnerabilityItem,
    )
    from app.client_nvd import (
        NVDClient,
        NVDClientError,
        NVDRateLimitError,
        NVDTimeoutError,
    )

# ============================================================================
# Logging Configuration
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("nvd_service.main")


# ============================================================================
# Database Configuration & Session Management
# ============================================================================
def get_database_url() -> str:
    """
    Constructs database URL from environment variables.
    Checks DATABASE_URL first; if absent, builds PostgreSQL connection string.
    """
    db_url = os.getenv("DATABASE_URL", "").strip()
    if db_url:
        return db_url

    user = os.getenv("POSTGRES_USER", "secops_user")
    password = quote_plus(os.getenv("POSTGRES_PASSWORD", "secops_secure_password"))
    host = os.getenv("POSTGRES_HOST", "postgres")
    port = os.getenv("POSTGRES_PORT", "5432")
    db_name = os.getenv("POSTGRES_DB", "secops_astrea_db")

    return f"postgresql://{user}:{password}@{host}:{port}/{db_name}"


DATABASE_URL = get_database_url()

engine_kwargs = {"pool_pre_ping": True}
if not DATABASE_URL.startswith("sqlite"):
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 300
    })
else:
    engine_kwargs.update({
        "connect_args": {"check_same_thread": False}
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency providing a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# Client Lifecycle & FastAPI Application
# ============================================================================
nvd_client: Optional[NVDClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager: handles startup database initialization,
    HTTP client setup, and graceful shutdown.
    """
    global nvd_client
    logger.info("Initializing NVD Vulnerability Service...")

    # 1. Initialize NVD Client
    nvd_client = NVDClient()

    # 2. Verify Database connection & ensure tables exist
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            logger.info("Connected successfully to PostgreSQL database.")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified/created successfully.")
    except Exception as e:
        logger.warning(
            f"Could not connect to database during startup ({e}). "
            "Service will start and retry connections during requests."
        )

    yield

    # Shutdown logic
    logger.info("Shutting down NVD Vulnerability Service...")
    if nvd_client:
        await nvd_client.close()
        logger.info("NVD HTTP client closed.")
    engine.dispose()
    logger.info("Database engine connections disposed.")


app = FastAPI(
    title="SecOps Astrea - NVD Vulnerability Analyst API",
    version="1.0.0",
    description="Microservicio de detección y análisis de vulnerabilidades NIST NVD API 2.0 con caché en PostgreSQL.",
    lifespan=lifespan
)

# Enable CORS for internal platform microservices and dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Exception Handlers
# ============================================================================
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validation error on {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Entrada inválida", "errors": exc.errors()}
    )


@app.exception_handler(NVDRateLimitError)
async def rate_limit_exception_handler(request: Request, exc: NVDRateLimitError):
    logger.error(f"Rate limit exceeded querying NVD API: {exc}")
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Límite de solicitudes de NIST NVD excedido. Intente nuevamente en unos instantes."}
    )


@app.exception_handler(NVDTimeoutError)
async def timeout_exception_handler(request: Request, exc: NVDTimeoutError):
    logger.error(f"Timeout querying NVD API: {exc}")
    return JSONResponse(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        content={"detail": "Tiempo de espera agotado al consultar NIST NVD API."}
    )


@app.exception_handler(NVDClientError)
async def nvd_client_exception_handler(request: Request, exc: NVDClientError):
    logger.error(f"NVD Client error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content={"detail": f"Error en la comunicación con NIST NVD API: {str(exc)}"}
    )


# ============================================================================
# Cache Helper Functions
# ============================================================================
def _parse_datetime(dt_val) -> Optional[datetime]:
    """Helper to ensure datetime objects are passed to SQLAlchemy."""
    if isinstance(dt_val, str):
        try:
            return datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt_val


def upsert_vulnerability(db: Session, vuln_data: dict) -> NVDVulnerability:
    """
    Inserts or updates a vulnerability record in 'nvd_vulnerabilities'.
    """
    cve_id = vuln_data["cve_id"].strip().upper()
    now_utc = datetime.now(timezone.utc)

    pub_date = _parse_datetime(vuln_data.get("published_date"))
    mod_date = _parse_datetime(vuln_data.get("last_modified_date"))

    existing = db.query(NVDVulnerability).filter(NVDVulnerability.cve_id == cve_id).first()

    if existing:
        existing.description = vuln_data.get("description")
        existing.cvss_score = vuln_data.get("cvss_score")
        existing.cvss_vector = vuln_data.get("cvss_vector")
        existing.severity = vuln_data.get("severity")
        existing.cwe_id = vuln_data.get("cwe_id")
        existing.has_active_exploit = vuln_data.get("has_active_exploit", False)
        existing.published_date = pub_date
        existing.last_modified_date = mod_date
        existing.updated_at = now_utc
        return existing
    else:
        new_vuln = NVDVulnerability(
            cve_id=cve_id,
            description=vuln_data.get("description"),
            cvss_score=vuln_data.get("cvss_score"),
            cvss_vector=vuln_data.get("cvss_vector"),
            severity=vuln_data.get("severity"),
            cwe_id=vuln_data.get("cwe_id"),
            has_active_exploit=vuln_data.get("has_active_exploit", False),
            published_date=pub_date,
            last_modified_date=mod_date,
            updated_at=now_utc
        )
        db.add(new_vuln)
        return new_vuln


# ============================================================================
# Endpoints
# ============================================================================

@app.get("/", tags=["Info"])
async def root():
    """Root endpoint with service identity and documentation reference."""
    return {
        "service": "SecOps Astrea NVD Vulnerability Service",
        "status": "running",
        "documentation": "/docs",
        "health": "/health",
        "version": "1.0.0"
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
    """
    Service health check endpoint.
    Validates PostgreSQL connectivity and NVD API configuration.
    """
    db_status = "connected"
    http_status_code = status.HTTP_200_OK

    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database healthcheck failed: {e}")
        db_status = f"disconnected: {str(e)}"
        http_status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    nvd_configured = bool(os.getenv("NVD_API_KEY", "").strip())

    response_payload = HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        database=db_status,
        nvd_api_configured=nvd_configured,
        timestamp=datetime.now(timezone.utc),
        version="1.0.0"
    )

    if http_status_code != status.HTTP_200_OK:
        return JSONResponse(status_code=http_status_code, content=response_payload.model_dump(mode="json"))

    return response_payload


@app.post(
    "/api/v1/vulnerabilities/check",
    response_model=VulnerabilityCheckResponse,
    tags=["Vulnerabilities"]
)
async def check_vulnerabilities(
    request: VulnerabilityCheckRequest,
    db: Session = Depends(get_db)
):
    """
    Check software vulnerabilities by software name + version or CVE ID.
    Queries local PostgreSQL cache first. If absent or force_refresh is requested,
    queries NIST NVD API 2.0 asynchronously and updates the cache.
    """
    global nvd_client
    if not nvd_client:
        nvd_client = NVDClient()

    # Determine query representation
    query_str = ""
    if request.cve_id:
        query_str = request.cve_id
    elif request.software_name and request.version:
        query_str = f"{request.software_name} {request.version}"
    else:
        query_str = request.software_name or ""

    logger.info(f"Checking vulnerabilities for query: '{query_str}' (force_refresh={request.force_refresh})")

    # =========================================================================
    # Branch 1: Search by direct CVE ID
    # =========================================================================
    cve_regex = re.compile(r"^CVE-\d{4}-\d{4,8}$", re.IGNORECASE)
    is_direct_cve = bool(request.cve_id or (request.software_name and cve_regex.match(request.software_name.strip())))
    target_cve = (request.cve_id or (request.software_name if is_direct_cve else "")).strip().upper()

    if is_direct_cve and target_cve:
        # 1. Check PostgreSQL cache
        if not request.force_refresh:
            try:
                cached_cve = db.query(NVDVulnerability).filter(NVDVulnerability.cve_id == target_cve).first()
                if cached_cve:
                    logger.info(f"Cache HIT for CVE '{target_cve}'")
                    item = VulnerabilityItem(
                        cve_id=cached_cve.cve_id,
                        description=cached_cve.description,
                        cvss_score=float(cached_cve.cvss_score) if cached_cve.cvss_score is not None else None,
                        cvss_vector=cached_cve.cvss_vector,
                        severity=cached_cve.severity,
                        cwe_id=cached_cve.cwe_id,
                        has_active_exploit=bool(cached_cve.has_active_exploit),
                        published_date=cached_cve.published_date,
                        last_modified_date=cached_cve.last_modified_date,
                        source="CACHE"
                    )
                    return VulnerabilityCheckResponse(
                        query=target_cve,
                        software_name=request.software_name,
                        version=request.version,
                        cve_id=target_cve,
                        total_vulnerabilities=1,
                        cached=True,
                        vulnerabilities=[item],
                        message="Vulnerabilidad recuperada exitosamente desde caché local."
                    )
            except SQLAlchemyError as db_err:
                logger.warning(f"Database cache read failed for {target_cve}: {db_err}. Proceeding to NVD API.")

        # 2. Query NIST NVD API 2.0
        logger.info(f"Cache MISS for CVE '{target_cve}'. Querying NVD API 2.0...")
        nvd_data = await nvd_client.get_cve_by_id(target_cve)

        if not nvd_data:
            return VulnerabilityCheckResponse(
                query=target_cve,
                software_name=request.software_name,
                version=request.version,
                cve_id=target_cve,
                total_vulnerabilities=0,
                cached=False,
                vulnerabilities=[],
                message=f"No se encontró registro para {target_cve} en NIST NVD."
            )

        # 3. Cache result in PostgreSQL
        try:
            upsert_vulnerability(db, nvd_data)
            db.commit()
            logger.info(f"Successfully cached {target_cve} in PostgreSQL.")
        except SQLAlchemyError as db_err:
            db.rollback()
            logger.error(f"Failed to cache {target_cve} in PostgreSQL: {db_err}")

        item = VulnerabilityItem(**nvd_data)
        return VulnerabilityCheckResponse(
            query=target_cve,
            software_name=request.software_name,
            version=request.version,
            cve_id=target_cve,
            total_vulnerabilities=1,
            cached=False,
            vulnerabilities=[item],
            message="Vulnerabilidad consultada exitosamente desde NIST NVD API y almacenada en caché."
        )

    # =========================================================================
    # Branch 2: Search by Software Name and Version
    # =========================================================================
    software = request.software_name or ""
    version = request.version or ""

    # 1. Search PostgreSQL cache
    if not request.force_refresh and software:
        try:
            query = db.query(NVDVulnerability)
            query = query.filter(NVDVulnerability.description.ilike(f"%{software}%"))
            if version:
                query = query.filter(NVDVulnerability.description.ilike(f"%{version}%"))

            cached_records = query.order_by(NVDVulnerability.cvss_score.desc().nullslast()).all()

            if cached_records:
                logger.info(f"Cache HIT for software '{query_str}': found {len(cached_records)} records.")
                items = [
                    VulnerabilityItem(
                        cve_id=r.cve_id,
                        description=r.description,
                        cvss_score=float(r.cvss_score) if r.cvss_score is not None else None,
                        cvss_vector=r.cvss_vector,
                        severity=r.severity,
                        cwe_id=r.cwe_id,
                        has_active_exploit=bool(r.has_active_exploit),
                        published_date=r.published_date,
                        last_modified_date=r.last_modified_date,
                        source="CACHE"
                    )
                    for r in cached_records
                ]
                return VulnerabilityCheckResponse(
                    query=query_str,
                    software_name=software,
                    version=version or None,
                    cve_id=None,
                    total_vulnerabilities=len(items),
                    cached=True,
                    vulnerabilities=items,
                    message=f"Se encontraron {len(items)} vulnerabilidades en caché local."
                )
        except SQLAlchemyError as db_err:
            logger.warning(f"Database cache search failed: {db_err}. Querying NVD API directly.")

    # 2. Query NIST NVD API 2.0
    logger.info(f"Querying NVD API 2.0 for software '{query_str}'...")
    raw_results = await nvd_client.search_vulnerabilities(software, version, limit=25)

    # 3. Cache results in PostgreSQL
    cached_count = 0
    if raw_results:
        try:
            for vuln in raw_results:
                upsert_vulnerability(db, vuln)
                cached_count += 1
            db.commit()
            logger.info(f"Successfully cached {cached_count} vulnerabilities in PostgreSQL for '{query_str}'.")
        except SQLAlchemyError as db_err:
            db.rollback()
            logger.error(f"Error persisting NVD results in database: {db_err}")

    items = [VulnerabilityItem(**vuln) for vuln in raw_results]

    return VulnerabilityCheckResponse(
        query=query_str,
        software_name=software,
        version=version or None,
        cve_id=None,
        total_vulnerabilities=len(items),
        cached=False,
        vulnerabilities=items,
        message=(
            f"Se obtuvieron {len(items)} vulnerabilidades desde NIST NVD API y fueron guardadas en caché."
            if items else "No se encontraron vulnerabilidades para el software especificado."
        )
    )


@app.get(
    "/api/v1/vulnerabilities/{cve_id}",
    response_model=VulnerabilityCheckResponse,
    tags=["Vulnerabilities"]
)
async def get_vulnerability_by_cve(
    cve_id: str,
    force_refresh: bool = False,
    db: Session = Depends(get_db)
):
    """
    Convenience endpoint for direct CVE lookup via GET.
    """
    req = VulnerabilityCheckRequest(cve_id=cve_id, force_refresh=force_refresh)
    return await check_vulnerabilities(req, db)
