"""
Re-export FastAPI app for app.main namespace.
Allows starting the server using either 'uvicorn main:app' or 'uvicorn app.main:app'.
"""
try:
    from main import app, get_db, upsert_vulnerability
except ImportError:
    from ..main import app, get_db, upsert_vulnerability

__all__ = ["app", "get_db", "upsert_vulnerability"]
