"""
Re-export client for app namespace.
"""
try:
    from client_nvd import (
        NVDClient,
        NVDClientError,
        NVDRateLimitError,
        NVDTimeoutError,
    )
except ImportError:
    from ..client_nvd import (
        NVDClient,
        NVDClientError,
        NVDRateLimitError,
        NVDTimeoutError,
    )

__all__ = [
    "NVDClient",
    "NVDClientError",
    "NVDRateLimitError",
    "NVDTimeoutError",
]
