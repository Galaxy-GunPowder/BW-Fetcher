"""Registry of benchmark HTTP clients."""
from __future__ import annotations

from typing import Dict, List, Type

from .base import HttpClient
from .bw_fetcher import BwFetcherClient
from .curl_cffi_client import CurlCffiClient
from .curl_client import CurlClient
from .httpx_client import HttpxClient
from .requests_client import RequestsClient
from .urllib_client import UrllibClient

ALL_CLIENTS: List[Type[HttpClient]] = [
    BwFetcherClient,
    CurlCffiClient,
    CurlClient,
    HttpxClient,
    RequestsClient,
    UrllibClient,
]


def available_clients(names: List[str] | None = None) -> Dict[str, HttpClient]:
    """Instantiate clients that are installed and requested."""
    selected = {}
    for cls in ALL_CLIENTS:
        if names and cls.name not in names:
            continue
        if not cls.is_available():
            continue
        selected[cls.name] = cls()
    return selected


def list_client_info() -> List[dict]:
    rows = []
    for cls in ALL_CLIENTS:
        rows.append(
            {
                "name": cls.name,
                "description": cls.description,
                "available": cls.is_available(),
            }
        )
    return rows
