"""requests client (HTTP/1.1 via urllib3)."""
from __future__ import annotations

import time
from typing import Optional, Tuple

from .base import HttpClient

try:
    import requests as req_lib

    _REQUESTS = True
except ImportError:
    _REQUESTS = False


class RequestsClient(HttpClient):
    name = "requests"
    description = "Python requests (urllib3, typically HTTP/1.1)"

    @classmethod
    def is_available(cls) -> bool:
        return _REQUESTS

    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        t0 = time.perf_counter()
        response = req_lib.get(url, timeout=timeout, allow_redirects=True, stream=True)
        first_byte_at: Optional[float] = None
        chunks = []
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                if first_byte_at is None:
                    first_byte_at = time.perf_counter()
                chunks.append(chunk)
        body = b"".join(chunks)
        ttfb_ms = (first_byte_at - t0) * 1000.0 if first_byte_at else None
        return response.status_code, body, ttfb_ms
