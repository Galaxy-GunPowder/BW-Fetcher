"""httpx client with HTTP/2."""
from __future__ import annotations

import time
from typing import Optional, Tuple

from .base import HttpClient

try:
    import httpx

    _HTTPX = True
except ImportError:
    _HTTPX = False


class HttpxClient(HttpClient):
    name = "httpx"
    description = "Python httpx with HTTP/2 (h2)"

    def __init__(self, http2: bool = True) -> None:
        self._http2 = http2

    @classmethod
    def is_available(cls) -> bool:
        if not _HTTPX:
            return False
        try:
            import h2  # noqa: F401

            return True
        except ImportError:
            return False

    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        t0 = time.perf_counter()
        with httpx.Client(http2=self._http2, follow_redirects=True, timeout=timeout) as client:
            with client.stream("GET", url) as response:
                first_byte_at: Optional[float] = None
                chunks = []
                for chunk in response.iter_bytes():
                    if first_byte_at is None:
                        first_byte_at = time.perf_counter()
                    chunks.append(chunk)
                body = b"".join(chunks)
                status = response.status_code

        total_ms = (time.perf_counter() - t0) * 1000.0
        ttfb_ms = (first_byte_at - t0) * 1000.0 if first_byte_at else total_ms
        # total_ms is measured externally by runner; return ttfb only from client
        return status, body, ttfb_ms
