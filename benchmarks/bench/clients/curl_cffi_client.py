"""curl_cffi client — the closest peer to BW_Fetcher.

curl_cffi binds libcurl-impersonate, so like BW_Fetcher it sends a real
browser TLS (JA3/JA4) + HTTP/2 fingerprint and gets past bot detection that
blocks plain requests/httpx. This is the apples-to-apples comparison.
"""
from __future__ import annotations

import time
from typing import Optional, Tuple

from .base import HttpClient

try:
    from curl_cffi import requests as _cffi_requests

    _CURL_CFFI = True
except ImportError:
    _CURL_CFFI = False


class CurlCffiClient(HttpClient):
    name = "curl_cffi"
    description = "curl_cffi (curl-impersonate, Chrome TLS+HTTP/2 fingerprint)"

    def __init__(self, impersonate: str = "chrome") -> None:
        self._impersonate = impersonate

    @classmethod
    def is_available(cls) -> bool:
        return _CURL_CFFI

    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        t0 = time.perf_counter()
        resp = _cffi_requests.get(
            url,
            impersonate=self._impersonate,
            timeout=timeout,
            allow_redirects=True,
        )
        # curl_cffi buffers the full body, so a true TTFB isn't exposed here;
        # the runner still measures total wall-clock externally.
        first_byte_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status_code, resp.content, first_byte_ms
