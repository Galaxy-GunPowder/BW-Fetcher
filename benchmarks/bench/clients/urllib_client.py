"""stdlib urllib client baseline."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Optional, Tuple

from .base import HttpClient


class UrllibClient(HttpClient):
    name = "urllib"
    description = "Python urllib (stdlib, HTTP/1.1)"

    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "BW-Fetcher-Benchmark/1.0"},
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                first_byte_at = time.perf_counter()
                body = response.read()
                status = getattr(response, "status", 200)
        except urllib.error.HTTPError as e:
            body = e.read()
            status = e.code
            first_byte_at = time.perf_counter()

        ttfb_ms = (first_byte_at - t0) * 1000.0
        return status, body, ttfb_ms
