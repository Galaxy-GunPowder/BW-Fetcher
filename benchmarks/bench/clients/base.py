"""Abstract HTTP client adapter for benchmarks."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class HttpClient(ABC):
    """Fetch a URL and return (status, body_bytes, ttfb_ms_or_none)."""

    name: str
    description: str

    @abstractmethod
    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        """Perform one fetch. Raise on hard failures."""

    @classmethod
    def is_available(cls) -> bool:
        return True
