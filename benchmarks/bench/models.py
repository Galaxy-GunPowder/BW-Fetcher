"""Data models for benchmark runs and stored results."""
from __future__ import annotations

import json
import platform
import socket
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class FetchTiming:
    """Outcome of a single fetch attempt."""

    client: str
    url_name: str
    url: str
    ok: bool
    status: int = 0
    bytes_received: int = 0
    total_ms: float = 0.0
    ttfb_ms: Optional[float] = None
    error: str = ""
    run_index: int = 0
    is_warmup: bool = False

    @property
    def throughput_kbps(self) -> float:
        if self.total_ms <= 0 or self.bytes_received <= 0:
            return 0.0
        return (self.bytes_received * 8.0) / self.total_ms

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkSuite:
    """Full benchmark session written to disk."""

    created_at: str
    hostname: str
    platform: str
    python_version: str
    config: Dict[str, Any]
    clients: List[str]
    timings: List[FetchTiming] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "created_at": self.created_at,
            "hostname": self.hostname,
            "platform": self.platform,
            "python_version": self.python_version,
            "config": self.config,
            "clients": self.clients,
            "timings": [t.to_dict() for t in self.timings],
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "BenchmarkSuite":
        data = json.loads(path.read_text(encoding="utf-8"))
        timings = [FetchTiming(**t) for t in data.get("timings", [])]
        return cls(
            created_at=data["created_at"],
            hostname=data.get("hostname", ""),
            platform=data.get("platform", ""),
            python_version=data.get("python_version", ""),
            config=data.get("config", {}),
            clients=data.get("clients", []),
            timings=timings,
        )


def new_suite(config: Dict[str, Any], clients: List[str]) -> BenchmarkSuite:
    return BenchmarkSuite(
        created_at=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname(),
        platform=platform.platform(),
        python_version=sys.version.split()[0],
        config=config,
        clients=clients,
    )
