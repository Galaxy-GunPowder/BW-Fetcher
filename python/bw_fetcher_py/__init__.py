"""bw_fetcher_py — Python wrapper + bot-detection for BW-Fetcher (C++).

C++ ``BW-Fetcher-win64.exe`` / ``BW-Fetcher-linux64`` performs TLS-fingerprinted fetches.
Python classifies headers + HTML (+ optional challenge script downloads).

Example
-------
    >>> from bw_fetcher_py import probe
    >>> r = probe("https://example.com", fetch_challenge_scripts=True)
    >>> r.vendor
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ._locate import find_exe
from .detection import analyze, BotDetectionReport
from .probe import analyze_html_file, fetch_artifacts, probe

__all__ = [
    "fetch",
    "list_profiles",
    "probe",
    "fetch_artifacts",
    "analyze_html_file",
    "analyze",
    "FetchResult",
    "FetchError",
    "BotDetectionReport",
]


class FetchError(RuntimeError):
    """Raised when the BW-Fetcher process fails."""


@dataclass
class FetchResult:
    status: int
    body: bytes
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    ttfb_ms: int = 0
    profile: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def __repr__(self) -> str:
        return (f"FetchResult(status={self.status}, bytes={len(self.body)}, "
                f"url={self.url!r}, profile={self.profile!r})")


def _parse_summary(stdout: str) -> dict:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {}


def fetch(
    url: str,
    profile: str = "Chrome143",
    proxy: Optional[str] = None,
    proxy_user: Optional[str] = None,
    proxy_pass: Optional[str] = None,
    max_redirects: int = 5,
    timeout: float = 60.0,
    exe: Optional[str] = None,
) -> FetchResult:
    """Fetch ``url`` via native BW-Fetcher (Chrome/Firefox TLS fingerprint)."""
    ok, art = fetch_artifacts(
        url,
        profile=profile,
        proxy=proxy,
        proxy_user=proxy_user,
        proxy_pass=proxy_pass,
        max_redirects=max_redirects,
        timeout=timeout,
        exe=exe,
    )
    if not ok:
        raise FetchError(art.get("fetch_error") or "BW-Fetcher failed")
    return FetchResult(
        status=art["status"],
        body=art["body"],
        url=art["final_url"],
        headers=art["headers"],
        ttfb_ms=art["ttfb_ms"],
        profile=art["profile"],
    )


def list_profiles(exe: Optional[str] = None) -> List[str]:
    exe_path = find_exe(exe)
    proc = subprocess.run([str(exe_path), "--list-profiles"],
                          capture_output=True, timeout=15)
    out = proc.stdout.decode("utf-8", errors="replace")
    return [line.strip() for line in out.splitlines() if line.strip()]
