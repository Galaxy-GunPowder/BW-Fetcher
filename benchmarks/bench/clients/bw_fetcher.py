"""BW_Fetcher native executable client."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from .base import HttpClient

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PYTHON_PKG = _REPO_ROOT / "python"
if str(_PYTHON_PKG) not in sys.path:
    sys.path.insert(0, str(_PYTHON_PKG))

from bw_fetcher_py._locate import find_exe  # noqa: E402


class BwFetcherClient(HttpClient):
    name = "bw_fetcher_py"
    description = "BW-Fetcher (BoringSSL + nghttp2, Chrome TLS fingerprint)"

    def __init__(self, exe: Optional[str] = None, profile: str = "Chrome143") -> None:
        self._exe = find_exe(exe)
        self._profile = profile

    @classmethod
    def is_available(cls) -> bool:
        try:
            find_exe()
            return True
        except FileNotFoundError:
            return False

    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        with tempfile.TemporaryDirectory(prefix="bw_bench_") as td:
            out_file = Path(td) / "body.bin"
            args = [
                str(self._exe),
                "--url",
                url,
                "--profile",
                self._profile,
                "--out",
                str(out_file),
            ]
            proc = subprocess.run(
                args,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode != 0:
                stderr = proc.stderr.decode("utf-8", errors="replace").strip()
                tail = stderr.splitlines()[-1] if stderr else f"exit {proc.returncode}"
                raise RuntimeError(tail)

            body = out_file.read_bytes() if out_file.exists() else b""
            summary = self._parse_summary(proc.stdout.decode("utf-8", errors="replace"))
            status = int(summary.get("status", 0))
            ttfb = float(summary.get("ttfb_ms", 0)) or None
            return status, body, ttfb

    @staticmethod
    def _parse_summary(stdout: str) -> dict:
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {}
