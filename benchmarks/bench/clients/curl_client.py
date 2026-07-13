"""curl subprocess client (HTTP/2 when supported, else HTTP/1.1)."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from .base import HttpClient

_HTTP2_SUPPORTED: Optional[bool] = None


def _curl_supports_http2() -> bool:
    global _HTTP2_SUPPORTED
    if _HTTP2_SUPPORTED is not None:
        return _HTTP2_SUPPORTED
    if not shutil.which("curl"):
        _HTTP2_SUPPORTED = False
        return False
    proc = subprocess.run(
        ["curl", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    out = (proc.stdout + proc.stderr).lower()
    _HTTP2_SUPPORTED = "http2" in out and "not compiled in" not in out
    return _HTTP2_SUPPORTED


class CurlClient(HttpClient):
    name = "curl"
    description = "curl (HTTP/2 when libcurl supports it, else HTTP/1.1)"

    def __init__(self, http2: Optional[bool] = None) -> None:
        if http2 is None:
            self._http2 = _curl_supports_http2()
        else:
            self._http2 = http2
        if self._http2:
            self.description = "curl --http2 (system TLS stack)"
        else:
            self.description = "curl HTTP/1.1 (no HTTP/2 in this libcurl build)"

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("curl") is not None

    def fetch(self, url: str, timeout: float) -> Tuple[int, bytes, Optional[float]]:
        fmt = "%{http_code}|%{size_download}|%{time_starttransfer}|%{time_total}"
        with tempfile.TemporaryDirectory(prefix="curl_bench_") as td:
            out_file = Path(td) / "body.bin"
            args = [
                "curl",
                "-sS",
                "-L",
                "--max-time",
                str(max(1, int(timeout))),
                "-o",
                str(out_file),
                "-w",
                fmt,
            ]
            if self._http2:
                args.insert(1, "--http2")
            args.append(url)

            proc = subprocess.run(
                args, capture_output=True, timeout=timeout + 5, check=False
            )
            if proc.returncode != 0:
                err = proc.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(err or f"curl exit {proc.returncode}")

            trailer = proc.stdout.decode("ascii", errors="replace").strip()
            fields = trailer.split("|")
            if len(fields) != 4:
                raise RuntimeError(f"curl: unexpected trailer: {trailer!r}")

            status = int(fields[0] or "0")
            ttfb_ms = float(fields[2]) * 1000.0
            body = out_file.read_bytes() if out_file.exists() else b""
            return status, body, ttfb_ms
