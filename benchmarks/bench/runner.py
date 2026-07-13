"""Benchmark execution engine."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .clients import available_clients
from .models import BenchmarkSuite, FetchTiming, new_suite


def load_urls(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("urls", data))


def run_benchmark(
    urls_path: Path,
    *,
    client_names: Optional[List[str]] = None,
    runs: int = 3,
    warmup: int = 1,
    timeout: float = 60.0,
    profile: str = "Chrome143",
    bw_fetcher_exe: Optional[str] = None,
) -> BenchmarkSuite:
    """Fetch every URL with every available client; return stored suite."""
    url_entries = load_urls(urls_path)
    clients = available_clients(client_names)
    if not clients:
        raise RuntimeError("No benchmark clients available. Build BW_Fetcher or install optional deps.")

    if "bw_fetcher_py" in clients:
        from .clients.bw_fetcher import BwFetcherClient

        clients["bw_fetcher_py"] = BwFetcherClient(exe=bw_fetcher_exe, profile=profile)

    config = {
        "urls_file": str(urls_path),
        "runs": runs,
        "warmup": warmup,
        "timeout_s": timeout,
        "profile": profile,
        "url_count": len(url_entries),
    }
    suite = new_suite(config, sorted(clients.keys()))

    total_attempts = len(url_entries) * len(clients) * (warmup + runs)
    attempt = 0

    for entry in url_entries:
        name = entry.get("name") or entry["url"]
        url = entry["url"]
        min_bytes = int(entry.get("min_bytes", 0))

        for client_name, client in clients.items():
            for run_idx in range(warmup + runs):
                is_warmup = run_idx < warmup
                attempt += 1
                label = f"[{attempt}/{total_attempts}] {client_name} {name}"
                print(f"{label} ...", end=" ", flush=True)

                timing = _timed_fetch(
                    client_name=client_name,
                    client=client,
                    url_name=name,
                    url=url,
                    min_bytes=min_bytes,
                    timeout=timeout,
                    run_index=run_idx - warmup if not is_warmup else run_idx,
                    is_warmup=is_warmup,
                )
                suite.timings.append(timing)

                if timing.ok:
                    ttfb = f"{timing.ttfb_ms:.0f}ms" if timing.ttfb_ms is not None else "n/a"
                    print(
                        f"OK {timing.status} "
                        f"{timing.total_ms:.0f}ms "
                        f"ttfb={ttfb} "
                        f"{timing.bytes_received // 1024}KB"
                    )
                else:
                    print(f"FAIL {timing.error[:80]}")

    return suite


def _timed_fetch(
    *,
    client_name: str,
    client,
    url_name: str,
    url: str,
    min_bytes: int,
    timeout: float,
    run_index: int,
    is_warmup: bool,
) -> FetchTiming:
    t0 = time.perf_counter()
    try:
        status, body, ttfb_ms = client.fetch(url, timeout=timeout)
        total_ms = (time.perf_counter() - t0) * 1000.0
        ok = 200 <= status < 400 and len(body) >= min_bytes
        error = ""
        if not (200 <= status < 400):
            error = f"HTTP {status}"
        elif len(body) < min_bytes:
            error = f"body too small ({len(body)} < {min_bytes})"
    except Exception as exc:
        total_ms = (time.perf_counter() - t0) * 1000.0
        status, body, ttfb_ms = 0, b"", None
        ok = False
        error = str(exc)

    return FetchTiming(
        client=client_name,
        url_name=url_name,
        url=url,
        ok=ok,
        status=status,
        bytes_received=len(body),
        total_ms=total_ms,
        ttfb_ms=ttfb_ms,
        error=error,
        run_index=run_index,
        is_warmup=is_warmup,
    )
