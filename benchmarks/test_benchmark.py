"""Smoke tests for the benchmark harness (network required)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

BENCH_ROOT = Path(__file__).resolve().parent
REPO_ROOT = BENCH_ROOT.parent
RUN_PY = BENCH_ROOT / "run.py"


@pytest.fixture(scope="module")
def tiny_urls(tmp_path_factory):
    path = tmp_path_factory.mktemp("urls") / "tiny.json"
    path.write_text(
        json.dumps(
            {
                "urls": [
                    {"name": "example", "url": "https://example.com", "min_bytes": 100},
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_list_clients():
    proc = subprocess.run(
        [sys.executable, str(RUN_PY), "list-clients"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0
    assert "bw_fetcher_py" in proc.stdout


@pytest.mark.network
def test_quick_benchmark(tiny_urls):
    proc = subprocess.run(
        [
            sys.executable,
            str(RUN_PY),
            "--urls",
            str(tiny_urls),
            "--runs",
            "1",
            "--warmup",
            "0",
            "--clients",
            "urllib",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    assert "Results saved:" in proc.stdout

    latest = BENCH_ROOT / "results" / "latest.json"
    assert latest.is_file()
    data = json.loads(latest.read_text(encoding="utf-8"))
    assert data["timings"]
