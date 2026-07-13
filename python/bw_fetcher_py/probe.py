"""Fetch with BW_Fetcher (C++), analyze in Python, optionally fetch challenge JS."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from ._locate import find_exe
from .detection import analyze
from .detection.models import BotDetectionReport
from .detection.script_urls import extract_script_srcs, filter_challenge_script_urls


def _parse_summary(stdout: str) -> dict:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {}


def fetch_artifacts(
    url: str,
    *,
    profile: str = "Chrome143",
    proxy: Optional[str] = None,
    proxy_user: Optional[str] = None,
    proxy_pass: Optional[str] = None,
    max_redirects: int = 5,
    timeout: float = 60.0,
    exe: Optional[str] = None,
    also_fetch: Optional[List[str]] = None,
    auto_challenge_scripts: bool = False,
    max_challenge_scripts: int = 5,
    fetch_subresources: bool = False,
    max_subresources: int = 32,
) -> tuple[bool, dict]:
    """Run native BW_Fetcher.exe — returns (fetch_ok, artifacts dict).

    ``fetch_subresources`` scans the HTML **as it streams in** and GETs each
    discovered script URL (same-host on one HTTP/2 connection). Bodies land under
    ``also_bodies`` as ``[(url, bytes), ...]``; primary body is the page HTML.
    """
    exe_path = find_exe(exe)
    native_timeout_ms = max(1000, int(timeout * 1000) - 2000)
    extra_urls = also_fetch or []
    multi = bool(extra_urls) or auto_challenge_scripts or fetch_subresources

    with tempfile.TemporaryDirectory(prefix="bw_probe_") as td:
        td_path = Path(td)
        out_file = td_path / "response.bin"
        bundle_dir = td_path / "bundle"
        also_dir = td_path / "also"
        args = [
            str(exe_path),
            "--url", url,
            "--profile", profile,
            "--max-redirects", str(max_redirects),
            "--timeout", str(native_timeout_ms),
        ]
        if fetch_subresources:
            bundle_dir.mkdir()
            args += [
                "--fetch-subresources",
                "--max-subresources", str(max_subresources),
                "--out-dir", str(bundle_dir),
            ]
        else:
            args += ["--out", str(out_file)]
            if multi:
                also_dir.mkdir()
                args += ["--also-out-dir", str(also_dir)]
        if extra_urls:
            for u in extra_urls:
                args += ["--also-fetch", u]
        if auto_challenge_scripts and not fetch_subresources:
            args += [
                "--auto-challenge-scripts",
                "--max-challenge-scripts", str(max_challenge_scripts),
            ]

        env = os.environ.copy()
        if proxy:
            args += ["--proxy", proxy]
            if proxy_user:
                env["BW_FETCHER_PROXY_USER"] = proxy_user
            if proxy_pass:
                env["BW_FETCHER_PROXY_PASS"] = proxy_pass

        try:
            proc = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return False, {
                "target": url,
                "final_url": url,
                "status": 0,
                "headers": {},
                "body": b"",
                "also_bodies": [],
                "ttfb_ms": 0,
                "profile": profile,
                "fetch_ok": False,
                "fetch_error": f"timed out after {timeout}s",
                "stderr": "",
            }

        stderr = proc.stderr.decode("utf-8", errors="replace")
        stdout = proc.stdout.decode("utf-8", errors="replace")
        summary = _parse_summary(stdout)

        if fetch_subresources:
            run_dir_str = summary.get("run_dir")
            if run_dir_str:
                req_root = Path(run_dir_str) / "requests"
            else:
                run_candidates = sorted(
                    bundle_dir.glob("*/requests"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                req_root = run_candidates[0] if run_candidates else bundle_dir / "requests"
            primary_matches = sorted(req_root.glob("fetched/primary/*/000-primary/body.html"))
            if not primary_matches:
                primary_matches = sorted(req_root.glob("fetched/primary/*/*/body.html"))
            if not primary_matches:
                primary_matches = sorted(req_root.glob("primary/*/000-primary/body.html"))
            if not primary_matches:
                primary_matches = sorted(req_root.glob("primary/*/*/body.html"))
            if not primary_matches:
                primary_matches = sorted(req_root.glob("*/*/*-primary/body.*"))
            primary_path = primary_matches[0] if primary_matches else (
                req_root / "fetched" / "primary" / "html" / "000-primary" / "body.html"
            )
            body = primary_path.read_bytes() if primary_path.is_file() else b""
        else:
            body = out_file.read_bytes() if out_file.exists() else b""

        also_bodies: List[Tuple[str, bytes]] = []
        for sub in summary.get("subresources") or []:
            if not isinstance(sub, dict) or not sub.get("ok"):
                continue
            out_path = sub.get("out")
            if not out_path:
                continue
            p = Path(out_path)
            if p.is_file():
                also_bodies.append((sub.get("url", ""), p.read_bytes()))
        if fetch_subresources and not also_bodies:
            run_dir_str = summary.get("run_dir")
            if run_dir_str:
                req_root = Path(run_dir_str) / "requests"
            else:
                run_candidates = sorted(
                    bundle_dir.glob("*/requests"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                req_root = run_candidates[0] if run_candidates else bundle_dir / "requests"
            if req_root.is_dir():
                globs = [
                    "fetched/*/*/*/meta.json",
                    "*/*/*/meta.json",
                ]
                for pattern in globs:
                    for meta_path in sorted(req_root.glob(pattern)):
                        if meta_path.parent.name.endswith("-primary"):
                            continue
                        try:
                            meta = json.loads(meta_path.read_text(encoding="utf-8"))
                        except (json.JSONDecodeError, OSError):
                            continue
                        if meta.get("disposition") == "present":
                            continue
                        body_candidates = list(meta_path.parent.glob("body.*"))
                        if not body_candidates:
                            continue
                        also_bodies.append((meta.get("url", ""), body_candidates[0].read_bytes()))
                    if also_bodies:
                        break

        fetch_ok = proc.returncode == 0
        error = ""
        if not fetch_ok:
            error = next((l.strip() for l in reversed(stderr.splitlines()) if l.strip()), "")
            if error.startswith("[ERROR] Fetch failed:"):
                error = error.split(":", 1)[-1].strip()

        headers: Dict[str, str] = (
            summary.get("headers") if isinstance(summary.get("headers"), dict) else {}
        )

        return fetch_ok, {
            "target": url,
            "final_url": summary.get("url", url),
            "status": int(summary.get("status", 0)),
            "headers": headers,
            "body": body,
            "also_bodies": also_bodies,
            "ttfb_ms": int(summary.get("ttfb_ms", 0)),
            "profile": summary.get("profile", profile),
            "fetch_ok": fetch_ok,
            "fetch_error": error or None,
            "stderr": stderr,
        }


def probe(
    url: str,
    *,
    profile: str = "Chrome143",
    proxy: Optional[str] = None,
    proxy_user: Optional[str] = None,
    proxy_pass: Optional[str] = None,
    max_redirects: int = 5,
    timeout: float = 60.0,
    exe: Optional[str] = None,
    fetch_challenge_scripts: bool = False,
    max_challenge_scripts: int = 5,
    fetch_subresources: bool = False,
    max_subresources: int = 32,
) -> BotDetectionReport:
    """Fetch page with C++ BW_Fetcher, analyze in Python.

    ``fetch_subresources=True`` scans HTML **while it downloads** and GETs each
    ``<script src>`` (plus preload hints) — browser-style, not post-hoc.
    """
    fetch_ok, art = fetch_artifacts(
        url,
        profile=profile,
        proxy=proxy,
        proxy_user=proxy_user,
        proxy_pass=proxy_pass,
        max_redirects=max_redirects,
        timeout=timeout,
        exe=exe,
        auto_challenge_scripts=fetch_challenge_scripts,
        max_challenge_scripts=max_challenge_scripts,
        fetch_subresources=fetch_subresources,
        max_subresources=max_subresources,
    )

    external: List[Tuple[str, bytes]] = list(art.get("also_bodies") or [])
    fetched_sizes: Dict[str, int] = {u: len(b) for u, b in external}

    return analyze(
        art["target"],
        status=art["status"],
        headers=art["headers"],
        body=art["body"],
        fetch_ok=fetch_ok,
        fetch_error=art["fetch_error"],
        final_url=art["final_url"],
        ttfb_ms=art["ttfb_ms"],
        profile=art["profile"],
        external_script_bodies=external,
        fetched_scripts=fetched_sizes,
    )


def analyze_html_file(
    html_path: Union[str, Path],
    *,
    target_url: str = "",
    status: int = 200,
    headers: Optional[Dict[str, str]] = None,
    fetch_ok: bool = True,
) -> BotDetectionReport:
    path = Path(html_path)
    body = path.read_bytes()
    return analyze(
        target_url or f"file://{path.resolve()}",
        status=status,
        headers=headers or {},
        body=body,
        fetch_ok=fetch_ok,
        final_url=target_url or str(path),
    )
