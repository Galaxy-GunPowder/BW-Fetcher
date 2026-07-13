"""Locate the BW-Fetcher native binary."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from .binary_names import candidate_names, native_binary_name

_DEV_BUILD_DIRS = (
    ["cmake-build-release-visual-studio", "build-win"]
    if sys.platform == "win32"
    else ["build", "cmake-build-release", "cmake-build-debug"]
)

_PLATFORM_PREFIX = "BW-Fetcher_windows_" if sys.platform == "win32" else "BW-Fetcher_linux_"
_LATEST_POINTER = "latest_windows.txt" if sys.platform == "win32" else "latest_linux.txt"


def _bundled_exe() -> Path:
    return Path(__file__).resolve().parent / "_bin" / native_binary_name()


def _latest_stamp_build() -> Path | None:
    repo_root = Path(__file__).resolve().parents[2]
    builds = repo_root / "builds"

    latest = builds / _LATEST_POINTER
    if latest.is_file():
        p = Path(latest.read_text(encoding="utf-8").strip())
        if p.is_dir():
            return p

    # legacy pointer
    legacy = builds / "latest.txt"
    if legacy.is_file():
        p = Path(legacy.read_text(encoding="utf-8").strip())
        if p.is_dir():
            return p

    if builds.is_dir():
        prefixes = (_PLATFORM_PREFIX, "BW-Fetcher_")
        candidates = sorted(
            (
                d for d in builds.iterdir()
                if d.is_dir() and any(d.name.startswith(p) for p in prefixes)
            ),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            return candidates[0]
    return None


def _dev_build_exes() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[2]
    paths: list[Path] = []
    stamp_dir = _latest_stamp_build()
    if stamp_dir:
        for name in candidate_names():
            paths.append(stamp_dir / name)
    for d in _DEV_BUILD_DIRS:
        build_dir = repo_root / d
        for name in candidate_names():
            paths.append(build_dir / name)
    return paths


def find_exe(explicit: Optional[str] = None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("BW_FETCHER_EXE")
    if env:
        candidates.append(Path(env))
    candidates.append(_bundled_exe())
    candidates.extend(_dev_build_exes())

    for c in candidates:
        if c.is_file():
            return c

    for name in candidate_names():
        on_path = shutil.which(name)
        if on_path:
            return Path(on_path)

    script = "build_cpp_windows.ps1" if sys.platform == "win32" else "build_cpp_linux.sh"
    raise FileNotFoundError(
        f"{native_binary_name()} not found. Run scripts/{script}, "
        "scripts/stage_binaries.py, or set BW_FETCHER_EXE."
    )
