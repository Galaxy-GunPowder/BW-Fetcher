"""Platform-specific shipped binary names (must match CMake OUTPUT_NAME)."""
from __future__ import annotations

import sys

BINARY_WIN = "BW-Fetcher-win64.exe"
BINARY_LINUX = "BW-Fetcher-linux64"


def native_binary_name() -> str:
    return BINARY_WIN if sys.platform == "win32" else BINARY_LINUX


def candidate_names() -> tuple[str, ...]:
    name = native_binary_name()
    return (name,)
