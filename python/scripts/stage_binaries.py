#!/usr/bin/env python3
"""Copy BW-Fetcher binary (+ runtime libs) into bw_fetcher_py/_bin/."""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PKG_ROOT = Path(__file__).resolve().parents[1]
DEST = PKG_ROOT / "bw_fetcher_py" / "_bin"

sys.path.insert(0, str(PKG_ROOT))
from bw_fetcher_py.binary_names import candidate_names, native_binary_name  # noqa: E402
from bw_fetcher_py._locate import _latest_stamp_build  # noqa: E402

if sys.platform == "win32":
    DLLS = ["brotlicommon.dll", "brotlidec.dll", "nghttp2.dll", "zlib1.dll"]
else:
    DLLS = []

DEFAULT_BUILD = _latest_stamp_build() or (
    REPO_ROOT / "cmake-build-release-visual-studio"
    if sys.platform == "win32"
    else REPO_ROOT / "build"
)


def find_built_exe(build: Path) -> Path:
    for name in candidate_names():
        p = build / name
        if p.is_file():
            return p
    tried = ", ".join(candidate_names())
    raise FileNotFoundError(
        f"none of {{{tried}}} found in {build} — build: cmake --build ... --target BW_Fetcher"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default=str(DEFAULT_BUILD))
    args = ap.parse_args()

    build = Path(args.build_dir)
    try:
        src_exe = find_built_exe(build)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    staged_name = native_binary_name()
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True, exist_ok=True)

    dst_exe = DEST / staged_name
    shutil.copy2(src_exe, dst_exe)
    dst_exe.chmod(0o755)
    print(f"staged {staged_name} -> {DEST}")

    missing = []
    for dll in DLLS:
        src = build / dll
        if src.is_file():
            shutil.copy2(src, DEST / dll)
            print(f"staged {dll}")
        else:
            missing.append(dll)
    if missing:
        print(f"warning: missing DLLs: {', '.join(missing)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
