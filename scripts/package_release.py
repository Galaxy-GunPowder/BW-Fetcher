#!/usr/bin/env python3
"""Package a built BW_Fetcher binary into a *download-&-run* archive.

This is the non-Python distribution path: the user grabs one archive from the
GitHub release, unpacks it, and runs the binary. No compiler, no pip, nothing to
build.

    Windows -> BW_Fetcher-<ver>-windows-x64.zip
                 BW_Fetcher-<ver>-windows-x64/
                   BW-Fetcher-win64.exe  + the 4 runtime DLLs  + README + LICENSE

    Linux   -> BW_Fetcher-<ver>-linux-x64.tar.gz
                 BW_Fetcher-<ver>-linux-x64/
                   bin/BW-Fetcher-linux64   (the real ELF binary)
                   lib/*.so*               (bundled non-glibc deps)
                   bw-fetcher              (launcher: sets LD_LIBRARY_PATH)
                   README + LICENSE

The Linux launcher exists because the binary links libnghttp2/brotli/zlib which
a fresh box may not have. We bundle those `.so` files next to the binary and
point `LD_LIBRARY_PATH` at them, leaving only the glibc core (always present) to
the system. This mirrors what `auditwheel` does for the wheel, minus the
manylinux retagging.

Usage:
    python scripts/package_release.py [--build-dir PATH] [--outdir PATH]

The version is read from python/pyproject.toml so it always matches the wheel.
"""
from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "python" / "pyproject.toml"
LICENSE = REPO_ROOT / "LICENSE"
README = REPO_ROOT / "README.md"
PYTHON_PKG = REPO_ROOT / "python"

sys.path.insert(0, str(PYTHON_PKG))
from bw_fetcher_py.binary_names import candidate_names, native_binary_name  # noqa: E402

# Windows runtime DLLs that vcpkg's applocal step drops next to the exe.
WIN_DLLS = ["brotlicommon.dll", "brotlidec.dll", "nghttp2.dll", "zlib1.dll"]

# Shared libraries the system always provides (glibc + loader + libstdc++/gcc are
# left to the system would be risky, so we DO bundle libstdc++/libgcc_s). Only
# the genuine glibc core is excluded from bundling.
LINUX_SKIP_LIBS = (
    "linux-vdso",
    "ld-linux",
    "libc.so",
    "libm.so",
    "libpthread.so",
    "libdl.so",
    "librt.so",
    "libresolv.so",
)


def read_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        sys.exit(f"error: could not find version in {PYPROJECT}")
    return m.group(1)


def default_build_dir() -> Path:
    if sys.platform == "win32":
        return REPO_ROOT / "cmake-build-release-visual-studio"
    return REPO_ROOT / "build"


def find_built_binary(build: Path) -> Path:
    for name in candidate_names():
        p = build / name
        if p.is_file():
            return p
    tried = ", ".join(candidate_names())
    sys.exit(f"error: none of {{{tried}}} found in {build} — build BW_Fetcher first")


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
def package_windows(build: Path, staging: Path) -> None:
    exe = find_built_binary(build)
    staged = staging / native_binary_name()
    shutil.copy2(exe, staged)

    missing = []
    for dll in WIN_DLLS:
        src = build / dll
        if src.is_file():
            shutil.copy2(src, staging / dll)
        else:
            missing.append(dll)
    if missing:
        print(f"warning: DLLs missing from build dir: {', '.join(missing)}",
              file=sys.stderr)


# --------------------------------------------------------------------------- #
# Linux
# --------------------------------------------------------------------------- #
def _ldd_deps(binary: Path) -> list[Path]:
    """Resolve the shared libraries a binary needs (via ldd), minus the glibc
    core. Returns absolute paths to the .so files to bundle."""
    try:
        out = subprocess.run(["ldd", str(binary)], capture_output=True,
                             text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"warning: ldd failed ({e}); shipping binary without bundled libs",
              file=sys.stderr)
        return []

    deps: list[Path] = []
    for line in out.splitlines():
        # lines look like:  libnghttp2.so.14 => /lib/x86_64-linux-gnu/libnghttp2.so.14 (0x...)
        if "=>" not in line:
            continue
        name, _, rest = line.strip().partition("=>")
        name = name.strip()
        if any(name.startswith(skip) for skip in LINUX_SKIP_LIBS):
            continue
        path = rest.strip().split(" (")[0].strip()
        if path and os.path.exists(path):
            deps.append(Path(path))
    return deps


def package_linux(build: Path, staging: Path) -> None:
    binary = find_built_binary(build)

    bindir = staging / "bin"
    libdir = staging / "lib"
    bindir.mkdir()
    libdir.mkdir()

    bin_name = native_binary_name()
    dst_bin = bindir / bin_name
    shutil.copy2(binary, dst_bin)
    dst_bin.chmod(0o755)

    for so in _ldd_deps(binary):
        shutil.copy2(so, libdir / so.name)
        print(f"bundled lib: {so.name}")

    launcher = staging / "BW-Fetcher-linux64"
    launcher.write_text(
        '#!/bin/sh\n'
        '# Self-contained launcher for BW-Fetcher (Linux).\n'
        'HERE="$(cd "$(dirname "$0")" && pwd)"\n'
        'export LD_LIBRARY_PATH="$HERE/lib:$LD_LIBRARY_PATH"\n'
        f'exec "$HERE/bin/{bin_name}" "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)


# --------------------------------------------------------------------------- #
# Archive helpers
# --------------------------------------------------------------------------- #
def make_zip(staging: Path, archive: Path) -> None:
    root = staging.name
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, Path(root) / path.relative_to(staging))


def make_tar_gz(staging: Path, archive: Path) -> None:
    # arcname keeps the top-level folder so extraction is tidy; preserves the
    # exec bits we set on the binary + launcher.
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(staging, arcname=staging.name)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default=str(default_build_dir()),
                    help=f"CMake build directory (default: {default_build_dir()})")
    ap.add_argument("--outdir", default=str(REPO_ROOT / "release"),
                    help="where to write the archive (default: ./release)")
    args = ap.parse_args()

    build = Path(args.build_dir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    version = read_version()
    is_win = sys.platform == "win32"
    osname = "windows" if is_win else "linux"
    arch = "x64" if platform.machine().lower() in ("amd64", "x86_64") else platform.machine().lower()
    name = f"BW_Fetcher-{version}-{osname}-{arch}"

    staging = outdir / name
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    if is_win:
        package_windows(build, staging)
    else:
        package_linux(build, staging)

    # Drop README + LICENSE in every archive so it's self-documenting.
    for doc in (README, LICENSE):
        if doc.is_file():
            shutil.copy2(doc, staging / doc.name)

    if is_win:
        archive = outdir / f"{name}.zip"
        make_zip(staging, archive)
    else:
        archive = outdir / f"{name}.tar.gz"
        make_tar_gz(staging, archive)

    shutil.rmtree(staging)  # keep only the archive
    size_kb = archive.stat().st_size / 1024
    print(f"-> {archive}  ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
