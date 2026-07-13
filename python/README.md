# bw-fetcher-py

Python wrapper + bot-detection for **BW-Fetcher** (C++ TLS-fingerprint HTTP/2 fetcher).

## For users (everyone installs this way)

```bash
pip install bw-fetcher-py
```

That downloads from **PyPI** (Python’s package index). PyPI stores **wheels** (`.whl`) — prebuilt install packages. Users never build anything; `pip` picks the Windows or Linux wheel automatically.

You only need to **upload** wheels to PyPI when you publish a release (GitHub Actions does this on `v*` tags — see `.github/workflows/release.yml`).

## For developers (you — no wheels needed locally)

See [RELEASING.md](RELEASING.md) for **GitHub** vs **GitLab** CI (separate YAML files, separate job names; same PyPI package).

```powershell
# 1. C++ Windows binary
.\scripts\build_cpp_windows.ps1

# 2. Copy exe into the Python package
python python\scripts\stage_binaries.py

# 3. Editable install (live .py edits, uses staged exe)
pip install -e D:\C++\BW_Fetcher\python
```

Or skip staging and point at the build folder:

```powershell
$env:BW_FETCHER_EXE = "D:\C++\BW_Fetcher\builds\BW-Fetcher_windows_...\BW-Fetcher-win64.exe"
pip install -e D:\C++\BW_Fetcher\python
```

## Build scripts (local)

| Script | What |
|--------|------|
| `scripts/build_cpp_windows.ps1` | C++ → `builds/BW-Fetcher_windows_.../` |
| `scripts/build_cpp_linux.sh` | C++ on Linux (for CI / release) |

Pointer: `builds/latest_windows.txt` (or `latest_linux.txt` on Linux).

## CLI

```bash
bw-fetcher-py https://example.com -o page.html
bw-fetcher-py https://example.com --report
```

```python
from bw_fetcher_py import fetch, probe
```
